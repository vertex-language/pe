package link

import (
	"sort"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/implib"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// .idata is four tables and one duplication.
//
// The import directory holds one descriptor per DLL and a zero descriptor to
// end it. Each descriptor points at two arrays of thunks that are *identical
// on disk*: the lookup table says what is imported, the address table is where
// the loader writes the answers, and before the image loads they hold the same
// bytes. That is why link builds one description and emits it twice, and why
// __imp_foo is a meaningful address in a file that has never been run.
//
// An import contributes one IAT slot and one or two symbols. __imp_foo names
// the slot; with __declspec(dllimport) the compiler emits an indirect call
// through it, which is the more efficient code and the PE analogue of ELF's
// -fno-plt. If the code instead calls the unprefixed foo, a thunk is retained
// that jumps through the slot. scan tracked those two liveness questions
// separately, which is why a dllimport-only program gets no thunks at all.
//
// Sizes are exact here. Every count is known once scan has run — how many
// DLLs, how many entries each, how long each name is — so this is the clean
// case for image.Synthetic's two steps: Prepare settles the size, Generate
// fills in the RVAs layout assigned.

// imports is the .idata synthetic. It owns the directory, both thunk tables,
// and the hint/name table.
type imports struct {
	l    *Linker
	dlls []*importDLL

	// The IAT is a chunk of its own because the IAT data directory has to
	// name it exactly: its RVA and its size, covering every slot and no
	// other table. A directory entry that overlapped the lookup table would
	// tell the loader to make the wrong pages writable.
	iat *image.Chunk

	// rest holds the directory, the lookup tables, and the names, in that
	// order. They are one chunk because nothing needs to name them
	// individually and one chunk is one placement decision.
	rest *image.Chunk

	iatSize  uint32
	restSize uint32

	dirOff  uint32
	iltOff  uint32
	nameOff uint32
}

// importDLL is one DLL and the entries the image actually uses.
type importDLL struct {
	dll     string
	entries []*importEntry

	// Offsets within their tables, assigned by Prepare and unchanged after.
	iatOff  uint32
	iltOff  uint32
	nameOff uint32 // the DLL's own name, within the name blob
}

// importEntry is one imported symbol.
type importEntry struct {
	entry implib.Entry

	// slot is __imp_$sym, defined at this entry's position in the IAT.
	slot *image.Symbol

	// thunk is the chunk holding the jump through the slot, or nil when
	// nothing referenced the unprefixed name.
	thunk *image.Chunk

	// hintOff is this entry's position in the hint/name blob, or zero for
	// an import by ordinal, which has no name at all.
	hintOff uint32
}

func (e *importEntry) byOrdinal() bool { return e.entry.NameKind == implib.NameOrdinal }

// Size, Align, and Bytes are the ChunkSource half of the synthetic. The
// interface is satisfied by two small adapters rather than by this type,
// because it owns two chunks and a ChunkSource owns one.
type importPart struct {
	size uint32
}

func (p *importPart) Size() uint32           { return p.size }
func (p *importPart) Align() int             { return 4 }
func (p *importPart) Bytes() ([]byte, error) { return make([]byte, p.size), nil }

// addGNUImportTerminator appends the all-zero import descriptor that
// terminates a GNU-style .idata$2 table, if one is needed and not already
// present.
//
// A GNU import library contributes only real descriptors: dlltool's "head"
// object per DLL provides one .idata$2 entry and nothing supplies the
// null-descriptor the loader's walk stops on. GNU ld's own linker script
// closes that gap by appending five zero longs after every real one,
// unconditionally — this is the one line of that script this tree has no
// other way to run, since it has no linker script at all. Without it, a
// loader walking the descriptor table past the real entries reads whatever
// bytes follow — the hint/name table — as more descriptors.
//
// It must run before merge groups chunks into sections, since the new
// chunk's $3 suffix is what places it right after $2 and before $4.
func (l *Linker) addGNUImportTerminator() {
	haveDescriptor, haveTerminator := false, false
	for _, c := range l.chunks {
		if !c.Live() {
			continue
		}
		switch c.Name {
		case ".idata$2":
			haveDescriptor = true
		case ".idata$3":
			haveTerminator = true
		}
	}
	if !haveDescriptor || haveTerminator {
		return
	}
	term := image.NewChunk(".idata$3", "<link>", &importPart{size: format.ImportDescriptorSize})
	term.Reachable = true
	l.chunks = append(l.chunks, term)
}

// Size reports the whole synthetic's footprint, for a caller inspecting the
// link. The chunks carry their own sizes.
func (im *imports) Size() uint32           { return im.iatSize + im.restSize }
func (im *imports) Align() int             { return 4 }
func (im *imports) Bytes() ([]byte, error) { return nil, nil }

// Prepare collects the live imports, lays the tables out, and defines every
// __imp_ symbol against its slot.
func (im *imports) Prepare(img *image.Image) error {
	l := im.l
	if err := im.collect(); err != nil {
		return err
	}
	if len(im.dlls) == 0 {
		return nil
	}

	word := uint32(format.ThunkDataSize(l.opt.Target.Width()))

	// The IAT: every DLL's slots, each run terminated by a zero entry. The
	// terminator is per DLL and not per table, because a descriptor points
	// at the start of its own run and the loader walks to the zero.
	var iatSize uint32
	for _, d := range im.dlls {
		d.iatOff = iatSize
		iatSize += uint32(len(d.entries)+1) * word
	}
	im.iatSize = iatSize

	// The rest: directory, then the lookup tables, then the names.
	im.dirOff = 0
	im.iltOff = uint32(len(im.dlls)+1) * format.ImportDescriptorSize

	off := im.iltOff
	for _, d := range im.dlls {
		d.iltOff = off
		off += uint32(len(d.entries)+1) * word
	}

	im.nameOff = off
	for _, d := range im.dlls {
		for _, e := range d.entries {
			if e.byOrdinal() {
				continue
			}
			e.hintOff = off
			off += uint32(format.HintNameSize(e.entry.Exported()))
		}
		d.nameOff = off
		off += uint32(len(d.dll) + 1)
	}
	// The DLL names are ASCII and unpadded, so the blob can end odd. The
	// chunk's own alignment covers the next chunk; nothing inside reads
	// past here.
	im.restSize = off

	sec, err := l.section(".idata", pe.SecInitData, pe.SecRead|pe.SecWrite)
	if err != nil {
		return err
	}

	im.iat = image.NewChunk(".idata", "<link>", &importPart{size: im.iatSize})
	im.iat.Reachable = true
	if err := sec.Add(im.iat); err != nil {
		return l.fail(err)
	}
	l.chunks = append(l.chunks, im.iat)

	im.rest = image.NewChunk(".idata", "<link>", &importPart{size: im.restSize})
	im.rest.Reachable = true
	if err := sec.Add(im.rest); err != nil {
		return l.fail(err)
	}
	l.chunks = append(l.chunks, im.rest)

	return im.defineSymbols(word)
}

// collect groups the live imports by DLL, in the order the IAT slots were
// recorded.
//
// The order is not cosmetic. Reqs hands back its slices in recording order,
// which is the order the slots are laid out, and the import name table has to
// match it entry for entry — the loader reads the n-th name to fill the n-th
// slot. Sorting either one alone binds every import to the wrong address.
func (im *imports) collect() error {
	l := im.l
	byDLL := make(map[string]*importDLL)
	seen := make(map[*image.Symbol]bool)

	wanted := func(sym *image.Symbol) (*Sym, bool) {
		s := l.symOf[sym]
		if s == nil || s.Kind != SymImport || s.imp == nil {
			return nil, false
		}
		return s, true
	}

	for _, sym := range l.reqs.IATSlots() {
		if seen[sym] {
			continue
		}
		seen[sym] = true

		s, ok := wanted(sym)
		if !ok {
			continue
		}
		entry, found := findEntry(s.imp, s.Name)
		if !found {
			// A slot whose import record no longer names it. resolve
			// created both, so this is a linker bug rather than a bad
			// input, and it would otherwise surface as an IAT entry
			// pointing at nothing.
			return l.fail(&InputError{Name: s.Name, Err: implib.ErrBadMember})
		}

		d := byDLL[s.imp.DLL]
		if d == nil {
			d = &importDLL{dll: s.imp.DLL}
			byDLL[s.imp.DLL] = d
			im.dlls = append(im.dlls, d)
		}
		d.entries = append(d.entries, &importEntry{entry: entry, slot: sym})
	}

	// Thunks are matched to the slots collected above rather than gathered
	// separately, so a thunk can never name a slot that does not exist.
	need := make(map[string]bool)
	for _, sym := range l.reqs.ImportThunks() {
		s, ok := wanted(sym)
		if !ok {
			continue
		}
		if !isImpName(s.Name) {
			need[s.imp.DLL+"\x00"+s.Name] = true
		}
	}
	for _, d := range im.dlls {
		for _, e := range d.entries {
			if need[d.dll+"\x00"+e.entry.Symbol] {
				e.thunk = image.NewChunk(".text", "<link>", nil)
			}
		}
	}
	return nil
}

// findEntry locates the import record behind an __imp_ name.
func findEntry(imp *Import, name string) (implib.Entry, bool) {
	want := name
	if isImpName(want) {
		want = want[len(impPrefix):]
	}
	for _, e := range imp.Entries {
		if e.Symbol == want {
			return e, true
		}
	}
	return implib.Entry{}, false
}

// defineSymbols binds __imp_$sym to its slot, and $sym to its thunk.
//
// The thunk chunks are created here rather than in collect, because a chunk
// needs its size and the size comes from the backend's shape. Each is a
// separate chunk so that /OPT:REF can drop one whose caller was swept — which
// it cannot today, since sweep has already run, but which costs nothing to
// keep true.
func (im *imports) defineSymbols(word uint32) error {
	l := im.l
	tab := l.tabs[0]
	shape := l.be.ImportThunk()

	var text *image.Section
	for _, d := range im.dlls {
		for i, e := range d.entries {
			off := d.iatOff + uint32(i)*word
			tab.view.Symbols.Define("__imp_"+e.entry.Symbol, im.iat, off)
			if s := tab.Lookup("__imp_" + e.entry.Symbol); s != nil {
				s.chunk, s.off, s.Kind = im.iat, off, SymDefined
			}

			if e.thunk == nil {
				continue
			}
			if text == nil {
				var err error
				text, err = l.section(".text", pe.SecCode,
					pe.SecExecute|pe.SecRead)
				if err != nil {
					return err
				}
			}
			c := image.NewChunk(".text", "<import thunk>",
				&importPart{size: uint32(shape.Size())})
			c.Reachable = true
			if err := text.Add(c); err != nil {
				return l.fail(err)
			}
			l.chunks = append(l.chunks, c)
			e.thunk = c

			tab.view.Symbols.Define(e.entry.Symbol, c, 0)
			if s := tab.Lookup(e.entry.Symbol); s != nil {
				s.chunk, s.off, s.Kind = c, 0, SymDefined
			}
		}
	}
	return nil
}

// Generate writes the tables. It runs frozen, so every RVA is final.
func (im *imports) Generate(img *image.Image) error {
	if im.rest == nil {
		return nil
	}
	l := im.l
	w := l.opt.Target.Width()
	word := uint32(format.ThunkDataSize(w))

	iatRVA, err := im.iat.RVA()
	if err != nil {
		return err
	}
	restRVA, err := im.rest.RVA()
	if err != nil {
		return err
	}

	// The directory and the lookup tables.
	b := binio.NewBufSize(int(im.restSize))
	for _, d := range im.dlls {
		desc := format.ImportDescriptor{
			ImportLookupTableRVA:  uint32(restRVA) + d.iltOff,
			NameRVA:               uint32(restRVA) + d.nameOff,
			ImportAddressTableRVA: uint32(iatRVA) + d.iatOff,
			// TimeDateStamp and ForwarderChain stay zero: this tree
			// never binds, and a stale binding is worse than none.
		}
		desc.Encode(b)
	}
	(&format.ImportDescriptor{}).Encode(b) // the terminator

	for _, d := range im.dlls {
		for _, e := range d.entries {
			im.thunkData(e, restRVA).Encode(b, w)
		}
		(&format.ThunkData{}).Encode(b, w)
	}

	for _, d := range im.dlls {
		for _, e := range d.entries {
			if e.byOrdinal() {
				continue
			}
			hn := format.HintName{Hint: 0, Name: e.entry.Exported()}
			hn.Encode(b)
		}
		b.CStr(d.dll)
	}

	data, err := b.Data()
	if err != nil {
		return err
	}
	if err := writeAt(img, restRVA, im.restSize, data); err != nil {
		return err
	}

	// The address table is the lookup table again, byte for byte. Building
	// it from the same description rather than copying the bytes keeps the
	// two from drifting if one ever gains a field the other does not.
	ib := binio.NewBufSize(int(im.iatSize))
	for _, d := range im.dlls {
		for _, e := range d.entries {
			im.thunkData(e, restRVA).Encode(ib, w)
		}
		(&format.ThunkData{}).Encode(ib, w)
	}
	idata, err := ib.Data()
	if err != nil {
		return err
	}
	if err := writeAt(img, iatRVA, im.iatSize, idata); err != nil {
		return err
	}

	return im.writeThunks(img, iatRVA, word)
}

// thunkData is one entry of either table.
//
// The high bit is the ordinal flag — bit 31 under PE32 and bit 63 under
// PE32+, which is Width doing real work rather than describing something. With
// it clear the rest is an RVA to a hint/name pair.
func (im *imports) thunkData(e *importEntry, restRVA pe.RVA) *format.ThunkData {
	if e.byOrdinal() {
		return &format.ThunkData{ByOrdinal: true, Ordinal: e.entry.Ordinal}
	}
	return &format.ThunkData{HintNameRVA: uint32(restRVA) + e.hintOff}
}

// writeThunks emits each retained thunk's code.
func (im *imports) writeThunks(img *image.Image, iatRVA pe.RVA, word uint32) error {
	shape := im.l.be.ImportThunk()
	for _, d := range im.dlls {
		for i, e := range d.entries {
			if e.thunk == nil {
				continue
			}
			site, err := backend.NewSite(img, e.thunk)
			if err != nil {
				return err
			}
			slot := iatRVA.Add(d.iatOff + uint32(i)*word)
			if err := shape.Write(site, slot); err != nil {
				return im.l.fail(&OverflowError{Input: e.thunk.Input, Err: err})
			}
		}
	}
	return nil
}

// Dirs returns the data directory entries this synthetic fills: the import
// directory and the IAT.
//
// The IAT has an entry of its own because the loader makes those pages
// writable to fill them and read-only afterwards, and it needs to know exactly
// which pages those are. It is the one data directory that describes a
// permission rather than a structure.
func (im *imports) Dirs() []dirEntry {
	var dirs []dirEntry
	if im.rest != nil {
		restRVA, err := im.rest.RVA()
		if err != nil {
			return nil
		}
		iatRVA, err := im.iat.RVA()
		if err != nil {
			return nil
		}
		dirs = []dirEntry{
			{pe.DirImport, restRVA, uint32(len(im.dlls)+1) * format.ImportDescriptorSize},
			{pe.DirIAT, iatRVA, im.iatSize},
		}
	} else {
		// im.rest is nil when nothing pulled in an MS-style short-import
		// member, which is also true of a link that imports nothing at
		// all — and of one that imports only through GNU-style import
		// libraries. Those route their import descriptor and IAT
		// content through the ordinary $-group section merge instead of
		// through this synthetic: .idata$2 for the descriptor table,
		// .idata$5 for the IAT, exactly the convention dlltool's
		// generated members use. The bytes land correctly either way
		// merge.go groups them — what a plain section merge cannot do
		// on its own is tell the loader where to find them, since the
		// loader reads the data directory and never guesses from
		// section names the way a disassembler's heuristics do.
		dirs = gnuImportDirs(im.l, ".idata", gnuImportDirSpec{Descriptor: pe.DirImport, IAT: pe.DirIAT, HasIAT: true})
	}

	// A GNU delay-import archive (dlltool -y) uses the identical
	// convention one letter over: .didat$2 through .didat$7, merged into
	// a .didat section rather than .idata. It is checked unconditionally,
	// independent of which branch above ran, because nothing stops a
	// link from mixing an MS-format regular import library with a GNU
	// delay-import one. Nothing downstream of merge tells .idata and
	// .didat apart — chunkRank's .idata$4/.idata$5 special case in
	// merge.go already covers .didat$4/.didat$5 the same way — so the one
	// thing still missing once a .didat section exists is telling the
	// loader where it is, which is what this adds.
	dirs = append(dirs, gnuImportDirs(im.l, ".didat", gnuImportDirSpec{Descriptor: pe.DirDelayImport})...)
	return dirs
}

// gnuImportDirSpec names the directory indices a GNU-shaped import section
// registers: Descriptor always does, IAT only for a regular import section —
// a delay-import directory's size covers only the descriptor array, since
// the descriptor itself carries the IAT's address and nothing reads its
// extent from the data directory the way the loader does for DirIAT.
type gnuImportDirSpec struct {
	Descriptor pe.DataDirIndex
	IAT        pe.DataDirIndex
	HasIAT     bool
}

// gnuImportDirs derives the import and IAT directory entries from a
// GNU-style import section (.idata or .didat) by finding the RVA extent of
// its $2 (descriptor) and $5 (IAT) contributions.
func gnuImportDirs(l *Linker, secName string, spec gnuImportDirSpec) []dirEntry {
	var sec *image.Section
	for _, s := range l.img.Sections() {
		if s.Name == secName {
			sec = s
			break
		}
	}
	if sec == nil {
		return nil
	}
	// The descriptor table is $2 plus the $3 terminator
	// addGNUImportTerminator ensures exists alongside it for a regular
	// import section. A delay-import section has no $3: its directory
	// entry's own Size says how many descriptors there are, so the loader
	// never needs a null terminator to know where the table ends.
	descNames := []string{secName + "$2"}
	if spec.HasIAT {
		descNames = append(descNames, secName+"$3")
	}
	descRVA, descSize, ok1 := chunkRangeByName(sec, descNames...)
	if !ok1 {
		return nil
	}
	dirs := []dirEntry{{spec.Descriptor, descRVA, descSize}}
	if spec.HasIAT {
		iatRVA, iatSize, ok2 := chunkRangeByName(sec, secName+"$5")
		if !ok2 {
			return nil
		}
		dirs = append(dirs, dirEntry{spec.IAT, iatRVA, iatSize})
	}
	return dirs
}

// chunkRangeByName returns the RVA and total size spanned by every live
// chunk in sec whose full (un-grouped) name matches one of names. Chunks
// contributing to one $-group are placed contiguously by merge's sort, so
// the range is a single run, but it is computed as a min/max over every
// match rather than assumed contiguous, which costs nothing and does not
// depend on that staying true.
func chunkRangeByName(sec *image.Section, names ...string) (rva pe.RVA, size uint32, ok bool) {
	var start, end pe.RVA
	matches := func(n string) bool {
		for _, want := range names {
			if n == want {
				return true
			}
		}
		return false
	}
	for _, c := range sec.Chunks() {
		if !matches(c.Name) || !c.Live() {
			continue
		}
		crva, err := c.RVA()
		if err != nil {
			continue
		}
		cend := crva + pe.RVA(c.Size())
		if !ok || crva < start {
			start = crva
		}
		if cend > end {
			end = cend
		}
		ok = true
	}
	return start, uint32(end - start), ok
}

// dirEntry is one data directory this synthetic is responsible for. fill
// collects them rather than each synthetic writing into Dirs itself, so that
// the directories are filled in one place and at one time.
type dirEntry struct {
	Index pe.DataDirIndex
	RVA   pe.RVA
	Size  uint32
}

// writeAt copies a synthetic's bytes into the frozen image.
func writeAt(img *image.Image, rva pe.RVA, size uint32, data []byte) error {
	if uint32(len(data)) != size {
		return &image.LayoutError{
			Reason: "synthetic generated a size different from the one it reserved",
			RVA:    rva,
		}
	}
	out, err := img.AtRVA(rva, int(size))
	if err != nil {
		return err
	}
	copy(out, data)
	return nil
}

// sortDLLs orders the import directory by DLL name.
//
// Nothing requires it — the loader walks the descriptors in order and stops at
// the terminator — but link.exe emits them sorted, and a byte diff against its
// output that differs only in descriptor order is a diff nobody reads past.
func sortDLLs(dlls []*importDLL) {
	sort.SliceStable(dlls, func(i, j int) bool { return dlls[i].dll < dlls[j].dll })
}