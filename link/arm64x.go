package link

import (
	"sort"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// An ARM64X image is one file with two interpretations, and the difference
// between them is not stored twice. It is stored once, as a table of fixups
// the kernel applies while mapping when the loading process is an emulated x64
// one — so the file carries one COFF header, one data directory array, one of
// everything, and a list of the words that would have to change.
//
// The canonical example is the machine field. The header literally holds
// 0xAA64, which is what a native ARM64 process needs to see. A single VALUE
// fixup over those two bytes writes 0x8664, and an emulated process therefore
// finds an AMD64 module. Nothing was duplicated; two bytes were described.
//
// The same mechanism carries everything else the views disagree about: the
// entry point, the load configuration directory's address and size, and the
// export and exception directories when the two halves of the image have their
// own. All of those live in the headers, at RVA 0, which is why almost every
// fixup this pass emits lands in a single page block.
//
// Two things make this the last structural decision the tree has to make.
// The fixups patch bytes emit has not written when layout runs, so the table
// has to be *sized* before the values are knowable — the same circularity
// image.Synthetic exists for, one step further out, since here even Generate
// is too early. And the table lives in .reloc, after the base relocation
// blocks, reachable only through two fields of the load configuration.

// arm64x is the dynamic value relocation table.
type arm64x struct {
	l *Linker

	entries  []format.ARM64XEntry
	pageRVA  pe.RVA
	reserved uint32
	written  uint32
	chunk    *image.Chunk
}

func (a *arm64x) Size() uint32           { return a.reserved }
func (a *arm64x) Align() int             { return 4 }
func (a *arm64x) Bytes() ([]byte, error) { return make([]byte, a.reserved), nil }

// Prepare reserves space for the table.
//
// The count is known here even though the values are not: the fixups are one
// per header word the views can disagree about, and which words those are is a
// property of the format rather than of this link. So the reservation is exact
// in the number of entries and generous in their width — every entry is sized
// as a VALUE with an eight-byte payload, which is the largest form — and
// Generate writes the real table into the front of it.
//
// Reserving rather than iterating is the same choice basereloc.go makes and
// for the same reason: growing a section after layout silently overlaps the
// next one, and the phases exist to make that impossible rather than unlikely.
func (a *arm64x) Prepare(img *image.Image) error {
	l := a.l
	if !img.Hybrid() {
		return nil
	}
	if err := a.checkCHPE(); err != nil {
		return err
	}

	const maxEntries = 8 // machine, entry point, and three directories' RVA/size pairs
	const maxEntrySize = 2 + 8

	w := l.opt.Target.Width()
	a.reserved = uint32(format.DynamicRelocTableHeaderSize +
		format.DynamicRelocSize(w) +
		format.BaseRelocBlockHeaderSize +
		maxEntries*maxEntrySize)
	a.reserved = (a.reserved + 3) &^ 3

	sec, err := l.section(".reloc", pe.SecInitData, pe.SecRead|pe.SecDiscardable)
	if err != nil {
		return err
	}
	a.chunk = image.NewChunk(".reloc", "<link>", a)
	a.chunk.Reachable = true
	if err := sec.Add(a.chunk); err != nil {
		return l.fail(err)
	}
	l.chunks = append(l.chunks, a.chunk)
	return nil
}

// checkCHPE requires the EC view's CHPE metadata.
//
// __chpe_metadata is what the emulator reads to find the auxiliary import
// table, the range tables, and the alternate entry point. An ARM64X image
// without it links, loads, and dispatches every cross-boundary call
// incorrectly — which is a runtime failure with no diagnostic anywhere, so
// this is a warning by default and an error under Options.Strict.
func (a *arm64x) checkCHPE() error {
	l := a.l
	if len(l.tabs) < 2 {
		return nil
	}
	s := l.tabs[1].Lookup("__chpe_metadata")
	if s != nil && s.Kind.rank() > SymWeakExternal.rank() {
		return nil
	}
	if !l.opt.Strict {
		l.warn("__chpe_metadata is missing from the EC view; " +
			"the image will not dispatch correctly across the ABI boundary")
		return nil
	}
	return l.fail(&UndefinedError{Name: "__chpe_metadata", Refs: []string{"<ec view>"}})
}

// Generate does nothing.
//
// It is here because Synthetic requires it and because its absence is the
// point: every value this table carries is a header field, and the headers are
// serialized by emit, which runs after every synthetic has generated. The
// table is written by Write, below, and the pipeline calls it between emit and
// the checksum.
func (a *arm64x) Generate(img *image.Image) error { return nil }

// Write builds the fixups and emits the table.
//
// It runs after emit and before the checksum. After emit because the bytes it
// describes do not exist until the headers are serialized — an offset into the
// COFF header is meaningless while the header is still a struct. Before the
// checksum because the checksum covers the file and this writes to it.
func (a *arm64x) Write() error {
	l := a.l
	if a.chunk == nil {
		return nil
	}
	native, ec := l.img.Native(), l.img.EC()
	if ec == nil {
		return nil
	}

	hdr, err := l.checksumOffset()
	if err != nil {
		return err
	}
	// The headers sit at RVA 0 and are copied to the file verbatim, so a
	// header field's file offset is its RVA. That equality is what lets
	// this describe a position in the mapped image using an offset it
	// computed against the buffer.
	base := uint32(hdr) - checksumFieldOffset - format.FileHeaderSize

	// The machine field: two bytes at the head of the COFF header. This is
	// the fixup the whole mechanism exists for.
	a.value(base+0, 2, uint64(ec.Machine))

	optOff := base + format.FileHeaderSize
	if native.Entry != ec.Entry {
		// AddressOfEntryPoint is at offset 16 of the optional header at
		// both widths — it is inside the standard fields, which PE32+
		// does not disturb.
		a.value(optOff+16, 4, uint64(ec.Entry))
	}

	dirOff := optOff + uint32(format.OptionalHeaderSize(l.opt.Target.Width(), 0))
	a.directory(dirOff, pe.DirLoadConfig, native.LoadConfig, ec.LoadConfig)
	a.directory(dirOff, pe.DirExport, native.Export, ec.Export)
	a.directory(dirOff, pe.DirException, native.Exception, ec.Exception)

	return a.emitTable()
}

// directory records the two fixups one data directory entry needs when the
// views disagree about it.
//
// Address and size are separate entries because they are separate words and
// the format has no fixup that writes eight bytes across a struct boundary.
// Emitting only the address is the mistake worth naming: the EC view would
// then find its own export directory described with the native one's length,
// and every name past that length would be missing.
func (a *arm64x) directory(dirOff uint32, i pe.DataDirIndex, nat, ec image.DirValue) {
	if nat == ec || ec.IsZero() {
		return
	}
	off := dirOff + uint32(int(i)*pe.DataDirSize)
	a.value(off+0, 4, uint64(ec.RVA))
	a.value(off+4, 4, uint64(ec.Size))
}

func (a *arm64x) value(off uint32, size int, v uint64) {
	a.entries = append(a.entries, format.ARM64XEntry{
		Offset: uint16(off & (pe.BaseRelocPageSize - 1)),
		Type:   format.ARM64XValue,
		Size:   size,
		Value:  int64(v),
	})
}

// emitTable writes the nested headers and the one page block.
//
// Every fixup this pass produces is in the headers, so they all share page
// zero and there is exactly one block. That is a property of what this tree
// currently diffs and not of the format: delay-load tables need DELTA fixups
// over entries scattered through .didat, and a general implementation groups
// by page the way basereloc.go does.
func (a *arm64x) emitTable() error {
	l := a.l
	if len(a.entries) == 0 {
		return nil
	}
	sort.SliceStable(a.entries, func(i, j int) bool {
		return a.entries[i].Offset < a.entries[j].Offset
	})

	w := l.opt.Target.Width()

	// The block first, because both enclosing headers state the size of
	// what they contain and the innermost thing is the only one whose size
	// is not a function of another's.
	blk := binio.NewBuf()
	for _, e := range a.entries {
		if err := format.EncodeARM64XEntry(blk, e); err != nil {
			return l.fail(err)
		}
	}
	blk.Align(pe.BaseRelocBlockAlign)
	body, err := blk.Data()
	if err != nil {
		return l.fail(err)
	}
	blockSize := uint32(format.BaseRelocBlockHeaderSize + len(body))

	b := binio.NewBufSize(int(a.reserved))
	tab := format.DynamicRelocTable{
		Version: format.DynamicRelocTableVersion,
		Size:    uint32(format.DynamicRelocSize(w)) + blockSize,
	}
	tab.Encode(b)
	rec := format.DynamicReloc{
		Symbol:        format.DynamicRelocARM64X,
		BaseRelocSize: blockSize,
	}
	rec.Encode(b, w)
	hdr := format.BaseRelocBlock{PageRVA: 0, BlockSize: blockSize}
	hdr.Encode(b)
	b.Bytes(body)

	data, err := b.Data()
	if err != nil {
		return l.fail(err)
	}
	if uint32(len(data)) > a.reserved {
		return l.fail(&image.LayoutError{
			Section: ".reloc",
			Reason:  "dynamic relocation table exceeded its reserved size",
		})
	}

	rva, err := a.chunk.RVA()
	if err != nil {
		return l.fail(err)
	}
	out, err := l.img.AtRVA(rva, int(a.reserved))
	if err != nil {
		return l.fail(err)
	}
	copy(out, data)
	a.written = uint32(len(data))
	return a.pointLoadConfig(rva)
}

// pointLoadConfig writes the table's position into the load configuration.
//
// It goes in as an offset and a one-based section index rather than as an RVA,
// which is the one place in this format where an address is spelled that way.
// The reason is that the DVRT is applied while the image is being mapped —
// before the base relocations, and therefore before an RVA in a mapped page
// means anything the kernel can use — so it is located by walking the section
// table instead.
//
// This is also the one place the linker writes into the load config directly.
// Everything else in that structure arrives through symbols the CRT's
// initializers reference, and this has no symbol convention because the value
// is not an address.
func (a *arm64x) pointLoadConfig(rva pe.RVA) error {
	l := a.l
	lc := l.loadcfg
	if lc == nil || lc.chunk == nil {
		return l.fail(&UndefinedError{
			Name: loadConfigSymbol(l.opt.Target.Machine),
			Refs: []string{"<arm64x>"},
		})
	}
	sec := l.img.SectionAt(rva)
	if sec == nil {
		return l.fail(&image.LayoutError{
			Section: ".reloc",
			Reason:  "dynamic relocation table is in no output section",
			RVA:     rva,
		})
	}
	secRVA, err := sec.RVA()
	if err != nil {
		return l.fail(err)
	}

	lcRVA, err := lc.sym.RVA()
	if err != nil {
		return l.fail(err)
	}
	buf, err := l.img.AtRVA(lcRVA, int(lc.declared))
	if err != nil {
		return l.fail(err)
	}
	view, err := format.NewLoadConfigView(buf, l.opt.Target.Width())
	if err != nil {
		return l.fail(err)
	}
	if !view.Has(format.LCDynamicValueRelocTableSection) {
		return l.fail(&image.LayoutError{
			Section: lc.chunk.Name,
			Reason: "load configuration declares " + itoa(int(lc.declared)) +
				" bytes, too few to locate the dynamic relocation table",
		})
	}
	view.SetU32(format.LCDynamicValueRelocTableOffset, uint32(rva-secRVA))
	view.SetU16(format.LCDynamicValueRelocTableSection, uint16(sec.Number()))
	return nil
}

// Dirs returns nothing.
//
// The dynamic relocation table has no data directory of its own: it is found
// through the load configuration and nowhere else, which is why an image whose
// load config predates those two fields cannot carry one at all.
func (a *arm64x) Dirs() []dirEntry { return nil }