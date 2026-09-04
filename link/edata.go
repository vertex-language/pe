package link

import (
	"sort"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// .edata is three parallel tables and one indirection.
//
// The export address table is indexed by ordinal minus the ordinal base and
// holds an RVA per slot, gaps included. The name pointer table holds RVAs to
// names, sorted, so the loader can binary search it. The ordinal table runs
// alongside the name pointers and gives, for each one, the index into the
// address table — so a lookup by name finds a position in the name table and
// reads the answer out of the ordinal table at the same position.
//
// Getting those two out of step produces a DLL that dumpbin renders correctly
// and GetProcAddress cannot use, which is why they are built from one sorted
// list rather than sorted separately.
//
// A forwarder is not a flag. It is an export whose address RVA falls *inside
// the export directory's own range*, where the bytes are a "OTHER.func"
// string. That is the only way the format distinguishes one, and it means the
// forwarder strings have to be placed inside .edata and the directory's size
// has to cover them — a constraint this asserts rather than assumes.

// exports is the .edata synthetic.
type exports struct {
	l *Linker

	// slots is the address table: one entry per ordinal from base upward,
	// with holes for ordinals nobody claimed.
	slots []exportSlot

	// named is the exports that carry a name, sorted by it.
	named []*exportSlot

	base  uint32
	chunk *image.Chunk
	size  uint32

	addrOff  uint32
	nameOff  uint32
	ordOff   uint32
	strOff   uint32
	dllOff   uint32
}

// exportSlot is one entry of the address table.
type exportSlot struct {
	name    string // the exported name, empty for a gap or a NONAME export
	ordinal uint32
	sym     *image.Symbol

	// forward is the "OTHER.func" string for a forwarder, empty otherwise.
	// A slot has either a symbol or a forwarder and never both.
	forward string

	nameStrOff uint32
	fwdStrOff  uint32
	used       bool
}

func (e *exports) Size() uint32           { return e.size }
func (e *exports) Align() int             { return 4 }
func (e *exports) Bytes() ([]byte, error) { return make([]byte, e.size), nil }

// Prepare assigns ordinals, lays the tables out, and reserves the chunk.
func (e *exports) Prepare(img *image.Image) error {
	l := e.l
	if len(l.opt.Exports) == 0 {
		return nil
	}
	if err := e.assignOrdinals(); err != nil {
		return err
	}

	n := uint32(len(e.slots))
	m := uint32(len(e.named))

	e.addrOff = format.ExportDirectorySize
	e.nameOff = e.addrOff + n*format.ExportAddressSize
	e.ordOff = e.nameOff + m*format.ExportNamePointerSize
	e.strOff = e.ordOff + m*format.ExportOrdinalSize

	off := e.strOff
	e.dllOff = off
	off += uint32(len(l.outputName()) + 1)

	for _, s := range e.named {
		s.nameStrOff = off
		off += uint32(len(s.name) + 1)
	}
	// Forwarder strings go last and, crucially, inside this chunk. An
	// export forwards if and only if its address RVA lands within the
	// directory's own extent, so a string placed anywhere else is an
	// address the loader will call.
	for i := range e.slots {
		s := &e.slots[i]
		if s.forward == "" {
			continue
		}
		s.fwdStrOff = off
		off += uint32(len(s.forward) + 1)
	}
	e.size = off

	sec, err := l.section(".edata", pe.SecInitData, pe.SecRead)
	if err != nil {
		return err
	}
	e.chunk = image.NewChunk(".edata", "<link>", e)
	e.chunk.Reachable = true
	if err := sec.Add(e.chunk); err != nil {
		return l.fail(err)
	}
	l.chunks = append(l.chunks, e.chunk)
	return nil
}

// assignOrdinals turns the export list into an address table.
//
// Explicit ordinals are honoured and everything else is packed into the gaps
// above them. The base is the lowest ordinal assigned, because a lookup by
// ordinal reads slot ordinal-base — so a base that disagrees with the ordinals
// resolves every export to the wrong function rather than to none.
//
// The space is one-based and 16 bits, and real projects have reached the end
// of it. Past 65,535 there is nowhere to put an export and no way to say so in
// the format.
func (e *exports) assignOrdinals() error {
	l := e.l
	taken := make(map[uint32]string)
	var explicit, implicit []pe.Export

	for _, x := range l.opt.Exports {
		if x.Private {
			// PRIVATE keeps the export out of the import library and
			// not out of the DLL. It has no effect here.
		}
		if x.Ordinal == 0 {
			implicit = append(implicit, x)
			continue
		}
		if prev, dup := taken[uint32(x.Ordinal)]; dup {
			return l.fail(&OrdinalError{
				Name: x.Exported(), Ordinal: uint32(x.Ordinal), Other: prev,
			})
		}
		taken[uint32(x.Ordinal)] = x.Exported()
		explicit = append(explicit, x)
	}

	next := uint32(1)
	for _, x := range implicit {
		for taken[next] != "" {
			next++
		}
		if next > 65535 {
			return l.fail(&OrdinalError{Name: x.Exported(), Ordinal: next})
		}
		taken[next] = x.Exported()
		x.Ordinal = uint16(next)
		explicit = append(explicit, x)
	}

	min, max := uint32(65536), uint32(0)
	for ord := range taken {
		if ord < min {
			min = ord
		}
		if ord > max {
			max = ord
		}
	}
	e.base = min
	e.slots = make([]exportSlot, max-min+1)
	for i := range e.slots {
		e.slots[i].ordinal = min + uint32(i)
	}

	tab := l.tabs[0]
	for _, x := range explicit {
		s := &e.slots[uint32(x.Ordinal)-min]
		s.used = true
		s.ordinal = uint32(x.Ordinal)

		if fwd, ok := x.Forwarder(); ok {
			s.forward = fwd
		} else {
			sym := tab.Lookup(x.Name)
			if sym == nil || sym.Kind.rank() <= SymWeakExternal.rank() {
				return l.fail(&UndefinedError{
					Name: x.Name, Refs: []string{"<export>"},
				})
			}
			s.sym = sym.Out
		}
		if !x.NoName {
			// NONAME keeps the name out of the DLL entirely, so
			// GetProcAddress works only by ordinal. The slot still
			// exists; it simply has no entry in either name table.
			s.name = x.Exported()
		}
	}

	for i := range e.slots {
		if e.slots[i].name != "" {
			e.named = append(e.named, &e.slots[i])
		}
	}
	// Sorted by name, because the loader binary searches the name pointer
	// table. The comparison is a plain byte comparison, so this must be too.
	sort.Slice(e.named, func(i, j int) bool { return e.named[i].name < e.named[j].name })
	return nil
}

// Generate writes the directory and its three tables.
func (e *exports) Generate(img *image.Image) error {
	if e.chunk == nil {
		return nil
	}
	rva, err := e.chunk.RVA()
	if err != nil {
		return err
	}
	base := uint32(rva)

	b := binio.NewBufSize(int(e.size))
	dir := format.ExportDirectory{
		TimeDateStamp:         e.l.opt.TimeStamp,
		NameRVA:               base + e.dllOff,
		OrdinalBase:           e.base,
		AddressTableEntries:   uint32(len(e.slots)),
		NumberOfNamePointers:  uint32(len(e.named)),
		ExportAddressTableRVA: base + e.addrOff,
		NamePointerRVA:        base + e.nameOff,
		OrdinalTableRVA:       base + e.ordOff,
	}
	dir.Encode(b)

	for i := range e.slots {
		s := &e.slots[i]
		switch {
		case !s.used:
			// A gap. Zero is not a valid RVA for an export and is how
			// an unassigned ordinal is spelled.
			b.U32(0)
		case s.forward != "":
			b.U32(base + s.fwdStrOff)
		default:
			target, err := s.sym.RVA()
			if err != nil {
				return err
			}
			b.U32(uint32(target))
		}
	}

	for _, s := range e.named {
		b.U32(base + s.nameStrOff)
	}
	for _, s := range e.named {
		// The ordinal table holds the *index* into the address table,
		// not the ordinal. Writing the ordinal here is the classic way
		// to build a DLL whose every by-name lookup is off by the base.
		b.U16(uint16(s.ordinal - e.base))
	}

	b.CStr(e.l.outputName())
	for _, s := range e.named {
		b.CStr(s.name)
	}
	for i := range e.slots {
		if e.slots[i].forward != "" {
			b.CStr(e.slots[i].forward)
		}
	}

	data, err := b.Data()
	if err != nil {
		return err
	}
	if err := e.checkForwarders(rva); err != nil {
		return err
	}
	return writeAt(img, rva, e.size, data)
}

// checkForwarders asserts the one constraint the format leaves implicit.
//
// An export is a forwarder if and only if its address RVA falls inside the
// export directory's own range. So every forwarder string must be inside this
// chunk and the directory's reported size must cover it — otherwise the loader
// reads the string's RVA as a function address and calls into the middle of a
// filename.
//
// The layout above puts them there by construction. This checks anyway,
// because "by construction" is a property of the code as it is today and the
// failure it prevents is a DLL that loads and jumps into text.
func (e *exports) checkForwarders(rva pe.RVA) error {
	lo, hi := uint32(rva), uint32(rva)+e.size
	for i := range e.slots {
		s := &e.slots[i]
		if s.forward == "" {
			continue
		}
		addr := uint32(rva) + s.fwdStrOff
		if addr < lo || addr+uint32(len(s.forward))+1 > hi {
			return &image.LayoutError{
				Section: ".edata",
				Reason:  "forwarder string for " + s.name + " falls outside the export directory",
				RVA:     pe.RVA(addr),
			}
		}
	}
	return nil
}

// Dirs returns the export data directory entry.
//
// Its size covers the whole chunk rather than just the header, which is what
// makes the forwarder test above work: the loader compares an address against
// this extent, so a size that stopped at the tables would make every forwarder
// look like a function.
func (e *exports) Dirs() []dirEntry {
	if e.chunk == nil {
		return nil
	}
	rva, err := e.chunk.RVA()
	if err != nil {
		return nil
	}
	return []dirEntry{{pe.DirExport, rva, e.size}}
}

// outputName is the name the DLL reports as its own.
//
// It need not match the file on disk, which is how a renamed DLL still answers
// to the name it was built as — and how a forwarder in another module finds
// it. There is no output filename on Options because this package returns an
// image rather than writing one, so a caller that cares sets it explicitly.
func (l *Linker) outputName() string {
	if l.opt.ModuleName != "" {
		return l.opt.ModuleName
	}
	return "unnamed.dll"
}