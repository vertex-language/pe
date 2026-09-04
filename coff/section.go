package coff

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// Section is one entry of the section table, with its data read on demand.
type Section struct {
	// Name is the resolved name, including any $ suffix.
	//
	// The $ survives. The linker discards it and everything after when
	// deciding which image section a contribution lands in, but the full
	// name decides ordering — .CRT$XCA through .CRT$XCZ bracket the C++
	// initializer array, and .CRT$XLB is where TLS callbacks land. Stripping
	// it here would destroy the only information that makes CRT startup work.
	Name string

	// Size is the section's size in bytes. In an object this is
	// SizeOfRawData; VirtualSize is zero and carries no meaning.
	Size uint32

	f     *File
	index int
	hdr   format.SectionHeader

	kind  pe.SecKind
	prot  pe.SecProt
	align int
}

func newSection(f *File, i int, h *format.SectionHeader) (*Section, error) {
	name, err := f.strs.SectionName(h.Name)
	if err != nil {
		return nil, &SectionError{Index: i, Name: string(h.Name[:]), Err: err}
	}
	kind, prot, align := pe.SplitSecChar(h.Characteristics)
	return &Section{
		Name:  name,
		Size:  h.SizeOfRawData,
		f:     f,
		index: i,
		hdr:   *h,
		kind:  kind,
		prot:  prot,
		align: align,
	}, nil
}

// Index returns this section's zero-based position in the section table. The
// section *number* used by symbols and by associative COMDATs is one-based, so
// it is Index()+1.
func (s *Section) Index() int { return s.index }

// Number returns the one-based section number, as symbols reference it.
func (s *Section) Number() int32 { return int32(s.index) + 1 }

// Kind returns the content flags.
func (s *Section) Kind() pe.SecKind { return s.kind }

// Prot returns the memory flags.
func (s *Section) Prot() pe.SecProt { return s.prot }

// Align returns the required alignment in bytes, never the nibble.
func (s *Section) Align() int { return s.align }

// Characteristics returns the raw field, for a caller that needs to compare
// against another object byte for byte.
func (s *Section) Characteristics() uint32 { return s.hdr.Characteristics }

// GroupName returns the name with the $ suffix removed: the image section this
// contribution will land in.
func (s *Section) GroupName() string {
	for i := 0; i < len(s.Name); i++ {
		if s.Name[i] == '$' {
			return s.Name[:i]
		}
	}
	return s.Name
}

// The COMDAT predicate is IsComdat, in comdat.go, beside Comdat — which
// returns the election terms and needs the symbol table to answer. One name
// cannot be both, and the terms are what a caller almost always wants next.

// BSS reports whether the section has no file content. Its data is a run of
// zeroes of length Size, and PointerToRawData is zero.
func (s *Section) BSS() bool { return s.kind.Has(pe.SecUninitData) }

// Data returns the section's contents.
//
// For a BSS section it returns nil rather than allocating Size zero bytes: an
// uninitialized section can be large, and a caller that wants zeroes can make
// them more cheaply than this can.
func (s *Section) Data() ([]byte, error) {
	if s.BSS() || s.hdr.PointerToRawData == 0 || s.Size == 0 {
		return nil, nil
	}
	return s.f.ext.At(int64(s.hdr.PointerToRawData), int64(s.Size))
}

// Open returns a cursor over the section's contents.
func (s *Section) Open() (*binio.Cursor, error) {
	if s.BSS() || s.hdr.PointerToRawData == 0 || s.Size == 0 {
		return binio.NewCursor(nil), nil
	}
	return s.f.ext.Cursor(int64(s.hdr.PointerToRawData), int64(s.Size))
}

// NumRelocs returns the section's relocation count, resolving the overflow
// escape.
//
// When a section has more than 0xffff relocations, its header count reads
// 0xffff, LNK_NRELOC_OVFL is set, and the real count lives in the
// VirtualAddress field of the first relocation record — which is therefore not
// a relocation and must be skipped. Both the count and the skip are handled
// here and in Relocs, and neither surfaces in this package's API.
func (s *Section) NumRelocs() (uint32, error) {
	if !s.hdr.HasRelocOverflow() {
		return uint32(s.hdr.NumberOfRelocations), nil
	}
	c, err := s.f.ext.Cursor(int64(s.hdr.PointerToRelocations), format.RelocationSize)
	if err != nil {
		return 0, &SectionError{Index: s.index, Name: s.Name, Err: err}
	}
	var r format.Relocation
	if err := r.Decode(c); err != nil {
		return 0, &SectionError{Index: s.index, Name: s.Name, Err: err}
	}
	if r.VirtualAddress == 0 {
		return 0, &SectionError{Index: s.index, Name: s.Name, Err: ErrCorrupt}
	}
	// The count includes the pseudo-record holding it.
	return r.VirtualAddress - 1, nil
}

// Reloc is one COFF relocation.
//
// SymIndex is a physical slot in the symbol table — except in a PAIR or ADDEND
// record, where it is a displacement instead and names no symbol at all. IsPair
// says which, and resolving the field without asking is how a reader ends up
// relocating against an arbitrary symbol.
type Reloc struct {
	Address  uint32
	SymIndex uint32
	Type     uint16
}

// IsPair reports whether this record's SymIndex is a displacement rather than
// a symbol slot.
func (r Reloc) IsPair(m pe.Machine) bool { return pe.RelocIsPair(m, r.Type) }

// Relocs returns the section's relocations, in file order.
//
// The order is preserved exactly. PAIR and ADDEND records are valid only
// immediately after the entry they modify, and nothing in either record names
// the other, so sorting them — for any reason, including determinism — breaks
// the only thing that associates them.
func (s *Section) Relocs() ([]Reloc, error) {
	n, err := s.NumRelocs()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	off := int64(s.hdr.PointerToRelocations)
	if s.hdr.HasRelocOverflow() {
		off += format.RelocationSize // skip the pseudo-record holding the count
	}
	c, err := s.f.ext.Table("relocations", off, n, format.RelocationSize)
	if err != nil {
		return nil, &SectionError{Index: s.index, Name: s.Name, Err: err}
	}
	out := make([]Reloc, n)
	for i := range out {
		var r format.Relocation
		if err := r.Decode(c); err != nil {
			return nil, &SectionError{Index: s.index, Name: s.Name, Err: err}
		}
		out[i] = Reloc{Address: r.VirtualAddress, SymIndex: r.SymbolTableIndex, Type: r.Type}
	}
	return out, nil
}

// File returns the object this section belongs to.
//
// It exists for one caller: link's COMDAT comparison, which resolves a
// relocation's symbol slot to a name and needs the symbol table of the object
// the relocation came from. Slot numbers are physical positions in one
// object's table, so two candidate sections from two objects cannot be
// compared by slot at all — the numbers are unrelated — and the comparison has
// to go through each section's own file to get names out.
//
// Nothing else should want this. A Section that can reach back to its File is
// one step from a caller walking the whole object through a section handle,
// which is how a decoder's invariants become conventions.
func (s *Section) File() *File { return s.f }