package format

import "github.com/vertex-language/pe/internal/binio"

// SectionHeaderSize is one row of the section table.
const SectionHeaderSize = 40

// SectionNameSize is the inline name field. A name of exactly eight bytes has
// no terminator.
const SectionNameSize = 8

// SectionHeader is one row of the section table.
//
// Name is kept as raw bytes rather than a string because it has three possible
// meanings — an inline name, a "/N" decimal offset into the string table, or
// the "//" base64 form — and choosing between them requires the string table,
// which this package does not have. strtab resolves it.
type SectionHeader struct {
	Name                 [SectionNameSize]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

func (s *SectionHeader) Decode(c *binio.Cursor) error {
	copy(s.Name[:], c.Bytes(SectionNameSize))
	s.VirtualSize = c.U32()
	s.VirtualAddress = c.U32()
	s.SizeOfRawData = c.U32()
	s.PointerToRawData = c.U32()
	s.PointerToRelocations = c.U32()
	s.PointerToLinenumbers = c.U32()
	s.NumberOfRelocations = c.U16()
	s.NumberOfLinenumbers = c.U16()
	s.Characteristics = c.U32()
	return c.Err()
}

func (s *SectionHeader) Encode(b *binio.Buf) {
	b.Bytes(s.Name[:])
	b.U32(s.VirtualSize)
	b.U32(s.VirtualAddress)
	b.U32(s.SizeOfRawData)
	b.U32(s.PointerToRawData)
	b.U32(s.PointerToRelocations)
	b.U32(s.PointerToLinenumbers)
	b.U16(s.NumberOfRelocations)
	b.U16(s.NumberOfLinenumbers)
	b.U32(s.Characteristics)
}

// RelocOverflow is the escape used when a section has more relocations than
// the 16-bit count can hold: the count reads 0xffff, the LNK_NRELOC_OVFL flag
// is set, and the real count lives in the VirtualAddress field of the first
// relocation record.
const RelocOverflow = 0xffff

// HasRelocOverflow reports whether this header uses that escape.
//
// The flag alone is not enough. The specification makes it an error for the
// flag to be set with fewer than 0xffff relocations, so both conditions are
// checked, and a header with the flag but an ordinary count is treated as
// having an ordinary count rather than as licence to read a count out of the
// section's first relocation.
func (s *SectionHeader) HasRelocOverflow() bool {
	const lnkNRelocOvfl = 0x01000000
	return s.Characteristics&lnkNRelocOvfl != 0 && s.NumberOfRelocations == RelocOverflow
}

// RelocationSize is one COFF relocation record.
const RelocationSize = 10

// Relocation is one COFF relocation record.
//
// SymbolTableIndex does not always name a symbol. In a PAIR or ADDEND record
// it holds a displacement, and nothing in either record points at the other —
// the pairing is positional. A reader that resolves this field without first
// asking whether the type is a pair will look up an arbitrary symbol.
type Relocation struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

func (r *Relocation) Decode(c *binio.Cursor) error {
	r.VirtualAddress = c.U32()
	r.SymbolTableIndex = c.U32()
	r.Type = c.U16()
	return c.Err()
}

func (r *Relocation) Encode(b *binio.Buf) {
	b.U32(r.VirtualAddress)
	b.U32(r.SymbolTableIndex)
	b.U16(r.Type)
}