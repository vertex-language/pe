package format

import "github.com/vertex-language/pe/internal/binio"

const (
	// SymbolSlot16 is one symbol table slot in a standard object.
	SymbolSlot16 = 18
	// SymbolSlot32 is one slot in a bigobj, widened by the 32-bit
	// SectionNumber. Nothing else about the record changes.
	SymbolSlot32 = 20

	// AuxContentSize is the meaningful size of every auxiliary record, in
	// both object kinds.
	//
	// This does not track the slot size, and that is the trap. An aux
	// record occupies a full slot, so in a bigobj it is 18 bytes of content
	// followed by 2 bytes of padding. A writer that omits the padding
	// shifts every slot after it; a reader that assumes 20 bytes of content
	// reads two bytes of the next record as part of this one.
	AuxContentSize = 18

	// SymbolNameSize is the inline name field.
	SymbolNameSize = 8
)

// SymbolSlotSize returns the slot stride for an object kind.
//
// Every index into the symbol table is a physical slot number, so this is the
// multiplier for all of them. It is also the only thing bigobj changes about
// the symbol table, which is why the flag threads through rather than there
// being two families of type.
func SymbolSlotSize(bigObj bool) int {
	if bigObj {
		return SymbolSlot32
	}
	return SymbolSlot16
}

// AuxPadding returns the bytes of padding after an aux record's content.
func AuxPadding(bigObj bool) int { return SymbolSlotSize(bigObj) - AuxContentSize }

// Symbol is one standard symbol table record.
//
// SectionNumber is int32 in both object kinds. The wire width differs — signed
// 16-bit in a standard object, signed 32-bit in a bigobj — and the sign
// extension happens on decode, so 0xffff becomes -1 in one and stays 65535 in
// the other without any caller having to know which.
type Symbol struct {
	// NameInline holds the eight raw name bytes. If the first four are
	// zero, the name lives in the string table and NameOffset holds its
	// offset; otherwise these bytes are the name, with no terminator when
	// it fills the field.
	NameInline [SymbolNameSize]byte

	Value              uint32
	SectionNumber      int32
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

// LongName reports whether the name is a string table reference, and returns
// the offset if so.
//
// The test is the first four bytes being zero. A name can therefore never
// begin with a NUL, which is not a restriction anyone notices.
func (s *Symbol) LongName() (uint32, bool) {
	if s.NameInline[0] != 0 || s.NameInline[1] != 0 ||
		s.NameInline[2] != 0 || s.NameInline[3] != 0 {
		return 0, false
	}
	return uint32(s.NameInline[4]) | uint32(s.NameInline[5])<<8 |
		uint32(s.NameInline[6])<<16 | uint32(s.NameInline[7])<<24, true
}

// SetLongName writes a string table offset into the name field.
func (s *Symbol) SetLongName(off uint32) {
	s.NameInline = [SymbolNameSize]byte{
		0, 0, 0, 0,
		byte(off), byte(off >> 8), byte(off >> 16), byte(off >> 24),
	}
}

// SetShortName writes an inline name. It reports false if the name does not
// fit, which is the caller's cue to add it to the string table instead.
func (s *Symbol) SetShortName(name string) bool {
	if len(name) > SymbolNameSize {
		return false
	}
	s.NameInline = [SymbolNameSize]byte{}
	copy(s.NameInline[:], name)
	return true
}

func (s *Symbol) Decode(c *binio.Cursor, bigObj bool) error {
	copy(s.NameInline[:], c.Bytes(SymbolNameSize))
	s.Value = c.U32()
	if bigObj {
		s.SectionNumber = c.I32()
	} else {
		s.SectionNumber = int32(c.I16())
	}
	s.Type = c.U16()
	s.StorageClass = c.U8()
	s.NumberOfAuxSymbols = c.U8()
	return c.Err()
}

func (s *Symbol) Encode(b *binio.Buf, bigObj bool) {
	b.Bytes(s.NameInline[:])
	b.U32(s.Value)
	if bigObj {
		b.U32(uint32(s.SectionNumber))
	} else {
		b.U16(uint16(int16(s.SectionNumber)))
	}
	b.U16(s.Type)
	b.U8(s.StorageClass)
	b.U8(s.NumberOfAuxSymbols)
}

// AuxFunctionDef is auxiliary format 1, following a function definition.
type AuxFunctionDef struct {
	TagIndex              uint32
	TotalSize             uint32
	PointerToLinenumber   uint32
	PointerToNextFunction uint32
}

func (a *AuxFunctionDef) Decode(c *binio.Cursor, bigObj bool) error {
	a.TagIndex = c.U32()
	a.TotalSize = c.U32()
	a.PointerToLinenumber = c.U32()
	a.PointerToNextFunction = c.U32()
	c.Skip(2 + AuxPadding(bigObj))
	return c.Err()
}

func (a *AuxFunctionDef) Encode(b *binio.Buf, bigObj bool) {
	b.U32(a.TagIndex)
	b.U32(a.TotalSize)
	b.U32(a.PointerToLinenumber)
	b.U32(a.PointerToNextFunction)
	b.Zero(2 + AuxPadding(bigObj))
}

// AuxBfEf is auxiliary format 2, following a .bf or .ef symbol.
type AuxBfEf struct {
	Linenumber            uint16
	PointerToNextFunction uint32
}

func (a *AuxBfEf) Decode(c *binio.Cursor, bigObj bool) error {
	c.Skip(4)
	a.Linenumber = c.U16()
	c.Skip(6)
	a.PointerToNextFunction = c.U32()
	c.Skip(2 + AuxPadding(bigObj))
	return c.Err()
}

func (a *AuxBfEf) Encode(b *binio.Buf, bigObj bool) {
	b.Zero(4)
	b.U16(a.Linenumber)
	b.Zero(6)
	b.U32(a.PointerToNextFunction)
	b.Zero(2 + AuxPadding(bigObj))
}

// AuxWeakExternal is auxiliary format 3, following a weak external symbol.
//
// Characteristics is the search behaviour, and it carries the ARM64EC
// anti-dependency alias as a fourth value alongside the three search modes —
// a different kind of thing wearing the same storage class.
type AuxWeakExternal struct {
	TagIndex        uint32
	Characteristics uint32
}

func (a *AuxWeakExternal) Decode(c *binio.Cursor, bigObj bool) error {
	a.TagIndex = c.U32()
	a.Characteristics = c.U32()
	c.Skip(10 + AuxPadding(bigObj))
	return c.Err()
}

func (a *AuxWeakExternal) Encode(b *binio.Buf, bigObj bool) {
	b.U32(a.TagIndex)
	b.U32(a.Characteristics)
	b.Zero(10 + AuxPadding(bigObj))
}

// AuxFile is auxiliary format 4: a .file symbol's filename.
//
// Unlike every other aux format this one is not a single record. The filename
// occupies all NumberOfAuxSymbols slots consecutively, NUL-padded, so a long
// path spans several — which is why Decode takes the count and why the padding
// is part of the string rather than trailing each record.
type AuxFile struct {
	Name string
}

// DecodeAuxFile reads n consecutive aux slots as one filename.
func DecodeAuxFile(c *binio.Cursor, n int, bigObj bool) (AuxFile, error) {
	if n <= 0 {
		return AuxFile{}, nil
	}
	raw := c.Bytes(n * SymbolSlotSize(bigObj))
	if raw == nil {
		return AuxFile{}, c.Err()
	}
	end := len(raw)
	for i, b := range raw {
		if b == 0 {
			end = i
			break
		}
	}
	return AuxFile{Name: string(raw[:end])}, c.Err()
}

// Encode writes the filename across n slots. It reports how many slots were
// needed, which the caller must store in the parent symbol's
// NumberOfAuxSymbols.
func (a *AuxFile) Encode(b *binio.Buf, bigObj bool) int {
	slot := SymbolSlotSize(bigObj)
	n := (len(a.Name) + slot - 1) / slot
	if n == 0 {
		n = 1
	}
	b.Bytes([]byte(a.Name))
	b.Zero(n*slot - len(a.Name))
	return n
}

// AuxSectionDef is auxiliary format 5, following a section definition symbol.
//
// Number identifies the associated section for an associative COMDAT. It is a
// 32-bit value assembled from two non-adjacent fields: a low half where the
// specification puts Number, and a high half inside what the specification
// calls unused padding. The high half is meaningful only in a bigobj — which
// is the point, since only a bigobj can have a section number above 65535 to
// associate with.
type AuxSectionDef struct {
	Length              uint32
	NumberOfRelocations uint16
	NumberOfLinenumbers uint16
	CheckSum            uint32
	Number              uint32
	Selection           uint8
}

func (a *AuxSectionDef) Decode(c *binio.Cursor, bigObj bool) error {
	a.Length = c.U32()
	a.NumberOfRelocations = c.U16()
	a.NumberOfLinenumbers = c.U16()
	a.CheckSum = c.U32()
	low := c.U16()
	a.Selection = c.U8()
	c.Skip(1)
	high := c.U16()
	if bigObj {
		a.Number = uint32(low) | uint32(high)<<16
	} else {
		a.Number = uint32(low)
	}
	c.Skip(AuxPadding(bigObj))
	return c.Err()
}

func (a *AuxSectionDef) Encode(b *binio.Buf, bigObj bool) {
	b.U32(a.Length)
	b.U16(a.NumberOfRelocations)
	b.U16(a.NumberOfLinenumbers)
	b.U32(a.CheckSum)
	b.U16(uint16(a.Number))
	b.U8(a.Selection)
	b.Zero(1)
	if bigObj {
		b.U16(uint16(a.Number >> 16))
	} else {
		if a.Number > 0xffff {
			b.Fail(&FieldError{"AuxSectionDef", "Number", uint64(a.Number),
				"exceeds 16 bits in a standard object"})
			return
		}
		b.Zero(2)
	}
	b.Zero(AuxPadding(bigObj))
}

// RelocCount returns the section's relocation count, resolving the overflow
// escape.
//
// When a section carries more than 0xffff relocations its header count reads
// 0xffff and the real count lives in the first relocation's VirtualAddress.
// The aux record's own NumberOfRelocations is 16-bit and has the same problem,
// so a caller holding both should prefer the header's resolution.
func (a *AuxSectionDef) RelocCount() (uint32, bool) {
	if a.NumberOfRelocations == RelocOverflow {
		return 0, false
	}
	return uint32(a.NumberOfRelocations), true
}

// AuxCLRToken is auxiliary format 6. AuxType must be 1; it is the only aux
// format that identifies itself rather than being inferred from its parent.
type AuxCLRToken struct {
	AuxType          uint8
	SymbolTableIndex uint32
}

func (a *AuxCLRToken) Decode(c *binio.Cursor, bigObj bool) error {
	a.AuxType = c.U8()
	c.Skip(1)
	a.SymbolTableIndex = c.U32()
	c.Skip(12 + AuxPadding(bigObj))
	return c.Err()
}

func (a *AuxCLRToken) Encode(b *binio.Buf, bigObj bool) {
	b.U8(a.AuxType)
	b.Zero(1)
	b.U32(a.SymbolTableIndex)
	b.Zero(12 + AuxPadding(bigObj))
}

// AuxOpaque is an aux slot this tree does not interpret.
//
// It holds the full slot, padding included, so it round-trips byte for byte.
// The traditional COFF array and structure aux formats land here, as does
// anything a future toolchain invents; preserving them unchanged is cheaper
// than guessing and safer than dropping.
type AuxOpaque struct {
	Raw []byte
}

func (a *AuxOpaque) Decode(c *binio.Cursor, bigObj bool) error {
	raw := c.Bytes(SymbolSlotSize(bigObj))
	if raw == nil {
		return c.Err()
	}
	a.Raw = append([]byte(nil), raw...)
	return c.Err()
}

func (a *AuxOpaque) Encode(b *binio.Buf, bigObj bool) {
	slot := SymbolSlotSize(bigObj)
	if len(a.Raw) != slot {
		b.Fail(&FieldError{"AuxOpaque", "Raw", uint64(len(a.Raw)),
			"does not fill exactly one symbol slot"})
		return
	}
	b.Bytes(a.Raw)
}