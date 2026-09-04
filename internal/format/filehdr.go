package format

import "github.com/vertex-language/pe/internal/binio"

const (
	// FileHeaderSize is the standard COFF file header.
	FileHeaderSize = 20
	// BigObjHeaderSize is ANON_OBJECT_HEADER_BIGOBJ.
	BigObjHeaderSize = 56
	// PESignatureSize is "PE\0\0".
	PESignatureSize = 4
)

// PESignature is the four bytes that follow the MS-DOS stub in an image.
var PESignature = [PESignatureSize]byte{'P', 'E', 0, 0}

// BigObjClassID identifies ANON_OBJECT_HEADER_BIGOBJ. As a GUID it is
// {D1BAA1C7-BAEE-4BA9-AF20-FAF66AA4DCB8}; these are its bytes in file order.
var BigObjClassID = [16]byte{
	0xc7, 0xa1, 0xba, 0xd1, 0xee, 0xba, 0xa9, 0x4b,
	0xaf, 0x20, 0xfa, 0xf6, 0x6a, 0xa4, 0xdc, 0xb8,
}

// MinBigObjVersion is the lowest Version a bigobj header may carry. Version 0
// is a short-import header and version 1 is a plain anonymous object; neither
// is this.
const MinBigObjVersion = 2

// FileHeader is the standard COFF file header, at the start of an object and
// immediately after the PE signature in an image.
type FileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

func (h *FileHeader) Decode(c *binio.Cursor) error {
	h.Machine = c.U16()
	h.NumberOfSections = c.U16()
	h.TimeDateStamp = c.U32()
	h.PointerToSymbolTable = c.U32()
	h.NumberOfSymbols = c.U32()
	h.SizeOfOptionalHeader = c.U16()
	h.Characteristics = c.U16()
	return c.Err()
}

func (h *FileHeader) Encode(b *binio.Buf) {
	b.U16(h.Machine)
	b.U16(h.NumberOfSections)
	b.U32(h.TimeDateStamp)
	b.U32(h.PointerToSymbolTable)
	b.U32(h.NumberOfSymbols)
	b.U16(h.SizeOfOptionalHeader)
	b.U16(h.Characteristics)
}

// SectionTableOffset returns the offset of the section table relative to the
// start of this file header.
//
// This is the one use Windows makes of SizeOfOptionalHeader, and it is the
// reason the field cannot simply be ignored even though the loader consults it
// for nothing else. The section table begins immediately after whatever the
// optional header claims to be, whether or not that claim is consistent with
// the header's contents.
func (h *FileHeader) SectionTableOffset() int64 {
	return FileHeaderSize + int64(h.SizeOfOptionalHeader)
}

// BigObjHeader is ANON_OBJECT_HEADER_BIGOBJ: the header of an object with more
// sections than a 16-bit count can hold.
//
// It shares nothing structurally with FileHeader. The two are distinguished by
// the first two words, which in a bigobj are an unknown machine and 0xFFFF —
// values a real file header cannot usefully hold.
type BigObjHeader struct {
	Sig1                 uint16 // must be 0
	Sig2                 uint16 // must be 0xffff
	Version              uint16
	Machine              uint16
	TimeDateStamp        uint32
	ClassID              [16]byte
	SizeOfData           uint32
	Flags                uint32
	MetaDataSize         uint32
	MetaDataOffset       uint32
	NumberOfSections     uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
}

func (h *BigObjHeader) Decode(c *binio.Cursor) error {
	h.Sig1 = c.U16()
	h.Sig2 = c.U16()
	h.Version = c.U16()
	h.Machine = c.U16()
	h.TimeDateStamp = c.U32()
	copy(h.ClassID[:], c.Bytes(16))
	h.SizeOfData = c.U32()
	h.Flags = c.U32()
	h.MetaDataSize = c.U32()
	h.MetaDataOffset = c.U32()
	h.NumberOfSections = c.U32()
	h.PointerToSymbolTable = c.U32()
	h.NumberOfSymbols = c.U32()
	if err := c.Err(); err != nil {
		return err
	}
	if h.Sig1 != 0 || h.Sig2 != 0xffff || h.ClassID != BigObjClassID {
		return ErrBadMagic
	}
	if h.Version < MinBigObjVersion {
		return &FieldError{"BigObjHeader", "Version", uint64(h.Version),
			"below the minimum bigobj version"}
	}
	return nil
}

func (h *BigObjHeader) Encode(b *binio.Buf) {
	b.U16(h.Sig1)
	b.U16(h.Sig2)
	b.U16(h.Version)
	b.U16(h.Machine)
	b.U32(h.TimeDateStamp)
	b.Bytes(h.ClassID[:])
	b.U32(h.SizeOfData)
	b.U32(h.Flags)
	b.U32(h.MetaDataSize)
	b.U32(h.MetaDataOffset)
	b.U32(h.NumberOfSections)
	b.U32(h.PointerToSymbolTable)
	b.U32(h.NumberOfSymbols)
}

// NewBigObjHeader returns a header with the constant fields already set, so a
// writer cannot forget the signature or the ClassID.
func NewBigObjHeader(machine uint16) BigObjHeader {
	return BigObjHeader{
		Sig1:    0,
		Sig2:    0xffff,
		Version: MinBigObjVersion,
		Machine: machine,
		ClassID: BigObjClassID,
	}
}