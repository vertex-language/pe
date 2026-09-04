package format

import "github.com/vertex-language/pe/internal/binio"

// ImportHeaderSize is IMPORT_OBJECT_HEADER, the whole of a short-import
// member's fixed part. The symbol name and the DLL name follow it as two
// NUL-terminated strings — and, under the EXPORTAS name type, the exported
// name as a third.
const ImportHeaderSize = 20

// Import types: what the import refers to, and therefore how many symbols the
// member contributes.
const (
	ImportCode  = 0
	ImportData  = 1
	ImportConst = 2

	// MaxImportType is the highest defined value.
	MaxImportType = ImportConst
)

// Import name types: the rule relating the symbol name stored in the member to
// the name the DLL exports.
//
// The published specification stops at UNDECORATE. EXPORTAS was added later,
// is emitted by current lib.exe and llvm-lib, and is how every ARM64EC import
// library works — the symbol is the mangled name and the export is the
// demangled one, which no prefix rule can express. A reader that enforces the
// published range rejects those libraries outright, so the bound here is the
// implemented one rather than the documented one.
const (
	ImportNameOrdinal    = 0
	ImportName           = 1
	ImportNameNoPrefix   = 2
	ImportNameUndecorate = 3
	ImportNameExportAs   = 4

	// MaxImportNameType is the highest defined value.
	MaxImportNameType = ImportNameExportAs
)

// ImportHeader is the header of a short-import pseudo-object: the member kind
// that makes up most of an import library.
//
// It shares its first two words with the bigobj and /GL headers — zero, then
// 0xFFFF — and is told apart by Version being 0 and by the region a ClassID
// would occupy holding SizeOfData, OrdinalHint, and TypeInfo instead.
type ImportHeader struct {
	Sig1          uint16 // must be 0
	Sig2          uint16 // must be 0xffff
	Version       uint16 // must be 0 for an import object
	Machine       uint16
	TimeDateStamp uint32
	SizeOfData    uint32 // the names that follow

	// OrdinalHint is the ordinal when importing by ordinal, and a hint into
	// the exporting DLL's name table otherwise. The two share a field and
	// NameType decides which it is.
	OrdinalHint uint16

	// TypeInfo packs Type in bits 0-1, NameType in bits 2-4, and eleven
	// reserved bits above them.
	TypeInfo uint16
}

// Bit layout of TypeInfo.
const (
	importTypeMask      = 0x0003
	importNameTypeShift = 2
	importNameTypeMask  = 0x0007
	importReservedShift = 5
)

// Type returns the import kind: code, data, or const.
//
// This decides how many symbols the member contributes, which is the whole
// reason the field matters. A data import defines only __imp_$sym; a code
// import defines __imp_$sym and also $sym, a thunk jumping through the slot.
func (h *ImportHeader) Type() uint8 { return uint8(h.TypeInfo & importTypeMask) }

// NameType returns the mangling rule relating the symbol name to the name
// exported by the DLL.
//
// The field is three bits wide, so it can hold values this tree does not know.
// Decode bounds it against MaxImportNameType rather than against the mask.
func (h *ImportHeader) NameType() uint8 {
	return uint8((h.TypeInfo >> importNameTypeShift) & importNameTypeMask)
}

// HasExportName reports whether a third NUL-terminated string follows the
// symbol and DLL names.
//
// Only EXPORTAS carries one. The strings after the header are positional and
// unlabelled, so a reader that does not consult this will take the next
// member's bytes for an exported name, or miss one that is there.
func (h *ImportHeader) HasExportName() bool {
	return h.NameType() == ImportNameExportAs
}

// Reserved returns the eleven bits above the two fields, which must be zero.
func (h *ImportHeader) Reserved() uint16 { return h.TypeInfo >> importReservedShift }

// SetTypeInfo packs the two fields. It reports false if either is out of
// range.
//
// The check is against the highest *defined* value, not against the field
// width: a writer emitting an undefined name type is producing a library only
// it can read, and there is no reason to let it.
func (h *ImportHeader) SetTypeInfo(typ, nameType uint8) bool {
	if typ > MaxImportType || nameType > MaxImportNameType {
		return false
	}
	h.TypeInfo = uint16(typ) | uint16(nameType)<<importNameTypeShift
	return true
}

// Decode reads the header and validates the bit fields.
//
// The validation matters more here than elsewhere. link.exe treats each of
// these as a fatal error with its own diagnostic — LNK1197 for a Type above 2,
// LNK1198 for a NameType out of range, LNK1199 for non-zero reserved bits —
// because an import library that decodes to nonsense produces a DLL reference
// that resolves to the wrong export rather than failing to resolve.
//
// The NameType bound is MaxImportNameType, which is 4. LNK1198's own bound
// predates EXPORTAS; matching the diagnostic's historical range would mean
// rejecting libraries that link.exe itself now produces, so this follows the
// format rather than the error message.
func (h *ImportHeader) Decode(c *binio.Cursor) error {
	h.Sig1 = c.U16()
	h.Sig2 = c.U16()
	h.Version = c.U16()
	h.Machine = c.U16()
	h.TimeDateStamp = c.U32()
	h.SizeOfData = c.U32()
	h.OrdinalHint = c.U16()
	h.TypeInfo = c.U16()
	if err := c.Err(); err != nil {
		return err
	}
	if h.Sig1 != 0 || h.Sig2 != 0xffff || h.Version != 0 {
		return ErrBadMagic
	}
	if h.Type() > MaxImportType {
		return &FieldError{"ImportHeader", "Type", uint64(h.Type()),
			"above the highest defined import type"}
	}
	if h.NameType() > MaxImportNameType {
		return &FieldError{"ImportHeader", "NameType", uint64(h.NameType()),
			"above the highest defined import name type"}
	}
	if r := h.Reserved(); r != 0 {
		return &FieldError{"ImportHeader", "Reserved", uint64(r),
			"reserved bits must be zero"}
	}
	return nil
}

func (h *ImportHeader) Encode(b *binio.Buf) {
	b.U16(h.Sig1)
	b.U16(h.Sig2)
	b.U16(h.Version)
	b.U16(h.Machine)
	b.U32(h.TimeDateStamp)
	b.U32(h.SizeOfData)
	b.U16(h.OrdinalHint)
	b.U16(h.TypeInfo)
}

// NewImportHeader returns a header with the constant fields set.
func NewImportHeader(machine uint16) ImportHeader {
	return ImportHeader{Sig1: 0, Sig2: 0xffff, Version: 0, Machine: machine}
}