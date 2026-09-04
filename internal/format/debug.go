package format

import (
	"github.com/vertex-language/pe/internal/binio"
)

// The debug data directory is an array of fixed-size directory entries, each
// naming a blob of type-specific data elsewhere in the image. Nothing here
// writes a PDB — this tree does not produce debug symbols — but a CodeView
// entry naming one is what every real toolchain emits regardless, since a
// debugger that finds none simply reports "no symbols" rather than failing,
// while a debugger that cannot find the directory at all does not know to
// look. IMAGE_DEBUG_TYPE_REPRO and IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS ride
// in the same array as further entries of different types.

// DebugDirectorySize is IMAGE_DEBUG_DIRECTORY: seven fields, 28 bytes.
const DebugDirectorySize = 28

// Debug directory entry types this tree writes. The specification defines
// many more (COFF line numbers, FPO, borland, VC++ misc) that no toolchain in
// the last twenty years produces and nothing here needs to.
const (
	// DebugTypeCodeView names a CV_INFO_PDB70 record: a GUID, an age, and
	// the PDB's path. It is what a debugger reads to find symbols.
	DebugTypeCodeView = 2

	// DebugTypeRepro carries a content hash rather than a timestamp, which
	// is what makes two builds from identical inputs byte-identical: the
	// COFF header's TimeDateStamp is zeroed and this hash stands in for it
	// as the thing that actually changed when the input did.
	DebugTypeRepro = 16

	// DebugTypeExDLLCharacteristics carries the extended DLL characteristics
	// bitmask — CET shadow-stack compatibility and anything added after the
	// sixteen bits in the optional header's own DllCharacteristics field
	// ran out.
	DebugTypeExDLLCharacteristics = 20
)

// DebugDirectory is one IMAGE_DEBUG_DIRECTORY entry.
type DebugDirectory struct {
	Characteristics  uint32
	TimeDateStamp    uint32
	MajorVersion     uint16
	MinorVersion     uint16
	Type             uint32
	SizeOfData       uint32
	AddressOfRawData uint32
	PointerToRawData uint32
}

func (d *DebugDirectory) Encode(b *binio.Buf) {
	b.U32(d.Characteristics)
	b.U32(d.TimeDateStamp)
	b.U16(d.MajorVersion)
	b.U16(d.MinorVersion)
	b.U32(d.Type)
	b.U32(d.SizeOfData)
	b.U32(d.AddressOfRawData)
	b.U32(d.PointerToRawData)
}

func (d *DebugDirectory) Decode(c *binio.Cursor) error {
	d.Characteristics = c.U32()
	d.TimeDateStamp = c.U32()
	d.MajorVersion = c.U16()
	d.MinorVersion = c.U16()
	d.Type = c.U32()
	d.SizeOfData = c.U32()
	d.AddressOfRawData = c.U32()
	d.PointerToRawData = c.U32()
	return c.Err()
}

// CodeViewSignature is 'RSDS', the magic of the PDB 7.0 CodeView record —
// the only form any current tool writes or reads. The 2.0 ('NB10') form
// predates PDB 7.0 and nothing here produces it.
const CodeViewSignature = 0x53445352

// CodeViewGUIDSize is the GUID field's width: 16 bytes, treated as an opaque
// identifier rather than decoded into its RFC 4122 substructure, since
// nothing here or in a debugger constructs one from those fields — it only
// has to match the PDB's own copy, which no PDB exists to compare against.
const CodeViewGUIDSize = 16

// CodeViewRecord is CV_INFO_PDB70.
type CodeViewRecord struct {
	GUID    [CodeViewGUIDSize]byte
	Age     uint32
	PDBPath string
}

// Size returns the record's encoded length, including the path's NUL.
func (r *CodeViewRecord) Size() int {
	return 4 + CodeViewGUIDSize + 4 + len(r.PDBPath) + 1
}

func (r *CodeViewRecord) Encode(b *binio.Buf) {
	b.U32(CodeViewSignature)
	b.Bytes(r.GUID[:])
	b.U32(r.Age)
	b.CStr(r.PDBPath)
}
