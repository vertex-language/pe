package format

import "github.com/vertex-language/pe/internal/binio"

// The export directory: what a DLL offers, and the only way anything outside
// it can find a name.
//
// Three parallel tables and one indirection. The export address table is
// indexed by ordinal minus the ordinal base and holds an RVA per slot. The
// name pointer table holds RVAs to names, sorted so the loader can binary
// search it. The ordinal table runs alongside the name pointers and gives, for
// each one, the index into the address table — so a lookup by name finds a
// position in the name table and reads the answer out of the ordinal table at
// the same position.
//
// Getting the two name-side tables out of step is the classic way to build a
// DLL that dumpbin renders correctly and GetProcAddress cannot use.

// ExportDirectorySize is IMAGE_EXPORT_DIRECTORY.
const ExportDirectorySize = 40

// ExportAddressSize, ExportNamePointerSize, and ExportOrdinalSize are the
// widths of one entry of each table. None of them depends on the image's
// width: every address in the export directory is a 32-bit RVA, in a 64-bit
// image as much as a 32-bit one.
const (
	ExportAddressSize     = 4
	ExportNamePointerSize = 4
	ExportOrdinalSize     = 2
)

// ExportDirectory is the header of .edata.
type ExportDirectory struct {
	// ExportFlags is reserved and must be zero.
	ExportFlags uint32

	TimeDateStamp uint32
	MajorVersion  uint16
	MinorVersion  uint16

	// NameRVA points at the DLL's own name. It is what a forwarder in
	// another module resolves against and what the loader reports, and it
	// need not match the file's name on disk — which is how a renamed DLL
	// still answers to the name it was built as.
	NameRVA uint32

	// OrdinalBase is the ordinal of the first entry in the address table.
	// A lookup by ordinal reads slot ordinal-OrdinalBase, so a base that
	// disagrees with the ordinals actually assigned resolves every export
	// to the wrong function rather than to none.
	OrdinalBase uint32

	// AddressTableEntries counts the address table, gaps included.
	AddressTableEntries uint32

	// NumberOfNamePointers counts the name pointer table and the ordinal
	// table, which are always the same length. Exports by ordinal only —
	// NONAME — appear in the address table and in neither of these.
	NumberOfNamePointers uint32

	ExportAddressTableRVA uint32
	NamePointerRVA        uint32
	OrdinalTableRVA       uint32
}

func (d *ExportDirectory) Decode(c *binio.Cursor) error {
	d.ExportFlags = c.U32()
	d.TimeDateStamp = c.U32()
	d.MajorVersion = c.U16()
	d.MinorVersion = c.U16()
	d.NameRVA = c.U32()
	d.OrdinalBase = c.U32()
	d.AddressTableEntries = c.U32()
	d.NumberOfNamePointers = c.U32()
	d.ExportAddressTableRVA = c.U32()
	d.NamePointerRVA = c.U32()
	d.OrdinalTableRVA = c.U32()
	return c.Err()
}

func (d *ExportDirectory) Encode(b *binio.Buf) {
	b.U32(d.ExportFlags)
	b.U32(d.TimeDateStamp)
	b.U16(d.MajorVersion)
	b.U16(d.MinorVersion)
	b.U32(d.NameRVA)
	b.U32(d.OrdinalBase)
	b.U32(d.AddressTableEntries)
	b.U32(d.NumberOfNamePointers)
	b.U32(d.ExportAddressTableRVA)
	b.U32(d.NamePointerRVA)
	b.U32(d.OrdinalTableRVA)
}