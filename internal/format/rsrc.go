package format

import (
	"unicode/utf16"

	"github.com/vertex-language/pe/internal/binio"
)

// Two formats live here and they are not the same format.
//
// A .res file is rc.exe's output: a flat run of entries, each a header and a
// blob, DWORD-aligned. Nothing in it is a tree and nothing in it is an
// address.
//
// A .rsrc section is what the loader walks: a three-level tree of directories
// — type, then name, then language — with data entries as leaves. Every offset
// inside it is relative to the start of the directory, which is what lets the
// whole structure be built before its address is known.
//
// Every offset except one. IMAGE_RESOURCE_DATA_ENTRY.OffsetToData is a true
// RVA, image-relative like everything else in a PE table. Mixing the two
// conventions produces a tree dumpbin walks happily and FindResource cannot
// use, because dumpbin is reading the directory-relative offsets and the
// loader is dereferencing the one that is not.

// ResHeaderFixedSize is the part of a .res entry header that follows the
// variable-width type and name: DataVersion, MemoryFlags, LanguageId, Version,
// and Characteristics.
const ResHeaderFixedSize = 16

// ResAlign is the boundary every .res header and every blob is padded to.
const ResAlign = 4

// ResOrdinalEscape marks a type or name field as an ordinal rather than a
// string. It is 0xFFFF because that is not a valid UTF-16 code unit, so no
// real name can collide with it.
const ResOrdinalEscape uint16 = 0xffff

// ResID is a resource type, name, or language: a number or a string.
//
// The two are not interchangeable and the format keeps them apart at every
// level. A resource named "1" and one with ordinal 1 are different resources,
// they sort into different runs of the directory, and FindResource reaches
// them through different calls.
type ResID struct {
	// Name is the string form, in UTF-16 on the wire and stored here as
	// Go's UTF-8. Empty when the identifier is an ordinal.
	Name string

	// Ordinal is the numeric form, valid when IsName is false.
	Ordinal uint16

	IsName bool
}

// NewResName returns a string identifier.
func NewResName(s string) ResID { return ResID{Name: s, IsName: true} }

// NewResOrdinal returns a numeric identifier.
func NewResOrdinal(n uint16) ResID { return ResID{Ordinal: n} }

// EncodedSize returns the bytes this identifier occupies in a .res header: two
// for an ordinal's escape plus two for the value, or two per code unit plus a
// terminator for a name.
func (r ResID) EncodedSize() int {
	if !r.IsName {
		return 4
	}
	return 2*len(utf16.Encode([]rune(r.Name))) + 2
}

func (r ResID) String() string {
	if r.IsName {
		return r.Name
	}
	return "#" + itoaFormat(int(r.Ordinal))
}

// DecodeResID reads a type or name field from a .res header.
//
// The discriminator is the first word: 0xFFFF means an ordinal follows,
// anything else means the field is a NUL-terminated UTF-16 string that starts
// with that word. A reader that assumes a fixed width here reads the next
// field as part of this one and desynchronises the rest of the file.
func DecodeResID(c *binio.Cursor) (ResID, error) {
	first := c.U16()
	if err := c.Err(); err != nil {
		return ResID{}, err
	}
	if first == ResOrdinalEscape {
		return ResID{Ordinal: c.U16()}, c.Err()
	}
	units := []uint16{}
	for w := first; w != 0; w = c.U16() {
		if err := c.Err(); err != nil {
			return ResID{}, err
		}
		units = append(units, w)
		if len(units) > 1<<16 {
			return ResID{}, &FieldError{"ResID", "Name", uint64(len(units)),
				"unterminated resource name"}
		}
	}
	return ResID{Name: string(utf16.Decode(units)), IsName: true}, c.Err()
}

// EncodeResID writes a type or name field.
func EncodeResID(b *binio.Buf, r ResID) {
	if !r.IsName {
		b.U16(ResOrdinalEscape)
		b.U16(r.Ordinal)
		return
	}
	for _, u := range utf16.Encode([]rune(r.Name)) {
		b.U16(u)
	}
	b.U16(0)
}

// ResHeader is one .res entry header, minus the two variable-width
// identifiers.
//
// HeaderSize covers the whole header including those identifiers and the
// padding after them, which is why it is the field a walk advances by rather
// than a size this package can compute alone.
type ResHeader struct {
	DataSize   uint32
	HeaderSize uint32

	Type ResID
	Name ResID

	DataVersion uint32

	// MemoryFlags are the MOVEABLE, PURE, PRELOAD attributes an .rc script
	// can set. Windows has ignored every one of them since Win32; they are
	// carried because rc.exe still emits them and a round trip that dropped
	// them would not be a round trip.
	MemoryFlags uint16

	// LanguageId is the third level of the resource tree, and the reason
	// the tree has three levels rather than two.
	LanguageId uint16

	Version         uint32
	Characteristics uint32
}

// Decode reads one header. The cursor must be positioned at its first byte,
// and is left just past the header — that is, at the entry's data.
func (h *ResHeader) Decode(c *binio.Cursor) error {
	start := c.Off()
	h.DataSize = c.U32()
	h.HeaderSize = c.U32()
	if err := c.Err(); err != nil {
		return err
	}

	var err error
	if h.Type, err = DecodeResID(c); err != nil {
		return err
	}
	if h.Name, err = DecodeResID(c); err != nil {
		return err
	}
	// The type and name are made of words, so no padding is needed between
	// them — but a WORD may be needed after the pair to bring the rest of
	// the header back to a DWORD boundary.
	if (c.Off()-start)%4 != 0 {
		c.Skip(2)
	}

	h.DataVersion = c.U32()
	h.MemoryFlags = c.U16()
	h.LanguageId = c.U16()
	h.Version = c.U32()
	h.Characteristics = c.U32()
	if err := c.Err(); err != nil {
		return err
	}

	if got := uint32(c.Off() - start); got != h.HeaderSize {
		// The declared size and the fields disagree. Trusting either
		// one alone lands the next entry in the middle of this one's
		// data, so neither is trusted.
		return &FieldError{"ResHeader", "HeaderSize", uint64(h.HeaderSize),
			"disagrees with the header actually read"}
	}
	return nil
}

// ResHeaderSize returns the encoded size of a header with these identifiers,
// padding included.
func ResHeaderSize(typ, name ResID) uint32 {
	n := 8 + typ.EncodedSize() + name.EncodedSize()
	if n%4 != 0 {
		n += 2
	}
	return uint32(n + ResHeaderFixedSize)
}

// Encode writes one header, padding included.
func (h *ResHeader) Encode(b *binio.Buf) {
	start := b.Len()
	b.U32(h.DataSize)
	b.U32(ResHeaderSize(h.Type, h.Name))
	EncodeResID(b, h.Type)
	EncodeResID(b, h.Name)
	if (b.Len()-start)%4 != 0 {
		b.Zero(2)
	}
	b.U32(h.DataVersion)
	b.U16(h.MemoryFlags)
	b.U16(h.LanguageId)
	b.U32(h.Version)
	b.U32(h.Characteristics)
}

// IsNull reports whether this is the empty entry every .res file begins with.
//
// rc.exe writes it as a marker and it describes no resource: type and name are
// both ordinal zero and there is no data. A reader that takes it for a real
// resource builds a tree with a type-zero branch, which nothing will ever ask
// for and which dumpbin renders as a phantom.
func (h *ResHeader) IsNull() bool {
	return h.DataSize == 0 && !h.Type.IsName && h.Type.Ordinal == 0 &&
		!h.Name.IsName && h.Name.Ordinal == 0
}

// The .rsrc structures. Everything below is the image side.

const (
	// ResourceDirectorySize is IMAGE_RESOURCE_DIRECTORY.
	ResourceDirectorySize = 16

	// ResourceEntrySize is IMAGE_RESOURCE_DIRECTORY_ENTRY.
	ResourceEntrySize = 8

	// ResourceDataEntrySize is IMAGE_RESOURCE_DATA_ENTRY.
	ResourceDataEntrySize = 16

	// ResourceNameFlag marks an entry's Name field as an offset to a
	// string rather than an ordinal.
	ResourceNameFlag uint32 = 0x80000000

	// ResourceDirFlag marks an entry's OffsetToData as pointing at a
	// subdirectory rather than a data entry.
	ResourceDirFlag uint32 = 0x80000000
)

// ResourceDirectory is one node of the tree.
//
// The two counts are separate because the entries are two sorted runs, not
// one: every named entry precedes every ID entry, and each run is sorted
// within itself, because the loader binary-searches them separately.
type ResourceDirectory struct {
	Characteristics uint32
	TimeDateStamp   uint32
	MajorVersion    uint16
	MinorVersion    uint16

	NumberOfNamedEntries uint16
	NumberOfIdEntries    uint16
}

func (d *ResourceDirectory) Decode(c *binio.Cursor) error {
	d.Characteristics = c.U32()
	d.TimeDateStamp = c.U32()
	d.MajorVersion = c.U16()
	d.MinorVersion = c.U16()
	d.NumberOfNamedEntries = c.U16()
	d.NumberOfIdEntries = c.U16()
	return c.Err()
}

func (d *ResourceDirectory) Encode(b *binio.Buf) {
	b.U32(d.Characteristics)
	b.U32(d.TimeDateStamp)
	b.U16(d.MajorVersion)
	b.U16(d.MinorVersion)
	b.U16(d.NumberOfNamedEntries)
	b.U16(d.NumberOfIdEntries)
}

// ResourceEntry is one directory entry: an identifier and a destination.
//
// Both fields are unions decided by their high bit, and the two bits mean
// unrelated things. Name's high bit says the low 31 are an offset to a
// counted UTF-16 string; OffsetToData's says the low 31 are an offset to
// another directory rather than to a data entry. Both offsets are relative to
// the start of the resource directory.
type ResourceEntry struct {
	Name         uint32
	OffsetToData uint32
}

func (e *ResourceEntry) Decode(c *binio.Cursor) error {
	e.Name = c.U32()
	e.OffsetToData = c.U32()
	return c.Err()
}

func (e *ResourceEntry) Encode(b *binio.Buf) {
	b.U32(e.Name)
	b.U32(e.OffsetToData)
}

// IsName reports whether Name is an offset to a string.
func (e *ResourceEntry) IsName() bool { return e.Name&ResourceNameFlag != 0 }

// IsDirectory reports whether OffsetToData points at a subdirectory.
func (e *ResourceEntry) IsDirectory() bool { return e.OffsetToData&ResourceDirFlag != 0 }

// ResourceDataEntry is a leaf: where the bytes are and how many.
//
// OffsetToData is the exception this whole file warns about. Every other
// offset in the tree is relative to the directory's start; this one is an RVA.
// It is therefore the only field in a resource tree that a linker cannot fill
// until layout has run, which is why rsrc.Build hands back a list of the
// positions rather than an address.
type ResourceDataEntry struct {
	OffsetToData uint32
	Size         uint32

	// CodePage decodes code points inside the data. Zero means the
	// default, and zero is what everything anyone still ships writes.
	CodePage uint32
	Reserved uint32
}

func (d *ResourceDataEntry) Decode(c *binio.Cursor) error {
	d.OffsetToData = c.U32()
	d.Size = c.U32()
	d.CodePage = c.U32()
	d.Reserved = c.U32()
	return c.Err()
}

func (d *ResourceDataEntry) Encode(b *binio.Buf) {
	b.U32(d.OffsetToData)
	b.U32(d.Size)
	b.U32(d.CodePage)
	b.U32(d.Reserved)
}

// ResourceStringSize returns the encoded size of a directory string: a word of
// length in code units, then the units, with no terminator.
func ResourceStringSize(s string) int { return 2 + 2*len(utf16.Encode([]rune(s))) }

// EncodeResourceString writes a counted UTF-16 string.
//
// The count is in code units and not in bytes, and there is no NUL. A reader
// that treats it as a C string reads into whatever follows, which in a tree
// this package builds is the next name.
func EncodeResourceString(b *binio.Buf, s string) {
	units := utf16.Encode([]rune(s))
	b.U16(uint16(len(units)))
	for _, u := range units {
		b.U16(u)
	}
}

// DecodeResourceString reads one.
func DecodeResourceString(c *binio.Cursor) (string, error) {
	n := c.U16()
	if err := c.Err(); err != nil {
		return "", err
	}
	units := make([]uint16, n)
	for i := range units {
		units[i] = c.U16()
	}
	return string(utf16.Decode(units)), c.Err()
}