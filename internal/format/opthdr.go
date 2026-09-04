package format

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/binio"
)

// Optional header magic numbers.
const (
	MagicPE32     uint16 = 0x10b
	MagicPE32Plus uint16 = 0x20b
	// MagicROM is a ROM image. This tree does not produce or parse one; the
	// constant exists so a ROM image is rejected by name rather than as an
	// unrecognized number.
	MagicROM uint16 = 0x107
)

const (
	// optHeaderFixed32 is the standard plus Windows-specific fields for
	// PE32: 28 bytes of standard fields including BaseOfData, then 68.
	optHeaderFixed32 = 96
	// optHeaderFixed64 is the same for PE32+: 24 bytes of standard fields,
	// BaseOfData absent, then 88.
	optHeaderFixed64 = 112
)

// OptionalHeaderSize returns the size of an optional header with ndirs data
// directories at the given width.
//
// This is the only code in the tree that knows BaseOfData exists in PE32 and
// not in PE32+, and the only code that knows the directory count is variable.
// A caller wanting the conventional full header passes pe.NumDataDirs, which
// yields 224 for PE32 and 240 for PE32+.
func OptionalHeaderSize(w pe.Width, ndirs int) int {
	if ndirs < 0 {
		ndirs = 0
	}
	switch w {
	case pe.Width32:
		return optHeaderFixed32 + ndirs*pe.DataDirSize
	case pe.Width64:
		return optHeaderFixed64 + ndirs*pe.DataDirSize
	}
	return 0
}

// MagicFor returns the optional header magic for a width.
func MagicFor(w pe.Width) (uint16, error) {
	switch w {
	case pe.Width32:
		return MagicPE32, nil
	case pe.Width64:
		return MagicPE32Plus, nil
	}
	return 0, ErrWidth
}

// WidthFor returns the width a magic number implies.
func WidthFor(magic uint16) (pe.Width, error) {
	switch magic {
	case MagicPE32:
		return pe.Width32, nil
	case MagicPE32Plus:
		return pe.Width64, nil
	}
	return pe.WidthUnknown, ErrBadMagic
}

// DataDir is one entry of the data directory array: an address and a size.
//
// The first word is an RVA for fifteen of the sixteen and a file offset for
// the Certificate Table. This structure keeps it as a plain uint32 because it
// is the wire; the packages above give it a type, and image.DataDir carries
// the certificate entry in a separate Off-typed field for exactly that reason.
type DataDir struct {
	VirtualAddress uint32
	Size           uint32
}

func (d *DataDir) Decode(c *binio.Cursor) error {
	d.VirtualAddress = c.U32()
	d.Size = c.U32()
	return c.Err()
}

func (d *DataDir) Encode(b *binio.Buf) {
	b.U32(d.VirtualAddress)
	b.U32(d.Size)
}

// OptionalHeader is the image-only header between the file header and the
// section table.
//
// The four width-dependent fields are held as uint64 regardless of width and
// narrowed on encode, so the structure has one shape and the width lives only
// in the Decode and Encode arguments. There is no OptionalHeader32 and no
// OptionalHeader64.
type OptionalHeader struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	BaseOfData              uint32 // PE32 only; zero and unwritten under PE32+

	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32

	// Dirs holds the directories actually read. Its length is the smaller
	// of NumberOfRvaAndSizes and what the bytes allowed, so len(Dirs) is
	// always safe to range over while NumberOfRvaAndSizes preserves what
	// the file claimed. Truncated records whether they differed.
	Dirs      []DataDir
	Truncated bool
}

// Decode reads an optional header of the given width from c, which must be
// bounded to the header's extent — that is, to SizeOfOptionalHeader bytes.
//
// The directory count is not trusted. NumberOfRvaAndSizes is read as declared
// and then clamped to the bytes the cursor actually has, because the field is
// attacker-controlled and values of 0x20 and 0xFFFF both occur in the wild:
// the first in files that run correctly, the second in files built to break
// parsers. Reading past the cursor's bound would consume the section table as
// directory entries, which is a documented failure mode of at least one PE
// viewer.
//
// Truncated is set when the two disagree, so a caller can warn without this
// function having to decide whether a disagreement is fatal. It usually is
// not: a count *below* what the bytes allow is how a .NET binary hides its CLR
// directory from tools that honour the count, and the CLR loader parses it
// anyway.
func (h *OptionalHeader) Decode(c *binio.Cursor, w pe.Width) error {
	if !w.Valid() {
		return ErrWidth
	}
	h.Magic = c.U16()
	h.MajorLinkerVersion = c.U8()
	h.MinorLinkerVersion = c.U8()
	h.SizeOfCode = c.U32()
	h.SizeOfInitializedData = c.U32()
	h.SizeOfUninitializedData = c.U32()
	h.AddressOfEntryPoint = c.U32()
	h.BaseOfCode = c.U32()

	if w == pe.Width32 {
		h.BaseOfData = c.U32()
		h.ImageBase = uint64(c.U32())
	} else {
		h.BaseOfData = 0
		h.ImageBase = c.U64()
	}

	h.SectionAlignment = c.U32()
	h.FileAlignment = c.U32()
	h.MajorOperatingSystemVersion = c.U16()
	h.MinorOperatingSystemVersion = c.U16()
	h.MajorImageVersion = c.U16()
	h.MinorImageVersion = c.U16()
	h.MajorSubsystemVersion = c.U16()
	h.MinorSubsystemVersion = c.U16()
	h.Win32VersionValue = c.U32()
	h.SizeOfImage = c.U32()
	h.SizeOfHeaders = c.U32()
	h.CheckSum = c.U32()
	h.Subsystem = c.U16()
	h.DllCharacteristics = c.U16()

	if w == pe.Width32 {
		h.SizeOfStackReserve = uint64(c.U32())
		h.SizeOfStackCommit = uint64(c.U32())
		h.SizeOfHeapReserve = uint64(c.U32())
		h.SizeOfHeapCommit = uint64(c.U32())
	} else {
		h.SizeOfStackReserve = c.U64()
		h.SizeOfStackCommit = c.U64()
		h.SizeOfHeapReserve = c.U64()
		h.SizeOfHeapCommit = c.U64()
	}

	h.LoaderFlags = c.U32()
	h.NumberOfRvaAndSizes = c.U32()

	if err := c.Err(); err != nil {
		return err
	}

	fit := c.Len() / pe.DataDirSize
	n := int(h.NumberOfRvaAndSizes)
	if h.NumberOfRvaAndSizes > uint32(fit) {
		n = fit
		h.Truncated = true
	}
	h.Dirs = make([]DataDir, n)
	for i := range h.Dirs {
		if err := h.Dirs[i].Decode(c); err != nil {
			return err
		}
	}
	return c.Err()
}

// Encode writes the header at the given width, including len(Dirs)
// directories.
//
// NumberOfRvaAndSizes is written from len(Dirs), not from the field, so an
// encoder cannot emit a count that disagrees with what follows it.
func (h *OptionalHeader) Encode(b *binio.Buf, w pe.Width) {
	magic, err := MagicFor(w)
	if err != nil {
		b.Fail(err)
		return
	}
	b.U16(magic)
	b.U8(h.MajorLinkerVersion)
	b.U8(h.MinorLinkerVersion)
	b.U32(h.SizeOfCode)
	b.U32(h.SizeOfInitializedData)
	b.U32(h.SizeOfUninitializedData)
	b.U32(h.AddressOfEntryPoint)
	b.U32(h.BaseOfCode)

	if w == pe.Width32 {
		b.U32(h.BaseOfData)
		b.U32(uint32(h.ImageBase))
	} else {
		b.U64(h.ImageBase)
	}

	b.U32(h.SectionAlignment)
	b.U32(h.FileAlignment)
	b.U16(h.MajorOperatingSystemVersion)
	b.U16(h.MinorOperatingSystemVersion)
	b.U16(h.MajorImageVersion)
	b.U16(h.MinorImageVersion)
	b.U16(h.MajorSubsystemVersion)
	b.U16(h.MinorSubsystemVersion)
	b.U32(h.Win32VersionValue)
	b.U32(h.SizeOfImage)
	b.U32(h.SizeOfHeaders)
	b.U32(h.CheckSum)
	b.U16(h.Subsystem)
	b.U16(h.DllCharacteristics)

	if w == pe.Width32 {
		b.U32(uint32(h.SizeOfStackReserve))
		b.U32(uint32(h.SizeOfStackCommit))
		b.U32(uint32(h.SizeOfHeapReserve))
		b.U32(uint32(h.SizeOfHeapCommit))
	} else {
		b.U64(h.SizeOfStackReserve)
		b.U64(h.SizeOfStackCommit)
		b.U64(h.SizeOfHeapReserve)
		b.U64(h.SizeOfHeapCommit)
	}

	b.U32(h.LoaderFlags)
	b.U32(uint32(len(h.Dirs)))
	for i := range h.Dirs {
		h.Dirs[i].Encode(b)
	}
}

// Dir returns directory i if it is present and readable.
//
// This is the one probe check the tree performs, and the reason it exists in
// exactly one place. Two rules apply and they are not the same rule:
//
// The count bounds meaning. Windows resolves every directory access through
// RtlImageDirectoryEntryToData, which rejects an index at or above
// NumberOfRvaAndSizes — so a directory past the count does not exist, whatever
// bytes may sit there.
//
// The bytes bound safety. Decode already clamped Dirs to what was present, so
// indexing it cannot read the section table.
//
// Honouring only the first is how a viewer ends up rendering section headers
// as directories. Honouring only the second is how a shrunken count gets
// ignored. Both are checked here so that no caller has to remember either.
func (h *OptionalHeader) Dir(i pe.DataDirIndex) (DataDir, bool) {
	if i < 0 || uint32(i) >= h.NumberOfRvaAndSizes || int(i) >= len(h.Dirs) {
		return DataDir{}, false
	}
	return h.Dirs[i], true
}

// Size returns the encoded size of this header at the given width.
func (h *OptionalHeader) Size(w pe.Width) int {
	return OptionalHeaderSize(w, len(h.Dirs))
}