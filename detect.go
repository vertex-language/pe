package pe

import "bytes"

// COFF has no magic number. An image is identifiable — the MS-DOS stub holds
// the file offset of the PE signature at 0x3c — but an object is only
// identifiable by a plausible machine type followed by a structurally coherent
// header. Everything here is inference, and each check says what it is for
// rather than leaving a constant to be puzzled over later.
//
// The awkward case is the family that shares a lead-in. A bigobj, an MSVC /GL
// object, and a short-import member all begin with the two words 0x0000 and
// 0xFFFF, which no COFF file header can produce because those would be an
// unknown machine and a section count of 65535. What separates them is a
// 16-byte ClassID at offset 12 — present in the first two, absent in the
// third, where those bytes are ordinary header fields that match neither GUID.

// Buffer sizes the detection functions require. A shorter buffer is not an
// error; the functions simply decline to identify what they cannot see.
const (
	// MagicSize is the bytes needed to test for the MS-DOS "MZ" stub.
	MagicSize = 2

	// ImagePrefix is the bytes IsImage needs before it can read the PE
	// signature's offset. Confirming the signature itself needs the buffer
	// to extend to that offset, which is why IsImage takes a slice long
	// enough to reach it rather than a fixed-size array.
	ImagePrefix = 0x40

	// KindPrefix is the bytes KindOf needs to distinguish every case. The
	// binding constraint is the bigobj ClassID: 16 bytes at offset 12.
	KindPrefix = 28

	// ArchiveMagicSize is the bytes needed to test for an archive.
	ArchiveMagicSize = 8

	// FileHeaderSize is the size of the COFF file header, and the minimum
	// a relocatable object can be.
	FileHeaderSize = 20

	// MaxSections16 is the highest section number a 16-bit count can hold.
	// Numbers above it are reserved, which is why a larger object must be
	// promoted to bigobj rather than simply using the remaining values.
	MaxSections16 = 65279

	// MaxImageSections is the Windows loader's cap on sections in an image.
	// It is low enough that /MERGE is a correctness feature.
	MaxImageSections = 96
)

var (
	dosMagic     = []byte("MZ")
	peSignature  = []byte("PE\x00\x00")
	archiveMagic = []byte("!<arch>\n")
	thinMagic    = []byte("!<thin>\n")

	// anonPrefix is Sig1 = IMAGE_FILE_MACHINE_UNKNOWN, Sig2 = 0xFFFF.
	anonPrefix = []byte{0x00, 0x00, 0xff, 0xff}

	// bigObjClassID identifies ANON_OBJECT_HEADER_BIGOBJ. As a GUID it is
	// {D1BAA1C7-BAEE-4BA9-AF20-FAF66AA4DCB8}; these are its bytes in file
	// order, which differ because a GUID's first three fields are stored
	// little-endian.
	bigObjClassID = []byte{
		0xc7, 0xa1, 0xba, 0xd1, 0xee, 0xba, 0xa9, 0x4b,
		0xaf, 0x20, 0xfa, 0xf6, 0x6a, 0xa4, 0xdc, 0xb8,
	}

	// ltcgClassID identifies an MSVC /GL object, whose contents are the
	// compiler's IR rather than sections.
	ltcgClassID = []byte{
		0x38, 0xfe, 0xb3, 0x0c, 0xa5, 0xd9, 0xab, 0x4d,
		0xac, 0x9b, 0xd6, 0xb6, 0x22, 0x26, 0x53, 0xc2,
	}

	// resMagic is the null resource entry every .res file starts with: a
	// 32-bit zero data size, a 32-bit header size of 32, and type and name
	// both the ordinal escape 0xFFFF followed by ordinal zero.
	resMagic = []byte{
		0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
	}

	// anonVersion values, at offset 4 of a file with anonPrefix.
	//   0 — IMPORT_OBJECT_HEADER, a short-import member
	//   1 — ANON_OBJECT_HEADER, which carries a ClassID
	//   2 — ANON_OBJECT_HEADER_BIGOBJ
	_ = 0
)

func u16(b []byte, off int) uint16 {
	return uint16(b[off]) | uint16(b[off+1])<<8
}

func u32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 |
		uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

// Is reports whether head begins a relocatable COFF object with a standard
// 20-byte file header. It is inference, not a magic-number test.
//
// The machine must be one this tree has seeded, or UNKNOWN. UNKNOWN is not a
// missing answer: it is how a producer says the object targets no machine in
// particular, and the Microsoft C runtime is full of them — libcmt.lib ships
// _setjmp.obj as a machine-agnostic object carrying nothing but a .debug$S
// section. Such an object contributes to a link for any machine, so rejecting
// it here rejects the whole library.
//
// A machine of UNKNOWN needs one more fact to be an object at all, because
// zero is what a run of zero bytes says for every field: it must have a
// section or a symbol table. An object with neither contributes nothing and is
// indistinguishable from padding.
//
// Is does not recognize bigobj, short-import members, or /GL objects; each has
// its own leading signature and its own Kind.
func Is(head []byte) bool {
	if len(head) < FileHeaderSize {
		return false
	}
	// A file header cannot begin with the anonymous-object signature: that
	// pair would mean an unknown machine and 65535 sections.
	if bytes.HasPrefix(head, anonPrefix) {
		return false
	}
	if m := Machine(u16(head, 0)); !m.Supported() {
		if m != MachineUnknown {
			return false
		}
		if u16(head, 2) == 0 && u32(head, 8) == 0 {
			return false
		}
	}
	// Section numbers above MaxSections16 are reserved; a count in that
	// range means the file is not what it claims.
	if u16(head, 2) > MaxSections16 {
		return false
	}
	// The specification says SizeOfOptionalHeader should be zero in an
	// object. Some producers emit one anyway, so this only rejects a value
	// too large to be any optional header at all.
	if u16(head, 16) > 0xf0 {
		return false
	}
	// A symbol table pointer of zero must come with a count of zero. The
	// converse is not required: an object may have no symbols.
	if u32(head, 8) == 0 && u32(head, 12) != 0 {
		return false
	}
	return true
}

// IsImage reports whether head begins a linked PE image: the MS-DOS "MZ" stub,
// then the four-byte "PE\0\0" signature at the file offset stored at 0x3c.
//
// head must extend to that offset for the answer to be yes. A buffer that
// holds only the stub cannot confirm an image, so IsImage returns false; use
// HasDOSStub to distinguish "definitely not" from "cannot tell yet".
func IsImage(head []byte) bool {
	if !HasDOSStub(head) || len(head) < ImagePrefix {
		return false
	}
	off := u32(head, 0x3c)
	// Reject an offset that would wrap or that no plausible stub reaches
	// before checking the slice, so a corrupt value cannot index wildly.
	if off < ImagePrefix || uint64(off)+4 > uint64(len(head)) {
		return false
	}
	return bytes.Equal(head[off:off+4], peSignature)
}

// HasDOSStub reports whether head starts with the "MZ" magic. This is
// necessary but nowhere near sufficient for an image: every MS-DOS executable
// ever written also passes.
func HasDOSStub(head []byte) bool {
	return len(head) >= MagicSize && bytes.HasPrefix(head, dosMagic)
}

// IsArchive reports whether head begins an archive, thin or otherwise. The
// BSD variant shares this magic and is separated by ar, which rejects it.
func IsArchive(head []byte) bool {
	if len(head) < ArchiveMagicSize {
		return false
	}
	return bytes.HasPrefix(head, archiveMagic) || bytes.HasPrefix(head, thinMagic)
}

// KindOf identifies what head begins, returning KindUnknown when nothing
// matches. It needs KindPrefix bytes to separate every case, and rather more
// for an image, since confirming one means reaching the PE signature.
//
// It is spelled KindOf rather than Kind because Kind is the type it returns,
// and a package cannot hold both. MachineOf reads the same way for the same
// reason.
//
// The order below is not arbitrary. Archives and images are checked first
// because their signatures are unambiguous. The anonymous-object family comes
// next, because its members would otherwise fall through to a COFF inference
// that cannot describe them. A .res is checked before that inference too: it
// opens with four zero bytes, which is an unknown machine and no sections.
func KindOf(head []byte) Kind {
	switch {
	case IsArchive(head):
		return KindArchive
	case IsImage(head):
		return KindImage
	case bytes.HasPrefix(head, anonPrefix):
		return anonKind(head)
	case len(head) >= len(resMagic) && bytes.Equal(head[:len(resMagic)], resMagic):
		return KindRes
	case Is(head):
		return KindObject
	}
	return KindUnknown
}

// anonKind separates the three file types that share the 0x0000, 0xFFFF
// lead-in. The ClassID decides, and its absence is itself the answer: a
// short-import header is only 20 bytes, so the region a ClassID would occupy
// holds SizeOfData, the ordinal or hint, and the type bit field instead.
func anonKind(head []byte) Kind {
	if len(head) < KindPrefix {
		// Too short to hold a ClassID at all, which is consistent only
		// with the short-import header.
		return KindShortImport
	}
	switch id := head[12:KindPrefix]; {
	case bytes.Equal(id, bigObjClassID):
		return KindBigObj
	case bytes.Equal(id, ltcgClassID):
		return KindLTCG
	}
	return KindShortImport
}

// MachineOf returns the machine type recorded in head, for any of the object
// kinds. The field is at a different offset in each: 0 in a COFF file header,
// and 6 in the anonymous-object family, after Sig1, Sig2, and Version.
//
// It reports false for an image, because an image's header machine is not its
// target machine — see Machine.ImageMachine — and answering with the header
// value would invite exactly the confusion that method exists to prevent.
//
// ar uses this to route members to the /<ECSYMBOLS>/ index without having to
// understand COFF.
func MachineOf(head []byte) (Machine, bool) {
	switch KindOf(head) {
	case KindObject:
		return Machine(u16(head, 0)), true
	case KindBigObj, KindLTCG, KindShortImport:
		if len(head) < 8 {
			return MachineUnknown, false
		}
		return Machine(u16(head, 6)), true
	}
	return MachineUnknown, false
}