package pe

import "strconv"

// FileChar is the Characteristics field of the COFF file header (offset 18).
// Most of its bits are deprecated; the ones this tree sets are marked.
type FileChar uint16

const (
	// FileRelocsStripped means the image has no base relocations and must
	// load at its preferred base. Image only.
	FileRelocsStripped FileChar = 0x0001
	// FileExecutable means the image is valid and can be run. Its absence
	// in an image indicates a linker error. Image only. Set by this tree.
	FileExecutable FileChar = 0x0002
	// FileLineNumsStripped is deprecated and should be zero.
	FileLineNumsStripped FileChar = 0x0004
	// FileLocalSymsStripped is deprecated and should be zero.
	FileLocalSymsStripped FileChar = 0x0008
	// FileAggressiveWSTrim is obsolete and must be zero for Windows 2000
	// and later.
	FileAggressiveWSTrim FileChar = 0x0010
	// FileLargeAddressAware means the application handles addresses above
	// 2 GB. Set by this tree for 64-bit images.
	FileLargeAddressAware FileChar = 0x0020
	// FileBytesReversedLo is deprecated and should be zero.
	FileBytesReversedLo FileChar = 0x0080
	// File32BitMachine means the machine is 32-bit word architecture. Set
	// by this tree when Width is Width32.
	File32BitMachine FileChar = 0x0100
	// FileDebugStripped means debugging information was removed.
	FileDebugStripped FileChar = 0x0200
	// FileRemovableRunFromSwap means copy to swap if on removable media.
	FileRemovableRunFromSwap FileChar = 0x0400
	// FileNetRunFromSwap means copy to swap if on network media.
	FileNetRunFromSwap FileChar = 0x0800
	// FileSystem means a system file, not a user program. Set for .sys.
	FileSystem FileChar = 0x1000
	// FileDLL means a dynamic-link library. Set by this tree for .dll.
	FileDLL FileChar = 0x2000
	// FileUPSystemOnly means run only on a uniprocessor machine.
	FileUPSystemOnly FileChar = 0x4000
	// FileBytesReversedHi is deprecated and should be zero.
	FileBytesReversedHi FileChar = 0x8000
)

// Has reports whether every bit in c is set in f.
func (f FileChar) Has(c FileChar) bool { return f&c == c }

func (f FileChar) String() string {
	if f == 0 {
		return "0"
	}
	names := []struct {
		bit  FileChar
		name string
	}{
		{FileRelocsStripped, "RELOCS_STRIPPED"},
		{FileExecutable, "EXECUTABLE_IMAGE"},
		{FileLineNumsStripped, "LINE_NUMS_STRIPPED"},
		{FileLocalSymsStripped, "LOCAL_SYMS_STRIPPED"},
		{FileAggressiveWSTrim, "AGGRESSIVE_WS_TRIM"},
		{FileLargeAddressAware, "LARGE_ADDRESS_AWARE"},
		{FileBytesReversedLo, "BYTES_REVERSED_LO"},
		{File32BitMachine, "32BIT_MACHINE"},
		{FileDebugStripped, "DEBUG_STRIPPED"},
		{FileRemovableRunFromSwap, "REMOVABLE_RUN_FROM_SWAP"},
		{FileNetRunFromSwap, "NET_RUN_FROM_SWAP"},
		{FileSystem, "SYSTEM"},
		{FileDLL, "DLL"},
		{FileUPSystemOnly, "UP_SYSTEM_ONLY"},
		{FileBytesReversedHi, "BYTES_REVERSED_HI"},
	}
	s := ""
	rest := f
	for _, n := range names {
		if f&n.bit != 0 {
			if s != "" {
				s += "|"
			}
			s += n.name
			rest &^= n.bit
		}
	}
	if rest != 0 {
		if s != "" {
			s += "|"
		}
		s += "0x" + strconv.FormatUint(uint64(rest), 16)
	}
	return s
}

// Kind is what a buffer turned out to be. It is the result of Kind, which
// infers rather than looks up a magic number, because COFF has none.
type Kind uint8

const (
	// KindUnknown means no rule matched. It is the zero value, so a Kind
	// that was never assigned reads as unknown rather than as an object.
	KindUnknown Kind = iota
	// KindObject is a relocatable COFF object with a 20-byte file header
	// and 18-byte symbol records.
	KindObject
	// KindBigObj is the ANON_OBJECT_HEADER_BIGOBJ variant: a 32-bit section
	// count and 20-byte symbol records.
	KindBigObj
	// KindShortImport is a short-import pseudo-object, the member kind that
	// makes up most of an import library.
	KindShortImport
	// KindLTCG is an MSVC /GL object. Its contents are the compiler's
	// intermediate representation, not COFF sections. This tree rejects it
	// rather than misparsing it.
	KindLTCG
	// KindImage is a linked PE image: .exe, .dll, .sys, or .efi.
	KindImage
	// KindArchive is a .lib or .a, including the thin variant.
	KindArchive
	// KindRes is a compiled resource file, rc.exe's output and rsrc's
	// input. It is detected here only because a .res begins with zero bytes
	// and would otherwise reach COFF inference.
	KindRes
)

// IsObject reports whether k is a relocatable object this tree can read,
// which excludes short-import members and /GL objects.
func (k Kind) IsObject() bool { return k == KindObject || k == KindBigObj }

func (k Kind) String() string {
	switch k {
	case KindObject:
		return "object"
	case KindBigObj:
		return "bigobj"
	case KindShortImport:
		return "short-import"
	case KindLTCG:
		return "ltcg"
	case KindImage:
		return "image"
	case KindArchive:
		return "archive"
	case KindRes:
		return "res"
	}
	return "unknown"
}