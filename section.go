package pe

import (
	"fmt"
	"strconv"
)

// A section's Characteristics field is one uint32 on the wire carrying three
// unrelated things: what the section contains, how it may be mapped, and how
// it must be aligned. They are three types here, packed only at the wire edge
// by PackSecChar and split by SplitSecChar.
//
// Keeping them apart matters because they have different lifetimes. Content
// flags come from the object and mostly survive to the image; memory flags are
// frequently overridden by /SECTION; and alignment is an object-file property
// that has no meaning in an image at all.

// SecKind is the content half of a section's characteristics: the
// IMAGE_SCN_CNT_*, IMAGE_SCN_LNK_*, and IMAGE_SCN_TYPE_* bits.
type SecKind uint32

const (
	// SecTypeNoLoad is not in the published specification, which lists
	// 0x00000002 as reserved, but appears in winnt.h and in real objects.
	SecTypeNoLoad SecKind = 0x00000002
	// SecTypeNoPad is obsolete, superseded by an alignment of 1 byte. It is
	// valid in objects only, and DecodeAlign honours it.
	SecTypeNoPad SecKind = 0x00000008

	SecCode       SecKind = 0x00000020 // IMAGE_SCN_CNT_CODE
	SecInitData   SecKind = 0x00000040 // IMAGE_SCN_CNT_INITIALIZED_DATA
	SecUninitData SecKind = 0x00000080 // IMAGE_SCN_CNT_UNINITIALIZED_DATA

	SecLnkOther SecKind = 0x00000100 // reserved
	// SecLnkInfo marks a section of comments or directives. .drectve has
	// it, and it is valid in objects only.
	SecLnkInfo SecKind = 0x00000200
	// SecLnkRemove marks a section that will not become part of the image.
	SecLnkRemove SecKind = 0x00000800
	// SecLnkComdat marks a COMDAT section, which must have a key symbol.
	SecLnkComdat SecKind = 0x00001000

	// SecGPRel marks data referenced through the global pointer.
	SecGPRel SecKind = 0x00008000

	// SecLnkNRelocOvfl is the escape for a section with more than 0xffff
	// relocations: NumberOfRelocations reads 0xffff and the real count
	// lives in the first relocation's VirtualAddress.
	//
	// It is handled in both directions by coff and never surfaces in that
	// package's API, so a caller neither sets nor observes it. The constant
	// exists so the reader and writer can name what they are stripping.
	SecLnkNRelocOvfl SecKind = 0x01000000
)

// secKindMask is every bit SecKind owns. Bits outside it belong to SecProt or
// to the alignment nibble.
//
// It is written as the union of the constants rather than as a literal,
// because a literal is a second place to state the same fact and the two
// disagreed once already: a mask missing CNT_UNINITIALIZED_DATA and LNK_COMDAT
// makes SplitSecChar strip both on read — every COMDAT in every object decodes
// as an ordinary section — and makes PackSecChar reject them on write. Neither
// failure says anything about a mask.
const secKindMask = SecTypeNoLoad | SecTypeNoPad |
	SecCode | SecInitData | SecUninitData |
	SecLnkOther | SecLnkInfo | SecLnkRemove | SecLnkComdat |
	SecGPRel | SecLnkNRelocOvfl

func (k SecKind) Has(b SecKind) bool { return k&b == b }

func (k SecKind) String() string {
	names := []struct {
		bit  SecKind
		name string
	}{
		{SecTypeNoLoad, "TYPE_NOLOAD"},
		{SecTypeNoPad, "TYPE_NO_PAD"},
		{SecCode, "CNT_CODE"},
		{SecInitData, "CNT_INITIALIZED_DATA"},
		{SecUninitData, "CNT_UNINITIALIZED_DATA"},
		{SecLnkOther, "LNK_OTHER"},
		{SecLnkInfo, "LNK_INFO"},
		{SecLnkRemove, "LNK_REMOVE"},
		{SecLnkComdat, "LNK_COMDAT"},
		{SecGPRel, "GPREL"},
		{SecLnkNRelocOvfl, "LNK_NRELOC_OVFL"},
	}
	return flagString(uint32(k), func(i int) (uint32, string, bool) {
		if i >= len(names) {
			return 0, "", false
		}
		return uint32(names[i].bit), names[i].name, true
	})
}

// SecProt is the memory half of a section's characteristics: the
// IMAGE_SCN_MEM_* bits. These are the protections the loader applies, and the
// three that matter are Execute, Read, and Write.
type SecProt uint32

const (
	SecMemPurgeable SecProt = 0x00020000 // reserved
	SecMem16Bit     SecProt = 0x00020000 // reserved; aliases Purgeable
	SecMemLocked    SecProt = 0x00040000 // reserved
	SecMemPreload   SecProt = 0x00080000 // reserved

	// SecDiscardable marks a section the loader may drop, such as .reloc.
	SecDiscardable SecProt = 0x02000000
	SecNotCached   SecProt = 0x04000000
	SecNotPaged    SecProt = 0x08000000
	SecShared      SecProt = 0x10000000
	SecExecute     SecProt = 0x20000000
	SecRead        SecProt = 0x40000000
	SecWrite       SecProt = 0x80000000
)

// secProtMask is every bit SecProt owns. SecMem16Bit is omitted only because
// it aliases SecMemPurgeable; including it would change nothing.
const secProtMask = SecMemPurgeable | SecMemLocked | SecMemPreload |
	SecDiscardable | SecNotCached | SecNotPaged | SecShared |
	SecExecute | SecRead | SecWrite

// The three halves of the field must not overlap. A non-zero intersection
// makes one of these indices out of range, which is a compile error here
// rather than a section whose flags change as they round-trip.
var (
	_ = [1]struct{}{}[uint32(secKindMask)&uint32(secProtMask)]
	_ = [1]struct{}{}[uint32(secKindMask)&secAlignMask]
	_ = [1]struct{}{}[uint32(secProtMask)&secAlignMask]
)

func (p SecProt) Has(b SecProt) bool { return p&b == b }

func (p SecProt) String() string {
	names := []struct {
		bit  SecProt
		name string
	}{
		{SecMemPurgeable, "MEM_PURGEABLE"},
		{SecMemLocked, "MEM_LOCKED"},
		{SecMemPreload, "MEM_PRELOAD"},
		{SecDiscardable, "MEM_DISCARDABLE"},
		{SecNotCached, "MEM_NOT_CACHED"},
		{SecNotPaged, "MEM_NOT_PAGED"},
		{SecShared, "MEM_SHARED"},
		{SecExecute, "MEM_EXECUTE"},
		{SecRead, "MEM_READ"},
		{SecWrite, "MEM_WRITE"},
	}
	return flagString(uint32(p), func(i int) (uint32, string, bool) {
		if i >= len(names) {
			return 0, "", false
		}
		return uint32(names[i].bit), names[i].name, true
	})
}

// Alignment lives in bits 20 through 23 as a nibble whose value is
// log2(bytes)+1: IMAGE_SCN_ALIGN_1BYTES is 0x00100000 and each step doubles,
// up to 8192 bytes at 0x00E00000.
//
// Align is in bytes on both sides of this package. The log2-plus-one form
// exists only between these two functions and never escapes.
const (
	secAlignMask  uint32 = 0x00f00000
	secAlignShift uint32 = 20

	// MaxAlign is the largest alignment the nibble can express.
	MaxAlign = 8192

	// DefaultAlign is what an absent alignment nibble means. The
	// specification does not define nibble zero; link.exe and lld both
	// treat it as 16 bytes, and this tree follows them. The writer always
	// emits an explicit nibble, so this affects reading only.
	DefaultAlign = 16
)

// DecodeAlign returns the alignment, in bytes, encoded in a section's
// characteristics.
//
// A zero nibble yields DefaultAlign. IMAGE_SCN_TYPE_NO_PAD, the obsolete
// spelling of "do not pad", yields 1.
func DecodeAlign(char uint32) int {
	if n := (char & secAlignMask) >> secAlignShift; n > 0 {
		return 1 << (n - 1)
	}
	if SecKind(char)&SecTypeNoPad != 0 {
		return 1
	}
	return DefaultAlign
}

// EncodeAlign returns the nibble, already shifted into place, for an alignment
// given in bytes. align must be a power of two between 1 and MaxAlign.
func EncodeAlign(align int) (uint32, error) {
	if align <= 0 || align > MaxAlign || align&(align-1) != 0 {
		return 0, fmt.Errorf("pe: alignment %d is not a power of two in 1..%d", align, MaxAlign)
	}
	n := uint32(0)
	for v := align; v > 1; v >>= 1 {
		n++
	}
	return (n + 1) << secAlignShift, nil
}

// SplitSecChar decomposes a section's Characteristics field into its three
// independent parts. It is one of exactly two places in this module that know
// the packing; PackSecChar is the other.
func SplitSecChar(char uint32) (SecKind, SecProt, int) {
	return SecKind(char) & secKindMask, SecProt(char) & secProtMask, DecodeAlign(char)
}

// PackSecChar composes a section's Characteristics field. It reports an error
// for an unencodable alignment, and for kind or prot bits that stray outside
// the half they own — which would otherwise silently corrupt the other two
// fields on the round trip.
func PackSecChar(kind SecKind, prot SecProt, align int) (uint32, error) {
	if kind&^secKindMask != 0 {
		return 0, fmt.Errorf("pe: SecKind %#08x has bits outside the content mask", uint32(kind))
	}
	if prot&^secProtMask != 0 {
		return 0, fmt.Errorf("pe: SecProt %#08x has bits outside the memory mask", uint32(prot))
	}
	nibble, err := EncodeAlign(align)
	if err != nil {
		return 0, err
	}
	return uint32(kind) | uint32(prot) | nibble, nil
}

func flagString(v uint32, at func(int) (uint32, string, bool)) string {
	if v == 0 {
		return "0"
	}
	s, rest := "", v
	for i := 0; ; i++ {
		bit, name, ok := at(i)
		if !ok {
			break
		}
		if v&bit != 0 && rest&bit != 0 {
			if s != "" {
				s += "|"
			}
			s += name
			rest &^= bit
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