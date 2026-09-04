package format

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/binio"
)

// The load configuration directory is the only structure in this format that
// the linker neither builds nor owns. The CRT declares it — as
// _load_config_used — with its initializers already referencing symbols the
// linker is expected to define, and the linker's part is to define those
// symbols and, in two places, to write bytes into the structure directly.
//
// Three properties decide whether an implementation is correct, and all three
// are easy to get wrong in a way that produces a plausible file.
//
// It grows. Every Windows SDK appends fields, and the structure's own first
// DWORD states how much of it exists. A field past that Size is not a field:
// the bytes there belong to whatever the CRT placed after the struct, and a
// linker that writes GuardEHContinuationTable into a load config from a
// toolchain that predates it corrupts an unrelated object. Every accessor here
// is bounded by the *declared* size rather than by this layout's, which is why
// LoadConfigView exists and why no raw offset escapes the package.
//
// It is packed to four bytes. winnt.h declares the structure #pragma pack(4),
// so a 64-bit field sits at a 4-aligned offset with no padding in front of it.
// Laying it out with natural alignment gives a structure eight bytes too long
// by GuardFlags and wrong in every field after DeCommitFreeBlockThreshold —
// which is to say, wrong in every field a linker touches. The check that this
// layout is right is that it produces 320 bytes at PE32+ and 192 at PE32, and
// those are the sizes real images carry.
//
// And the two width variants are not the same structure with wider fields.
// ProcessHeapFlags and ProcessAffinityMask appear in the opposite order in the
// 32-bit declaration. A layout derived from the 64-bit one by narrowing every
// pointer is correct up to VirtualMemoryThreshold and shifted by four bytes
// from there to the end.

// LoadConfigField names one field of the directory.
type LoadConfigField int

const (
	LCSize LoadConfigField = iota
	LCTimeDateStamp
	LCMajorVersion
	LCMinorVersion
	LCGlobalFlagsClear
	LCGlobalFlagsSet
	LCCriticalSectionDefaultTimeout
	LCDeCommitFreeBlockThreshold
	LCDeCommitTotalFreeThreshold
	LCLockPrefixTable
	LCMaximumAllocationSize
	LCVirtualMemoryThreshold
	LCProcessAffinityMask
	LCProcessHeapFlags
	LCCSDVersion
	LCDependentLoadFlags
	LCEditList
	LCSecurityCookie
	LCSEHandlerTable
	LCSEHandlerCount
	LCGuardCFCheckFunctionPointer
	LCGuardCFDispatchFunctionPointer
	LCGuardCFFunctionTable
	LCGuardCFFunctionCount
	LCGuardFlags
	LCCodeIntegrity
	LCGuardAddressTakenIatEntryTable
	LCGuardAddressTakenIatEntryCount
	LCGuardLongJumpTargetTable
	LCGuardLongJumpTargetCount
	LCDynamicValueRelocTable
	LCCHPEMetadataPointer
	LCGuardRFFailureRoutine
	LCGuardRFFailureRoutineFunctionPointer
	LCDynamicValueRelocTableOffset
	LCDynamicValueRelocTableSection
	LCReserved2
	LCGuardRFVerifyStackPointerFunctionPointer
	LCHotPatchTableOffset
	LCReserved3
	LCEnclaveConfigurationPointer
	LCVolatileMetadataPointer
	LCGuardEHContinuationTable
	LCGuardEHContinuationCount
	LCGuardXFGCheckFunctionPointer
	LCGuardXFGDispatchFunctionPointer
	LCGuardXFGTableDispatchFunctionPointer
	LCCastGuardOsDeterminedFailureMode
	LCGuardMemcpyFunctionPointer

	numLoadConfigFields
)

// lcKind is a field's width class. lcPtr is the target's pointer size, which
// in this structure covers both the genuine pointers and the ULONGLONG counts
// and thresholds — they narrow together.
type lcKind uint8

const (
	lcU16 lcKind = iota
	lcU32
	lcPtr
	lcCodeIntegrity // IMAGE_LOAD_CONFIG_CODE_INTEGRITY: 2+2+4+4
)

// CodeIntegritySize is the embedded IMAGE_LOAD_CONFIG_CODE_INTEGRITY, which is
// the same twelve bytes at both widths.
const CodeIntegritySize = 12

func (k lcKind) size(w pe.Width) int {
	switch k {
	case lcU16:
		return 2
	case lcU32:
		return 4
	case lcPtr:
		return w.Bytes()
	case lcCodeIntegrity:
		return CodeIntegritySize
	}
	return 0
}

type lcEntry struct {
	field LoadConfigField
	kind  lcKind
}

// lcHead is the run up to the field pair the two widths disagree about.
var lcHead = []lcEntry{
	{LCSize, lcU32},
	{LCTimeDateStamp, lcU32},
	{LCMajorVersion, lcU16},
	{LCMinorVersion, lcU16},
	{LCGlobalFlagsClear, lcU32},
	{LCGlobalFlagsSet, lcU32},
	{LCCriticalSectionDefaultTimeout, lcU32},
	{LCDeCommitFreeBlockThreshold, lcPtr},
	{LCDeCommitTotalFreeThreshold, lcPtr},
	{LCLockPrefixTable, lcPtr},
	{LCMaximumAllocationSize, lcPtr},
	{LCVirtualMemoryThreshold, lcPtr},
}

// lcTail is everything after it.
var lcTail = []lcEntry{
	{LCCSDVersion, lcU16},
	{LCDependentLoadFlags, lcU16},
	{LCEditList, lcPtr},
	{LCSecurityCookie, lcPtr},
	{LCSEHandlerTable, lcPtr},
	{LCSEHandlerCount, lcPtr},
	{LCGuardCFCheckFunctionPointer, lcPtr},
	{LCGuardCFDispatchFunctionPointer, lcPtr},
	{LCGuardCFFunctionTable, lcPtr},
	{LCGuardCFFunctionCount, lcPtr},
	{LCGuardFlags, lcU32},
	{LCCodeIntegrity, lcCodeIntegrity},
	{LCGuardAddressTakenIatEntryTable, lcPtr},
	{LCGuardAddressTakenIatEntryCount, lcPtr},
	{LCGuardLongJumpTargetTable, lcPtr},
	{LCGuardLongJumpTargetCount, lcPtr},
	{LCDynamicValueRelocTable, lcPtr},
	{LCCHPEMetadataPointer, lcPtr},
	{LCGuardRFFailureRoutine, lcPtr},
	{LCGuardRFFailureRoutineFunctionPointer, lcPtr},
	{LCDynamicValueRelocTableOffset, lcU32},
	{LCDynamicValueRelocTableSection, lcU16},
	{LCReserved2, lcU16},
	{LCGuardRFVerifyStackPointerFunctionPointer, lcPtr},
	{LCHotPatchTableOffset, lcU32},
	{LCReserved3, lcU32},
	{LCEnclaveConfigurationPointer, lcPtr},
	{LCVolatileMetadataPointer, lcPtr},
	{LCGuardEHContinuationTable, lcPtr},
	{LCGuardEHContinuationCount, lcPtr},
	{LCGuardXFGCheckFunctionPointer, lcPtr},
	{LCGuardXFGDispatchFunctionPointer, lcPtr},
	{LCGuardXFGTableDispatchFunctionPointer, lcPtr},
	{LCCastGuardOsDeterminedFailureMode, lcPtr},
	{LCGuardMemcpyFunctionPointer, lcPtr},
}

// lcSlot is one field's resolved position.
type lcSlot struct {
	off  int
	size int
	ok   bool
}

// The two offset tables, computed once from the layout above rather than
// written out as literals. A literal table is a second place to state the same
// fact, and this structure changes every SDK.
var (
	lcOffsets32, lcTotal32 = buildLoadConfigOffsets(pe.Width32)
	lcOffsets64, lcTotal64 = buildLoadConfigOffsets(pe.Width64)
)

func buildLoadConfigOffsets(w pe.Width) ([numLoadConfigFields]lcSlot, int) {
	var out [numLoadConfigFields]lcSlot

	// The order of these two is the difference between the widths, and it
	// is the whole difference: everything before them and everything after
	// them is the same sequence with narrower fields.
	pair := []lcEntry{{LCProcessAffinityMask, lcPtr}, {LCProcessHeapFlags, lcU32}}
	if w == pe.Width32 {
		pair = []lcEntry{{LCProcessHeapFlags, lcU32}, {LCProcessAffinityMask, lcPtr}}
	}

	off := 0
	place := func(entries []lcEntry) {
		for _, e := range entries {
			n := e.kind.size(w)
			out[e.field] = lcSlot{off: off, size: n, ok: true}
			off += n
		}
	}
	place(lcHead)
	place(pair)
	place(lcTail)
	return out, off
}

// LoadConfigSize returns the size of the largest load configuration this tree
// knows how to describe: 192 bytes at PE32 and 320 at PE32+.
//
// It is not the size to write anywhere. The structure in the image is the
// CRT's, and its own Size field is authoritative — see LoadConfigView.
func LoadConfigSize(w pe.Width) int {
	switch w {
	case pe.Width32:
		return lcTotal32
	case pe.Width64:
		return lcTotal64
	}
	return 0
}

// LoadConfigOffset returns a field's offset and size at a width, according to
// the full layout. It does not say whether the field is present in any
// particular image; LoadConfigView.Has answers that.
func LoadConfigOffset(f LoadConfigField, w pe.Width) (off, size int, ok bool) {
	if f < 0 || f >= numLoadConfigFields {
		return 0, 0, false
	}
	var s lcSlot
	switch w {
	case pe.Width32:
		s = lcOffsets32[f]
	case pe.Width64:
		s = lcOffsets64[f]
	default:
		return 0, 0, false
	}
	return s.off, s.size, s.ok
}

// LoadConfigView is a read/write window onto a load configuration that already
// exists in a buffer.
//
// It is a view rather than a decoded structure because the linker's whole
// interaction with this directory is "fill in the fields the CRT left for me,
// and leave every byte I do not understand exactly as it was". Decoding to a
// struct and re-encoding would rewrite fields this tree has no opinion about,
// including any the running SDK added after this file was written.
//
// Every access is bounded by the declared size. A field the CRT's structure is
// too short to contain reports false rather than reaching past it.
type LoadConfigView struct {
	b        []byte
	w        pe.Width
	declared uint32
}

// NewLoadConfigView wraps b, which must begin at the directory's first byte.
//
// It reads and validates the declared size: a structure claiming more than the
// buffer holds, or fewer than the four bytes it takes to state its own size,
// is malformed rather than merely unfamiliar.
func NewLoadConfigView(b []byte, w pe.Width) (*LoadConfigView, error) {
	if !w.Valid() {
		return nil, ErrWidth
	}
	if len(b) < 4 {
		return nil, &FieldError{"LoadConfig", "Size", uint64(len(b)),
			"buffer too short to hold the size field"}
	}
	n := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	if n < 4 || uint64(n) > uint64(len(b)) {
		return nil, &FieldError{"LoadConfig", "Size", uint64(n),
			"declared size is outside the bytes available"}
	}
	return &LoadConfigView{b: b, w: w, declared: n}, nil
}

// DeclaredSize returns the structure's own Size field, which is what the data
// directory's size entry must report and what bounds every access here.
func (v *LoadConfigView) DeclaredSize() uint32 { return v.declared }

// Has reports whether the structure is long enough to contain a field.
//
// This is the question to ask before writing anything. /GUARD:CF against a CRT
// whose load config stops before GuardFlags is not a link that quietly does
// less — it is a link that would write into someone else's bytes, and the
// caller wants to hear about it.
func (v *LoadConfigView) Has(f LoadConfigField) bool {
	off, size, ok := LoadConfigOffset(f, v.w)
	return ok && uint64(off)+uint64(size) <= uint64(v.declared)
}

func (v *LoadConfigView) slot(f LoadConfigField, want int) ([]byte, bool) {
	off, size, ok := LoadConfigOffset(f, v.w)
	if !ok || (want > 0 && size != want) {
		return nil, false
	}
	if uint64(off)+uint64(size) > uint64(v.declared) {
		return nil, false
	}
	return v.b[off : off+size], true
}

// U32 reads a DWORD field.
func (v *LoadConfigView) U32(f LoadConfigField) (uint32, bool) {
	s, ok := v.slot(f, 4)
	if !ok {
		return 0, false
	}
	return uint32(s[0]) | uint32(s[1])<<8 | uint32(s[2])<<16 | uint32(s[3])<<24, true
}

// SetU32 writes a DWORD field.
func (v *LoadConfigView) SetU32(f LoadConfigField, val uint32) bool {
	s, ok := v.slot(f, 4)
	if !ok {
		return false
	}
	s[0], s[1], s[2], s[3] = byte(val), byte(val>>8), byte(val>>16), byte(val>>24)
	return true
}

// SetU16 writes a WORD field.
func (v *LoadConfigView) SetU16(f LoadConfigField, val uint16) bool {
	s, ok := v.slot(f, 2)
	if !ok {
		return false
	}
	s[0], s[1] = byte(val), byte(val>>8)
	return true
}

// Ptr reads a pointer-width field, zero-extended.
func (v *LoadConfigView) Ptr(f LoadConfigField) (uint64, bool) {
	s, ok := v.slot(f, v.w.Bytes())
	if !ok {
		return 0, false
	}
	var val uint64
	for i := len(s) - 1; i >= 0; i-- {
		val = val<<8 | uint64(s[i])
	}
	return val, true
}

// SetPtr writes a pointer-width field. A value too large for the width is
// refused rather than truncated: these fields hold virtual addresses, and a
// truncated address points into an unrelated page rather than being a smaller
// address.
func (v *LoadConfigView) SetPtr(f LoadConfigField, val uint64) bool {
	s, ok := v.slot(f, v.w.Bytes())
	if !ok {
		return false
	}
	if len(s) == 4 && val > 0xffffffff {
		return false
	}
	for i := range s {
		s[i] = byte(val >> (8 * i))
	}
	return true
}

// Decode reads the Size field alone, for a caller holding only a prefix. It is
// the one field guaranteed to be present in every version of the structure.
func DecodeLoadConfigSize(c *binio.Cursor) (uint32, error) {
	n := c.U32()
	return n, c.Err()
}