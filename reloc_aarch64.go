package pe

// RelocARM64 is a COFF relocation type for ARM64 processors. It covers plain
// AArch64, ARM64EC, and the AArch64 half of ARM64X: the instruction encodings
// are the same in all three, and the ABI difference lives elsewhere.
type RelocARM64 uint16

const (
	IMAGE_REL_ARM64_ABSOLUTE RelocARM64 = 0x0000
	// IMAGE_REL_ARM64_ADDR32 is the 32-bit VA of the target. Absolute, so
	// it needs a HIGHLOW base relocation despite the 64-bit machine.
	IMAGE_REL_ARM64_ADDR32 RelocARM64 = 0x0001
	// IMAGE_REL_ARM64_ADDR32NB is the 32-bit RVA of the target.
	IMAGE_REL_ARM64_ADDR32NB RelocARM64 = 0x0002
	// IMAGE_REL_ARM64_BRANCH26 is the 26-bit displacement of a B or BL.
	// It reaches +/-128 MiB, which is why the aarch64 backend must
	// implement Thunker and why its layout fixpoint has to converge on
	// thunk growth rather than running once.
	IMAGE_REL_ARM64_BRANCH26 RelocARM64 = 0x0003
	// IMAGE_REL_ARM64_PAGEBASE_REL21 is the page base of the target, for
	// ADRP. Paired in practice with a PAGEOFFSET_12A or _12L, though not
	// by the PAIR mechanism — the two are independent relocations and
	// either may appear without the other.
	IMAGE_REL_ARM64_PAGEBASE_REL21 RelocARM64 = 0x0004
	// IMAGE_REL_ARM64_REL21 is the 21-bit relative displacement to the
	// target, for ADR.
	//
	// The published specification describes this as 12-bit, which
	// contradicts the constant's own name and the instruction's range;
	// it appears to be copied from the PAGEOFFSET_12A row. ADR encodes 21
	// bits, and that is what this is.
	IMAGE_REL_ARM64_REL21 RelocARM64 = 0x0005
	// IMAGE_REL_ARM64_PAGEOFFSET_12A is the 12-bit page offset, for
	// ADD/ADDS immediate with zero shift.
	IMAGE_REL_ARM64_PAGEOFFSET_12A RelocARM64 = 0x0006
	// IMAGE_REL_ARM64_PAGEOFFSET_12L is the 12-bit page offset, for LDR
	// with an unsigned scaled immediate. The scaling depends on the
	// instruction's access size, so applying this one requires decoding
	// the instruction — a backend concern, not a table concern.
	IMAGE_REL_ARM64_PAGEOFFSET_12L RelocARM64 = 0x0007
	// IMAGE_REL_ARM64_SECREL is the 32-bit offset from the start of the
	// target's section. Debug information and static TLS.
	IMAGE_REL_ARM64_SECREL RelocARM64 = 0x0008
	// The SECREL_LOW12A, HIGH12A, and LOW12L forms carry slices of a
	// section offset in the immediate field of a specific instruction.
	IMAGE_REL_ARM64_SECREL_LOW12A  RelocARM64 = 0x0009 // bits 0:11, ADD/ADDS
	IMAGE_REL_ARM64_SECREL_HIGH12A RelocARM64 = 0x000A // bits 12:23, ADD/ADDS
	IMAGE_REL_ARM64_SECREL_LOW12L  RelocARM64 = 0x000B // bits 0:11, LDR
	IMAGE_REL_ARM64_TOKEN          RelocARM64 = 0x000C
	// IMAGE_REL_ARM64_SECTION is the 16-bit index of the target's section.
	IMAGE_REL_ARM64_SECTION RelocARM64 = 0x000D
	// IMAGE_REL_ARM64_ADDR64 is the 64-bit VA of the target, needing a
	// DIR64 base relocation.
	IMAGE_REL_ARM64_ADDR64 RelocARM64 = 0x000E
	// IMAGE_REL_ARM64_BRANCH19 is the 19-bit offset of a conditional B.
	// Its reach is far shorter than BRANCH26 and it cannot be thunked the
	// same way, since a veneer for a conditional branch needs an inverted
	// branch over an unconditional one.
	IMAGE_REL_ARM64_BRANCH19 RelocARM64 = 0x000F
	// IMAGE_REL_ARM64_BRANCH14 is the 14-bit offset of TBZ or TBNZ.
	IMAGE_REL_ARM64_BRANCH14 RelocARM64 = 0x0010
	// IMAGE_REL_ARM64_REL32 is the 32-bit displacement from the byte
	// following the relocation.
	IMAGE_REL_ARM64_REL32 RelocARM64 = 0x0011
)

// IsPair reports whether r is a PAIR entry. No ARM64 relocation is; the
// method exists so every table in this package answers the same questions.
func (r RelocARM64) IsPair() bool { return false }

// TakesPair reports whether r must be followed by a PAIR. None is.
func (r RelocARM64) TakesPair() bool { return false }

// IsAbsolute reports whether r is the ignored type.
func (r RelocARM64) IsAbsolute() bool { return r == IMAGE_REL_ARM64_ABSOLUTE }

// IsBranch reports whether r is a branch displacement, and so a candidate for
// a range-extension thunk when its target ends up too far away.
func (r RelocARM64) IsBranch() bool {
	switch r {
	case IMAGE_REL_ARM64_BRANCH26, IMAGE_REL_ARM64_BRANCH19, IMAGE_REL_ARM64_BRANCH14:
		return true
	}
	return false
}

func (r RelocARM64) String() string {
	switch r {
	case IMAGE_REL_ARM64_ABSOLUTE:
		return "IMAGE_REL_ARM64_ABSOLUTE"
	case IMAGE_REL_ARM64_ADDR32:
		return "IMAGE_REL_ARM64_ADDR32"
	case IMAGE_REL_ARM64_ADDR32NB:
		return "IMAGE_REL_ARM64_ADDR32NB"
	case IMAGE_REL_ARM64_BRANCH26:
		return "IMAGE_REL_ARM64_BRANCH26"
	case IMAGE_REL_ARM64_PAGEBASE_REL21:
		return "IMAGE_REL_ARM64_PAGEBASE_REL21"
	case IMAGE_REL_ARM64_REL21:
		return "IMAGE_REL_ARM64_REL21"
	case IMAGE_REL_ARM64_PAGEOFFSET_12A:
		return "IMAGE_REL_ARM64_PAGEOFFSET_12A"
	case IMAGE_REL_ARM64_PAGEOFFSET_12L:
		return "IMAGE_REL_ARM64_PAGEOFFSET_12L"
	case IMAGE_REL_ARM64_SECREL:
		return "IMAGE_REL_ARM64_SECREL"
	case IMAGE_REL_ARM64_SECREL_LOW12A:
		return "IMAGE_REL_ARM64_SECREL_LOW12A"
	case IMAGE_REL_ARM64_SECREL_HIGH12A:
		return "IMAGE_REL_ARM64_SECREL_HIGH12A"
	case IMAGE_REL_ARM64_SECREL_LOW12L:
		return "IMAGE_REL_ARM64_SECREL_LOW12L"
	case IMAGE_REL_ARM64_TOKEN:
		return "IMAGE_REL_ARM64_TOKEN"
	case IMAGE_REL_ARM64_SECTION:
		return "IMAGE_REL_ARM64_SECTION"
	case IMAGE_REL_ARM64_ADDR64:
		return "IMAGE_REL_ARM64_ADDR64"
	case IMAGE_REL_ARM64_BRANCH19:
		return "IMAGE_REL_ARM64_BRANCH19"
	case IMAGE_REL_ARM64_BRANCH14:
		return "IMAGE_REL_ARM64_BRANCH14"
	case IMAGE_REL_ARM64_REL32:
		return "IMAGE_REL_ARM64_REL32"
	}
	return "IMAGE_REL_ARM64(" + itoa(int(r)) + ")"
}