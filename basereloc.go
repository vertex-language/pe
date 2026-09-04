package pe

// The base relocation table exists because pointers in a PE image are
// absolute VAs while the image itself may move. It is a list of blocks, one
// per 4K page, each starting with the page's RVA and the block's total size,
// followed by any number of 16-bit entries whose high four bits are the type
// and low twelve the offset within that page.
//
// Blocks are 32-bit aligned, which is why type zero exists: ABSOLUTE entries
// are the padding that gets a block back to alignment, and the loader skips
// them.

// BaseRelocKind is the four-bit type of a base relocation entry.
//
// The values are not machine-independent — 5, 7, and 8 mean different things
// on MIPS, ARM, and RISC-V, and 9 is shared between MIPS and Itanium. There is
// deliberately no String method that resolves them, because rendering one
// without knowing the machine would be a guess presented as a fact. Use
// BaseRelocKind.Name(Machine) instead.
type BaseRelocKind uint8

const (
	// BaseRelocAbsolute is skipped by the loader. It is block padding.
	BaseRelocAbsolute BaseRelocKind = 0
	// BaseRelocHigh applies the high 16 bits of the delta to a 16-bit field.
	BaseRelocHigh BaseRelocKind = 1
	// BaseRelocLow applies the low 16 bits of the delta to a 16-bit field.
	BaseRelocLow BaseRelocKind = 2
	// BaseRelocHighLow applies all 32 bits of the delta to a 32-bit field.
	// This is the one a 32-bit image uses, and — importantly — the one a
	// 64-bit image uses for an ADDR32.
	BaseRelocHighLow BaseRelocKind = 3
	// BaseRelocHighAdj applies the high 16 bits of the delta to a 16-bit
	// field and consumes a second entry. See Slots.
	BaseRelocHighAdj BaseRelocKind = 4

	// 5, 7, 8, and 9 are per-machine. Named here for completeness; none is
	// produced by a seeded backend.
	BaseRelocMIPSJmpAddr   BaseRelocKind = 5 // also ARM_MOV32, RISCV_HIGH20
	BaseRelocARMMov32      BaseRelocKind = 5
	BaseRelocRISCVHigh20   BaseRelocKind = 5
	BaseRelocThumbMov32    BaseRelocKind = 7 // also REL, RISCV_LOW12I
	BaseRelocRISCVLow12I   BaseRelocKind = 7
	BaseRelocRISCVLow12S   BaseRelocKind = 8
	BaseRelocMIPSJmpAddr16 BaseRelocKind = 9 // also IA64_IMM64

	// BaseRelocDir64 applies the delta to a 64-bit field. This and
	// HighLow are the only two a seeded backend emits.
	BaseRelocDir64 BaseRelocKind = 10
)

const (
	// BaseRelocPageSize is the span one block covers, and the reason the
	// offset field is twelve bits.
	BaseRelocPageSize = 0x1000

	// BaseRelocBlockHeaderSize is the page RVA plus the block size.
	BaseRelocBlockHeaderSize = 8

	// BaseRelocEntrySize is one 16-bit entry.
	BaseRelocEntrySize = 2

	// BaseRelocBlockAlign is the alignment every block start must meet,
	// achieved by padding with ABSOLUTE entries.
	BaseRelocBlockAlign = 4

	baseRelocTypeShift  = 12
	baseRelocOffsetMask = 0x0fff
)

// Slots returns how many 16-bit entries this kind occupies in a block.
//
// Every kind occupies one except HIGHADJ, which occupies two: the entry
// itself carries the type and offset, and the entry immediately after it is
// not a relocation at all but a raw 16-bit value, the low half of the target,
// needed because applying only the high half loses the carry.
//
// This is the base-relocation twin of the COFF PAIR rule. A consumer that
// walks a block by incrementing one entry at a time will read that raw value
// as a relocation and corrupt whatever its bogus offset points at, so the
// walk must consult this.
func (k BaseRelocKind) Slots() int {
	if k == BaseRelocHighAdj {
		return 2
	}
	return 1
}

// Name returns the spelling of k for a given machine. The machine is required
// because several values are shared. An unknown pairing renders as the number.
func (k BaseRelocKind) Name(m Machine) string {
	switch k {
	case BaseRelocAbsolute:
		return "ABSOLUTE"
	case BaseRelocHigh:
		return "HIGH"
	case BaseRelocLow:
		return "LOW"
	case BaseRelocHighLow:
		return "HIGHLOW"
	case BaseRelocHighAdj:
		return "HIGHADJ"
	case BaseRelocDir64:
		return "DIR64"
	}
	switch m.Arch() {
	case ArchARM64:
		// AArch64 uses only ABSOLUTE and DIR64; the MOV32 forms belong to
		// AArch32, which is not seeded.
	}
	return "basereloc(" + itoa(int(k)) + ")"
}

// EncodeBaseRelocEntry packs a type and a page offset into one entry. offset
// must be within a page; a caller that has an RVA should mask it with
// BaseRelocPageSize-1 only after confirming the entry belongs to that block.
func EncodeBaseRelocEntry(kind BaseRelocKind, offset uint16) (uint16, error) {
	if kind > 0x0f {
		return 0, errBaseRelocKind(kind)
	}
	if offset >= BaseRelocPageSize {
		return 0, errBaseRelocOffset(offset)
	}
	return uint16(kind)<<baseRelocTypeShift | offset, nil
}

// DecodeBaseRelocEntry splits an entry into its type and page offset. It
// cannot fail: every 16-bit value is a well-formed entry, which is precisely
// why a walk has to use Slots to know whether the next word is one.
func DecodeBaseRelocEntry(e uint16) (BaseRelocKind, uint16) {
	return BaseRelocKind(e >> baseRelocTypeShift), e & baseRelocOffsetMask
}