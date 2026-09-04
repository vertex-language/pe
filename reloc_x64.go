package pe

// RelocAMD64 is a COFF relocation type for x64 and compatible processors.
type RelocAMD64 uint16

const (
	// IMAGE_REL_AMD64_ABSOLUTE is ignored. Unlike the base-relocation
	// ABSOLUTE, this one is not used as padding; it just means nothing.
	IMAGE_REL_AMD64_ABSOLUTE RelocAMD64 = 0x0000
	// IMAGE_REL_AMD64_ADDR64 is the 64-bit VA of the target. Being
	// absolute, it needs a DIR64 base relocation.
	IMAGE_REL_AMD64_ADDR64 RelocAMD64 = 0x0001
	// IMAGE_REL_AMD64_ADDR32 is the 32-bit VA of the target. It needs a
	// HIGHLOW base relocation even though the machine is 64-bit — mapping
	// it to nothing has been a real bug in shipping linkers, producing an
	// image that runs at its preferred base and faults once ASLR moves it.
	IMAGE_REL_AMD64_ADDR32 RelocAMD64 = 0x0002
	// IMAGE_REL_AMD64_ADDR32NB is the 32-bit RVA of the target. Being
	// image-relative it needs no base relocation, which is why every PE
	// table that stores an address stores one of these.
	IMAGE_REL_AMD64_ADDR32NB RelocAMD64 = 0x0003
	// IMAGE_REL_AMD64_REL32 is the 32-bit displacement from the byte
	// following the relocation. Signed and 32-bit, so it reaches anywhere
	// in a 4 GB image — which is why the x64 backend needs no Thunker and
	// the layout fixpoint stays trivial.
	IMAGE_REL_AMD64_REL32 RelocAMD64 = 0x0004
	// The REL32_1 through REL32_5 forms are the same displacement measured
	// from 1 to 5 bytes further on, for instructions with trailing
	// immediates after the displacement field.
	IMAGE_REL_AMD64_REL32_1 RelocAMD64 = 0x0005
	IMAGE_REL_AMD64_REL32_2 RelocAMD64 = 0x0006
	IMAGE_REL_AMD64_REL32_3 RelocAMD64 = 0x0007
	IMAGE_REL_AMD64_REL32_4 RelocAMD64 = 0x0008
	IMAGE_REL_AMD64_REL32_5 RelocAMD64 = 0x0009
	// IMAGE_REL_AMD64_SECTION is the 16-bit index of the section holding
	// the target. Debug information only.
	IMAGE_REL_AMD64_SECTION RelocAMD64 = 0x000A
	// IMAGE_REL_AMD64_SECREL is the 32-bit offset of the target from the
	// start of its section. Used by debug information and, importantly, by
	// static TLS: an access to a thread-local resolves to an offset within
	// the TLS template rather than to an address.
	IMAGE_REL_AMD64_SECREL RelocAMD64 = 0x000B
	// IMAGE_REL_AMD64_SECREL7 is a 7-bit unsigned section offset.
	IMAGE_REL_AMD64_SECREL7 RelocAMD64 = 0x000C
	// IMAGE_REL_AMD64_TOKEN is a CLR token. This tree does not link
	// managed code and passes it through only as far as rejecting it.
	IMAGE_REL_AMD64_TOKEN RelocAMD64 = 0x000D
	// IMAGE_REL_AMD64_SREL32 is a 32-bit signed span-dependent value
	// emitted into the object. It is followed by a PAIR.
	IMAGE_REL_AMD64_SREL32 RelocAMD64 = 0x000E
	// IMAGE_REL_AMD64_PAIR must immediately follow a span-dependent value.
	// Its SymbolTableIndex is a displacement, not a symbol index. See
	// RelocIsPair.
	IMAGE_REL_AMD64_PAIR RelocAMD64 = 0x000F
	// IMAGE_REL_AMD64_SSPAN32 is a 32-bit signed span-dependent value
	// applied at link time.
	IMAGE_REL_AMD64_SSPAN32 RelocAMD64 = 0x0010
)

// IsPair reports whether r is a PAIR entry, whose SymbolTableIndex field
// carries a displacement rather than an index.
func (r RelocAMD64) IsPair() bool { return r == IMAGE_REL_AMD64_PAIR }

// TakesPair reports whether r must be immediately followed by a PAIR entry.
//
// The specification says a PAIR follows "every span-dependent value", of which
// SREL32 is unambiguously one. SSPAN32 is described as applied at link time
// rather than emitted into the object, and observed output does not pair it,
// so it is excluded here. If a real object turns up that pairs an SSPAN32,
// this is the one line to change.
func (r RelocAMD64) TakesPair() bool { return r == IMAGE_REL_AMD64_SREL32 }

// IsAbsolute reports whether r is the ignored type.
func (r RelocAMD64) IsAbsolute() bool { return r == IMAGE_REL_AMD64_ABSOLUTE }

func (r RelocAMD64) String() string {
	switch r {
	case IMAGE_REL_AMD64_ABSOLUTE:
		return "IMAGE_REL_AMD64_ABSOLUTE"
	case IMAGE_REL_AMD64_ADDR64:
		return "IMAGE_REL_AMD64_ADDR64"
	case IMAGE_REL_AMD64_ADDR32:
		return "IMAGE_REL_AMD64_ADDR32"
	case IMAGE_REL_AMD64_ADDR32NB:
		return "IMAGE_REL_AMD64_ADDR32NB"
	case IMAGE_REL_AMD64_REL32:
		return "IMAGE_REL_AMD64_REL32"
	case IMAGE_REL_AMD64_REL32_1:
		return "IMAGE_REL_AMD64_REL32_1"
	case IMAGE_REL_AMD64_REL32_2:
		return "IMAGE_REL_AMD64_REL32_2"
	case IMAGE_REL_AMD64_REL32_3:
		return "IMAGE_REL_AMD64_REL32_3"
	case IMAGE_REL_AMD64_REL32_4:
		return "IMAGE_REL_AMD64_REL32_4"
	case IMAGE_REL_AMD64_REL32_5:
		return "IMAGE_REL_AMD64_REL32_5"
	case IMAGE_REL_AMD64_SECTION:
		return "IMAGE_REL_AMD64_SECTION"
	case IMAGE_REL_AMD64_SECREL:
		return "IMAGE_REL_AMD64_SECREL"
	case IMAGE_REL_AMD64_SECREL7:
		return "IMAGE_REL_AMD64_SECREL7"
	case IMAGE_REL_AMD64_TOKEN:
		return "IMAGE_REL_AMD64_TOKEN"
	case IMAGE_REL_AMD64_SREL32:
		return "IMAGE_REL_AMD64_SREL32"
	case IMAGE_REL_AMD64_PAIR:
		return "IMAGE_REL_AMD64_PAIR"
	case IMAGE_REL_AMD64_SSPAN32:
		return "IMAGE_REL_AMD64_SSPAN32"
	}
	return "IMAGE_REL_AMD64(" + itoa(int(r)) + ")"
}