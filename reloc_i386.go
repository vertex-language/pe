package pe

// RelocI386 is a COFF relocation type for Intel 386 and compatible processors.
//
// The value space is sparse: 3, 4, 5, 8, and 0x0e through 0x13 are unassigned,
// and REL32 sits alone at 0x14. Several of the low values are listed in the
// specification as "not supported", meaning they are named but no Microsoft
// tool produces or consumes them.
type RelocI386 uint16

const (
	IMAGE_REL_I386_ABSOLUTE RelocI386 = 0x0000
	IMAGE_REL_I386_DIR16    RelocI386 = 0x0001 // not supported
	IMAGE_REL_I386_REL16    RelocI386 = 0x0002 // not supported
	// IMAGE_REL_I386_DIR32 is the target's 32-bit VA. Absolute, so it
	// needs a HIGHLOW base relocation.
	IMAGE_REL_I386_DIR32 RelocI386 = 0x0006
	// IMAGE_REL_I386_DIR32NB is the target's 32-bit RVA.
	IMAGE_REL_I386_DIR32NB RelocI386 = 0x0007
	IMAGE_REL_I386_SEG12   RelocI386 = 0x0009 // not supported
	// IMAGE_REL_I386_SECTION is the 16-bit index of the target's section.
	IMAGE_REL_I386_SECTION RelocI386 = 0x000A
	// IMAGE_REL_I386_SECREL is the 32-bit offset from the start of the
	// target's section. Debug information and static TLS.
	IMAGE_REL_I386_SECREL RelocI386 = 0x000B
	IMAGE_REL_I386_TOKEN  RelocI386 = 0x000C
	// IMAGE_REL_I386_SECREL7 is a 7-bit section offset.
	IMAGE_REL_I386_SECREL7 RelocI386 = 0x000D
	// IMAGE_REL_I386_REL32 is the 32-bit displacement to the target,
	// supporting the x86 relative branch and call instructions.
	IMAGE_REL_I386_REL32 RelocI386 = 0x0014
)

// IsPair reports whether r is a PAIR entry. No i386 relocation is.
func (r RelocI386) IsPair() bool { return false }

// TakesPair reports whether r must be followed by a PAIR. None is.
func (r RelocI386) TakesPair() bool { return false }

// IsAbsolute reports whether r is the ignored type.
func (r RelocI386) IsAbsolute() bool { return r == IMAGE_REL_I386_ABSOLUTE }

// Supported reports whether r is one the specification marks as usable, as
// opposed to the three it names but records as not supported.
func (r RelocI386) Supported() bool {
	switch r {
	case IMAGE_REL_I386_DIR16, IMAGE_REL_I386_REL16, IMAGE_REL_I386_SEG12:
		return false
	}
	return true
}

func (r RelocI386) String() string {
	switch r {
	case IMAGE_REL_I386_ABSOLUTE:
		return "IMAGE_REL_I386_ABSOLUTE"
	case IMAGE_REL_I386_DIR16:
		return "IMAGE_REL_I386_DIR16"
	case IMAGE_REL_I386_REL16:
		return "IMAGE_REL_I386_REL16"
	case IMAGE_REL_I386_DIR32:
		return "IMAGE_REL_I386_DIR32"
	case IMAGE_REL_I386_DIR32NB:
		return "IMAGE_REL_I386_DIR32NB"
	case IMAGE_REL_I386_SEG12:
		return "IMAGE_REL_I386_SEG12"
	case IMAGE_REL_I386_SECTION:
		return "IMAGE_REL_I386_SECTION"
	case IMAGE_REL_I386_SECREL:
		return "IMAGE_REL_I386_SECREL"
	case IMAGE_REL_I386_TOKEN:
		return "IMAGE_REL_I386_TOKEN"
	case IMAGE_REL_I386_SECREL7:
		return "IMAGE_REL_I386_SECREL7"
	case IMAGE_REL_I386_REL32:
		return "IMAGE_REL_I386_REL32"
	}
	return "IMAGE_REL_I386(" + itoa(int(r)) + ")"
}