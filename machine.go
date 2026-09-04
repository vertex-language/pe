package pe

import (
	"fmt"
	"strconv"
)

// Machine is the wire value of the Machine field at offset 0 of the COFF file
// header. It identifies the target CPU and, for ARM64EC, the ABI.
//
// A constant being defined here does not mean this tree supports it. The
// seeded set is I386, AMD64, ARM64, ARM64EC, and ARM64X; everything else
// yields ArchUnknown, WidthUnknown, and ErrUnsupportedMachine.
type Machine uint16

// Machine types. Names follow the IMAGE_FILE_MACHINE_* constants of the
// PE/COFF specification.
const (
	MachineUnknown Machine = 0x0000 // IMAGE_FILE_MACHINE_UNKNOWN
	MachineI386    Machine = 0x014c // IMAGE_FILE_MACHINE_I386
	MachineARMNT   Machine = 0x01c4 // IMAGE_FILE_MACHINE_ARMNT — named, not seeded
	MachineAMD64   Machine = 0x8664 // IMAGE_FILE_MACHINE_AMD64
	MachineARM64EC Machine = 0xa641 // IMAGE_FILE_MACHINE_ARM64EC — objects only
	MachineARM64X  Machine = 0xa64e // IMAGE_FILE_MACHINE_ARM64X — objects only
	MachineARM64   Machine = 0xaa64 // IMAGE_FILE_MACHINE_ARM64
)

// Arch is the coarse instruction-set family. It is the grouping a backend
// registry would key on if SubArch did not exist; because SubArch does exist,
// Arch deliberately does not distinguish ARM64 from ARM64EC. The two share an
// instruction set and differ in ABI, and that difference is SubArch's axis.
type Arch uint8

const (
	ArchUnknown Arch = iota
	ArchX86
	ArchAMD64
	ArchARM64
)

func (a Arch) String() string {
	switch a {
	case ArchX86:
		return "x86"
	case ArchAMD64:
		return "amd64"
	case ArchARM64:
		return "arm64"
	}
	return "arch(" + strconv.Itoa(int(a)) + ")"
}

// SubArch is the ABI axis of Machine. It is not a refinement of Arch: a
// backend is registered on the (Machine, SubArch) pair, and there is no
// fallback from a specific subarch to a generic one, because a backend decides
// which ABI a call site speaks.
type SubArch uint8

const (
	SubArchNone SubArch = iota
	SubArchEC           // the ARM64EC ABI
)

func (s SubArch) String() string {
	switch s {
	case SubArchNone:
		return "none"
	case SubArchEC:
		return "ec"
	}
	return "subarch(" + strconv.Itoa(int(s)) + ")"
}

// Width is the address width of a machine, in bits. It is never stored: it is
// derived from Machine and nowhere else. There is no Bits field, no PE32Plus
// bool, and no independently settable width in any exported API of this
// module, because a width that disagrees with its machine is a file no loader
// will accept and a bug no test will catch.
//
// Width decides the optional-header magic, the size of ImageBase and the four
// stack and heap fields, whether BaseOfData is present, and which bit of an
// import thunk is the ordinal flag.
//
// The zero value is invalid. An unseeded machine yields WidthUnknown rather
// than defaulting to 32, so the mistake surfaces as an error instead of a
// plausible wrong file.
type Width uint8

const (
	WidthUnknown Width = 0
	Width32      Width = 32
	Width64      Width = 64
)

// Bits returns the address width in bits, or 0 if unknown.
func (w Width) Bits() int { return int(w) }

// Bytes returns the address width in bytes, or 0 if unknown.
func (w Width) Bytes() int { return int(w) / 8 }

// Valid reports whether w is one of the two defined widths.
func (w Width) Valid() bool { return w == Width32 || w == Width64 }

func (w Width) String() string {
	if !w.Valid() {
		return "unknown"
	}
	return strconv.Itoa(int(w))
}

type machineInfo struct {
	m     Machine
	name  string
	arch  Arch
	sub   SubArch
	width Width

	// image is the Machine value a linked image carries in its COFF header,
	// which is not always m. See Machine.ImageMachine.
	image Machine
}

// The seeded table. A fifth architecture is a row here plus a
// reloc_<machine>.go with a String method; nothing else in the tree changes.
var machines = [...]machineInfo{
	{MachineI386, "x86", ArchX86, SubArchNone, Width32, MachineI386},
	{MachineAMD64, "amd64", ArchAMD64, SubArchNone, Width64, MachineAMD64},
	{MachineARM64, "arm64", ArchARM64, SubArchNone, Width64, MachineARM64},
	{MachineARM64EC, "arm64ec", ArchARM64, SubArchEC, Width64, MachineAMD64},
	{MachineARM64X, "arm64x", ArchARM64, SubArchNone, Width64, MachineARM64},
}

func (m Machine) info() *machineInfo {
	for i := range machines {
		if machines[i].m == m {
			return &machines[i]
		}
	}
	return nil
}

// Supported reports whether m is in this tree's seeded table.
func (m Machine) Supported() bool { return m.info() != nil }

// Arch returns the instruction-set family, or ArchUnknown.
func (m Machine) Arch() Arch {
	if i := m.info(); i != nil {
		return i.arch
	}
	return ArchUnknown
}

// SubArch returns the ABI axis that m requires. It is a property of the
// machine, not a free choice: a Target whose SubArch disagrees with its
// Machine is invalid, so this is the value Validate checks against.
func (m Machine) SubArch() SubArch {
	if i := m.info(); i != nil {
		return i.sub
	}
	return SubArchNone
}

// Width returns the address width, or WidthUnknown for an unseeded machine.
func (m Machine) Width() Width {
	if i := m.info(); i != nil {
		return i.width
	}
	return WidthUnknown
}

// ObjectOnly reports whether m may appear in a relocatable object or an
// archive member but never in the COFF header of a linked image.
//
// ARM64EC (0xA641) and ARM64X (0xA64E) are both object-only. Microsoft
// documents 0xA641 as an internal MSVC identifier that is not defined in
// winnt.h and is not a valid final PE machine type. An image writer that
// copies its target machine straight into the header produces a file the
// loader rejects, which is why ImageMachine exists and why nothing in this
// tree writes Machine to a header directly.
func (m Machine) ObjectOnly() bool {
	return m == MachineARM64EC || m == MachineARM64X
}

// ImageMachine returns the Machine value a linked image for m carries in its
// COFF header.
//
// For every machine except the two hybrid ones this is m itself. An ARM64EC
// image is marked AMD64, so the x64 loader path accepts it; the fact that it
// is really ARM64EC is recoverable only by walking the load config to the CHPE
// metadata pointer. An ARM64X image is marked ARM64 here.
//
// ARM64X is the one case where the choice is genuinely open: AA64 and 8664 are
// both legal, and the choice decides how the image launches by default — AA64
// as a native ARM64 process, 8664 as an emulated x64 one. This method returns
// the native default; selecting the other is a link option, not a property of
// the machine, and belongs in link.Options rather than here.
func (m Machine) ImageMachine() Machine {
	if i := m.info(); i != nil {
		return i.image
	}
	return m
}

// Hybrid reports whether an image for m carries two views, native and EC, in
// one file. Only ARM64X does.
func (m Machine) Hybrid() bool { return m == MachineARM64X }

func (m Machine) String() string {
	if i := m.info(); i != nil {
		return i.name
	}
	switch m {
	case MachineUnknown:
		return "unknown"
	case MachineARMNT:
		return "armnt"
	}
	return fmt.Sprintf("machine(%#04x)", uint16(m))
}

// Machines returns the seeded machine types, in a stable order.
func Machines() []Machine {
	out := make([]Machine, 0, len(machines))
	for i := range machines {
		out = append(out, machines[i].m)
	}
	return out
}