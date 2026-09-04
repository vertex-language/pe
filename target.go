package pe

import (
	"fmt"
	"strconv"
	"strings"
)

// ABI selects the toolchain conventions a link follows. It is load-bearing,
// not cosmetic: MSVC and MinGW differ on default entry points, library naming,
// C++ mangling, .def handling, import-library shape, and whether auto-export
// applies.
type ABI uint8

const (
	ABIUnknown ABI = iota
	ABIMSVC
	ABIMinGW
)

func (a ABI) String() string {
	switch a {
	case ABIMSVC:
		return "msvc"
	case ABIMinGW:
		return "gnu"
	}
	return "abi(" + strconv.Itoa(int(a)) + ")"
}

// OS selects the loader an image is built for. It changes the default
// subsystem and, for UEFI, turns on the flat-image alignment mode in which
// section data must sit at the same file offset as its RVA.
type OS uint8

const (
	OSUnknown OS = iota
	OSWindows
	OSUEFI
)

func (o OS) String() string {
	switch o {
	case OSWindows:
		return "windows"
	case OSUEFI:
		return "uefi"
	}
	return "os(" + strconv.Itoa(int(o)) + ")"
}

// Version is the Major/Minor pair used by the four version fields of the
// optional header: operating system, image, subsystem, and linker.
type Version struct {
	Major uint16
	Minor uint16
}

// ParseVersion parses "MAJOR" or "MAJOR.MINOR".
func ParseVersion(s string) (Version, error) {
	maj, min, hasMinor := strings.Cut(s, ".")
	m, err := strconv.ParseUint(maj, 10, 16)
	if err != nil {
		return Version{}, fmt.Errorf("pe: bad version %q: major", s)
	}
	v := Version{Major: uint16(m)}
	if hasMinor {
		n, err := strconv.ParseUint(min, 10, 16)
		if err != nil {
			return Version{}, fmt.Errorf("pe: bad version %q: minor", s)
		}
		v.Minor = uint16(n)
	}
	return v, nil
}

func (v Version) String() string {
	return strconv.Itoa(int(v.Major)) + "." + strconv.Itoa(int(v.Minor))
}

// IsZero reports whether v is unset.
func (v Version) IsZero() bool { return v == Version{} }

// Target is everything a decode or a link needs to know about what it is
// producing, other than the contents.
//
// Width is not a field. A Target claiming 64-bit width for a 32-bit machine
// cannot be constructed, because width is asked of the machine.
type Target struct {
	Machine Machine
	SubArch SubArch // must equal Machine.SubArch()
	ABI     ABI
	OS      OS
	MinOS   Version // zero means unset; the emitter supplies a default
}

// Width returns the target's address width.
func (t Target) Width() Width { return t.Machine.Width() }

// Hybrid reports whether this target links to an image with two views.
func (t Target) Hybrid() bool { return t.Machine.Hybrid() }

// Validate returns nil if t is internally consistent and its machine is
// seeded, and an error wrapping ErrInvalidTarget or ErrUnsupportedMachine
// otherwise.
//
// The zero Target is invalid, which is deliberate: coff.Options.Target at its
// zero value is an error rather than a silent default to x86.
func (t Target) Validate() error {
	i := t.Machine.info()
	if i == nil {
		return fmt.Errorf("%w: %s", ErrUnsupportedMachine, t.Machine)
	}
	if t.SubArch != i.sub {
		return fmt.Errorf("%w: machine %s requires subarch %s, got %s",
			ErrInvalidTarget, t.Machine, i.sub, t.SubArch)
	}
	if t.ABI != ABIMSVC && t.ABI != ABIMinGW {
		return fmt.Errorf("%w: unset or unknown ABI", ErrInvalidTarget)
	}
	if t.OS != OSWindows && t.OS != OSUEFI {
		return fmt.Errorf("%w: unset or unknown OS", ErrInvalidTarget)
	}
	return nil
}

// Valid reports whether Validate returns nil.
func (t Target) Valid() bool { return t.Validate() == nil }

// String renders the target as machine/os-abi/width, e.g. "arm64ec/windows-msvc/64".
func (t Target) String() string {
	return t.Machine.String() + "/" + t.OS.String() + "-" + t.ABI.String() + "/" + t.Width().String()
}

// archTokens maps the architecture component of a triple to a machine.
var archTokens = map[string]Machine{
	"x86_64":  MachineAMD64,
	"amd64":   MachineAMD64,
	"x64":     MachineAMD64,
	"i386":    MachineI386,
	"i486":    MachineI386,
	"i586":    MachineI386,
	"i686":    MachineI386,
	"x86":     MachineI386,
	"aarch64": MachineARM64,
	"arm64":   MachineARM64,
	"arm64ec": MachineARM64EC,
	"arm64x":  MachineARM64X,
}

// osTokens maps an OS component to an OS and, where the spelling also fixes
// the environment, an ABI. "mingw32" names both at once.
var osTokens = map[string]struct {
	os  OS
	abi ABI
}{
	"windows": {OSWindows, ABIUnknown},
	"win32":   {OSWindows, ABIUnknown},
	"uefi":    {OSUEFI, ABIUnknown},
	"mingw32": {OSWindows, ABIMinGW},
	"mingw64": {OSWindows, ABIMinGW},
}

// abiTokens maps an environment component to an ABI. "gnullvm" is llvm-mingw:
// UCRT and LLVM tools, but MinGW-shaped import libraries and mangling, which
// is what this axis actually selects.
var abiTokens = map[string]ABI{
	"msvc":    ABIMSVC,
	"gnu":     ABIMinGW,
	"mingw":   ABIMinGW,
	"gnullvm": ABIMinGW,
}

// ParseTarget parses an LLVM-style target triple: arch-vendor-os-env, with the
// vendor and the environment both optional and the vendor ignored when
// present. Empty components are accepted, since LLVM normalizes an elided
// vendor to "x86_64--windows-msvc".
//
// An unrecognized component is an error rather than a guess. A triple that
// silently loses its environment produces a link that succeeds against the
// wrong conventions, which is worse than one that fails.
//
// When the OS is known and no environment is given, the ABI defaults to MSVC,
// matching LLVM's canonicalization of Windows triples.
func ParseTarget(triple string) (Target, error) {
	if triple == "" {
		return Target{}, fmt.Errorf("%w: empty triple", ErrInvalidTarget)
	}
	parts := strings.Split(strings.ToLower(triple), "-")

	m, ok := archTokens[parts[0]]
	if !ok {
		return Target{}, fmt.Errorf("%w: unrecognized architecture %q in %q",
			ErrInvalidTarget, parts[0], triple)
	}
	t := Target{Machine: m, SubArch: m.SubArch()}

	var sawOS, sawABI, sawVendor bool
	for _, p := range parts[1:] {
		if p == "" {
			continue // an elided vendor slot
		}
		if e, ok := osTokens[p]; ok {
			if sawOS {
				return Target{}, fmt.Errorf("%w: two OS components in %q",
					ErrInvalidTarget, triple)
			}
			t.OS, sawOS = e.os, true
			if e.abi != ABIUnknown {
				if sawABI && t.ABI != e.abi {
					return Target{}, fmt.Errorf("%w: %q contradicts the environment in %q",
						ErrInvalidTarget, p, triple)
				}
				t.ABI, sawABI = e.abi, true
			}
			continue
		}
		if a, ok := abiTokens[p]; ok {
			if sawABI && t.ABI != a {
				return Target{}, fmt.Errorf("%w: two environment components in %q",
					ErrInvalidTarget, triple)
			}
			t.ABI, sawABI = a, true
			continue
		}
		if !sawOS && !sawVendor {
			sawVendor = true // pc, unknown, w64, none: carries nothing we need
			continue
		}
		return Target{}, fmt.Errorf("%w: unrecognized component %q in %q",
			ErrInvalidTarget, p, triple)
	}

	if !sawOS {
		return Target{}, fmt.Errorf("%w: no OS component in %q", ErrInvalidTarget, triple)
	}
	if !sawABI {
		t.ABI = ABIMSVC
	}
	if err := t.Validate(); err != nil {
		return Target{}, err
	}
	return t, nil
}