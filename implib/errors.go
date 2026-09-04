// Package implib reads and writes import libraries: archives whose members are
// mostly short-import pseudo-objects rather than COFF objects.
//
// A short-import member is a 20-byte header followed by the symbol name and the
// DLL name, and — for the EXPORTAS name type — the exported name as well. It
// describes one import; the archive as a whole describes one DLL.
package implib

import (
	"errors"
	"strconv"

	"github.com/vertex-language/pe"
)

var (
	// ErrNotImportLib means an archive contained no short-import members.
	// A static library and an import library are the same container, so
	// this is a judgement about contents, not a magic-number test.
	ErrNotImportLib = errors.New("implib: no short-import members found")

	// ErrBadOrdinal means an ordinal of zero, or one above 65535. The
	// export ordinal space is one-based and 16 bits, and real projects
	// have hit the ceiling.
	ErrBadOrdinal = errors.New("implib: ordinal outside 1..65535")

	// ErrBadMember means a short-import member's trailing strings did not
	// match what its header declared.
	ErrBadMember = errors.New("implib: short-import member is malformed")

	// ErrNoDLL means Options.DLL was empty. The DLL name is written into
	// every member and into the import descriptor's name table; there is
	// no default for it.
	ErrNoDLL = errors.New("implib: no DLL name")

	// ErrBadExport means an export could not be turned into an import:
	// an alias whose target does not appear in the name, or an ARM64EC
	// function name that is neither mangled nor manglable.
	ErrBadExport = errors.New("implib: export cannot be expressed as an import")

	// ErrGNUUnimplemented is unused by Write itself, kept for callers that
	// referred to it while the GNU shape had no writer at all. Write now
	// reports an unsupported machine through UnsupportedGNUMachineError
	// instead, since AMD64 is implemented and the failure is per-machine
	// rather than per-shape.
	ErrGNUUnimplemented = errors.New("implib: GNU-shaped import libraries are not implemented")
)

// UnsupportedGNUMachineError means Write was asked for a GNU-shaped (MinGW
// ABI) import library for a machine writeGNU does not implement.
//
// AMD64 is the only one that is: dlltool's i386 objects follow a different
// internal convention, and no GNU toolchain consumes this shape for
// ARM64/ARM64EC at all, so producing bytes for either would be a guess this
// package has no way to check against a real linker.
type UnsupportedGNUMachineError struct {
	Machine pe.Machine
}

func (e *UnsupportedGNUMachineError) Error() string {
	return "implib: GNU-shaped import libraries are not implemented for " + e.Machine.String()
}

// MemberError names the archive member that failed.
type MemberError struct {
	Index int
	Name  string
	Err   error
}

func (e *MemberError) Error() string {
	s := "implib: member " + strconv.Itoa(e.Index)
	if e.Name != "" {
		s += " (" + e.Name + ")"
	}
	return s + ": " + e.Err.Error()
}

func (e *MemberError) Unwrap() error { return e.Err }