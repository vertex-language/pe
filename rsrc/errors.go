// Package rsrc turns rc.exe's output into a PE resource directory.
//
// It takes a .res file — a flat run of headers and blobs — and builds the
// three-level tree the Windows loader walks: type, then name, then language,
// with the data entries as leaves. Build emits the bytes plus a list of the
// positions that need the section's final RVA added, so the whole structure is
// assembled before layout has run and finished afterwards without being
// rebuilt.
//
// That two-step is the reason this package is outside link rather than inside
// it. Everything else a linker synthesizes needs addresses to exist; this
// needs exactly one field per resource, and asking for the address up front
// would make the resource tree a layout dependency instead of an input.
//
// There is no .rc parser here and there will not be one. Compiling a script is
// rc.exe's job, or llvm-rc's, and the preprocessor alone is a project.
package rsrc

import (
	"errors"
	"strconv"
)

var (
	// ErrBadResFile means the .res could not be walked: a header whose
	// declared size disagrees with its fields, a data size running past
	// the end, or a header that does not advance.
	ErrBadResFile = errors.New("rsrc: malformed .res file")

	// ErrDuplicateResource means two entries shared a (type, name,
	// language) triple.
	//
	// The tree has no way to hold both — the third level is keyed on
	// language and a key appears once — so one would silently replace the
	// other. rc.exe rejects the duplicate in a single script; two scripts
	// merged by a build system are how it happens in practice, and the
	// answer is always to rename one.
	ErrDuplicateResource = errors.New("rsrc: two resources share a type, name, and language")

	// ErrTooLarge means the tree exceeded what a 31-bit directory offset
	// can address. The offsets are relative to the directory's start, so
	// the bound is on the tree and not on the image.
	ErrTooLarge = errors.New("rsrc: resource directory exceeds 2 GB")

	// ErrEmpty means a .res held no resources beyond the null marker rc
	// writes at the head of every file.
	ErrEmpty = errors.New("rsrc: .res file contains no resources")
)

// ResourceError names the entry that failed. A .res holding four hundred icons
// is routine, and "malformed" without a position is not something anyone can
// act on.
type ResourceError struct {
	Index  int   // zero-based position in the walk
	Offset int64 // file offset of the entry's header
	Type   string
	Name   string
	Err    error
}

func (e *ResourceError) Error() string {
	s := "rsrc: resource " + strconv.Itoa(e.Index)
	if e.Type != "" || e.Name != "" {
		s += " (" + e.Type + "/" + e.Name + ")"
	}
	return s + " at 0x" + strconv.FormatInt(e.Offset, 16) + ": " + e.Err.Error()
}

func (e *ResourceError) Unwrap() error { return e.Err }