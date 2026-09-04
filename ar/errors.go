// Package ar reads and writes COFF archives: MSVC-layout .lib files in both
// directions, and MinGW's GNU-shaped .dll.a for reading.
//
// It does not import coff and has no idea what a COFF object is. A member is a
// name and a run of bytes; the caller supplies each member's symbol list. That
// is what keeps the dependency from running backwards — coff.NewFile takes an
// extent, and one member of a mapped archive is an extent.
package ar

import (
	"errors"
	"strconv"
)

var (
	// ErrNotArchive means the buffer did not begin with the archive magic.
	ErrNotArchive = errors.New("ar: missing !<arch> magic")

	// ErrBadHeader means a member header was malformed, or described a
	// member that does not advance the walk. A zero-size member with a
	// zero-size header is an infinite loop, so it is refused rather than
	// looped over.
	ErrBadHeader = errors.New("ar: malformed member header")

	// ErrBSDArchive means a BSD-variant archive, which stores long names
	// inline after the header as "#1/NN" rather than in a "//" member.
	//
	// It shares the !<arch> magic with the two layouts this package does
	// support, so it must be detected and refused rather than misparsed:
	// reading a BSD member header as a GNU one yields a member whose data
	// begins partway through its own name.
	ErrBSDArchive = errors.New("ar: BSD-variant archive is not supported")

	// ErrNoIndex means the archive carries no linker member, so nothing can
	// be looked up by symbol. Run lib /LIST to confirm.
	ErrNoIndex = errors.New("ar: archive has no linker member")

	// ErrBadIndex means an index member was inconsistent with the members
	// it names: an offset that is not a member header, or a symbol index
	// outside the offset table.
	ErrBadIndex = errors.New("ar: index inconsistent with archive members")

	// ErrNoLongNames means a member name escaped to the "//" member but no
	// such member is present.
	ErrNoLongNames = errors.New("ar: long member name with no // member")

	// ErrTooManyMembers means the archive exceeded what the second linker
	// member's 16-bit symbol index can address.
	ErrTooManyMembers = errors.New("ar: more members than a 16-bit index can name")

	// ErrClosed means a Writer was used after Close.
	ErrClosed = errors.New("ar: writer is closed")

	// ErrThinData means a member with contents was added to a thin archive,
	// which stores only paths.
	ErrThinData = errors.New("ar: thin archive members carry no data")
)

// MemberError names the member that failed. An archive is routinely tens of
// megabytes and hundreds of members; "malformed member header" without a
// position is not something anyone can act on.
type MemberError struct {
	Index  int    // zero-based position in the walk
	Name   string // resolved name, or the raw field if resolution failed
	Offset int64  // file offset of the member header
	Err    error
}

func (e *MemberError) Error() string {
	s := "ar: member " + strconv.Itoa(e.Index)
	if e.Name != "" {
		s += " (" + e.Name + ")"
	}
	return s + " at 0x" + strconv.FormatInt(e.Offset, 16) + ": " + e.Err.Error()
}

func (e *MemberError) Unwrap() error { return e.Err }