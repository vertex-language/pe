// Package binio provides bounded, little-endian byte access for the PE/COFF
// tree: a reading cursor, a writing buffer with deferred patches, and an
// extent that bounds both against a file of known size.
//
// The organizing decision is that errors latch. A Cursor or Buf accumulates
// the first failure and no-ops afterwards, so a decode pass is a straight run
// of calls with one check at the end rather than a check after every field.
// Checking after every field is where bounds bugs hide: the check that gets
// forgotten is never the one anybody notices.
package binio

import (
	"errors"
	"strconv"
)

// ErrTruncated means a read or a declared count ran past the end of the
// available bytes. Both BoundsError and CountError unwrap to it, so
// errors.Is(err, binio.ErrTruncated) catches either.
var ErrTruncated = errors.New("binio: read past end of buffer")

// ErrNameTooLong means a string did not fit a fixed-width field that has no
// escape to a string table.
var ErrNameTooLong = errors.New("binio: name too long for fixed-width field")

// BoundsError is a read that ran off the end. It carries enough to find the
// spot in a hex dump, because "unexpected EOF" is not a useful thing to be
// told about a 40 MB static library.
type BoundsError struct {
	Op   string // the accessor that failed, e.g. "U32"
	Off  int    // absolute offset within the underlying buffer
	Need int    // bytes the operation wanted
	Have int    // bytes actually remaining
}

func (e *BoundsError) Error() string {
	return "binio: " + e.Op + " at 0x" + strconv.FormatInt(int64(e.Off), 16) +
		" needs " + strconv.Itoa(e.Need) + " bytes, " +
		strconv.Itoa(e.Have) + " remain"
}

func (e *BoundsError) Unwrap() error { return ErrTruncated }

// CountError is a declared element count that cannot fit in the bytes that
// remain.
//
// This is raised from the arithmetic, before anything is allocated. A header
// claiming four billion symbols is a two-line rejection here; the same header
// reaching a make call is an out-of-memory kill, and reaching a loop that
// appends is a slow one. Every count in this format is attacker-controlled.
type CountError struct {
	What      string // what was being counted, e.g. "symbols"
	Count     uint64 // the declared count, as read
	ElemSize  int    // bytes per element
	Remaining int    // bytes actually available
}

func (e *CountError) Error() string {
	return "binio: " + strconv.FormatUint(e.Count, 10) + " " + e.What +
		" of " + strconv.Itoa(e.ElemSize) + " bytes need " +
		strconv.FormatUint(e.Count*uint64(e.ElemSize), 10) +
		" bytes, " + strconv.Itoa(e.Remaining) + " remain"
}

func (e *CountError) Unwrap() error { return ErrTruncated }