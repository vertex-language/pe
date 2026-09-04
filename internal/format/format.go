// Package format is the single definition of every on-disk structure in the
// PE/COFF tree.
//
// Every wire structure appears exactly once, here, with three things:
//
//	func (s *T) Decode(c *binio.Cursor) error
//	func (s *T) Encode(b *binio.Buf)
//	func TSize() int          // or TSize(args) for the variable ones
//
// coff, ar, image, and link's emitter all go through these. No literal
// structure size and no field offset appears anywhere else in the module. The
// rule earns its keep the first time a field moves: a structure whose size is
// computed in four places is a structure that will be encoded correctly in
// three of them.
//
// Decode returns the cursor's latched error, so a caller may check after each
// structure or once at the end of a run. Encode returns nothing and latches
// into the Buf, because an encoder that can fail per-field is an encoder whose
// error is checked nowhere.
//
// These types are the wire, not the model. Fields are named and typed as the
// specification has them — raw integers, not pe.RVA or pe.SecKind — and the
// conversion to the tree's types happens in the package that owns the meaning.
// A structure here knows its layout and nothing else.
package format

import (
	"errors"
	"strconv"
)

// ErrWidth means Decode or Encode was called with a width that is neither
// 32-bit nor 64-bit. It is separate from a bounds failure because the cause is
// a caller mistake, not a bad file.
var ErrWidth = errors.New("format: invalid width")

// ErrBadMagic means a structure's magic number or signature did not match.
var ErrBadMagic = errors.New("format: bad magic")

// A FieldError names a structure field whose value is impossible, as opposed
// to merely unexpected. Reserved fields that are non-zero are not this: the
// specification says consumers must ignore them.
type FieldError struct {
	Struct string
	Field  string
	Value  uint64
	Reason string
}

func (e *FieldError) Error() string {
	return "format: " + e.Struct + "." + e.Field + " = " +
		strconv.FormatUint(e.Value, 10) + ": " + e.Reason
}

// itoaFormat renders an integer for the String methods in this package.
//
// It exists as a named helper rather than as bare strconv.Itoa calls because
// pe and coff each hand-roll an itoa of their own — they import no strconv on
// purpose — and three functions doing the same job under three spellings makes
// a cross-package diff harder to read than it needs to be. This one is a
// wrapper, since strconv is already here for FieldError.
func itoaFormat(v int) string { return strconv.Itoa(v) }