package strtab

import "errors"

// ErrEmbeddedNUL means a name contained a NUL byte, which the table cannot
// represent because a NUL is its terminator.
var ErrEmbeddedNUL = errors.New("strtab: name contains a NUL byte")

// ErrOffsetTooLarge means a section name's string table offset needs more than
// the seven digits the decimal escape allows.
var ErrOffsetTooLarge = errors.New("strtab: section name offset too large for the decimal escape")