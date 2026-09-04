// Package strtab reads and writes the COFF string table, and resolves the
// three encodings a name field can carry.
//
// The table sits immediately after the symbol table. Its first four bytes are
// its own total size, including those four bytes, so the smallest legal table
// is the four-byte value 4 and the smallest legal string offset is also 4.
// Strings are NUL-terminated and offsets point at their first byte.
//
// Symbol names and section names do not share an encoding, which is the thing
// this package exists to hide:
//
// A symbol name is either eight inline bytes or, if the first four of those
// are zero, a 32-bit offset in the remaining four. One rule, no parsing.
//
// A section name is either eight inline bytes, or an ASCII form beginning with
// a slash. "/1234" is a decimal offset. "//" followed by base64 is an
// extension for offsets too large to express as decimal in the seven bytes
// available. The slash forms are text, not integers, and they are parsed.
package strtab

import (
	"errors"
	"strconv"
	"strings"

	"github.com/vertex-language/pe/internal/binio"
)

const (
	// SizeFieldLen is the length prefix at the head of the table.
	SizeFieldLen = 4

	// MinOffset is the lowest offset a string can occupy, since anything
	// below it is inside the size field. An offset below this is malformed,
	// not merely unusual.
	MinOffset = SizeFieldLen

	// NameFieldLen is the inline name field in both section and symbol
	// headers.
	NameFieldLen = 8
)

var (
	// ErrBadOffset means a name referenced an offset outside the table, or
	// one inside the size field.
	ErrBadOffset = errors.New("strtab: string offset outside table")

	// ErrUnterminated means a string ran to the end of the table with no
	// NUL. Returning the tail would let a truncated table produce a
	// plausible name.
	ErrUnterminated = errors.New("strtab: unterminated string")

	// ErrBadEscape means a section name began with a slash but the rest was
	// neither a decimal offset nor a supported base64 form.
	ErrBadEscape = errors.New("strtab: malformed long section name")

	// ErrNoStringTable means a long name was referenced but no table is
	// present. Images have no string table, so a long section name in one
	// is unresolvable by construction.
	ErrNoStringTable = errors.New("strtab: long name with no string table")
)

// Table is a read-only view of a decoded string table.
//
// It holds the raw bytes and slices them on demand. Nothing is copied and no
// index is built: lookups are by offset, which is what the format stores, and
// building a map keyed on offsets nobody asks for would cost more than it
// saves.
type Table struct {
	raw []byte
}

// Decode reads a string table from c.
//
// The declared size is checked against what is actually present. A table that
// claims more than it has is truncated rather than fatal, because the size
// field is the last thing written by many producers and is sometimes stale,
// but a claim below the minimum is rejected outright.
func Decode(c *binio.Cursor) (*Table, error) {
	if c.Len() == 0 {
		// No table at all is legal and common: an object with no long
		// names may omit it entirely.
		return &Table{}, nil
	}
	size := c.U32()
	if err := c.Err(); err != nil {
		return nil, err
	}
	if size < SizeFieldLen {
		return nil, &SizeError{Declared: size, Available: uint32(c.Len()) + SizeFieldLen}
	}
	want := int(size) - SizeFieldLen
	if have := c.Len(); want > have {
		want = have
	}
	body := c.Bytes(want)
	if err := c.Err(); err != nil {
		return nil, err
	}
	// raw is indexed by the offsets the format uses, which count the size
	// field, so a leading pad of SizeFieldLen keeps the arithmetic honest
	// rather than subtracting four at every lookup.
	raw := make([]byte, SizeFieldLen+len(body))
	copy(raw[SizeFieldLen:], body)
	return &Table{raw: raw}, nil
}

// New returns a Table over bytes that already include the four-byte size
// prefix.
func New(raw []byte) *Table { return &Table{raw: raw} }

// SizeError is a declared table size that cannot be right.
type SizeError struct {
	Declared  uint32
	Available uint32
}

func (e *SizeError) Error() string {
	return "strtab: declared size " + strconv.FormatUint(uint64(e.Declared), 10) +
		" is below the four-byte minimum (" +
		strconv.FormatUint(uint64(e.Available), 10) + " bytes available)"
}

// Empty reports whether there is no table.
func (t *Table) Empty() bool { return t == nil || len(t.raw) <= SizeFieldLen }

// Size returns the table's total size including the length prefix.
func (t *Table) Size() int {
	if t == nil {
		return 0
	}
	return len(t.raw)
}

// At returns the NUL-terminated string beginning at off.
func (t *Table) At(off uint32) (string, error) {
	if t == nil || len(t.raw) == 0 {
		return "", ErrNoStringTable
	}
	if off < MinOffset || int(off) >= len(t.raw) {
		return "", ErrBadOffset
	}
	rest := t.raw[off:]
	if i := indexByte(rest, 0); i >= 0 {
		return string(rest[:i]), nil
	}
	return "", ErrUnterminated
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// SymbolName resolves a symbol's eight-byte name field.
//
// The union is decided by the first four bytes being zero. A name may
// therefore never begin with a NUL, which costs nothing, and a name of exactly
// eight bytes has no terminator, which is why this must not be read as a C
// string.
func (t *Table) SymbolName(field [NameFieldLen]byte) (string, error) {
	if field[0] != 0 || field[1] != 0 || field[2] != 0 || field[3] != 0 {
		return trimNUL(field[:]), nil
	}
	off := uint32(field[4]) | uint32(field[5])<<8 |
		uint32(field[6])<<16 | uint32(field[7])<<24
	return t.At(off)
}

// SectionName resolves a section's eight-byte name field.
//
// A leading slash marks an escape to the string table. Everything else is the
// name itself, trimmed at the first NUL.
//
// This is where the two name encodings diverge and why they cannot share a
// function: a section name field beginning with four zero bytes is an empty
// name, not an offset, and a symbol name field beginning with a slash is a
// symbol literally called "/something".
func (t *Table) SectionName(field [NameFieldLen]byte) (string, error) {
	if field[0] != '/' {
		return trimNUL(field[:]), nil
	}
	off, err := parseEscape(trimNUL(field[:]))
	if err != nil {
		return "", err
	}
	return t.At(off)
}

// parseEscape reads a "/N" or "//base64" section name escape and returns the
// string table offset it names.
func parseEscape(s string) (uint32, error) {
	rest, ok := strings.CutPrefix(s, "//")
	if ok {
		return decodeBase64Offset(rest)
	}
	rest, ok = strings.CutPrefix(s, "/")
	if !ok {
		return 0, ErrBadEscape
	}
	if rest == "" {
		return 0, ErrBadEscape
	}
	v, err := strconv.ParseUint(rest, 10, 32)
	if err != nil {
		return 0, ErrBadEscape
	}
	return uint32(v), nil
}

// decodeBase64Offset decodes the "//" form's payload.
//
// UNVERIFIED. The decimal escape has seven bytes to work with, so it cannot
// express an offset above 9,999,999; the base64 form exists for tables larger
// than that, and both MSVC and lld emit it. What could not be confirmed from a
// primary source is the exact scheme, and there are two plausible readings:
// standard byte-oriented base64 of a 32-bit value, or — as implemented here —
// a base-64 *number* with the most significant digit first over the alphabet
// A-Z, a-z, 0-9, +, /.
//
// The second is what the six-character payload limit implies (64^6 just
// exceeds 2^32) and what LLVM's helper name suggests, but it is a belief and
// not a citation. Nothing in this tree writes this form, so the risk is
// confined to reading third-party objects with very large string tables. It
// must be checked against a real lld-produced object before it is trusted, and
// it is isolated here so that check touches one function.
func decodeBase64Offset(s string) (uint32, error) {
	if s == "" || len(s) > 6 {
		return 0, ErrBadEscape
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		d, ok := base64Digit(s[i])
		if !ok {
			return 0, ErrBadEscape
		}
		v = v*64 + uint64(d)
		if v > 0xffffffff {
			return 0, ErrBadEscape
		}
	}
	return uint32(v), nil
}

func base64Digit(c byte) (uint8, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A', true
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26, true
	case c >= '0' && c <= '9':
		return c - '0' + 52, true
	case c == '+':
		return 62, true
	case c == '/':
		return 63, true
	}
	return 0, false
}

func trimNUL(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}