package strtab

import (
	"github.com/vertex-language/pe/internal/binio"
)

// Builder accumulates strings and assigns them offsets.
//
// Identical strings are stored once. That is not only a size optimization: a
// C++ object can carry the same mangled name in many roles, and emitting it
// repeatedly makes byte-for-byte comparison against link.exe output noisier
// than it needs to be.
//
// Offsets are assigned on Add and never move, so a caller may record one
// immediately and encode the table last.
type Builder struct {
	// Long section names are conventionally written before long symbol
	// names, which keeps section-name offsets small enough for the decimal
	// escape. Keeping insertion order preserves whatever discipline the
	// caller applies.
	order []string
	off   map[string]uint32
	next  uint32
	err   error
}

// NewBuilder returns an empty Builder. Its next assigned offset is MinOffset,
// since offsets below that fall inside the size field.
func NewBuilder() *Builder {
	return &Builder{off: make(map[string]uint32), next: MinOffset}
}

// Err returns the first error latched, or nil.
func (b *Builder) Err() error { return b.err }

// Add records s and returns its offset, adding it only if it is new.
//
// An embedded NUL is rejected rather than silently truncating the name at the
// point where it would be read back. Names come from source identifiers and
// from directives, and a NUL in one means something upstream is already wrong.
func (b *Builder) Add(s string) uint32 {
	if b.err != nil {
		return 0
	}
	if off, ok := b.off[s]; ok {
		return off
	}
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			b.err = ErrEmbeddedNUL
			return 0
		}
	}
	off := b.next
	b.off[s] = off
	b.order = append(b.order, s)
	b.next += uint32(len(s)) + 1
	return off
}

// Len returns the encoded size of the table, including the size field.
//
// This is needed before the table is written, because the symbol table's file
// offset and the object's total size both depend on it.
func (b *Builder) Len() int { return int(b.next) }

// Empty reports whether no strings were added.
//
// An empty table may be omitted from an object entirely, or written as the
// four-byte value 4. Both are accepted by every reader; this tree writes the
// four bytes, because a reader that seeks to the table and finds end-of-file
// has to distinguish "absent" from "truncated" and the explicit form spares it.
func (b *Builder) Empty() bool { return len(b.order) == 0 }

// Encode writes the table: the total size, then each string with its
// terminator, in the order added.
func (b *Builder) Encode(buf *binio.Buf) {
	if b.err != nil {
		buf.Fail(b.err)
		return
	}
	buf.U32(b.next)
	for _, s := range b.order {
		buf.CStr(s)
	}
}

// SymbolName returns the eight bytes to place in a symbol's name field,
// adding s to the table if it does not fit inline.
//
// This is the only place a symbol name's two encodings are chosen between, so
// a writer cannot produce an inline name and a table entry for the same
// symbol, or reference an offset it never added.
func (b *Builder) SymbolName(s string) [NameFieldLen]byte {
	var f [NameFieldLen]byte
	if len(s) <= NameFieldLen {
		copy(f[:], s)
		return f
	}
	off := b.Add(s)
	f[4] = byte(off)
	f[5] = byte(off >> 8)
	f[6] = byte(off >> 16)
	f[7] = byte(off >> 24)
	return f
}

// SectionName returns the eight bytes to place in a section's name field.
//
// A name that fits goes inline. A longer one is added to the table and
// referenced by the decimal escape. If the offset needs more than seven
// digits, ErrOffsetTooLarge is latched rather than the base64 form being
// emitted: this tree can read that form but has never had its reading of it
// checked against a real file, and writing an encoding you cannot verify is
// how you produce objects only you can read.
//
// In practice the limit is unreachable — it needs a string table approaching
// ten megabytes — and a caller that hits it should shorten its section names.
func (b *Builder) SectionName(s string) [NameFieldLen]byte {
	var f [NameFieldLen]byte
	if len(s) <= NameFieldLen {
		copy(f[:], s)
		return f
	}
	off := b.Add(s)
	esc := "/" + u32ToDecimal(off)
	if len(esc) > NameFieldLen {
		if b.err == nil {
			b.err = ErrOffsetTooLarge
		}
		return f
	}
	copy(f[:], esc)
	return f
}

func u32ToDecimal(v uint32) string {
	if v == 0 {
		return "0"
	}
	var d [10]byte
	i := len(d)
	for v > 0 {
		i--
		d[i] = byte('0' + v%10)
		v /= 10
	}
	return string(d[i:])
}