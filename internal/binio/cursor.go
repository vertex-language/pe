package binio

// Cursor is a bounded reader over a byte slice.
//
// Every PE structure is little-endian. The specification defines big-endian
// machine types and a BYTES_REVERSED_HI characteristic, but marks both
// reversal flags deprecated and required to be zero, and no machine this tree
// seeds is big-endian. So there is no byte-order argument and no field holding
// one: if a big-endian target ever arrives it will arrive as a compile error
// here, which is the right place for that conversation to happen.
//
// Reads past the end return the zero value and latch a *BoundsError. The
// cursor does not advance after latching, so a run of reads following a
// failure is harmless and produces one error rather than a cascade.
type Cursor struct {
	b    []byte
	i    int
	base int // offset of b[0] in the original buffer, for error messages
	err  error
}

// NewCursor returns a Cursor over b.
func NewCursor(b []byte) *Cursor {
	return &Cursor{b: b}
}

// NewCursorAt returns a Cursor over b whose reported offsets are shifted by
// base. Use it when b is a window into a larger file and errors should name
// positions in that file rather than in the window.
func NewCursorAt(b []byte, base int) *Cursor {
	return &Cursor{b: b, base: base}
}

// Err returns the first error latched, or nil.
func (c *Cursor) Err() error { return c.err }

// Fail latches err if no error is latched yet. It lets a caller report a
// semantic failure — a bad magic number, an impossible field — through the
// same channel as a bounds failure, so one check at the end covers both.
func (c *Cursor) Fail(err error) {
	if c.err == nil && err != nil {
		c.err = err
	}
}

// Off returns the current absolute offset.
func (c *Cursor) Off() int { return c.base + c.i }

// Len returns the bytes remaining. It reports zero once an error is latched,
// so a loop conditioned on Len terminates on failure.
func (c *Cursor) Len() int {
	if c.err != nil {
		return 0
	}
	return len(c.b) - c.i
}

// take advances by n and returns the bytes, or nil after latching.
func (c *Cursor) take(op string, n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || len(c.b)-c.i < n {
		c.err = &BoundsError{Op: op, Off: c.Off(), Need: n, Have: len(c.b) - c.i}
		return nil
	}
	s := c.b[c.i : c.i+n]
	c.i += n
	return s
}

// U8 reads one byte.
func (c *Cursor) U8() uint8 {
	s := c.take("U8", 1)
	if s == nil {
		return 0
	}
	return s[0]
}

// U16 reads a little-endian uint16.
func (c *Cursor) U16() uint16 {
	s := c.take("U16", 2)
	if s == nil {
		return 0
	}
	return uint16(s[0]) | uint16(s[1])<<8
}

// U32 reads a little-endian uint32.
func (c *Cursor) U32() uint32 {
	s := c.take("U32", 4)
	if s == nil {
		return 0
	}
	return uint32(s[0]) | uint32(s[1])<<8 | uint32(s[2])<<16 | uint32(s[3])<<24
}

// U64 reads a little-endian uint64.
func (c *Cursor) U64() uint64 {
	s := c.take("U64", 8)
	if s == nil {
		return 0
	}
	return uint64(s[0]) | uint64(s[1])<<8 | uint64(s[2])<<16 | uint64(s[3])<<24 |
		uint64(s[4])<<32 | uint64(s[5])<<40 | uint64(s[6])<<48 | uint64(s[7])<<56
}

// I16 reads a little-endian int16. COFF section numbers in a standard object
// are signed and their sentinels are negative, so the sign extension has to
// happen at the read rather than at the comparison.
func (c *Cursor) I16() int16 { return int16(c.U16()) }

// I32 reads a little-endian int32.
func (c *Cursor) I32() int32 { return int32(c.U32()) }

// Bytes returns the next n bytes as a subslice of the underlying buffer.
//
// It does not copy. That is the point — it is what lets a mapped archive be
// parsed without materializing each member — but it means the result aliases
// the input and must not be retained past the input's lifetime or mutated.
// Callers that keep the bytes should copy them.
func (c *Cursor) Bytes(n int) []byte { return c.take("Bytes", n) }

// Skip advances by n without reading.
func (c *Cursor) Skip(n int) { c.take("Skip", n) }

// Seek positions the cursor at an absolute offset within its own window.
// Seeking outside the window latches an error rather than clamping, because a
// clamped seek reads the wrong structure and says nothing about it.
func (c *Cursor) Seek(off int) {
	if c.err != nil {
		return
	}
	if off < 0 || off > len(c.b) {
		c.err = &BoundsError{Op: "Seek", Off: c.base + off, Need: 0, Have: len(c.b)}
		return
	}
	c.i = off
}

// CStr reads a NUL-terminated string and consumes the terminator.
//
// A run of bytes with no NUL before the end of the window is a bounds error,
// not a string: returning the unterminated tail would let a truncated file
// produce a plausible-looking name.
func (c *Cursor) CStr() string {
	if c.err != nil {
		return ""
	}
	for j := c.i; j < len(c.b); j++ {
		if c.b[j] == 0 {
			s := string(c.b[c.i:j])
			c.i = j + 1
			return s
		}
	}
	c.err = &BoundsError{Op: "CStr", Off: c.Off(), Need: len(c.b) - c.i + 1, Have: len(c.b) - c.i}
	return ""
}

// FixedStr reads exactly n bytes and returns them up to the first NUL.
//
// A name that fills the field has no terminator — the eight-byte section and
// symbol name fields are the reason this exists — so this must be used rather
// than CStr wherever the format specifies a fixed width.
func (c *Cursor) FixedStr(n int) string {
	s := c.take("FixedStr", n)
	if s == nil {
		return ""
	}
	for j, b := range s {
		if b == 0 {
			return string(s[:j])
		}
	}
	return string(s)
}

// Sub returns an independent Cursor over the next n bytes and advances this
// one past them.
//
// The sub-cursor has its own position and its own error. Errors do not
// propagate automatically, because a sub-window is often optional — a data
// directory that may be absent, an aux record this tree does not parse — and
// a failure inside it should not always condemn the outer parse. Fold makes
// the propagation explicit where it is wanted.
func (c *Cursor) Sub(n int) *Cursor {
	s := c.take("Sub", n)
	if s == nil {
		return &Cursor{err: c.err}
	}
	return &Cursor{b: s, base: c.base + c.i - n}
}

// Fold merges a sub-cursor's error into this one.
func (c *Cursor) Fold(sub *Cursor) {
	if sub != nil {
		c.Fail(sub.Err())
	}
}

// Table validates that count records of size elem fit in the remaining bytes
// and returns a Cursor over exactly those bytes.
//
// count is a uint32 because that is what the format stores, and the product is
// computed in uint64 so a large count cannot wrap into a small one. This is
// the only place in the tree where a declared count becomes a length, which is
// why the check can be relied on rather than repeated.
func (c *Cursor) Table(what string, count uint32, elem int) *Cursor {
	if c.err != nil {
		return &Cursor{err: c.err}
	}
	need := uint64(count) * uint64(elem)
	rem := len(c.b) - c.i
	if elem < 0 || need > uint64(rem) {
		c.err = &CountError{What: what, Count: uint64(count), ElemSize: elem, Remaining: rem}
		return &Cursor{err: c.err}
	}
	return c.Sub(int(need))
}

// Slot positions the cursor at record i of a fixed-size record array that
// begins at the start of this cursor's window.
//
// The COFF symbol table is an array of 18-byte records in which auxiliary
// records occupy slots of their own, so an index into it is a physical slot
// and not an ordinal into "the symbols". Bigobj widens the record to 20 bytes,
// which changes this arithmetic and nothing else. Doing the multiplication
// here, once, is what keeps that difference from leaking into every caller.
func (c *Cursor) Slot(i int, size int) {
	if c.err != nil {
		return
	}
	if i < 0 || size <= 0 {
		c.err = &BoundsError{Op: "Slot", Off: c.base, Need: 0, Have: len(c.b)}
		return
	}
	off := int64(i) * int64(size)
	if off > int64(len(c.b)) {
		c.err = &CountError{What: "slots", Count: uint64(i), ElemSize: size, Remaining: len(c.b)}
		return
	}
	c.i = int(off)
}