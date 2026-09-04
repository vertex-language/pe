package binio

// Buf is an append-only little-endian byte buffer with deferred patches.
//
// Like Cursor, it latches: the first failure is kept and every later write is
// a no-op, so an encode pass is a straight run of calls with one check at
// Data. Unlike Cursor there is no bounds failure to latch — the buffer grows —
// so the errors that reach it come from Fail and from the fixed-width writers.
type Buf struct {
	b   []byte
	err error
}

// NewBuf returns an empty Buf.
func NewBuf() *Buf { return &Buf{} }

// NewBufSize returns an empty Buf with room for n bytes reserved.
func NewBufSize(n int) *Buf { return &Buf{b: make([]byte, 0, n)} }

// Err returns the first error latched, or nil.
func (b *Buf) Err() error { return b.err }

// Fail latches err if no error is latched yet.
func (b *Buf) Fail(err error) {
	if b.err == nil && err != nil {
		b.err = err
	}
}

// Len returns the bytes written so far. It keeps reporting the true length
// after an error, so a caller computing an offset from it does not silently
// get zero.
func (b *Buf) Len() int { return len(b.b) }

// Data returns the accumulated bytes, or the latched error.
func (b *Buf) Data() ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.b, nil
}

func (b *Buf) U8(v uint8) {
	if b.err != nil {
		return
	}
	b.b = append(b.b, v)
}

func (b *Buf) U16(v uint16) {
	if b.err != nil {
		return
	}
	b.b = append(b.b, byte(v), byte(v>>8))
}

func (b *Buf) U32(v uint32) {
	if b.err != nil {
		return
	}
	b.b = append(b.b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func (b *Buf) U64(v uint64) {
	if b.err != nil {
		return
	}
	b.b = append(b.b,
		byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

// Bytes appends p verbatim.
func (b *Buf) Bytes(p []byte) {
	if b.err != nil {
		return
	}
	b.b = append(b.b, p...)
}

// Zero appends n zero bytes.
func (b *Buf) Zero(n int) {
	if b.err != nil || n <= 0 {
		return
	}
	b.b = append(b.b, make([]byte, n)...)
}

// Pad appends the given byte n times. Archive members pad with newlines and
// member headers with spaces, so the fill is not always zero.
func (b *Buf) Pad(fill byte, n int) {
	if b.err != nil || n <= 0 {
		return
	}
	for i := 0; i < n; i++ {
		b.b = append(b.b, fill)
	}
}

// Align pads with zero bytes until the length is a multiple of n, which must
// be a power of two. Returns the number of bytes added.
//
// Several structures in this format are aligned by padding rather than by
// their own size: base relocation blocks to four bytes, certificate table
// entries to eight, archive members to two. Getting the padding wrong shifts
// everything after it.
func (b *Buf) Align(n int) int {
	if b.err != nil || n <= 1 {
		return 0
	}
	pad := (n - len(b.b)%n) % n
	b.Zero(pad)
	return pad
}

// CStr appends s and a NUL terminator.
func (b *Buf) CStr(s string) {
	if b.err != nil {
		return
	}
	b.b = append(b.b, s...)
	b.b = append(b.b, 0)
}

// FixedStr appends s in exactly n bytes, NUL-padded.
//
// A string of exactly n bytes is written with no terminator, matching the
// eight-byte name fields. A longer one latches ErrNameTooLong rather than
// truncating: a silently shortened name produces a file whose symbols cannot
// be found again, and the caller is the only one who knows whether an escape
// to the string table is available.
func (b *Buf) FixedStr(s string, n int) {
	if b.err != nil {
		return
	}
	if len(s) > n {
		b.err = ErrNameTooLong
		return
	}
	b.b = append(b.b, s...)
	b.Zero(n - len(s))
}

// A Patch is a reserved position in a Buf, filled once its value is known.
//
// Almost every container in this format states its own size or the offset of
// something that follows it, so an encoder either makes two passes or reserves
// and backfills. Reserving is exact where a size computation is a second place
// to be wrong.
type Patch struct {
	off  int
	size int
}

// Valid reports whether p refers to a reserved position.
func (p Patch) Valid() bool { return p.size != 0 }

// PatchU16 reserves two bytes and returns a handle to them.
func (b *Buf) PatchU16() Patch { return b.reserve(2) }

// PatchU32 reserves four bytes and returns a handle to them.
func (b *Buf) PatchU32() Patch { return b.reserve(4) }

// PatchU64 reserves eight bytes and returns a handle to them.
func (b *Buf) PatchU64() Patch { return b.reserve(8) }

func (b *Buf) reserve(n int) Patch {
	if b.err != nil {
		return Patch{}
	}
	off := len(b.b)
	b.Zero(n)
	return Patch{off: off, size: n}
}

// Set writes v into a reserved position.
//
// The width is checked against what was reserved, and a value too large for
// that width latches an error rather than truncating — a size field that wraps
// produces a container the loader walks off the end of.
func (b *Buf) Set(p Patch, v uint64) {
	if b.err != nil {
		return
	}
	if !p.Valid() || p.off < 0 || p.off+p.size > len(b.b) {
		b.err = &BoundsError{Op: "Set", Off: p.off, Need: p.size, Have: len(b.b) - p.off}
		return
	}
	if p.size < 8 && v >= uint64(1)<<(8*p.size) {
		b.err = &BoundsError{Op: "Set", Off: p.off, Need: 8, Have: p.size}
		return
	}
	for i := 0; i < p.size; i++ {
		b.b[p.off+i] = byte(v >> (8 * i))
	}
}

// SetLenSince writes the number of bytes appended since off into p. It is the
// common case for a container that states its own size, including its header.
func (b *Buf) SetLenSince(p Patch, off int) {
	if b.err != nil {
		return
	}
	if off < 0 || off > len(b.b) {
		b.err = &BoundsError{Op: "SetLenSince", Off: off, Need: 0, Have: len(b.b)}
		return
	}
	b.Set(p, uint64(len(b.b)-off))
}