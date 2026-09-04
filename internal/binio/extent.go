package binio

import (
	"errors"
	"io"
	"math"
	"strconv"
)

// ErrFileTooLarge means a file exceeds what PE offsets can address.
//
// This is the one place in the tree where an int64 becomes a 32-bit offset.
// Every file-pointer field in the format is a DWORD — PointerToRawData,
// PointerToSymbolTable, the certificate table's directory entry, the member
// offsets in an archive's second linker index — so a file above 4 GiB has
// regions it cannot name. Rejecting it here, once, is why pe.Off can stay
// uint32 and why nothing downstream carries a cast.
var ErrFileTooLarge = errors.New("binio: file larger than 4 GiB cannot be addressed by PE offsets")

// MaxFileSize is the largest file an Extent will open.
const MaxFileSize = int64(math.MaxUint32)

// Extent is a bounded window onto an io.ReaderAt of known size.
//
// It exists so a member of a mapped static library can be parsed without
// copying it out. An archive is a sequence of members, each of which is a
// whole COFF object; handing coff.NewFile an Extent rather than a []byte means
// the bytes are read on demand from the region that member occupies, and a
// decode that walks off the end of its member hits the extent's bound rather
// than wandering into the next one.
//
// An Extent is immutable and safe for concurrent use if the underlying
// ReaderAt is, which io.ReaderAt requires of its implementations.
type Extent struct {
	r    io.ReaderAt
	off  int64 // absolute start of this window in the underlying reader
	size int64 // length of this window
}

// NewExtent returns an Extent covering the whole of r, which must be size
// bytes long.
//
// A negative size, or one above MaxFileSize, is an error. So is a size that
// disagrees with the reader, but that cannot be checked here and will surface
// as a short read later.
func NewExtent(r io.ReaderAt, size int64) (*Extent, error) {
	if r == nil {
		return nil, errors.New("binio: nil reader")
	}
	if size < 0 {
		return nil, errors.New("binio: negative size " + strconv.FormatInt(size, 10))
	}
	if size > MaxFileSize {
		return nil, ErrFileTooLarge
	}
	return &Extent{r: r, size: size}, nil
}

// Size returns the length of the window.
func (e *Extent) Size() int64 { return e.size }

// Base returns the window's absolute offset in the underlying reader. Error
// messages from sub-extents use it so a failure names a position in the file
// rather than in the member.
func (e *Extent) Base() int64 { return e.off }

// Sub returns an Extent covering n bytes starting at off within e.
//
// The result is independent: it has no error to latch and cannot read outside
// its own bounds, which is the property that makes it safe to hand one member
// of an archive to a decoder that knows nothing about archives.
func (e *Extent) Sub(off, n int64) (*Extent, error) {
	if off < 0 || n < 0 || off > e.size || n > e.size-off {
		return nil, &BoundsError{
			Op:   "Sub",
			Off:  int(e.off + off),
			Need: int(n),
			Have: int(e.size - min64(off, e.size)),
		}
	}
	return &Extent{r: e.r, off: e.off + off, size: n}, nil
}

// At reads n bytes at off within the window.
//
// Unlike Cursor.Bytes this always copies. An Extent's bytes come from a
// ReaderAt, which may be a file rather than a mapping, so there is nothing to
// alias — and a caller that has been handed a fresh slice cannot accidentally
// retain a view into someone else's buffer.
//
// A read that returns fewer bytes than requested is a bounds failure, not a
// partial success: io.ReaderAt requires a non-nil error in that case, so a
// short read always carries one.
func (e *Extent) At(off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || off > e.size || n > e.size-off {
		return nil, &BoundsError{
			Op:   "At",
			Off:  int(e.off + off),
			Need: int(n),
			Have: int(e.size - min64(off, e.size)),
		}
	}
	if n == 0 {
		return nil, nil
	}
	b := make([]byte, n)
	got, err := e.r.ReadAt(b, e.off+off)
	if err != nil && !(err == io.EOF && int64(got) == n) {
		return nil, err
	}
	if int64(got) != n {
		return nil, &BoundsError{Op: "At", Off: int(e.off + off), Need: int(n), Have: got}
	}
	return b, nil
}

// Cursor returns a Cursor over n bytes at off, whose reported offsets are
// absolute within the underlying reader.
//
// This is the bridge between the two halves of the package: an Extent bounds
// what may be read, a Cursor walks it. The base is set so that a bounds error
// deep inside a member of a library names a position in the library.
func (e *Extent) Cursor(off, n int64) (*Cursor, error) {
	b, err := e.At(off, n)
	if err != nil {
		return nil, err
	}
	return NewCursorAt(b, int(e.off+off)), nil
}

// All returns a Cursor over the entire window.
//
// It reads the whole window into memory, so it suits a header or a small
// member rather than a large one; prefer Cursor with an explicit length where
// the structure's size is known in advance, which for this format it almost
// always is.
func (e *Extent) All() (*Cursor, error) { return e.Cursor(0, e.size) }

// Off converts a position within this window to an absolute file offset of
// the type the rest of the tree uses.
//
// The narrowing is safe because NewExtent rejected anything above
// MaxFileSize, so every position an Extent can describe fits in 32 bits. This
// method is the only sanctioned way to produce a file offset from an extent
// position, and the second half of the answer to why pe.Off is uint32.
func (e *Extent) Off(off int64) (uint32, error) {
	if off < 0 || off > e.size {
		return 0, &BoundsError{Op: "Off", Off: int(e.off + off), Need: 0, Have: int(e.size)}
	}
	return uint32(e.off + off), nil
}

// Table validates that count records of size elem fit at off within the
// window, and returns a Cursor over exactly those bytes.
//
// The product is computed in int64 so a large count cannot wrap, and the
// failure is arithmetic: no allocation is attempted for a header claiming four
// billion symbols. Every count in this format is attacker-controlled, and this
// is the extent-level twin of Cursor.Table for the case where the bytes have
// not been read yet — which is the case that matters, since it is the one
// where believing the count would allocate.
func (e *Extent) Table(what string, off int64, count uint32, elem int) (*Cursor, error) {
	if elem <= 0 {
		return nil, &CountError{What: what, Count: uint64(count), ElemSize: elem, Remaining: 0}
	}
	rem := e.size - off
	if off < 0 || off > e.size {
		rem = 0
	}
	need := int64(count) * int64(elem)
	if need > rem {
		return nil, &CountError{
			What:      what,
			Count:     uint64(count),
			ElemSize:  elem,
			Remaining: int(max64(rem, 0)),
		}
	}
	return e.Cursor(off, need)
}

// Head returns the first n bytes of the window, or fewer if the window is
// shorter, without treating shortness as an error.
//
// Detection needs this. pe.Kind wants 28 bytes and pe.IsImage rather more, but
// a file too short to identify is unidentified rather than malformed — those
// functions answer false or KindUnknown for a short buffer by design, and
// making the read fail first would turn that into an error the caller has to
// distinguish from a real one.
func (e *Extent) Head(n int64) ([]byte, error) {
	if n < 0 {
		n = 0
	}
	if n > e.size {
		n = e.size
	}
	return e.At(0, n)
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}