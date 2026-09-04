package backend

import (
	"strconv"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
)

// A Site is one chunk's output bytes together with the address they will
// occupy.
//
// Every write a backend makes goes through it, and every write is bounds
// checked against the chunk rather than against the file. That is the
// difference that matters: a relocation running past the end of its own chunk
// is a bug in the object or in the backend, and catching it at the file
// boundary would let it corrupt the neighbouring chunk first and fail only if
// it also ran off the end of the image.
type Site struct {
	// Img is the frozen image the chunk belongs to.
	//
	// A backend needs it for the relocations that are not purely local:
	// ADDR32 wants the image base, SECREL wants the target's section start,
	// and SECTION wants its number. Everything else is answered from RVA
	// and the target alone.
	Img *image.Image

	// Chunk is the contribution being written.
	Chunk *image.Chunk

	// RVA is the chunk's address. A field at offset n within the chunk
	// occupies RVA+n, which is what a PC-relative relocation measures from.
	RVA pe.RVA

	data []byte
}

// NewSite returns a Site over a chunk's bytes in the frozen image.
//
// It fails for a chunk with no file content: a zero-filled chunk has an
// address and no bytes, so there is nothing to relocate into. A relocation
// against one is an object claiming .bss has content, which is a malformed
// input rather than a case to handle.
func NewSite(img *image.Image, c *image.Chunk) (*Site, error) {
	rva, err := c.RVA()
	if err != nil {
		return nil, err
	}
	b, err := img.AtRVA(rva, int(c.Size()))
	if err != nil {
		return nil, err
	}
	return &Site{Img: img, Chunk: c, RVA: rva, data: b}, nil
}

// Len returns the chunk's size in bytes.
func (s *Site) Len() int { return len(s.data) }

// AddrOf returns the address of a field at offset off within the chunk.
func (s *Site) AddrOf(off uint32) pe.RVA { return s.RVA.Add(off) }

// Bytes returns a writable window of n bytes at off.
func (s *Site) Bytes(off uint32, n int) ([]byte, error) {
	if n < 0 || uint64(off)+uint64(n) > uint64(len(s.data)) {
		return nil, s.bounds(off, n)
	}
	return s.data[off : uint64(off)+uint64(n)], nil
}

// U16, U32, and U64 read the field already in place.
//
// Reading before writing is not optional in COFF: the addend is implicit, it
// lives in the field, and a backend that overwrites without adding what was
// there loses it. The specification never states this because there is no
// addend field to describe. See Add32.
func (s *Site) U16(off uint32) (uint16, error) {
	b, err := s.Bytes(off, 2)
	if err != nil {
		return 0, err
	}
	return uint16(b[0]) | uint16(b[1])<<8, nil
}

func (s *Site) U32(off uint32) (uint32, error) {
	b, err := s.Bytes(off, 4)
	if err != nil {
		return 0, err
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, nil
}

func (s *Site) U64(off uint32) (uint64, error) {
	b, err := s.Bytes(off, 8)
	if err != nil {
		return 0, err
	}
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v, nil
}

// SetU16, SetU32, and SetU64 replace a field.
//
// A backend applying a relocation wants Add, not these. These are for a
// synthetic filling a table it built itself, where there is no addend because
// there was no compiler.
func (s *Site) SetU16(off uint32, v uint16) error {
	b, err := s.Bytes(off, 2)
	if err != nil {
		return err
	}
	b[0], b[1] = byte(v), byte(v>>8)
	return nil
}

func (s *Site) SetU32(off uint32, v uint32) error {
	b, err := s.Bytes(off, 4)
	if err != nil {
		return err
	}
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	return nil
}

func (s *Site) SetU64(off uint32, v uint64) error {
	b, err := s.Bytes(off, 8)
	if err != nil {
		return err
	}
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
	return nil
}

// Add16, Add32, and Add64 add a value to the field already in place.
//
// Adding rather than storing is not a style choice. A COFF relocation carries
// no addend: the addend is whatever the compiler left in the field, so
// `lea rax, [foo+8]` emits a REL32 against foo with an 8 already written
// there. A backend that stores loses the 8, and the result is a program that
// links cleanly and reads the wrong member of every struct — which is why
// every case in an Apply reaches for these and none reaches for SetU32.
//
// The addition wraps, which is what the format wants: a negative addend is
// stored as its two's complement in the same field.
func (s *Site) Add16(off uint32, v uint16) error {
	cur, err := s.U16(off)
	if err != nil {
		return err
	}
	return s.SetU16(off, cur+v)
}

func (s *Site) Add32(off uint32, v uint32) error {
	cur, err := s.U32(off)
	if err != nil {
		return err
	}
	return s.SetU32(off, cur+v)
}

func (s *Site) Add64(off uint32, v uint64) error {
	cur, err := s.U64(off)
	if err != nil {
		return err
	}
	return s.SetU64(off, cur+v)
}

// Add8 adds to a single byte. SECREL7 is the only relocation narrow enough to
// need it, and it exists so that case does not reach into Bytes by hand.
func (s *Site) Add8(off uint32, v uint8) error {
	b, err := s.Bytes(off, 1)
	if err != nil {
		return err
	}
	b[0] += v
	return nil
}

func (s *Site) bounds(off uint32, n int) error {
	return &RangeError{
		Chunk: s.Chunk.Name,
		Input: s.Chunk.Input,
		Off:   off,
		Reason: "field of " + strconv.Itoa(n) + " bytes runs past the end of a chunk of " +
			strconv.Itoa(len(s.data)),
	}
}

// RangeError is a value that did not fit the field being written, or a field
// that did not fit its chunk.
//
// It names the chunk and the input file because neither alone is actionable: a
// branch out of range is fixed by moving code, and "out of range" without
// knowing which function in which object leaves nowhere to start. link wraps
// it in *link.OverflowError, which adds the referencing input.
//
// Reason and the Value/Bits pair are alternatives. A failure with a number
// behind it — a displacement that did not fit — sets the pair; one without,
// such as an unsupported type, sets Reason.
type RangeError struct {
	Chunk  string
	Input  string
	Off    uint32
	Value  int64
	Bits   int
	Reason string
}

func (e *RangeError) Error() string {
	s := "backend: "
	if e.Chunk != "" {
		s += e.Chunk
		if e.Input != "" {
			s += " (" + e.Input + ")"
		}
		s += "+0x" + strconv.FormatUint(uint64(e.Off), 16) + ": "
	}
	if e.Reason != "" {
		return s + e.Reason
	}
	return s + "value " + strconv.FormatInt(e.Value, 10) +
		" does not fit a " + strconv.Itoa(e.Bits) + "-bit field"
}