package image

import (
	"strconv"

	"github.com/vertex-language/pe"
)

// A Chunk is one placeable contribution to an output section: an input
// section, a merged literal blob, a synthesized table, or a range-extension
// thunk.
//
// It is deliberately not split into read and write types the way coff.Section
// and coff.SectionBuilder are. A chunk read from an object and one the linker
// generated are placed, relocated, swept, and emitted by exactly the same
// code, and giving them separate types would mean writing that code twice and
// keeping the two copies agreeing.
//
// The relocations attached to a chunk are in reloc.go, beside the type they
// carry.
type Chunk struct {
	// Name is the contributing object section's full name, $ suffix
	// included. It decides ordering at merge — .CRT$XCA through .CRT$XCZ
	// bracket the C++ initializer array — and it is what a diagnostic
	// names. The image section this lands in is GroupName.
	Name string

	// Input is the file this came from, for diagnostics. A synthesized
	// chunk has no input and leaves it empty.
	Input string

	// Discarded means this chunk lost a COMDAT election. It is permanent,
	// set during resolve, and independent of Reachable.
	//
	// The two flags stay two flags. Collapsing them was a real bug class in
	// earlier designs of this linker: a chunk that lost an election is gone
	// no matter what references it, while one that is merely unreachable
	// comes back the moment something reaches it, and a single "live" bit
	// cannot express the difference.
	Discarded bool

	// Reachable means this chunk survived /OPT:REF. It is meaningless
	// until sweep has run, and sweep sets it on everything when /OPT:REF is
	// off.
	Reachable bool

	src    ChunkSource
	sec    *Section
	relocs []Reloc

	rva      pe.RVA
	assigned bool
}

// ChunkSource is where a chunk's bytes and its placement constraints come
// from.
//
// Bytes is called once, after Freeze, during the contents pass — which is what
// lets a synthesized table whose content is an RVA satisfy this interface at
// all. A source whose bytes are nil contributes Size zero-filled bytes and no
// file content; that is how .bss reaches the image without occupying it.
type ChunkSource interface {
	// Size is the chunk's size in bytes, known before layout.
	Size() uint32

	// Align is the required alignment in bytes, never the encoded nibble.
	Align() int

	// Bytes returns the contents, or nil for a chunk that is only zeroes.
	// The slice must be exactly Size bytes long when it is not nil.
	Bytes() ([]byte, error)
}

// NewChunk returns a chunk over src. It is not placed until it is added to a
// section and the image is laid out.
func NewChunk(name, input string, src ChunkSource) *Chunk {
	return &Chunk{Name: name, Input: input, src: src}
}

// Size returns the chunk's size in bytes.
func (c *Chunk) Size() uint32 { return c.src.Size() }

// Align returns the chunk's required alignment in bytes.
//
// A source reporting zero gets 1 rather than an error: an alignment of zero is
// how a source says it does not care, and AlignUp of 1 is the identity, so the
// two mean the same thing and only one of them needs handling downstream.
func (c *Chunk) Align() int {
	if a := c.src.Align(); a > 0 {
		return a
	}
	return 1
}

// Live reports whether this chunk reaches the image: it neither lost an
// election nor was swept.
func (c *Chunk) Live() bool { return !c.Discarded && c.Reachable }

// Section returns the output section holding this chunk, or nil before it is
// added to one.
func (c *Chunk) Section() *Section { return c.sec }

// GroupName returns the name with the $ suffix removed: the image section this
// contribution lands in.
//
// The specification is explicit that a section name in an image file never
// contains a '$', so this is the merge key rather than a convenience — the
// suffix decides ordering within the group and then does not survive.
func (c *Chunk) GroupName() string {
	for i := 0; i < len(c.Name); i++ {
		if c.Name[i] == '$' {
			return c.Name[:i]
		}
	}
	return c.Name
}

// RVA returns the address layout assigned, or ErrNoRVA if it has not run.
func (c *Chunk) RVA() (pe.RVA, error) {
	if !c.assigned {
		return 0, ErrNoRVA
	}
	return c.rva, nil
}

// Bytes returns the chunk's contents, or nil for one that is only zeroes.
func (c *Chunk) Bytes() ([]byte, error) { return c.src.Bytes() }

// HasContent reports whether this chunk occupies bytes in the file.
//
// A chunk that does not still occupies address space: it contributes to its
// section's VirtualSize and not to its SizeOfRawData. Because SizeOfRawData
// describes a prefix of the section rather than a subset of it, every chunk
// with content must precede every chunk without, which assign enforces.
//
// The test is an interface assertion rather than a fourth method on
// ChunkSource, because zero-fill is the rare case and the alternative is every
// source in the tree implementing a method to return false.
func (c *Chunk) HasContent() bool {
	if bss, ok := c.src.(interface{ Zeroes() bool }); ok {
		return !bss.Zeroes()
	}
	return true
}

func (c *Chunk) String() string {
	s := c.Name
	if s == "" {
		s = "<unnamed>"
	}
	if c.Input != "" {
		s += " (" + c.Input + ")"
	}
	if c.assigned {
		s += " at " + c.rva.String()
	}
	s += " size " + strconv.FormatUint(uint64(c.Size()), 10)
	return s
}

// Blob is a ChunkSource over bytes the linker already holds: a merged string
// literal, a thunk the backend built, a table rsrc produced.
type Blob struct {
	Data      []byte
	Alignment int
}

func (b *Blob) Size() uint32           { return uint32(len(b.Data)) }
func (b *Blob) Align() int             { return b.Alignment }
func (b *Blob) Bytes() ([]byte, error) { return b.Data, nil }

// Zeroed is a ChunkSource that occupies address space and no file space. It is
// what an uninitialized-data section becomes in the image.
//
// It reports its size and returns no bytes, rather than returning a run of
// zeroes: a .bss can be megabytes, and materializing it would put in the
// linker's memory exactly the thing the format exists to keep out of the file.
type Zeroed struct {
	Length    uint32
	Alignment int
}

func (z *Zeroed) Size() uint32           { return z.Length }
func (z *Zeroed) Align() int             { return z.Alignment }
func (z *Zeroed) Bytes() ([]byte, error) { return nil, nil }

// Zeroes marks this source as contributing no file content. HasContent looks
// for it.
func (z *Zeroed) Zeroes() bool { return true }