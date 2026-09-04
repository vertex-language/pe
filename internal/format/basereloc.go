package format

import "github.com/vertex-language/pe/internal/binio"

// A base relocation block: the page it covers, its own size, and then a run of
// 16-bit entries.
//
// The entry encoding and the page size live in pe, since they are constants a
// caller reasons about. What lives here is the block header, because it is the
// part with a layout — and because a block states its own size *including the
// header*, which is the detail every reimplementation gets wrong once.

// BaseRelocBlockHeaderSize is the page RVA plus the block size.
const BaseRelocBlockHeaderSize = 8

// BaseRelocBlock is one block header.
type BaseRelocBlock struct {
	// PageRVA is the page these entries are offsets within. The entries
	// carry twelve bits each, which is exactly a 4K page — that is why the
	// table is blocked at all.
	PageRVA uint32

	// BlockSize is the whole block: this header plus every entry plus any
	// ABSOLUTE padding. A walk advances by this, so a size that excludes
	// the header reads the last two entries of each block as the next
	// block's header.
	BlockSize uint32
}

func (h *BaseRelocBlock) Decode(c *binio.Cursor) error {
	h.PageRVA = c.U32()
	h.BlockSize = c.U32()
	return c.Err()
}

func (h *BaseRelocBlock) Encode(b *binio.Buf) {
	b.U32(h.PageRVA)
	b.U32(h.BlockSize)
}

// Entries returns how many 16-bit entries this block declares.
//
// It reports false for a size below the header or one that is not a whole
// number of entries past it. Both are corrupt, and both would otherwise
// produce a loop that reads past the block or never terminates.
func (h *BaseRelocBlock) Entries() (int, bool) {
	if h.BlockSize < BaseRelocBlockHeaderSize {
		return 0, false
	}
	n := h.BlockSize - BaseRelocBlockHeaderSize
	if n%2 != 0 {
		return 0, false
	}
	return int(n / 2), true
}

// BaseRelocBlockSize returns the encoded size of a block holding n entries,
// padding included.
//
// Blocks are 32-bit aligned, so a block with an odd number of entries carries
// one more. That padding entry is why relocation type zero exists: ABSOLUTE
// means nothing and the loader skips it, so a block can be brought back to
// alignment without describing a fixup that is not there.
func BaseRelocBlockSize(n int) int {
	size := BaseRelocBlockHeaderSize + 2*n
	return size + size%4
}

// BaseRelocPadEntries returns how many ABSOLUTE entries a block of n real
// entries needs to reach alignment.
func BaseRelocPadEntries(n int) int {
	if n%2 == 0 {
		return 0
	}
	return 1
}