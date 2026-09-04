package format

import "github.com/vertex-language/pe/internal/binio"

// DOSHeaderSize is the fixed portion of the MS-DOS stub that this tree reads.
// The stub itself is longer and its contents are arbitrary — /STUB replaces
// it — but only the first 64 bytes have fields anyone looks at.
const DOSHeaderSize = 0x40

// DOSMagic is "MZ".
const DOSMagic uint16 = 0x5a4d

// LfanewOffset is where the stub records the file offset of the PE signature.
// It is the only field in the stub the Windows loader reads.
const LfanewOffset = 0x3c

// DOSHeader is the part of the MS-DOS stub that matters.
//
// Only two fields do: the magic, and Lfanew. The rest is a real MS-DOS program
// that prints a message, and this tree neither interprets it nor requires it
// to be sane. It is preserved verbatim when rewriting an image, because a stub
// is a place people put things.
type DOSHeader struct {
	Magic  uint16
	Lfanew uint32
}

// Decode reads the fields this tree uses. The cursor must be positioned at the
// start of the stub, and is left just past DOSHeaderSize — Lfanew is the last
// four bytes of it, so reading the field is what advances there.
//
// The intervening bytes are skipped relative to the current position rather
// than sought to an absolute one. A Cursor's Seek is absolute within its own
// window, so a header decoded from a sub-cursor over a larger file would
// otherwise read from the wrong place, and a stub is exactly the structure
// someone will one day decode from the middle of a buffer.
func (h *DOSHeader) Decode(c *binio.Cursor) error {
	h.Magic = c.U16()
	if err := c.Err(); err != nil {
		return err
	}
	if h.Magic != DOSMagic {
		c.Fail(ErrBadMagic)
		return c.Err()
	}
	c.Skip(LfanewOffset - 2) // past the DOS fields nobody reads
	h.Lfanew = c.U32()
	return c.Err()
}

// Encode writes a minimal 64-byte stub header: the magic, zeroes, and Lfanew.
//
// It does not write the stub *program*. A caller that wants the familiar
// "This program cannot be run in DOS mode" behaviour supplies those bytes
// itself; a caller that does not gets a header whose stub does nothing, which
// is legal and which several real toolchains emit.
func (h *DOSHeader) Encode(b *binio.Buf) {
	start := b.Len()
	b.U16(DOSMagic)
	b.Zero(LfanewOffset - 2)
	b.U32(h.Lfanew)
	if pad := DOSHeaderSize - (b.Len() - start); pad > 0 {
		b.Zero(pad)
	}
}