package format

import (
	"unicode/utf16"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/binio"
)

// The TLS directory is the one structure in an image whose stored addresses
// are virtual addresses rather than RVAs. Four of its six fields are VAs, and
// each of them therefore needs a base relocation of its own — forgetting that
// produces a binary that works at its preferred base and crashes the moment
// ASLR moves it, which is the single most common way a hand-rolled TLS
// implementation fails.
//
// The width dependence is the usual one: the four address fields are the
// target's pointer size and the two trailing DWORDs are not, so a PE32
// directory is 24 bytes and a PE32+ one is 40. There is no TLSDirectory32 and
// no TLSDirectory64; the address fields are uint64 here and narrowed at the
// wire edge, the same arrangement OptionalHeader uses.

const (
	// TLSDirectorySize32 and TLSDirectorySize64 are the encoded sizes:
	// four pointer-width address fields plus two DWORDs.
	TLSDirectorySize32 = 4*4 + 8
	TLSDirectorySize64 = 4*8 + 8
)

// TLSDirectorySize returns the encoded size at a width, or 0 for an invalid
// one.
func TLSDirectorySize(w pe.Width) int {
	switch w {
	case pe.Width32:
		return TLSDirectorySize32
	case pe.Width64:
		return TLSDirectorySize64
	}
	return 0
}

// TLSDirectory is IMAGE_TLS_DIRECTORY.
type TLSDirectory struct {
	// StartAddressOfRawData and EndAddressOfRawData bound the TLS
	// template: the block of initialized data every new thread gets a
	// private copy of. Both are VAs. End is the address of the last byte
	// of initialized data, exclusive of the zero fill.
	StartAddressOfRawData uint64
	EndAddressOfRawData   uint64

	// AddressOfIndex is where the loader deposits this module's TLS index,
	// which is the number every static TLS access starts from. It is a VA
	// pointing into an ordinary writable data section, which is why the
	// CRT can give it a name — _tls_index — and reference it from code.
	AddressOfIndex uint64

	// AddressOfCallBacks points at a NUL-terminated array of function
	// pointers the loader calls on thread attach and detach. Those
	// pointers are VAs too, and so is this. An image with no callbacks
	// still points at an array — the CRT's, holding only the terminator —
	// rather than storing zero.
	AddressOfCallBacks uint64

	// SizeOfZeroFill is the bytes past EndAddressOfRawData that the loader
	// zeroes for each thread. It is how a thread-local with no initializer
	// costs nothing in the file.
	SizeOfZeroFill uint32

	// Characteristics is not a flag word despite the name. Its bits 20
	// through 23 are the same alignment nibble a section header carries,
	// with the same log2-plus-one encoding, and the rest is reserved.
	// See TLSAlignMask; this package stores the field raw and
	// pe.DecodeAlign reads it.
	Characteristics uint32
}

// The alignment nibble inside Characteristics. It is the section header's
// encoding exactly, which is why the mask and shift are the same numbers and
// why pe.DecodeAlign can be pointed at this field unchanged.
const (
	TLSAlignMask  uint32 = 0x00f00000
	TLSAlignShift uint32 = 20
)

func (d *TLSDirectory) Decode(c *binio.Cursor, w pe.Width) error {
	switch w {
	case pe.Width32:
		d.StartAddressOfRawData = uint64(c.U32())
		d.EndAddressOfRawData = uint64(c.U32())
		d.AddressOfIndex = uint64(c.U32())
		d.AddressOfCallBacks = uint64(c.U32())
	case pe.Width64:
		d.StartAddressOfRawData = c.U64()
		d.EndAddressOfRawData = c.U64()
		d.AddressOfIndex = c.U64()
		d.AddressOfCallBacks = c.U64()
	default:
		return ErrWidth
	}
	d.SizeOfZeroFill = c.U32()
	d.Characteristics = c.U32()
	return c.Err()
}

func (d *TLSDirectory) Encode(b *binio.Buf, w pe.Width) {
	switch w {
	case pe.Width32:
		b.U32(uint32(d.StartAddressOfRawData))
		b.U32(uint32(d.EndAddressOfRawData))
		b.U32(uint32(d.AddressOfIndex))
		b.U32(uint32(d.AddressOfCallBacks))
	case pe.Width64:
		b.U64(d.StartAddressOfRawData)
		b.U64(d.EndAddressOfRawData)
		b.U64(d.AddressOfIndex)
		b.U64(d.AddressOfCallBacks)
	default:
		b.Fail(ErrWidth)
		return
	}
	b.U32(d.SizeOfZeroFill)
	b.U32(d.Characteristics)
}

// TLSField names one field of the directory.
//
// The offsets exist as an API because link does not encode this structure —
// the CRT supplies it, already initialized, and the linker fills in whichever
// fields the CRT left at zero. Patching one field means knowing where it sits,
// and this is the only place that knows.
type TLSField int

const (
	TLSStart TLSField = iota
	TLSEnd
	TLSIndex
	TLSCallbacks
	TLSZeroFill
	TLSCharacteristics
)

// IsAddress reports whether this field holds a virtual address, and therefore
// whether writing it obliges the writer to produce a base relocation for it.
//
// The four that answer yes are the whole reason this method exists. Nothing
// else in an image stores a VA, so nothing else in the tree has to ask.
func (f TLSField) IsAddress() bool { return f >= TLSStart && f <= TLSCallbacks }

func (f TLSField) String() string {
	switch f {
	case TLSStart:
		return "StartAddressOfRawData"
	case TLSEnd:
		return "EndAddressOfRawData"
	case TLSIndex:
		return "AddressOfIndex"
	case TLSCallbacks:
		return "AddressOfCallBacks"
	case TLSZeroFill:
		return "SizeOfZeroFill"
	case TLSCharacteristics:
		return "Characteristics"
	}
	return "tlsfield(" + itoaFormat(int(f)) + ")"
}

// TLSFieldOffset returns a field's offset and size within the directory at a
// given width.
func TLSFieldOffset(f TLSField, w pe.Width) (off, size int, ok bool) {
	p := w.Bytes()
	if p == 0 {
		return 0, 0, false
	}
	switch f {
	case TLSStart:
		return 0, p, true
	case TLSEnd:
		return p, p, true
	case TLSIndex:
		return 2 * p, p, true
	case TLSCallbacks:
		return 3 * p, p, true
	case TLSZeroFill:
		return 4 * p, 4, true
	case TLSCharacteristics:
		return 4*p + 4, 4, true
	}
	return 0, 0, false
}

// TLSCallbackSize returns the width of one entry in the callback array, which
// is a pointer and therefore the target's word size. The array is terminated
// by a zero entry rather than by a count.
func TLSCallbackSize(w pe.Width) int { return w.Bytes() }

var _ = utf16.Encode // referenced by rsrc.go's sibling declarations