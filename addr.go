package pe

import "strconv"

// This file defines the three address kinds PE uses as three distinct types.
// Nothing converts implicitly between them.
//
// The reason is one field. Every one of the sixteen data directories stores an
// RVA in its first word — except the Certificate Table, whose first field is a
// file pointer, because the attribute certificates are not mapped into memory.
// In a uint32 world that distinction is a comment, and comments are ignored
// eventually. Here it is a type error, and image.DataDir carries the
// certificate directory in a separate Off-typed field.
//
// The only bridges are RVA.VA, below, and image.Image.Off, which needs the
// section table to answer and therefore cannot live in this package.

// RVA is a relative virtual address: an address after loading, with the image
// base subtracted. Pointers inside a PE image are 32-bit RVAs, which is why an
// image is capped at 4 GB even on a 64-bit machine.
//
// In an object file an RVA is an offset within its section; the specification
// suggests a compiler set the first RVA in each section to zero.
type RVA uint32

// Off is a file offset: a position in the file as stored on disk, which the
// specification calls a file pointer. The PE header fields that hold one are
// all 32-bit, so this type is too.
type Off uint32

// VA is a virtual address: an RVA with the image base added back. TLS
// directory fields are the one place in an image where VAs are stored rather
// than RVAs, which is why each of them needs a base relocation.
type VA uint64

// VA returns r as a virtual address relative to base. This is one of the two
// bridges between address kinds in this module.
func (r RVA) VA(base VA) VA { return base + VA(r) }

// Add returns r+n. Overflow wraps; callers doing layout are expected to bound
// their own arithmetic, and image layout reports overlap and overflow itself.
func (r RVA) Add(n uint32) RVA { return r + RVA(n) }

// AlignUp rounds r up to a multiple of align, which must be a power of two.
// AlignUp(0) is r.
func (r RVA) AlignUp(align uint32) RVA {
	if align <= 1 {
		return r
	}
	return (r + RVA(align) - 1) &^ (RVA(align) - 1)
}

// Aligned reports whether r is a multiple of align.
func (r RVA) Aligned(align uint32) bool {
	return align <= 1 || uint32(r)&(align-1) == 0
}

func (r RVA) String() string { return "0x" + strconv.FormatUint(uint64(r), 16) }

// Add returns o+n. Overflow wraps.
func (o Off) Add(n uint32) Off { return o + Off(n) }

// AlignUp rounds o up to a multiple of align, which must be a power of two.
func (o Off) AlignUp(align uint32) Off {
	if align <= 1 {
		return o
	}
	return (o + Off(align) - 1) &^ (Off(align) - 1)
}

// Aligned reports whether o is a multiple of align.
func (o Off) Aligned(align uint32) bool {
	return align <= 1 || uint32(o)&(align-1) == 0
}

func (o Off) String() string { return "@0x" + strconv.FormatUint(uint64(o), 16) }

// Add returns v+n. Overflow wraps.
func (v VA) Add(n uint64) VA { return v + VA(n) }

func (v VA) String() string { return "0x" + strconv.FormatUint(uint64(v), 16) }