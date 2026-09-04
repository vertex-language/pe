package format

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/binio"
)

// The import tables, which live in an image rather than in an object.
//
// They are separate from import.go, which holds IMPORT_OBJECT_HEADER: that is
// the header of a short-import archive member and it describes one import
// before anything has been linked. These describe the tables a finished image
// carries, and the two share nothing but a name.
//
// The shape is one descriptor per DLL, terminated by a zero descriptor, each
// pointing at two identical arrays of thunks. The lookup table says what is
// imported; the address table is where the loader writes the answers. They are
// identical on disk, which is why link builds one description and emits it
// twice — and why the loader can overwrite the second in place without
// consulting the first.

const (
	// ImportDescriptorSize is IMAGE_IMPORT_DESCRIPTOR: five 32-bit words.
	ImportDescriptorSize = 20

	// DelayDescriptorSize is ImgDelayDescr: eight 32-bit words.
	DelayDescriptorSize = 32

	// HintSize is the 16-bit hint at the head of a hint/name entry.
	HintSize = 2
)

// ImportDescriptor is one entry of the import directory table.
//
// The directory is terminated by an all-zero descriptor rather than by a
// count, so an emitter must write one and a reader must stop at one. Nothing
// in the optional header says how many there are; the directory's size covers
// the terminator too.
type ImportDescriptor struct {
	// ImportLookupTableRVA is the ILT: what is being imported. The
	// specification also calls this OriginalFirstThunk, which is what
	// winnt.h names it.
	ImportLookupTableRVA uint32

	// TimeDateStamp is zero in an unbound image, and the timestamp of the
	// bound DLL otherwise. This tree never binds, so it is always zero —
	// see Options.NoBind, which sets the NO_BIND characteristic to say so.
	TimeDateStamp uint32

	// ForwarderChain is the index of the first forwarder reference, or
	// 0xffffffff for none. It is bound-import machinery and is zero here.
	ForwarderChain uint32

	// NameRVA points at the DLL's name, a NUL-terminated ASCII string.
	NameRVA uint32

	// ImportAddressTableRVA is the IAT: where the loader writes the
	// resolved addresses. On disk it is a copy of the ILT, which is what
	// makes __imp_$sym a meaningful address before the image ever loads.
	ImportAddressTableRVA uint32
}

func (d *ImportDescriptor) Decode(c *binio.Cursor) error {
	d.ImportLookupTableRVA = c.U32()
	d.TimeDateStamp = c.U32()
	d.ForwarderChain = c.U32()
	d.NameRVA = c.U32()
	d.ImportAddressTableRVA = c.U32()
	return c.Err()
}

func (d *ImportDescriptor) Encode(b *binio.Buf) {
	b.U32(d.ImportLookupTableRVA)
	b.U32(d.TimeDateStamp)
	b.U32(d.ForwarderChain)
	b.U32(d.NameRVA)
	b.U32(d.ImportAddressTableRVA)
}

// IsTerminator reports whether this is the all-zero descriptor that ends the
// directory.
//
// The test is the name RVA rather than the whole structure. A descriptor with
// no name imports from nothing, so it cannot be a real entry whatever its
// other fields hold — and a reader that required every field to be zero would
// walk past a terminator some producer left a stale timestamp in.
func (d *ImportDescriptor) IsTerminator() bool { return d.NameRVA == 0 }

// ThunkDataSize returns the width of one lookup or address table entry, which
// is the target's pointer size.
func ThunkDataSize(w pe.Width) int { return w.Bytes() }

// ordinalFlag returns the bit that marks a thunk as an import by ordinal.
//
// It is the high bit of the word, so bit 31 under PE32 and bit 63 under PE32+.
// This is Width doing real work rather than describing something: a reader
// that tests bit 31 in a 64-bit image sees the ordinal flag set on every entry
// whose hint/name RVA happens to exceed 2 GB, and one that tests bit 63 in a
// 32-bit image never sees it at all.
func ordinalFlag(w pe.Width) uint64 {
	if w == pe.Width32 {
		return 1 << 31
	}
	return 1 << 63
}

// ThunkData is one entry of an import lookup or address table.
//
// Its meaning is a union decided by the high bit. With the bit set, the low 16
// bits are an ordinal and the rest must be zero. With it clear, the whole
// value is an RVA to a hint/name entry. There is no third case: a zero entry
// terminates the table.
type ThunkData struct {
	// Ordinal is the imported ordinal, valid when ByOrdinal is set.
	Ordinal uint16

	// HintNameRVA points at a HintName entry, valid when ByOrdinal is
	// clear.
	HintNameRVA uint32

	ByOrdinal bool
}

func (t *ThunkData) Decode(c *binio.Cursor, w pe.Width) error {
	var v uint64
	switch w {
	case pe.Width32:
		v = uint64(c.U32())
	case pe.Width64:
		v = c.U64()
	default:
		return ErrWidth
	}
	if err := c.Err(); err != nil {
		return err
	}
	if v&ordinalFlag(w) != 0 {
		t.ByOrdinal, t.Ordinal, t.HintNameRVA = true, uint16(v), 0
		return nil
	}
	t.ByOrdinal, t.Ordinal, t.HintNameRVA = false, 0, uint32(v)
	return nil
}

func (t *ThunkData) Encode(b *binio.Buf, w pe.Width) {
	var v uint64
	if t.ByOrdinal {
		v = ordinalFlag(w) | uint64(t.Ordinal)
	} else {
		v = uint64(t.HintNameRVA)
	}
	switch w {
	case pe.Width32:
		b.U32(uint32(v))
	case pe.Width64:
		b.U64(v)
	default:
		b.Fail(ErrWidth)
	}
}

// IsTerminator reports whether this is the zero entry that ends a table.
func (t *ThunkData) IsTerminator() bool {
	return !t.ByOrdinal && t.HintNameRVA == 0
}

// HintName is one entry of the hint/name table: a hint into the exporting
// DLL's name table, then the name itself.
//
// The hint is exactly that. The loader tries the export name table at that
// index first and falls back to a binary search when the name there does not
// match, so a stale hint costs a comparison and never a wrong answer. This
// tree writes zero, because it does not read the DLL it imports from.
type HintName struct {
	Hint uint16
	Name string
}

func (h *HintName) Decode(c *binio.Cursor) error {
	h.Hint = c.U16()
	h.Name = c.CStr()
	return c.Err()
}

// HintNameSize returns the encoded size of an entry, padding included.
//
// The entry is padded to an even length. That is not decoration: the next
// entry's RVA is stored in a thunk and the specification requires these to be
// even-aligned, so an odd-length name that is not padded shifts every entry
// after it onto an odd boundary.
func HintNameSize(name string) int {
	n := HintSize + len(name) + 1
	return n + n%2
}

func (h *HintName) Encode(b *binio.Buf) {
	start := b.Len()
	b.U16(h.Hint)
	b.CStr(h.Name)
	if pad := (b.Len() - start) % 2; pad != 0 {
		b.Zero(1)
	}
}

// Delay-load attribute bits.
const (
	// DelayAttrRVA means the descriptor's fields are RVAs rather than
	// virtual addresses. Every delay-load descriptor anyone still produces
	// sets it; the alternative is a pre-Vista form whose fields need base
	// relocations of their own.
	DelayAttrRVA uint32 = 0x1
)

// DelayDescriptor is ImgDelayDescr: one delay-loaded DLL.
//
// It is the same shape as an ordinary import with more tables hanging off it.
// The module handle slot is where the helper caches the HMODULE after the
// first call; the unload table is a copy of the original IAT, which is what
// __FUnloadDelayLoadedDLL2 restores over the live one — so a build that never
// unloads pays for a table it never reads, which is why emitting it is an
// option rather than a rule.
type DelayDescriptor struct {
	Attributes                 uint32
	DllNameRVA                 uint32
	ModuleHandleRVA            uint32
	ImportAddressTableRVA      uint32
	ImportNameTableRVA         uint32
	BoundImportAddressTableRVA uint32
	UnloadInformationTableRVA  uint32
	TimeDateStamp              uint32
}

func (d *DelayDescriptor) Decode(c *binio.Cursor) error {
	d.Attributes = c.U32()
	d.DllNameRVA = c.U32()
	d.ModuleHandleRVA = c.U32()
	d.ImportAddressTableRVA = c.U32()
	d.ImportNameTableRVA = c.U32()
	d.BoundImportAddressTableRVA = c.U32()
	d.UnloadInformationTableRVA = c.U32()
	d.TimeDateStamp = c.U32()
	return c.Err()
}

func (d *DelayDescriptor) Encode(b *binio.Buf) {
	b.U32(d.Attributes)
	b.U32(d.DllNameRVA)
	b.U32(d.ModuleHandleRVA)
	b.U32(d.ImportAddressTableRVA)
	b.U32(d.ImportNameTableRVA)
	b.U32(d.BoundImportAddressTableRVA)
	b.U32(d.UnloadInformationTableRVA)
	b.U32(d.TimeDateStamp)
}

// IsTerminator reports whether this is the zero descriptor ending the
// delay-load directory.
func (d *DelayDescriptor) IsTerminator() bool { return d.DllNameRVA == 0 }