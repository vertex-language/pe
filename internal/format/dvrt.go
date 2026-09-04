package format

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/binio"
)

// The dynamic value relocation table is a second relocation table that the
// kernel applies while mapping, rather than the loader applying after. It was
// introduced for Return Flow Guard and retpoline — patching code at map time
// to turn a mitigation on — and ARM64X reuses it for something else entirely:
// making one file answer differently depending on who loaded it.
//
// The nesting is three deep and each level states its own size, which is the
// part that makes a reimplementation walk off the end. The outer table has a
// version and a byte count covering everything after it. Inside that is a run
// of records, each naming a *symbol* — which is not a symbol at all but a
// small enumeration saying what kind of fixups follow — and a byte count of
// its own. Inside each record is a run of page blocks shaped exactly like base
// relocation blocks: a page RVA, a block size, and then entries.
//
// The entries are where ARM64X differs from every other DVRT kind, and where
// the specification is silence rather than prose. Each is a 16-bit word whose
// low twelve bits are an offset within the page and whose high four are
// metadata: the low two of those select the fixup type and the high two mean
// different things per type. A consumer that walks these by incrementing two
// bytes at a time reads a VALUE's payload as the next entry.

const (
	// DynamicRelocTableVersion is the only version anything emits.
	DynamicRelocTableVersion = 1

	// DynamicRelocTableHeaderSize is the version and the size.
	DynamicRelocTableHeaderSize = 8
)

// DynamicRelocKind is the Symbol field of a dynamic relocation record: what
// kind of fixups the record carries.
//
// The name is winnt.h's and it is misleading. These are not symbol values;
// they are a closed set of tags, and the ones below 6 describe mitigations
// this tree neither produces nor applies.
type DynamicRelocKind uint64

const (
	DynamicRelocGuardRFPrologue        DynamicRelocKind = 1
	DynamicRelocGuardRFEpilogue        DynamicRelocKind = 2
	DynamicRelocGuardImportControl     DynamicRelocKind = 3
	DynamicRelocGuardIndirControl      DynamicRelocKind = 4
	DynamicRelocGuardSwitchtableBranch DynamicRelocKind = 5

	// DynamicRelocARM64X is the hybrid-image record: the fixups that turn
	// the native view of the file into the EC one.
	DynamicRelocARM64X DynamicRelocKind = 6
)

// DynamicRelocTable is the outer header.
type DynamicRelocTable struct {
	Version uint32

	// Size covers every record after this header, and not this header. A
	// walk that includes it reads eight bytes past the last block.
	Size uint32
}

func (t *DynamicRelocTable) Decode(c *binio.Cursor) error {
	t.Version = c.U32()
	t.Size = c.U32()
	if err := c.Err(); err != nil {
		return err
	}
	if t.Version != DynamicRelocTableVersion {
		return &FieldError{"DynamicRelocTable", "Version", uint64(t.Version),
			"unrecognized dynamic relocation table version"}
	}
	return nil
}

func (t *DynamicRelocTable) Encode(b *binio.Buf) {
	b.U32(t.Version)
	b.U32(t.Size)
}

// DynamicRelocSize returns the size of one record header at a width. Symbol is
// pointer-width and BaseRelocSize is not, so the record header is 12 bytes
// under PE32 and 16 under PE32+.
func DynamicRelocSize(w pe.Width) int { return w.Bytes() + 4 }

// DynamicReloc is one record header: what kind of fixups follow and how many
// bytes of blocks they occupy.
type DynamicReloc struct {
	Symbol        DynamicRelocKind
	BaseRelocSize uint32
}

func (r *DynamicReloc) Decode(c *binio.Cursor, w pe.Width) error {
	switch w {
	case pe.Width32:
		r.Symbol = DynamicRelocKind(c.U32())
	case pe.Width64:
		r.Symbol = DynamicRelocKind(c.U64())
	default:
		return ErrWidth
	}
	r.BaseRelocSize = c.U32()
	return c.Err()
}

func (r *DynamicReloc) Encode(b *binio.Buf, w pe.Width) {
	switch w {
	case pe.Width32:
		b.U32(uint32(r.Symbol))
	case pe.Width64:
		b.U64(uint64(r.Symbol))
	default:
		b.Fail(ErrWidth)
		return
	}
	b.U32(r.BaseRelocSize)
}

// The ARM64X blocks inside a record are BaseRelocBlock exactly — the same page
// RVA, the same self-inclusive size, the same 4-byte alignment. Only the
// entries differ, which is why this file defines an entry encoding and reuses
// basereloc.go's block header rather than declaring a second one.

// ARM64XFixup is the type of an ARM64X entry, in the low two bits of the
// metadata nibble.
type ARM64XFixup uint8

const (
	// ARM64XZeroFill clears the target. The entry is the header alone.
	ARM64XZeroFill ARM64XFixup = 0

	// ARM64XValue overwrites the target with a value carried in the entry.
	// This is the one that does all the work: it is what rewrites the COFF
	// header's Machine field to AMD64 and what points the export directory
	// at the EC view's own table.
	ARM64XValue ARM64XFixup = 1

	// ARM64XDelta adds a scaled 16-bit displacement to a 32-bit target. It
	// exists because most of what differs between the views differs by a
	// small, aligned amount, and carrying a delta costs two bytes where a
	// value costs four.
	ARM64XDelta ARM64XFixup = 2
)

func (f ARM64XFixup) String() string {
	switch f {
	case ARM64XZeroFill:
		return "ZEROFILL"
	case ARM64XValue:
		return "VALUE"
	case ARM64XDelta:
		return "DELTA"
	}
	return "arm64xfixup(" + itoaFormat(int(f)) + ")"
}

const (
	arm64xOffsetMask  = 0x0fff
	arm64xMetaShift   = 12
	arm64xTypeMask    = 0x3
	arm64xUpperShift  = 2 // within the nibble
	arm64xDeltaSign   = 0x4 // meta bit 2
	arm64xDeltaScale8 = 0x8 // meta bit 3
)

// ARM64XEntry is one decoded fixup.
type ARM64XEntry struct {
	// Offset is the position within the block's page.
	Offset uint16

	Type ARM64XFixup

	// Size is the bytes VALUE writes or ZEROFILL clears: 1, 2, 4, or 8,
	// encoded as its log2 in the metadata's upper two bits. It is unused
	// for DELTA, which always targets four bytes.
	Size int

	// Value is the payload VALUE writes, or the signed displacement DELTA
	// applies. DELTA's wire form is an unsigned 16-bit magnitude with the
	// sign and a scale of four or eight in the metadata, so a delta is
	// always a multiple of four and never larger than +/-512K.
	Value int64
}

// EncodedSize returns the entry's total width including its header.
func (e ARM64XEntry) EncodedSize() int {
	switch e.Type {
	case ARM64XValue:
		return 2 + e.Size
	case ARM64XDelta:
		return 4
	}
	return 2
}

// EncodeARM64XEntry appends an entry to b.
//
// It refuses what it cannot represent rather than truncating: an offset past
// the page, a VALUE size that is not a power of two up to eight, or a DELTA
// that is not a multiple of four and within the scaled 16-bit range. Each of
// those, encoded anyway, produces a fixup the kernel applies to the wrong
// address or with the wrong magnitude — and there is no diagnostic anywhere,
// because the patch happens during mapping and the file on disk is fine.
func EncodeARM64XEntry(b *binio.Buf, e ARM64XEntry) error {
	if e.Offset > arm64xOffsetMask {
		return &FieldError{"ARM64XEntry", "Offset", uint64(e.Offset),
			"offset is not within the block's page"}
	}
	meta := uint16(e.Type) & arm64xTypeMask

	switch e.Type {
	case ARM64XZeroFill, ARM64XValue:
		log2, ok := sizeLog2(e.Size)
		if !ok {
			return &FieldError{"ARM64XEntry", "Size", uint64(e.Size),
				"size is not 1, 2, 4, or 8"}
		}
		meta |= uint16(log2) << arm64xUpperShift
		b.U16(meta<<arm64xMetaShift | e.Offset)
		if e.Type == ARM64XZeroFill {
			return nil
		}
		v := uint64(e.Value)
		for i := 0; i < e.Size; i++ {
			b.U8(byte(v >> (8 * i)))
		}
		return nil

	case ARM64XDelta:
		d := e.Value
		if d < 0 {
			meta |= arm64xDeltaSign
			d = -d
		}
		scale := int64(4)
		if d%8 == 0 && d/4 > 0xffff {
			scale, meta = 8, meta|arm64xDeltaScale8
		}
		if d%scale != 0 || d/scale > 0xffff {
			return &FieldError{"ARM64XEntry", "Value", uint64(e.Value),
				"delta is not a multiple of the scale or does not fit sixteen bits"}
		}
		b.U16(meta<<arm64xMetaShift | e.Offset)
		b.U16(uint16(d / scale))
		return nil
	}
	return &FieldError{"ARM64XEntry", "Type", uint64(e.Type), "unknown fixup type"}
}

// DecodeARM64XEntry reads one entry. It returns the entry and the bytes it
// consumed, so a block walk advances by the answer rather than by two.
func DecodeARM64XEntry(c *binio.Cursor) (ARM64XEntry, int, error) {
	w := c.U16()
	if err := c.Err(); err != nil {
		return ARM64XEntry{}, 0, err
	}
	meta := (w >> arm64xMetaShift) & 0xf
	e := ARM64XEntry{
		Offset: w & arm64xOffsetMask,
		Type:   ARM64XFixup(meta & arm64xTypeMask),
	}
	switch e.Type {
	case ARM64XZeroFill, ARM64XValue:
		e.Size = 1 << ((meta >> arm64xUpperShift) & 0x3)
		if e.Type == ARM64XZeroFill {
			return e, 2, nil
		}
		var v uint64
		for i := 0; i < e.Size; i++ {
			v |= uint64(c.U8()) << (8 * i)
		}
		e.Value = int64(v)
		return e, 2 + e.Size, c.Err()

	case ARM64XDelta:
		mag := int64(c.U16())
		scale := int64(4)
		if meta&arm64xDeltaScale8 != 0 {
			scale = 8
		}
		e.Value = mag * scale
		if meta&arm64xDeltaSign != 0 {
			e.Value = -e.Value
		}
		e.Size = 4
		return e, 4, c.Err()
	}
	return e, 2, &FieldError{"ARM64XEntry", "Type", uint64(e.Type), "unknown fixup type"}
}

func sizeLog2(n int) (int, bool) {
	switch n {
	case 1:
		return 0, true
	case 2:
		return 1, true
	case 4:
		return 2, true
	case 8:
		return 3, true
	}
	return 0, false
}