package rsrc

import (
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// Build lays the tree out and encodes it.
//
// The layout is four regions in one blob: every directory, breadth first; then
// the data descriptors; then the name strings; then the resource bytes. The
// order is not required by the format — every reference inside the tree is an
// explicit offset — and it is chosen to match what link.exe emits, so that a
// byte diff against its output is about content rather than arrangement.
//
// Two passes, and they cannot be one. Every directory entry holds the offset
// of what it points at, and a subdirectory's offset depends on how many
// directories precede it, which depends on the whole tree. So the first pass
// assigns positions and the second writes them.

// Fixup is a 32-bit field in the built blob that holds an RVA and therefore
// cannot be filled here.
//
// There is exactly one per resource: IMAGE_RESOURCE_DATA_ENTRY.OffsetToData.
// Every other offset in a resource tree is relative to the directory's own
// start and is final the moment Build returns; this one is image-relative, so
// the caller adds the section's address to Rel and stores the sum at Off.
//
// Handing back a list rather than asking for the address is what keeps this
// package out of the layout fixpoint: the tree's size is known before its
// position, which is exactly the property link needs to place it.
type Fixup struct {
	// Off is where the field sits within the blob.
	Off uint32

	// Rel is the target's position within the blob. The caller writes
	// Rel plus the blob's RVA.
	Rel uint32
}

// dataAlign is the boundary each resource blob starts on.
//
// The format requires nothing here — a data entry states its own address and
// size — but the loader hands the bytes to callers who cast them to structures
// with alignment requirements of their own, and an unaligned RT_RCDATA is a
// fault on a machine that cares. Four matches link.exe.
const dataAlign = 4

// Build encodes the tree and returns the bytes plus the fixups.
func (t *Tree) Build() ([]byte, []Fixup, error) {
	sortDir(&t.root)

	dirs, entries := t.walk()
	if len(entries) == 0 {
		return nil, nil, ErrEmpty
	}

	off := uint64(0)

	// Directories, breadth first. Each is its header plus its entries, and
	// the position assigned here is what every entry pointing at it will
	// carry.
	dirOff := make(map[*dirNode]uint32, len(dirs))
	for _, d := range dirs {
		dirOff[d] = uint32(off)
		off += format.ResourceDirectorySize +
			uint64(len(d.entries))*format.ResourceEntrySize
	}

	// The data descriptors. They are fixed width and contiguous, which is
	// not required either, but it puts every field a fixup touches in one
	// run and makes the fixup list a stride rather than a scatter.
	var leaves []*entryNode
	for _, e := range entries {
		if e.data == nil {
			continue
		}
		e.data.descOff = uint32(off)
		off += format.ResourceDataEntrySize
		leaves = append(leaves, e)
	}

	// The names. Word-aligned, because they are counted UTF-16 and an odd
	// offset makes every code unit straddle.
	for _, e := range entries {
		if !e.id.IsName {
			continue
		}
		off = align(off, 2)
		e.nameOff = uint32(off)
		off += uint64(format.ResourceStringSize(e.id.Name))
	}

	// The data.
	for _, e := range leaves {
		off = align(off, dataAlign)
		e.data.dataOff = uint32(off)
		off += uint64(len(e.data.Bytes))
	}

	if off > 0x7fffffff {
		// The directory offsets are 31 bits: the high bit of each is a
		// discriminator. A tree past that bound cannot address its own
		// tail, and the entries that would point into it would read as
		// subdirectory flags instead.
		return nil, nil, ErrTooLarge
	}

	b := binio.NewBufSize(int(off))
	for _, d := range dirs {
		writeDir(b, d, dirOff)
	}

	fixups := make([]Fixup, 0, len(leaves))
	for _, e := range leaves {
		fixups = append(fixups, Fixup{
			Off: uint32(b.Len()),
			Rel: e.data.dataOff,
		})
		// OffsetToData is written as zero and patched by the caller.
		// Writing the blob-relative value here and having the caller
		// add to it would work equally well and would hide the one
		// field in this format that is not what it looks like.
		d := format.ResourceDataEntry{
			OffsetToData: 0,
			Size:         uint32(len(e.data.Bytes)),
			CodePage:     e.data.CodePage,
		}
		d.Encode(b)
	}

	for _, e := range entries {
		if !e.id.IsName {
			continue
		}
		b.Align(2)
		format.EncodeResourceString(b, e.id.Name)
	}
	for _, e := range leaves {
		b.Align(dataAlign)
		b.Bytes(e.data.Bytes)
	}

	data, err := b.Data()
	if err != nil {
		return nil, nil, err
	}
	if uint64(len(data)) != off {
		// The two passes disagreed about a size. Returning the blob
		// anyway would return one whose internal offsets all point a
		// few bytes wrong, which renders correctly in every tool that
		// walks it by following the offsets and fails in the loader.
		return nil, nil, ErrBadResFile
	}
	return data, fixups, nil
}

// walk returns every directory in breadth-first order and every entry in the
// order their directories appear.
//
// Breadth first is what makes the level-one directory sit at offset zero,
// which the data directory's RVA points at and which every offset inside the
// tree is measured from.
func (t *Tree) walk() ([]*dirNode, []*entryNode) {
	dirs := []*dirNode{&t.root}
	var entries []*entryNode
	for i := 0; i < len(dirs); i++ {
		for _, e := range dirs[i].entries {
			entries = append(entries, e)
			if e.dir != nil {
				dirs = append(dirs, e.dir)
			}
		}
	}
	return dirs, entries
}

// writeDir encodes one directory and its entries.
func writeDir(b *binio.Buf, d *dirNode, dirOff map[*dirNode]uint32) {
	named, ids := d.counts()
	hdr := format.ResourceDirectory{
		// TimeDateStamp is zero rather than the link timestamp. The
		// loader ignores it, and a resource tree that changes when
		// nothing about the resources changed defeats a reproducible
		// build for no gain.
		NumberOfNamedEntries: named,
		NumberOfIdEntries:    ids,
	}
	hdr.Encode(b)

	for _, e := range d.entries {
		var ent format.ResourceEntry
		if e.id.IsName {
			ent.Name = format.ResourceNameFlag | e.nameOff
		} else {
			ent.Name = uint32(e.id.Ordinal)
		}
		if e.dir != nil {
			ent.OffsetToData = format.ResourceDirFlag | dirOff[e.dir]
		} else {
			ent.OffsetToData = e.data.descOff
		}
		ent.Encode(b)
	}
}

func align(v uint64, n uint64) uint64 { return (v + n - 1) &^ (n - 1) }