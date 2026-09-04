package link

import (
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/coff"
	"github.com/vertex-language/pe/image"
)

// Split builds the dependency graph sweep walks, and cuts .pdata into
// per-function pieces so that sweeping a function takes its unwind entry with
// it.
//
// There is no mergeable-section splitting here, and there is nothing missing.
// ELF has SHF_MERGE, which cuts a section into independently live pieces so a
// string literal can be deduplicated. PE has no such flag and does not need
// one: MSVC emits every string literal into its own COMDAT .rdata$ section
// with SELECT_ANY, so literal merging already happened during the election.
//
// What PE does need is the unwind pairing. .pdata is an array of fixed-width
// records, one per function, each holding the function's start RVA. In an
// object compiled with /Gy the compiler makes each one an associative COMDAT
// of its function and the association is explicit. In anything else — hand
// written assembly, a whole-file .pdata, an object from a toolchain that does
// not bother — .pdata arrives as one section describing every function in the
// object, and sweeping half of them has to leave the other half's records
// behind.

// chunkInfo is what link knows about a chunk that image does not.
//
// image deliberately has no idea what a COMDAT is: a chunk is bytes, a size,
// an alignment, and two liveness flags. Whether the bytes came from a section
// that could be elected is a linking question, so it lives here, keyed on the
// chunk rather than stored in it.
type chunkInfo struct {
	obj    *Object
	sec    *coff.Section
	comdat bool

	// addrTaken means some relocation referenced this chunk by address
	// rather than by a call. It is what /OPT:ICF:SAFE consults.
	addrTaken bool

	// follower means this chunk is live only because something else is:
	// the unwind records splitUnwind cut out of a whole-file .pdata are
	// these. Sweep treats a non-COMDAT chunk as a root, because nothing in
	// the format lets it prove a non-COMDAT section is unreferenced — but
	// a record this linker created itself is not a section, and the one
	// thing known about it is precisely which function it belongs to.
	follower bool
}

// split runs the split phase.
func (l *Linker) split() error {
	l.info = make(map[*image.Chunk]*chunkInfo, len(l.chunks))
	l.deps = make(map[*image.Chunk][]*image.Chunk)

	for _, o := range l.objects {
		for i, c := range o.chunks {
			if c == nil {
				continue
			}
			sec := o.File.Sections[i]
			l.info[c] = &chunkInfo{obj: o, sec: sec, comdat: sec.IsComdat()}
		}
	}

	if err := l.linkAssociative(); err != nil {
		return err
	}
	return l.splitUnwind()
}

// linkAssociative records the leader-to-follower edges of every associative
// COMDAT.
//
// comdat.go already propagated the *discard* direction: a follower whose
// leader lost the election is discarded. This is the other direction, and it
// only matters once sweeping starts. A follower is not referenced by anything
// — that is the entire reason associative COMDATs exist — so a mark-and-sweep
// pass that only walks relocations would collect every one of them, and the
// image would lose the unwind data for every function it kept.
func (l *Linker) linkAssociative() error {
	for _, o := range l.objects {
		for i, c := range o.chunks {
			if c == nil || c.Discarded {
				continue
			}
			sec := o.File.Sections[i]
			if !sec.IsComdat() {
				continue
			}
			cd, err := sec.Comdat()
			if err != nil {
				return l.fail(&InputError{Name: o.Name, Err: err})
			}
			if cd == nil || !cd.Selection.Associative() || cd.Associated == nil {
				continue
			}
			leader := o.chunks[cd.Associated.Index()]
			if leader == nil {
				continue
			}
			l.deps[leader] = append(l.deps[leader], c)
		}
	}
	return nil
}

// splitUnwind cuts each non-COMDAT .pdata chunk into one chunk per record.
//
// A COMDAT .pdata is left alone: it already describes exactly one function and
// its fate is that function's, recorded by linkAssociative. Splitting it again
// would produce a chunk whose leader edge points at its own parent.
//
// The record width comes from the backend because it is 12 bytes on x64 — a
// start RVA, an end RVA, and an RVA to the unwind information — and 8 on
// ARM64, whose second word packs the length and the unwind data together.
func (l *Linker) splitUnwind() error {
	width := uint32(l.be.UnwindEntrySize())
	if width == 0 {
		return nil
	}

	var added []*image.Chunk
	for _, c := range l.chunks {
		info := l.info[c]
		if info == nil || c.Discarded || info.comdat {
			continue
		}
		if c.GroupName() != ".pdata" || c.Size() == 0 {
			continue
		}
		if c.Size()%width != 0 {
			// A .pdata whose length is not a whole number of records
			// is not a .pdata. Splitting it would produce a trailing
			// fragment that relocates into nothing, so it is left
			// whole and stays live like any other unsplittable
			// section.
			continue
		}
		pieces, err := l.splitPdata(c, info, width)
		if err != nil {
			return err
		}
		added = append(added, pieces...)
	}
	l.chunks = append(l.chunks, added...)
	return nil
}

// splitPdata cuts one .pdata chunk into records and wires each to the function
// it describes.
//
// The first relocation inside a record names the function: every architecture
// puts the start RVA in the record's first word. Any further relocation in the
// record names something the record needs kept alive — on x64 that is the
// UNWIND_INFO in .xdata, reached by the third word.
//
// The .xdata side is not split. Its records are variable width, they chain
// through UNW_FLAG_CHAININFO, and there is an undocumented variant where the
// low bit of UnwindInfoAddress marks a pointer to another RUNTIME_FUNCTION
// rather than to an UNWIND_INFO. This tree treats .xdata as opaque bytes, so
// an .xdata chunk is kept whole if any live record points into it — which
// keeps more than it must and never keeps less.
func (l *Linker) splitPdata(c *image.Chunk, info *chunkInfo, width uint32) ([]*image.Chunk, error) {
	relocs := c.Relocs()
	n := c.Size() / width

	pieces := make([]*image.Chunk, 0, n)
	ri := 0
	for i := uint32(0); i < n; i++ {
		start, end := i*width, (i+1)*width

		piece := image.NewChunk(c.Name, c.Input, &subSource{
			sec:   info.sec,
			off:   start,
			size:  width,
			align: c.Align(),
		})

		// Relocations are in address order within a section, so the
		// records' shares are consecutive runs and one walk suffices.
		var own []image.Reloc
		for ri < len(relocs) && relocs[ri].Off < end {
			r := relocs[ri]
			ri++
			if r.Off < start {
				continue
			}
			r.Off -= start
			own = append(own, r)
		}
		piece.SetRelocs(own)
		l.info[piece] = &chunkInfo{obj: info.obj, sec: info.sec, follower: true}

		// A record whose function lost a COMDAT election describes code
		// that is not in the image. Discarding it here rather than
		// leaving it to sweep is what makes /OPT:REF:NO work: with
		// sweeping off every chunk is live, and a live record relocating
		// against a discarded function asks for the address of something
		// that was never placed.
		if fn := recordFunc(own); fn == nil || fn.Discarded {
			piece.Discarded = true
		}

		// The record lives if its function lives, so the edge runs from
		// the function to the record and not the other way round. A
		// record is never referenced by anything.
		for j, r := range own {
			if r.Sym == nil {
				continue
			}
			target := r.Sym.Chunk()
			if target == nil || piece.Discarded {
				continue
			}
			if j == 0 {
				l.deps[target] = append(l.deps[target], piece)
				continue
			}
			// Everything else the record points at — the unwind
			// information — has to outlive the record itself.
			l.deps[piece] = append(l.deps[piece], target)
		}
		pieces = append(pieces, piece)
	}

	// The parent is replaced by its pieces rather than kept alongside them.
	c.Discarded = true
	return pieces, nil
}

// subSource is a window onto part of an input section.
//
// It reads the whole section and returns a slice of it. That is deliberate:
// the alternative is one bounded read per record, and a .pdata with four
// thousand functions would make four thousand reads of twelve bytes each. The
// section is read once per record here, which is worse in principle and better
// in practice, since Bytes runs once and the operating system's cache has the
// page.
type subSource struct {
	sec   *coff.Section
	off   uint32
	size  uint32
	align int
}

func (s *subSource) Size() uint32 { return s.size }
func (s *subSource) Align() int   { return s.align }

func (s *subSource) Bytes() ([]byte, error) {
	b, err := s.sec.Data()
	if err != nil {
		return nil, err
	}
	if uint64(s.off)+uint64(s.size) > uint64(len(b)) {
		return nil, coff.ErrCorrupt
	}
	return b[s.off : s.off+s.size], nil
}

// markAddrTaken records which chunks are referenced by address rather than by
// a call. It is what makes /OPT:ICF:SAFE safe.
//
// The test is the relocation type, which is the same method gold uses: a call
// and an address reference use different relocations, so a chunk reached only
// by KindBranch or KindRelative is never named by a pointer and folding it
// cannot make two function pointers compare equal. A chunk reached by KindVA
// or KindRVA might be, and is conservatively excluded — not every address
// reference is a comparison, but nothing here can tell which are.
func (l *Linker) markAddrTaken() {
	for _, c := range l.chunks {
		if c.Discarded {
			continue
		}
		for _, r := range c.Relocs() {
			if r.Sym == nil {
				continue
			}
			target := r.Sym.Chunk()
			if target == nil {
				continue
			}
			switch l.be.Classify(r.Type) {
			case backend.KindVA, backend.KindRVA:
				if info := l.info[target]; info != nil {
					info.addrTaken = true
				}
			}
		}
	}
}
// recordFunc is the chunk an unwind record describes: the target of its first
// relocation, which every architecture puts in the record's first word.
//
// Nil when the record names no chunk — an unrelocated record, or one whose
// function resolved to something with no address of its own.
func recordFunc(own []image.Reloc) *image.Chunk {
	for _, r := range own {
		if r.Sym == nil {
			return nil
		}
		return r.Sym.Chunk()
	}
	return nil
}
