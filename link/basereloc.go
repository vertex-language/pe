package link

import (
	"sort"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// .reloc is the table that lets an image move.
//
// Every absolute pointer written into the image is correct only at the
// preferred base. The loader adds the delta between where the image wanted to
// be and where it went, at each address this table names. Under /DYNAMICBASE
// that always happens; without it the table may as well not exist.
//
// This synthetic has a wrinkle the others do not. Its size depends on how the
// sites distribute across 4K pages, and that depends on addresses layout has
// not assigned when Prepare runs. Rather than iterate — which would mean
// growing a section after layout, the mistake the phases exist to prevent —
// Prepare reserves an upper bound and Generate emits the real blocks into the
// front of it. The slack is left as zeroes and the data directory's size
// covers only what was written, which is what the loader walks by. The section
// is a little larger than it needs to be; nothing reads the difference.

// baseRelocs is the .reloc synthetic.
type baseRelocs struct {
	l     *Linker
	sites []backend.BaseRelocSite

	reserved uint32
	written  uint32
	chunk    *image.Chunk
}

// Size is the reserved upper bound, fixed by Prepare and unchanged afterwards.
func (b *baseRelocs) Size() uint32 { return b.reserved }

// Align is four, which is what a block start must meet.
func (b *baseRelocs) Align() int { return pe.BaseRelocBlockAlign }

// Bytes returns the reserved run as zeroes. Generate patches the real content
// in afterwards, once addresses exist — the contents pass writes chunks before
// synthetics generate, so returning anything meaningful here would be
// returning it too early.
func (b *baseRelocs) Bytes() ([]byte, error) { return make([]byte, b.reserved), nil }

// Emitted returns the bytes actually written, which is what the data directory
// must report. It is valid only after Generate.
func (b *baseRelocs) Emitted() uint32 { return b.written }

// Prepare collects the sites, checks that none is missing, and reserves space.
func (b *baseRelocs) Prepare(img *image.Image) error {
	l := b.l
	if !l.opt.DllChar.Has(pe.DynamicBase) {
		// No ASLR, no table. The image must then load at its preferred
		// base, which is what FileRelocsStripped tells the loader — set
		// during emit from this same condition.
		return nil
	}

	b.sites = l.reqs.BaseRelocs()
	if err := b.checkComplete(); err != nil {
		return err
	}
	if len(b.sites) == 0 {
		return nil
	}

	// The bound is one block per site: eight bytes of header, one entry,
	// and one ABSOLUTE entry to reach alignment. Real images are nowhere
	// near it — code and data cluster, so a page holds hundreds of sites —
	// but the bound has to hold for the input that does not cluster.
	b.reserved = uint32(len(b.sites)) * uint32(format.BaseRelocBlockSize(1))

	sec, err := l.section(".reloc", pe.SecInitData, pe.SecRead|pe.SecDiscardable)
	if err != nil {
		return err
	}
	b.chunk = image.NewChunk(".reloc", "<link>", b)
	b.chunk.Reachable = true
	if err := sec.Add(b.chunk); err != nil {
		return err
	}
	l.chunks = append(l.chunks, b.chunk)
	return nil
}

// checkComplete verifies that every absolute pointer produced a site.
//
// This is the check ErrUnrelocatable exists for, and it can only fire here:
// the backend records sites during Scan, and by apply the table has already
// been sized. A relocation the backend classified as an absolute address but
// reported no base relocation kind for is a fixup nobody will apply — an image
// that runs correctly at its preferred base and faults the first time ASLR
// moves it, which is a failure that appears in production and not in testing.
func (b *baseRelocs) checkComplete() error {
	have := make(map[relocSite]bool, len(b.sites))
	for _, s := range b.sites {
		have[relocSite{s.Chunk, s.Off}] = true
	}

	for _, c := range b.l.chunks {
		if !c.Live() {
			continue
		}
		for _, r := range c.Relocs() {
			if b.l.be.Classify(r.Type) != backend.KindVA {
				continue
			}
			if have[relocSite{c, r.Off}] {
				continue
			}
			return &UnrelocatableError{
				Chunk: c.Name,
				Input: c.Input,
				Off:   r.Off,
			}
		}
	}
	return nil
}

type relocSite struct {
	chunk *image.Chunk
	off   uint32
}

// Generate emits the blocks. It runs frozen, so every site has an address.
func (b *baseRelocs) Generate(img *image.Image) error {
	if b.chunk == nil {
		return nil
	}

	type entry struct {
		rva  pe.RVA
		kind pe.BaseRelocKind
	}
	entries := make([]entry, 0, len(b.sites))
	for _, s := range b.sites {
		rva, err := s.RVA()
		if err != nil {
			return err
		}
		entries = append(entries, entry{rva: rva, kind: s.Kind})
	}

	// Sorting is required, not merely tidy: the loader walks the blocks in
	// order and each covers a distinct page, so unsorted sites would
	// produce several blocks for one page and a walk that revisits it.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].rva != entries[j].rva {
			return entries[i].rva < entries[j].rva
		}
		return entries[i].kind < entries[j].kind
	})

	buf := binio.NewBufSize(int(b.reserved))
	for i := 0; i < len(entries); {
		page := entries[i].rva &^ pe.RVA(pe.BaseRelocPageSize-1)
		j := i
		for j < len(entries) && entries[j].rva&^pe.RVA(pe.BaseRelocPageSize-1) == page {
			j++
		}

		n := j - i
		hdr := format.BaseRelocBlock{
			PageRVA:   uint32(page),
			BlockSize: uint32(format.BaseRelocBlockSize(n)),
		}
		hdr.Encode(buf)

		for _, e := range entries[i:j] {
			off := uint16(uint32(e.rva) - uint32(page))
			v, err := pe.EncodeBaseRelocEntry(e.kind, off)
			if err != nil {
				return err
			}
			buf.U16(v)
		}
		// The padding is ABSOLUTE entries, which the loader skips. It is
		// the reason type zero exists.
		for k := 0; k < format.BaseRelocPadEntries(n); k++ {
			v, err := pe.EncodeBaseRelocEntry(pe.BaseRelocAbsolute, 0)
			if err != nil {
				return err
			}
			buf.U16(v)
		}
		i = j
	}

	data, err := buf.Data()
	if err != nil {
		return err
	}
	if uint32(len(data)) > b.reserved {
		// The bound was computed from the same site list this walked, so
		// this cannot happen from an input. It can happen from an
		// arithmetic mistake in BaseRelocBlockSize, which is worth
		// catching here rather than as an overlapping section.
		return &image.LayoutError{
			Section: ".reloc",
			Reason:  "base relocation table exceeded its reserved size",
		}
	}

	rva, err := b.chunk.RVA()
	if err != nil {
		return err
	}
	out, err := img.AtRVA(rva, int(b.reserved))
	if err != nil {
		return err
	}
	copy(out, data)
	b.written = uint32(len(data))
	return nil
}

// UnrelocatableError is an absolute pointer with no base relocation under
// /DYNAMICBASE.
//
// It names the chunk and the input because the fix is never in the linker: it
// is either a backend that does not map the relocation type, or an object
// carrying an absolute pointer in a section that was never meant to hold one.
type UnrelocatableError struct {
	Chunk string
	Input string
	Off   uint32
}

func (e *UnrelocatableError) Error() string {
	s := "link: " + e.Chunk
	if e.Input != "" {
		s += " (" + e.Input + ")"
	}
	return s + ": absolute pointer with no base relocation under /DYNAMICBASE"
}

func (e *UnrelocatableError) Unwrap() error { return ErrUnrelocatable }

// section returns the named output section, creating it if synth is the first
// thing to need it.
//
// The synthesized tables land in sections of their own rather than being
// merged into .rdata, which is what link.exe does and what makes .reloc
// discardable on its own — the loader drops it after applying it, and a page
// it shares with anything live is a page that stays resident.
func (l *Linker) section(name string, kind pe.SecKind, prot pe.SecProt) (*image.Section, error) {
	for _, s := range l.img.Sections() {
		if s.Name == name {
			return s, nil
		}
	}
	s, err := l.img.AddSection(name, kind, prot)
	if err != nil {
		return nil, l.fail(err)
	}
	return s, nil
}