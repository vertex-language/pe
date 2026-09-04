package image

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/format"
)

type phase uint8

const (
	phaseOpen phase = iota
	phaseSealed
	phaseFrozen
)

func (p phase) String() string {
	switch p {
	case phaseOpen:
		return "open"
	case phaseSealed:
		return "sealed"
	case phaseFrozen:
		return "frozen"
	}
	return "phase(?)"
}

// Config is everything layout needs that is not a section.
//
// Width is absent, as everywhere in this tree: it is Target.Machine's, and a
// Config claiming otherwise cannot be built.
type Config struct {
	Target pe.Target

	// ImageBase is the preferred load address, which the specification
	// requires to be a multiple of 64K.
	ImageBase pe.VA

	// SectionAlignment is the alignment of sections in memory, and
	// FileAlignment their alignment on disk. The relationship between them
	// and the architecture's page size decides whether this is a flat
	// image; see Validate.
	SectionAlignment uint32
	FileAlignment    uint32

	// StubSize is the MS-DOS stub's length, from its first byte to the PE
	// signature. It feeds SizeOfHeaders, which feeds the first section's
	// RVA, which is why /STUB changes addresses.
	StubSize uint32

	// NumDataDirs is how many directories the optional header carries. A
	// conventional image writes pe.NumDataDirs; the count is a field
	// because it is variable and because the header's size depends on it.
	NumDataDirs int
}

// ImageBaseGranularity is the multiple the specification requires of
// ImageBase.
const ImageBaseGranularity = 0x10000

// pageSize returns the architecture's page size, which is what decides whether
// an image is flat.
//
// The specification names 4K for x86 and MIPS and 8K for Itanium. AArch64
// pages on Windows are 4K. None of the machines this tree seeds is the
// exception, so this is one value with a switch around it for the day that
// changes.
func pageSize(m pe.Machine) uint32 {
	switch m.Arch() {
	case pe.ArchX86, pe.ArchAMD64, pe.ArchARM64:
		return 0x1000
	}
	return 0x1000
}

// Flat reports whether this configuration is a flat image: one whose
// SectionAlignment is below the architecture's page size, and in which a
// section's file offset must equal its RVA.
//
// It is declared up front rather than discovered during layout. EFI images and
// some drivers are built this way, and the constraint it imposes is not a
// rounding tweak — it removes the freedom to pack the file more tightly than
// memory, which is the freedom the two alignments exist to provide.
func (c Config) Flat() bool { return c.SectionAlignment < pageSize(c.Target.Machine) }

// Validate checks the alignments against the format's constraints.
//
// The three rules are the specification's, and the third is the one that makes
// flat mode consistent: FileAlignment is a power of two between 512 and 64K;
// SectionAlignment is at least FileAlignment; and when SectionAlignment is
// below the page size the two must be equal. Enforcing the third here is what
// lets assign place a flat image by simply reusing the RVA as the offset —
// once the alignments agree, the equality it must produce is achievable.
func (c Config) Validate() error {
	if err := c.Target.Validate(); err != nil {
		return err
	}
	if !isPow2(c.FileAlignment) || !isPow2(c.SectionAlignment) {
		return ErrBadAlignment
	}
	if c.SectionAlignment < c.FileAlignment {
		return ErrBadAlignment
	}
	if c.Flat() {
		if c.FileAlignment != c.SectionAlignment {
			return ErrBadAlignment
		}
	} else if c.FileAlignment < 512 || c.FileAlignment > 0x10000 {
		// The bound applies to an ordinary image. A flat one has already
		// been forced to match SectionAlignment, which is below a page
		// and therefore below 512 in every case that matters.
		return ErrBadAlignment
	}
	if uint64(c.ImageBase)%ImageBaseGranularity != 0 {
		return ErrBadAlignment
	}
	return nil
}

func isPow2(v uint32) bool { return v != 0 && v&(v-1) == 0 }

// Image is the output model: views, sections, the data directories, and the
// output buffer.
type Image struct {
	Cfg Config

	// Dirs holds the sixteen data directories as they are written to disk,
	// which for a hybrid image is the native view's answer.
	//
	// The EC view's differences are not stored a second time. They are
	// emitted as dynamic value relocations over these very bytes, so the
	// file carries one directory array and two interpretations of it —
	// which is why View has its own Export, Exception, and LoadConfig
	// fields and this does not become an array of two.
	Dirs DataDir

	views      []*View
	synthetics []Synthetic
	finalizers []Finalizer

	sections []*Section
	phase    phase

	sizeOfHeaders uint32
	sizeOfImage   uint32
	out           []byte
}

// New returns an open Image.
func New(cfg Config) (*Image, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.NumDataDirs < 0 || cfg.NumDataDirs > pe.NumDataDirs {
		return nil, ErrOutOfBounds
	}
	return &Image{Cfg: cfg, views: initViews(cfg.Target)}, nil
}

// Phase returns the image's current phase, for diagnostics.
func (img *Image) Phase() string { return img.phase.String() }

// Sections returns the output sections in placement order.
func (img *Image) Sections() []*Section { return img.sections }

// AddSection creates an output section. It is valid only while the image is
// open.
//
// A name longer than eight bytes is refused here rather than truncated. An
// image has no string table — the specification says so outright — so the
// escape an object file would use does not exist, and a silently shortened
// name is a section nobody can find again.
//
// The index is assigned here and not at Seal. A SECTION relocation writes
// Number, which is this plus one, and a section whose index was never set
// reports 1 — so every SECTION relocation in the image would name the first
// section and nothing would say so.
func (img *Image) AddSection(name string, kind pe.SecKind, prot pe.SecProt) (*Section, error) {
	if img.phase != phaseOpen {
		return nil, ErrPhase
	}
	if len(name) > format.SectionNameSize {
		return nil, &LayoutError{Section: name, Reason: "name longer than eight bytes"}
	}
	s := &Section{Name: name, Kind: kind, Prot: prot, img: img, index: len(img.sections)}
	img.sections = append(img.sections, s)
	return s, nil
}

// Seal ends the open phase. No section, chunk, or synthetic may be added
// afterwards.
func (img *Image) Seal() error {
	if img.phase != phaseOpen {
		return ErrPhase
	}
	if len(img.sections) == 0 {
		return ErrNoSections
	}
	if n := len(img.sections); n > pe.MaxImageSections {
		names := make([]string, 0, n)
		for _, s := range img.sections {
			names = append(names, s.Name)
		}
		return &SectionLimitError{Count: n, Names: names}
	}
	img.phase = phaseSealed
	return nil
}

// HeaderSize returns the bytes the headers occupy before rounding: the stub,
// the PE signature, the COFF header, the optional header, and the section
// table.
//
// It is an *input* to address assignment rather than an output of it, because
// the first section's RVA is this rounded up. The section count it depends on
// is what merge produced, so header size has to be settled before layout and
// re-settled if the count ever changes — which is why Assign recomputes it
// rather than caching it across calls.
func (img *Image) HeaderSize() uint32 {
	opt := format.OptionalHeaderSize(img.Cfg.Target.Width(), img.Cfg.NumDataDirs)
	n := img.Cfg.StubSize +
		format.PESignatureSize +
		format.FileHeaderSize +
		uint32(opt) +
		uint32(format.SectionHeaderSize*len(img.sections))
	return n
}

// Assign computes every RVA and file offset.
//
// It is idempotent and may be called repeatedly, which is what makes it usable
// inside the thunk-growth fixpoint: a backend grows a thunk, the sizes change,
// and this runs again over the same sections.
//
// The two assignments are independent and are computed as such. Section RVAs
// ascend, are adjacent, and are multiples of SectionAlignment; raw data is a
// multiple of FileAlignment; SizeOfRawData is rounded and VirtualSize is not.
// Deriving either from the other is the mistake this function is arranged to
// make impossible — except in flat mode, where the format requires them to be
// equal and the equality is applied explicitly rather than arrived at.
func (img *Image) Assign() error {
	if img.phase != phaseSealed {
		return ErrPhase
	}

	hdr := img.HeaderSize()
	img.sizeOfHeaders = alignUp32(hdr, img.Cfg.FileAlignment)

	rva := pe.RVA(img.sizeOfHeaders).AlignUp(img.Cfg.SectionAlignment)
	off := pe.Off(img.sizeOfHeaders)

	for _, s := range img.sections {
		if err := img.assignSection(s, rva, off); err != nil {
			return err
		}
		rva = pe.RVA(alignUp32(uint32(s.rva)+s.vsize, img.Cfg.SectionAlignment))
		if s.rawSize > 0 {
			off = pe.Off(uint32(s.off) + s.rawSize)
		}
	}

	last := img.sections[len(img.sections)-1]
	img.sizeOfImage = alignUp32(uint32(last.rva)+last.vsize, img.Cfg.SectionAlignment)
	return nil
}

// assignSection places one section and the chunks inside it.
func (img *Image) assignSection(s *Section, rva pe.RVA, off pe.Off) error {
	if img.Cfg.Flat() {
		// The specification requires the physical offset of section data
		// to equal its RVA. The alignments were forced equal by
		// Validate, so taking the offset from the address satisfies both
		// constraints at once rather than solving them separately and
		// hoping they agree.
		off = pe.Off(rva)
	}

	s.rva, s.off = rva, off
	cur := rva
	rawEnd := rva
	sawZeroFill := false

	for _, c := range s.chunks {
		if !c.Live() {
			continue
		}
		cur = cur.AlignUp(uint32(c.Align()))
		c.rva, c.assigned = cur, true
		cur = cur.Add(c.Size())

		if c.HasContent() {
			if sawZeroFill {
				// SizeOfRawData describes a prefix of the section,
				// not a subset of it, so file content after a
				// zero-filled chunk cannot be expressed: the
				// loader would either not read it or would read
				// the zeroes as content. Ordering is merge's job;
				// noticing is this one's.
				return &LayoutError{
					Section: s.Name,
					Reason:  "chunk with file content follows a zero-filled chunk",
					RVA:     c.rva,
					Off:     s.off,
				}
			}
			rawEnd = cur
		} else {
			sawZeroFill = true
		}
	}

	s.vsize = uint32(cur - rva)
	s.rawSize = alignUp32(uint32(rawEnd-rva), img.Cfg.FileAlignment)
	if s.rawSize == 0 {
		// A section with no file content has no file offset either. The
		// specification asks for zero in PointerToRawData, and a
		// plausible-looking offset there is how a reader ends up
		// reading another section's bytes as this one's.
		s.off = 0
	}
	s.assigned = true

	if !s.rva.Aligned(img.Cfg.SectionAlignment) {
		return &LayoutError{Section: s.Name, Reason: "RVA is not a multiple of SectionAlignment",
			RVA: s.rva, Off: s.off}
	}
	if s.rawSize > 0 && !s.off.Aligned(img.Cfg.FileAlignment) {
		return &LayoutError{Section: s.Name, Reason: "file offset is not a multiple of FileAlignment",
			RVA: s.rva, Off: s.off}
	}
	if img.Cfg.Flat() && s.rawSize > 0 && uint32(s.off) != uint32(s.rva) {
		return &LayoutError{Section: s.Name, Reason: "flat image requires the file offset to equal the RVA",
			RVA: s.rva, Off: s.off}
	}
	return nil
}

// Freeze ends layout. Every address is final afterwards, and the output buffer
// exists.
//
// It re-checks the whole placement rather than trusting the assignment that
// produced it: sections must ascend, be adjacent, and not overlap. Assign
// produces that by construction today, and the fixpoint that calls Assign is
// exactly the kind of loop that will one day produce something else.
func (img *Image) Freeze() error {
	if img.phase != phaseSealed {
		return ErrPhase
	}
	var prevEnd pe.RVA
	for i, s := range img.sections {
		if !s.assigned {
			return ErrNoRVA
		}
		if i > 0 {
			want := prevEnd.AlignUp(img.Cfg.SectionAlignment)
			if s.rva < want {
				return &LayoutError{Section: s.Name, Reason: "overlaps the previous section",
					RVA: s.rva, Off: s.off}
			}
			if s.rva != want {
				return &LayoutError{Section: s.Name, Reason: "is not adjacent to the previous section",
					RVA: s.rva, Off: s.off}
			}
		}
		prevEnd = s.rva.Add(s.vsize)
	}

	size := uint64(img.sizeOfHeaders)
	for _, s := range img.sections {
		if s.rawSize == 0 {
			continue
		}
		if end := uint64(s.off) + uint64(s.rawSize); end > size {
			size = end
		}
	}
	if size > uint64(^uint32(0)) {
		return &LayoutError{Reason: "file larger than a 32-bit file pointer can address"}
	}

	img.out = make([]byte, size)
	img.phase = phaseFrozen
	return nil
}

// SizeOfImage returns the memory size of the loaded image, a multiple of
// SectionAlignment and including the headers.
func (img *Image) SizeOfImage() (uint32, error) {
	if img.phase == phaseOpen {
		return 0, ErrNoRVA
	}
	return img.sizeOfImage, nil
}

// SizeOfHeaders returns the header size rounded up to FileAlignment.
func (img *Image) SizeOfHeaders() (uint32, error) {
	if img.phase == phaseOpen {
		return 0, ErrNoRVA
	}
	return img.sizeOfHeaders, nil
}

// Off converts an RVA to a file offset.
//
// This is one of the two bridges between address kinds in the module, and the
// one that cannot live in pe: answering needs the section table, since the
// mapping is per-section and is not a constant shift. The other is RVA.VA.
//
// An RVA inside the headers maps to the same offset, because the headers are
// at RVA 0 and are copied verbatim. An RVA inside a section's zero-filled tail
// has no file offset at all and reports ErrNoRVA — there are no bytes there to
// name.
func (img *Image) Off(rva pe.RVA) (pe.Off, error) {
	if img.phase == phaseOpen {
		return 0, ErrNoRVA
	}
	if uint32(rva) < img.sizeOfHeaders {
		return pe.Off(rva), nil
	}
	for _, s := range img.sections {
		if !s.Contains(rva) {
			continue
		}
		delta := uint32(rva - s.rva)
		if delta >= s.rawSize {
			return 0, ErrNoRVA
		}
		return s.off.Add(delta), nil
	}
	return 0, ErrNoRVA
}

// SectionAt returns the section containing rva, or nil.
func (img *Image) SectionAt(rva pe.RVA) *Section {
	for _, s := range img.sections {
		if s.Contains(rva) {
			return s
		}
	}
	return nil
}

// At returns a writable window on the output buffer at a file offset.
//
// Every write into the image goes through a bounds check, so a relocation that
// runs past the end of its own chunk fails naming that chunk rather than
// quietly corrupting its neighbour. backend.Site is the same idea one level
// up, bounded to a chunk rather than to the file.
func (img *Image) At(off pe.Off, n int) ([]byte, error) {
	if img.phase != phaseFrozen {
		return nil, ErrNotFrozen
	}
	if n < 0 || uint64(off)+uint64(n) > uint64(len(img.out)) {
		return nil, ErrOutOfBounds
	}
	return img.out[off : uint64(off)+uint64(n)], nil
}

// AtRVA returns a writable window on the bytes an RVA names.
//
// It is At composed with Off, and it exists because almost every caller has an
// address rather than an offset — a synthetic filling a table, a backend
// applying a relocation. An RVA in a zero-filled tail fails here for the
// reason Off gives: the bytes are not in the file, so there is nothing to
// hand back.
func (img *Image) AtRVA(rva pe.RVA, n int) ([]byte, error) {
	off, err := img.Off(rva)
	if err != nil {
		return nil, err
	}
	return img.At(off, n)
}

// Bytes returns the finished image.
func (img *Image) Bytes() ([]byte, error) {
	if img.phase != phaseFrozen {
		return nil, ErrNotFrozen
	}
	return img.out, nil
}

func alignUp32(v, align uint32) uint32 {
	if align <= 1 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}