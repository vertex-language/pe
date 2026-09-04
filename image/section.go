package image

import "github.com/vertex-language/pe"

// A Section is one row of the output section table and the chunks placed in
// it.
//
// Its name has no '$': the suffix decided which chunks land here and in what
// order, and then it is gone. There is no lookup by name here for the same
// reason there is none in coff — /MERGE and /SECTION mean the mapping from
// input name to output section is a decision link makes, not a fact to be
// queried.
type Section struct {
	// Name is the image section name, at most eight bytes. A longer name
	// has no representation in an image: the string-table escape is an
	// object-file feature, which is why link.exe truncates and this tree
	// errors.
	Name string

	// Kind and Prot are the two halves of the Characteristics field that
	// survive to an image. The alignment nibble does not — it is an
	// object-file property with no meaning here, since every image section
	// is aligned to SectionAlignment.
	Kind pe.SecKind
	Prot pe.SecProt

	img    *Image
	index  int
	chunks []*Chunk

	rva      pe.RVA
	off      pe.Off
	vsize    uint32 // unrounded: every byte the section occupies in memory
	rawSize  uint32 // rounded to FileAlignment: the bytes it occupies on disk
	assigned bool
}

// Index returns the section's zero-based position in the section table.
func (s *Section) Index() int { return s.index }

// Number returns the one-based section number.
//
// A SECTION relocation writes this, not Index. It is the same off-by-one
// coff.Section carries and for the same reason: the format numbers sections
// from one so that zero and the negative values are free to be the UNDEF,
// ABSOLUTE, and DEBUG sentinels.
func (s *Section) Number() int { return s.index + 1 }

// Add appends a chunk to this section. Chunks are placed in the order they are
// added, which is the order merge decided.
func (s *Section) Add(c *Chunk) error {
	if s.img.phase != phaseOpen {
		return ErrPhase
	}
	c.sec = s
	s.chunks = append(s.chunks, c)
	return nil
}

// Chunks returns the section's chunks in placement order.
func (s *Section) Chunks() []*Chunk { return s.chunks }

// Image returns the image this section belongs to.
func (s *Section) Image() *Image { return s.img }

// RVA returns the section's address, or ErrNoRVA before layout.
func (s *Section) RVA() (pe.RVA, error) {
	if !s.assigned {
		return 0, ErrNoRVA
	}
	return s.rva, nil
}

// Off returns the section's file offset, or ErrNoRVA before layout. A section
// with no file content has no offset and reports zero, which for
// PointerToRawData is the value the specification asks for.
func (s *Section) Off() (pe.Off, error) {
	if !s.assigned {
		return 0, ErrNoRVA
	}
	return s.off, nil
}

// VirtualSize returns the bytes the section occupies in memory, unrounded.
func (s *Section) VirtualSize() (uint32, error) {
	if !s.assigned {
		return 0, ErrNoRVA
	}
	return s.vsize, nil
}

// SizeOfRawData returns the bytes the section occupies on disk, rounded up to
// FileAlignment.
//
// Either this or VirtualSize may be the larger. This one is rounded and that
// one is not, so a small section is bigger on disk; a section with a
// zero-filled tail is bigger in memory. Code that assumes an order between
// them is wrong in one of the two directions.
func (s *Section) SizeOfRawData() (uint32, error) {
	if !s.assigned {
		return 0, ErrNoRVA
	}
	return s.rawSize, nil
}

// Contains reports whether rva falls within this section's memory extent.
//
// The extent is VirtualSize, not SizeOfRawData, so an address in the
// zero-filled tail is inside the section. That is the right answer for
// SectionAt — the address does belong here — and the wrong one for Off, which
// is why Off checks the raw size separately rather than relying on this.
func (s *Section) Contains(rva pe.RVA) bool {
	return s.assigned && rva >= s.rva && uint64(rva) < uint64(s.rva)+uint64(s.vsize)
}

// BSS reports whether the section has no file content at all.
func (s *Section) BSS() bool { return s.assigned && s.rawSize == 0 }

// Code reports whether the section holds executable code, which is what
// SizeOfCode in the optional header sums.
func (s *Section) Code() bool { return s.Kind.Has(pe.SecCode) }