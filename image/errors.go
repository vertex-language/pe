// Package image is the linked side of the tree: the output model a link
// builds and emits.
//
// An Image owns output sections, the chunks placed in them, one or two views,
// the sixteen data directories, and the output buffer. It moves through three
// phases and never goes backwards.
//
//	open    sections, chunks, and synthetics are added
//	sealed  the section set is fixed; addresses are being assigned
//	frozen  every address is final and the output buffer exists
//
// The phases exist because the two mistakes they prevent are both silent.
// Reading an RVA before it is assigned yields zero, and zero is a legal RVA —
// the image headers live there — so a caller that reads early gets an answer
// rather than a failure. Growing a section after layout overlaps the section
// that was placed after it, and nothing about the resulting file says so. Each
// is caught where the mistake is made rather than in the loader.
package image

import (
	"errors"
	"strconv"
	"strings"

	"github.com/vertex-language/pe"
)

// Sentinel errors returned, or wrapped, by this package. Callers match with
// errors.Is; the structured forms below carry the position and the names.
var (
	// ErrPhase means an operation was attempted in the wrong phase: adding
	// a section after Seal, or laying out before it.
	ErrPhase = errors.New("image: operation attempted in the wrong phase")

	// ErrNoRVA means an address or size was read before assignment. It is
	// an error rather than a zero because zero is a legal RVA — the headers
	// occupy it — so a zero return would be indistinguishable from a real
	// answer.
	//
	// Off also returns this for an RVA inside a section's zero-filled tail.
	// That address exists in memory and corresponds to no byte in the file,
	// which is a different fact with the same shape: there is no answer,
	// and the plausible one is wrong.
	ErrNoRVA = errors.New("image: address read before layout assigned one")

	// ErrNotFrozen means the output buffer was touched before Freeze.
	ErrNotFrozen = errors.New("image: output buffer touched before Freeze")

	// ErrOutOfBounds means a write fell outside the output buffer, or an
	// index outside the data directory array.
	ErrOutOfBounds = errors.New("image: write outside the buffer")

	// ErrLayout is what every *LayoutError unwraps to.
	ErrLayout = errors.New("image: layout violates a format constraint")

	// ErrTooManySections is what a *SectionLimitError unwraps to. The
	// Windows loader limits an image to 96 sections, which is low enough
	// that /MERGE is a correctness feature and not only a size
	// optimization.
	ErrTooManySections = errors.New("image: more sections than the loader accepts")

	// ErrBadAlignment means SectionAlignment, FileAlignment, or ImageBase
	// does not satisfy the format's constraints. See Config.Validate.
	ErrBadAlignment = errors.New("image: invalid section or file alignment")

	// ErrNoSections means Seal was called with nothing to place.
	ErrNoSections = errors.New("image: no sections to lay out")

	// ErrCertDirIsFileOffset means the Certificate Table was reached
	// through the RVA-typed accessors on DataDir.
	//
	// Its first field is a file pointer rather than an RVA, because the
	// attribute certificates are not mapped into memory. It therefore lives
	// in DataDir.CertDir, which is Off-typed, and having to reach for a
	// differently typed field is the point of the separation rather than an
	// inconvenience it causes.
	ErrCertDirIsFileOffset = errors.New("image: the certificate directory holds a file offset, not an RVA")

	// ErrReservedDir means a write to the Architecture or Reserved
	// directory. The specification requires both to be zero; a non-zero
	// value in one is not an error to read, but this tree never writes one.
	ErrReservedDir = errors.New("image: directory is reserved and must be zero")

	// ErrAbsoluteSymbol means an RVA was asked of a symbol whose value is a
	// constant. It is separate from ErrNoRVA because the answer is not
	// "not yet" but "never".
	ErrAbsoluteSymbol = errors.New("image: absolute symbol has no address")

	// ErrUndefinedSymbol means an address was asked of a name with no
	// definition. Reaching this during emit means check let one through,
	// and the useful diagnostic is *link.UndefinedError rather than this.
	ErrUndefinedSymbol = errors.New("image: symbol has no definition")

	// ErrNoView means an input's machine fits neither of the image's views.
	// link wraps it in a *ViewError naming the input, since the machine
	// alone does not say which file carried it.
	ErrNoView = errors.New("image: no view accepts this machine")
)

// LayoutError is a placement that violates one of the format's rules: an
// overlap, a gap where sections must be adjacent, a misalignment, a section
// whose file content follows its zero-filled tail, or a file offset that
// disagrees with its RVA in a flat image.
//
// Every rule it enforces is one the specification states as a requirement on
// the linker rather than on the loader. The loader does not check them, so
// breaking one produces a file that loads and then behaves as though the bytes
// were somewhere else — which is why these are errors at the point of
// assignment rather than warnings about the finished file.
//
// Section is empty for a failure that belongs to the image as a whole rather
// than to one section.
type LayoutError struct {
	Section string
	Reason  string
	RVA     pe.RVA
	Off     pe.Off
}

func (e *LayoutError) Error() string {
	s := "image: "
	if e.Section != "" {
		s += "section " + strconv.Quote(e.Section) + ": "
	}
	return s + e.Reason + " (rva " + e.RVA.String() + ", off " + e.Off.String() + ")"
}

func (e *LayoutError) Unwrap() error { return ErrLayout }

// SectionLimitError names the sections that pushed the count past the loader's
// limit.
//
// The names are carried because the actionable answer is a /MERGE, and a
// caller cannot suggest one from a count. link.ErrTooManyImageSections wraps
// this and is where the suggestion is made.
type SectionLimitError struct {
	Count int
	Names []string
}

func (e *SectionLimitError) Error() string {
	s := "image: " + strconv.Itoa(e.Count) + " sections exceeds the loader's limit of " +
		strconv.Itoa(pe.MaxImageSections)
	if len(e.Names) == 0 {
		return s
	}
	names := e.Names
	const show = 8
	if len(names) > show {
		return s + ": " + strings.Join(names[:show], ", ") + ", and " +
			strconv.Itoa(len(names)-show) + " more"
	}
	return s + ": " + strings.Join(names, ", ")
}

func (e *SectionLimitError) Unwrap() error { return ErrTooManySections }