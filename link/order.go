package link

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
)

// Order closes the open phase.
//
// It does not order anything, and the name is kept because the pipeline step
// is where ordering *ends*: merge decided the sequence of input-derived
// sections and synth appended the tables it built, so by the time control
// reaches here the section table is final and what remains is to check it and
// seal it.
//
// The alternative — deferring section creation to this step so that the order
// could be recomputed once everything was known — is not available, because
// backend.Scan walks img.Sections() and scan runs before synth. Sections have
// to exist for the backend to have anything to look at.

// order validates the section set and seals the image.
func (l *Linker) order() error {
	if err := l.checkSectionNames(); err != nil {
		return err
	}
	if err := l.checkSectionCount(); err != nil {
		return err
	}
	if err := l.img.Seal(); err != nil {
		return l.fail(err)
	}
	return nil
}

// checkSectionNames rejects a duplicate output section name.
//
// Two sections with one name is not a format violation — the section table is
// an array and the loader indexes it — but it is always a linker bug, because
// the merge that should have combined them did not. Catching it here is the
// difference between a diagnostic and an image where half of .data is
// unreachable from the symbols that name it.
func (l *Linker) checkSectionNames() error {
	seen := make(map[string]bool, len(l.img.Sections()))
	for _, s := range l.img.Sections() {
		if seen[s.Name] {
			return l.fail(&image.LayoutError{
				Section: s.Name,
				Reason:  "two output sections share a name",
			})
		}
		seen[s.Name] = true
	}
	return nil
}

// checkSectionCount enforces the loader's limit, and says what to do about it.
//
// The Windows loader caps an image at 96 sections. That is low enough that
// /MERGE is a correctness feature rather than a size optimization: a build with
// many /SECTION-named regions can fail to link without one. So the error names
// the sections it would merge if asked, because a caller cannot suggest a
// /MERGE from a count.
//
// Seal would catch the same thing a moment later. It is checked here so the
// message carries the suggestion, which image cannot make: image knows the
// names, and link knows that combining them is a thing the caller can ask for.
func (l *Linker) checkSectionCount() error {
	secs := l.img.Sections()
	if len(secs) <= pe.MaxImageSections {
		return nil
	}
	names := make([]string, 0, len(secs))
	for _, s := range secs {
		names = append(names, s.Name)
	}
	return l.fail(&SectionCountError{
		Err: &image.SectionLimitError{Count: len(secs), Names: names},
	})
}

// SectionCountError is the loader's section limit, wrapped with the advice
// image cannot give.
type SectionCountError struct {
	Err *image.SectionLimitError
}

func (e *SectionCountError) Error() string {
	return e.Err.Error() + "; combine some with MergeSections"
}

func (e *SectionCountError) Unwrap() error { return ErrTooManyImageSections }