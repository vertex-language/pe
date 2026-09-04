package coff

import (
	"errors"
	"strconv"
)

var (
	// ErrCorrupt is a structural failure in a COFF decode that no more
	// specific error covers.
	ErrCorrupt = errors.New("coff: corrupt object")

	// ErrShortImport means a short-import pseudo-object reached the COFF
	// reader. These live in import libraries and are implib's business.
	ErrShortImport = errors.New("coff: short-import member is not a COFF object")

	// ErrLTCGObject means an MSVC /GL object. Its contents are the
	// compiler's intermediate representation, not sections, so it is
	// rejected by name rather than misparsed into nonsense.
	ErrLTCGObject = errors.New("coff: /GL (LTCG) object is not a COFF object")

	// ErrBadAuxRecord means an auxiliary record was inconsistent with the
	// symbol it follows.
	ErrBadAuxRecord = errors.New("coff: auxiliary record inconsistent with its parent symbol")

	// ErrComdatCycle means an associative COMDAT chain did not terminate.
	// It is raised at parse time because a chain that loops is an infinite
	// loop in every consumer downstream.
	ErrComdatCycle = errors.New("coff: associative COMDAT chain does not terminate")

	// ErrNoComdatLeader means a section flagged LNK_COMDAT had no key
	// symbol. Without one there is nothing to elect on.
	ErrNoComdatLeader = errors.New("coff: COMDAT section has no key symbol")

	// ErrDirectiveRelocs means a .drectve section carried relocations or
	// line numbers, which the specification forbids.
	ErrDirectiveRelocs = errors.New("coff: .drectve section has relocations or line numbers")

	// ErrBadDirective means a directive string could not be tokenized:
	// an unterminated quote, or an option with no name.
	ErrBadDirective = errors.New("coff: malformed .drectve directive")

	// ErrClosed means a Writer was used after Close.
	ErrClosed = errors.New("coff: writer is closed")

	// ErrBigObjRequired means the section count passed the standard
	// ceiling with BigObjNever set.
	ErrBigObjRequired = errors.New("coff: too many sections for a standard object")

	// ErrBigObjDropsCharacteristics means an object with a non-zero
	// Characteristics field was promoted to bigobj, whose header has no
	// such field. Silently dropping it would produce an object that
	// differs from the one requested in a way nothing reports.
	ErrBigObjDropsCharacteristics = errors.New("coff: bigobj header cannot carry Characteristics")

	// ErrUnpairedReloc means a relocation that requires a PAIR was
	// submitted without one, or a PAIR was submitted without its partner.
	ErrUnpairedReloc = errors.New("coff: span-dependent relocation without its PAIR")

	// ErrBadRelocation means a relocation could not be encoded: no symbol
	// where one is required, or a symbol belonging to another Writer.
	ErrBadRelocation = errors.New("coff: unencodable relocation")

	// ErrBadSymbol means a symbol definition is internally inconsistent.
	ErrBadSymbol = errors.New("coff: inconsistent symbol definition")

	// ErrNoSections means Close was called with nothing to write.
	ErrNoSections = errors.New("coff: object has no sections")
)

// SectionError names a section that failed to decode. A structural error in a
// forty-megabyte object is unactionable without knowing which of six hundred
// sections it came from.
type SectionError struct {
	Index int    // zero-based index into File.Sections
	Name  string // resolved name, or the raw field if resolution failed
	Err   error
}

func (e *SectionError) Error() string {
	return "coff: section " + strconv.Itoa(e.Index) + " (" + e.Name + "): " + e.Err.Error()
}

func (e *SectionError) Unwrap() error { return e.Err }

// SymbolError names a symbol slot that failed to decode.
type SymbolError struct {
	Slot int // physical slot, not an ordinal into the symbols
	Name string
	Err  error
}

func (e *SymbolError) Error() string {
	s := "coff: symbol slot " + strconv.Itoa(e.Slot)
	if e.Name != "" {
		s += " (" + e.Name + ")"
	}
	return s + ": " + e.Err.Error()
}

func (e *SymbolError) Unwrap() error { return e.Err }