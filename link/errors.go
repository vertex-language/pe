// Package link is the linker: it takes objects, archives, import libraries,
// and resources, and produces a finished PE image.
//
// It is one flat package on purpose. .edata's contents depend on the symbol
// table, which depends on /OPT:REF, which depends on relocations, which depend
// on RVAs, which depend on SizeOfHeaders, which depends on how many sections
// merge produced. Splitting that into idata/, edata/, and basereloc/
// subpackages would mean exporting most of it or threading it through
// parameters.
//
// PE differs from ELF and Mach-O in three ways that shape everything here.
// Pointers in the image are 32-bit RVAs, so the whole image is capped at 4 GB
// even on x64 and the base relocation table exists to fix absolute pointers
// rather than to support PIC. There is no dynamic symbol table — .idata and
// .edata are fixed tables, so imports and exports are decided at link time and
// never interposed. And inputs beget inputs: .drectve sections replay linker
// options during ingest, so the input set grows to a fixpoint before
// resolution can start.
package link

import (
	"errors"
	"strconv"
	"strings"
)

// Sentinel errors returned, or wrapped, by this package. Callers match with
// errors.Is; the structured forms below carry the names and positions.
var (
	// ErrNoInputs means Link was called with nothing added.
	ErrNoInputs = errors.New("link: no input files")

	// ErrNoEntry means an image was requested with no resolvable entry
	// point and no default for the ABI and output kind.
	ErrNoEntry = errors.New("link: no entry point")

	// ErrLayoutDivergence means the thunk-growth loop did not converge: a
	// veneer grew a section, which moved a branch out of range, which
	// required another veneer, without end. It is a bound rather than a
	// proof — layout is monotonic in practice — so hitting it means either
	// a pathological input or a backend whose InRange disagrees with its
	// WriteThunk.
	ErrLayoutDivergence = errors.New("link: layout did not converge")

	// ErrMachineMismatch means an input's machine cannot be linked into
	// this target. The concrete error is a *ViewError, which names the
	// input; the machine alone does not say which file carried it.
	ErrMachineMismatch = errors.New("link: input machine disagrees with the target")

	// ErrUnrelocatable means an absolute pointer produced no base
	// relocation site under /DYNAMICBASE. It is an error rather than a
	// warning because the alternative is an image that runs correctly at
	// its preferred base and faults the first time ASLR moves it.
	ErrUnrelocatable = errors.New("link: absolute pointer with no base relocation")

	// ErrDirectiveNotAllowed means a .drectve carried an option this
	// linker will not honour from inside an object file. The concrete
	// error is a *DirectiveError naming the input and the option.
	ErrDirectiveNotAllowed = errors.New("link: option is not allowed in .drectve")

	// ErrGuardWithoutDynamicBase means /GUARD:CF with ASLR disabled. CFG
	// depends on the loader relocating the image, so this is an error
	// rather than a silently inert flag.
	ErrGuardWithoutDynamicBase = errors.New("link: /GUARD:CF requires /DYNAMICBASE")

	// ErrTooManyImageSections means the section count passed the loader's
	// limit of 96. The concrete error names the sections, because the
	// actionable answer is a /MERGE and a caller cannot suggest one from a
	// count.
	ErrTooManyImageSections = errors.New("link: more sections than the loader accepts")

	// ErrLibNotFound means a library named on the command line or by a
	// /DEFAULTLIB directive was not found on any search path. There is no
	// implicit path in this tree — see Linker.SetLibPath — so a bare name
	// with no path configured always lands here.
	ErrLibNotFound = errors.New("link: library not found on any search path")

	// ErrLinked means a Linker was used after Link.
	ErrLinked = errors.New("link: linker has already run")

	// ErrUnimplemented means a path this tree does not have yet. It is a
	// sentinel rather than a panic because the unimplemented parts are
	// named in the README and a caller may reasonably want to detect one.
	ErrUnimplemented = errors.New("link: not implemented")

	// ErrBadSubsystem means a /SUBSYSTEM directive named something that is
	// not one of the values the specification defines — a typo or a
	// version-specific spelling this tree does not know, not a feature
	// gap, which is why it is its own sentinel rather than
	// ErrUnimplemented.
	ErrBadSubsystem = errors.New("link: unrecognized subsystem name")
)

// InputError names the file that failed. It wraps whatever coff, ar, or the
// filesystem reported, so errors.Is still reaches the underlying cause.
type InputError struct {
	Name string
	Err  error
}

func (e *InputError) Error() string { return "link: " + e.Name + ": " + e.Err.Error() }
func (e *InputError) Unwrap() error { return e.Err }

// DirectiveError names an option inside a .drectve that could not be honoured,
// and the object that carried it.
//
// The object is not optional context. A build hits one of these because some
// library three levels down was compiled with a flag this linker does not
// implement, and without the file name there is nothing to go and look at.
type DirectiveError struct {
	Input  string
	Name   string // the normalized option name, without its leading slash
	Value  string
	Reason string
	Err    error
}

func (e *DirectiveError) Error() string {
	s := "link: " + e.Input + ": /" + e.Name
	if e.Value != "" {
		s += ":" + e.Value
	}
	if e.Reason != "" {
		return s + ": " + e.Reason
	}
	return s + ": " + e.Err.Error()
}

func (e *DirectiveError) Unwrap() error { return e.Err }

// MismatchError is a /FAILIFMISMATCH conflict: two objects declared the same
// key with different values.
//
// The directive comes from #pragma detect_mismatch, and the whole point of it
// is to turn an ABI incompatibility into a link failure rather than a
// crash — code built against one runtime library linked with code built
// against another, or one _MSC_VER against another. So this names both sides,
// because the answer is always "rebuild one of them" and the useful question
// is which.
type MismatchError struct {
	Key       string
	Value     string
	Input     string
	PrevValue string
	PrevInput string
}

func (e *MismatchError) Error() string {
	return "link: mismatch detected for " + strconv.Quote(e.Key) + ": value " +
		strconv.Quote(e.Value) + " in " + e.Input + " does not match " +
		strconv.Quote(e.PrevValue) + " in " + e.PrevInput
}

// UndefinedError is an unresolved name and the inputs that referenced it.
//
// Imp carries the hint that matters most often: the name would have resolved
// if the reference had gone through __imp_, which means the declaration was
// missing __declspec(dllimport). That is the single most common undefined
// symbol in a Windows link and the one whose cause is least obvious from the
// name alone.
type UndefinedError struct {
	Name string
	Refs []string
	Imp  bool
}

func (e *UndefinedError) Error() string {
	s := "link: undefined symbol " + e.Name
	if n := len(e.Refs); n > 0 {
		s += ", referenced by " + joinSome(e.Refs)
	}
	if e.Imp {
		s += " (a definition exists as __imp_" + e.Name +
			"; the declaration may be missing __declspec(dllimport))"
	}
	return s
}

// DuplicateError is a name with more than one strong definition, naming both.
type DuplicateError struct {
	Name   string
	First  string
	Second string
}

func (e *DuplicateError) Error() string {
	return "link: duplicate symbol " + e.Name + " in " + e.First + " and " + e.Second
}

// ComdatMismatchError is a SelectSameSize or SelectExactMatch election whose
// candidates disagreed. Those are the two selections that turn a duplicate
// into a diagnostic instead of a decision.
type ComdatMismatchError struct {
	Name   string
	First  string
	Second string
	Reason string
}

func (e *ComdatMismatchError) Error() string {
	return "link: COMDAT " + e.Name + " in " + e.First + " and " + e.Second + ": " + e.Reason
}

// OrdinalError is an export ordinal collision, or one outside 1..65535. The
// space is 16 bits and real projects have reached the end of it.
type OrdinalError struct {
	Name    string
	Ordinal uint32
	Other   string // the export already holding this ordinal, if any
}

func (e *OrdinalError) Error() string {
	s := "link: export " + e.Name + " ordinal " + strconv.FormatUint(uint64(e.Ordinal), 10)
	if e.Other != "" {
		return s + " is already used by " + e.Other
	}
	return s + " is outside 1..65535"
}

// OverflowError wraps a backend range failure with the input that produced it.
//
// The backend knows the chunk and the field; it does not know which object
// the chunk came from once the chunk has been merged with others. Adding that
// here is the difference between "a branch did not reach" and something a
// build can act on.
type OverflowError struct {
	Input string
	Err   error
}

func (e *OverflowError) Error() string { return "link: " + e.Input + ": " + e.Err.Error() }
func (e *OverflowError) Unwrap() error { return e.Err }

// ViewError is an input or a symbol that fits neither view of the image.
//
// For a non-hybrid link that means a machine that is not the target's. For an
// ARM64X link it means a machine that is neither ARM64 (native) nor ARM64EC or
// AMD64 (EC) — routing is by machine type and there is no per-input override,
// because an object's machine already says which view it belongs to.
type ViewError struct {
	Input   string
	Machine string
	Target  string
}

func (e *ViewError) Error() string {
	return "link: " + e.Input + " is " + e.Machine + ", which no view of a " +
		e.Target + " image accepts"
}

func (e *ViewError) Unwrap() error { return ErrMachineMismatch }

// joinSome renders a reference list without letting a symbol referenced by
// four hundred objects produce four hundred lines.
func joinSome(names []string) string {
	const show = 3
	if len(names) <= show {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:show], ", ") + ", and " +
		strconv.Itoa(len(names)-show) + " more"
}