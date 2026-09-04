package pe

// A COMDAT section is one whose duplicate definitions across objects are
// expected, and whose Selection says how the linker picks a winner. The
// selection lives in the auxiliary section-definition record of the section's
// key symbol — the first symbol with that section's number — which is why a
// LNK_COMDAT section with no key symbol is an error rather than a default.

// Selection is how the linker resolves duplicate COMDAT definitions.
type Selection uint8

const (
	// SelectNoDuplicates means a second definition is an error. This is
	// what a non-inline function in a header gets.
	SelectNoDuplicates Selection = 1
	// SelectAny means pick any one; they are assumed equivalent. This is
	// the common case, and what an inline function gets.
	SelectAny Selection = 2
	// SelectSameSize means pick any one, but error if the sizes differ.
	SelectSameSize Selection = 3
	// SelectExactMatch means pick any one, but error if the contents
	// differ. What "differ" means is the linker's business; this tree
	// compares bytes and relocations.
	SelectExactMatch Selection = 4
	// SelectAssociative means this section lives or dies with another one,
	// named by the Number field of the same auxiliary record. It is how
	// .pdata and .xdata stay attached to the function they describe, and
	// how a discarded function takes its unwind data with it.
	SelectAssociative Selection = 5
	// SelectLargest means pick the largest definition.
	SelectLargest Selection = 6
	// SelectNewest means pick the most recently compiled. It is documented
	// but effectively unused; link.exe does not implement it meaningfully.
	SelectNewest Selection = 7
)

// Valid reports whether s is one of the seven defined selections. Zero is not
// among them: a section flagged LNK_COMDAT whose key symbol reports selection
// zero is malformed, not defaulted.
func (s Selection) Valid() bool {
	return s >= SelectNoDuplicates && s <= SelectNewest
}

// Associative reports whether s makes this section's fate depend on another's.
// The associated section is named by the auxiliary record's Number field, and
// the chain it forms has to be checked for cycles at parse time — an
// associative chain that never terminates is an infinite loop in every
// consumer downstream, so the failure belongs where the file is read.
func (s Selection) Associative() bool { return s == SelectAssociative }

// Compares reports whether s requires the linker to compare candidates rather
// than simply pick one. These are the two selections that can turn a duplicate
// into a diagnostic instead of a decision.
func (s Selection) Compares() bool {
	return s == SelectSameSize || s == SelectExactMatch
}

func (s Selection) String() string {
	switch s {
	case SelectNoDuplicates:
		return "NODUPLICATES"
	case SelectAny:
		return "ANY"
	case SelectSameSize:
		return "SAME_SIZE"
	case SelectExactMatch:
		return "EXACT_MATCH"
	case SelectAssociative:
		return "ASSOCIATIVE"
	case SelectLargest:
		return "LARGEST"
	case SelectNewest:
		return "NEWEST"
	}
	return "selection(" + itoa(int(s)) + ")"
}