package backend

// Kind is what a relocation type does, expressed so that link can reason about
// it without knowing the machine.
//
// The classification exists because the same questions are asked of every
// relocation — does this need a base relocation, can this reach its target,
// does this name a symbol at all — and answering them by switching on a raw
// uint16 would mean link carrying every machine's table. A backend answers
// once and link works in these terms.
type Kind uint8

const (
	// KindUnsupported is a type this backend does not implement. It is
	// distinct from KindIgnored: one has no effect, the other has an
	// unknown effect, and treating the second as the first produces an
	// image quietly missing a fixup.
	KindUnsupported Kind = iota

	// KindIgnored is the machine's ABSOLUTE type, which means nothing and
	// names nothing. Unlike the base-relocation ABSOLUTE it is not padding;
	// it is simply skipped.
	KindIgnored

	// KindVA is an absolute address written into the image. It is the only
	// kind that needs a base relocation, and forgetting one produces a
	// binary that works at its preferred base and faults under ASLR.
	KindVA

	// KindRVA is an image-relative address. It needs no base relocation,
	// which is why every table the PE format defines stores one of these.
	KindRVA

	// KindRelative is a displacement from the relocation site whose field
	// is wide enough to reach anywhere in the image. x64's REL32 is this.
	KindRelative

	// KindBranch is a displacement whose field is *not* wide enough, and so
	// a candidate for a range-extension thunk. A backend reporting this for
	// any type must implement Thunker.
	KindBranch

	// KindSectionRel is an offset from the start of the target's section.
	// Debug information uses it, and so does static TLS: an access to a
	// thread-local resolves to an offset within the TLS template rather
	// than to an address, which is why the kind survives to the image at
	// all.
	KindSectionRel

	// KindSectionIndex is the target's one-based section number. Debug
	// information only.
	KindSectionIndex

	// KindPair is the second half of a span-dependent pair, whose symbol
	// field carries a displacement rather than an index. It names no
	// symbol.
	KindPair

	// KindToken is a CLR token. This tree does not link managed code and
	// carries the kind only far enough to reject it by name.
	KindToken
)

// NeedsSymbol reports whether a relocation of this kind names a symbol.
//
// The two that do not are the ignored type and the PAIR half. A caller that
// resolves the symbol field of either gets a real symbol — the field holds
// something, and for a PAIR that something is a displacement — and relocates
// against whatever it happens to name.
func (k Kind) NeedsSymbol() bool {
	switch k {
	case KindIgnored, KindPair, KindUnsupported:
		return false
	}
	return true
}

// Thunkable reports whether a relocation of this kind may need a veneer when
// its target ends up too far away.
func (k Kind) Thunkable() bool { return k == KindBranch }

func (k Kind) String() string {
	switch k {
	case KindIgnored:
		return "ignored"
	case KindVA:
		return "va"
	case KindRVA:
		return "rva"
	case KindRelative:
		return "relative"
	case KindBranch:
		return "branch"
	case KindSectionRel:
		return "secrel"
	case KindSectionIndex:
		return "section"
	case KindPair:
		return "pair"
	case KindToken:
		return "token"
	}
	return "unsupported"
}