package coff

import "github.com/vertex-language/pe"

// Weak describes a weak external symbol and the alternate it falls back to.
type Weak struct {
	// Sym is the weak symbol itself.
	Sym *Symbol
	// Alternate is the definition used if nothing else defines the name.
	Alternate *Symbol
	// Kind distinguishes the three search behaviours from the ARM64EC
	// anti-dependency alias, which shares the storage class and means
	// something different in kind.
	Kind pe.WeakKind
}

// AntiDependency reports whether this is an ARM64EC anti-dependency alias
// rather than an ordinary weak external.
//
// The distinction matters to resolution. An ordinary weak external's alternate
// is used only if the name is never defined; an anti-dependency alias exists
// to name the same entity under two spellings — the ARM64EC mangled form and
// the plain one — so that x64 and ARM64EC code can share a symbol namespace.
// Collapsing the two into a bool loses that.
func (w Weak) AntiDependency() bool { return w.Kind == pe.WeakAntiDependency }

// Weak returns the weak-external record for a symbol, if it has one.
func (s *Symbol) Weak() (Weak, bool) {
	if s.Class != pe.ClassWeakExternal {
		return Weak{}, false
	}
	for _, a := range s.aux {
		w, ok := a.(AuxWeakExternal)
		if !ok {
			continue
		}
		return Weak{
			Sym:       s,
			Alternate: s.f.SymbolAt(w.TagIndex),
			Kind:      w.Kind_,
		}, true
	}
	return Weak{}, false
}

// Weaks returns every weak external in the object.
//
// Resolution order is not this package's concern, but it is worth recording
// why link evaluates these last: a weak external's alternate is used only if
// nothing else ever defines the name, so resolving one before every archive
// has been searched makes command-line order decide the answer.
func (f *File) Weaks() ([]Weak, error) {
	syms, err := f.Symbols()
	if err != nil {
		return nil, err
	}
	var out []Weak
	for _, s := range syms {
		if w, ok := s.Weak(); ok {
			out = append(out, w)
		}
	}
	return out, nil
}