package link

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/coff"
)

// Weak externals and alternate names are the same idea arriving from two
// directions: a name whose definition is used only if nothing else ever
// defines it. Both are evaluated last, after every archive has been searched,
// because an alternate taken early makes command-line order decide an answer
// that nothing else in the format lets command-line order decide.
//
// The ARM64EC anti-dependency alias shares the WEAK_EXTERNAL storage class and
// is a different thing in kind rather than in degree. An ordinary weak
// external's alternate is a fallback. An anti-dependency alias exists to name
// one entity under two spellings — the ARM64EC mangled form and the plain
// one — so that x64 and ARM64EC code can share a namespace. Collapsing the two
// into a bool is how an ARM64EC alias becomes an ordinary weak reference and
// half the calls across the boundary bind to nothing.

// weakRef is one unresolved weak external, recorded during addSymbols and
// evaluated after resolution has otherwise finished.
type weakRef struct {
	obj  *Object
	name string
	alt  string
	kind pe.WeakKind
}

// addWeak records a weak external.
//
// The symbol is interned now so that a later definition of the same name wins
// on the lattice without this ever being consulted, and the alternate is
// referenced now so that it can pull an archive member in — a weak external
// whose alternate lives in an archive nobody else touches would otherwise
// resolve to nothing.
func (l *Linker) addWeak(o *Object, sym *coff.Symbol) error {
	w, ok := sym.Weak()
	if !ok || w.Alternate == nil {
		// A WEAK_EXTERNAL storage class with no auxiliary record, or one
		// whose TagIndex names a slot holding aux data. Either is a
		// malformed symbol rather than a weak external with no fallback.
		return l.fail(&InputError{Name: o.Name, Err: coff.ErrBadAuxRecord})
	}

	s := o.tab.intern(sym.Name)
	if s.Kind == SymUndefined {
		s.Kind = SymWeakExternal
	}
	if err := l.reference(o, w.Alternate.Name); err != nil {
		return err
	}
	l.weaks = append(l.weaks, weakRef{
		obj: o, name: sym.Name, alt: w.Alternate.Name, kind: w.Kind,
	})
	return nil
}

// resolveWeak binds every weak external and alternate name that is still
// unresolved.
func (l *Linker) resolveWeak() error {
	for _, w := range l.weaks {
		if err := l.bindAlias(w.obj.tab, w.name, w.alt, w.kind == pe.WeakAntiDependency); err != nil {
			return l.fail(err)
		}
	}
	// /ALTERNATENAME applies to the native view. A hybrid link's EC view
	// gets its aliases from the objects routed to it, which is where the
	// mangled and demangled forms of a name are related to each other.
	for _, a := range l.opt.AlternateNames {
		if err := l.bindAlias(l.tabs[0], a.From, a.To, false); err != nil {
			return l.fail(err)
		}
	}
	return nil
}

// bindAlias resolves name to the definition of alt, if name is still
// undefined and alt has one.
//
// Two guards, both of which come from the same real failure. The first: an
// alias is not taken when its target is itself undefined. Doing so looks
// harmless — the name resolves to something — but the target may still be
// satisfied by an archive member fetched later, and archive members do not
// override an alias that has already been bound. The eager binding therefore
// skips a definition that exists.
//
// The second: an anti-dependency alias whose target is another anti-dependency
// alias is refused rather than followed. Chaining them is not allowed, and a
// chain that is followed anyway resolves to the alias rather than to a
// definition, which surfaces as an undefined symbol a long way from here.
func (l *Linker) bindAlias(tab *symtab, name, alt string, antiDep bool) error {
	s := tab.Lookup(name)
	if s == nil {
		return nil
	}
	switch s.Kind {
	case SymUndefined, SymWeakExternal:
	default:
		return nil // something defined it; the alternate is not needed
	}

	t := tab.Lookup(alt)
	if t == nil {
		return nil
	}
	if t.Kind == SymLazy {
		if err := l.fetchLazy(tab, t); err != nil {
			return err
		}
	}
	if t.Kind.rank() <= SymWeakExternal.rank() {
		// The target has no definition of its own. Binding to it now
		// would fix the answer before the archives have had their say.
		return nil
	}
	if antiDep && t.Kind == SymWeakExternal {
		return nil
	}

	s.Kind, s.Obj, s.chunk, s.off, s.value = t.Kind, t.Obj, t.chunk, t.off, t.value
	switch t.Kind {
	case SymAbsolute:
		tab.view.Symbols.Absolute(name, t.value)
	case SymImport:
		s.imp = t.imp
	default:
		tab.view.Symbols.Define(name, t.chunk, t.off)
	}
	return nil
}