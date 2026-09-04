package link

import (
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/image"
)

// Scan is where the backend is asked what the link will need, and where link
// answers the questions the backend cannot.
//
// Everything recorded here is a size or a count and nothing is an address. The
// tables it drives — the IAT, .reloc, the guard tables — must all be sized
// before layout and filled after it, which is the same two-step circularity
// image.Synthetic exists for. Recording an RVA at this point would record
// zero, and zero is a legal RVA.
//
// The division of labour is worth stating because it is not obvious. The
// backend walks relocations and reports the ones that need a base relocation:
// that is a per-machine question and getting it wrong is silent. link walks
// symbols and reports which imports need slots and thunks: that is a
// resolution question the backend has no way to answer, since a relocation
// against an imported name looks exactly like one against a local definition.

// scan runs the scan phase.
func (l *Linker) scan() error {
	l.reqs = backend.NewReqs()
	l.buildSymIndex()

	if err := l.scanImports(); err != nil {
		return err
	}
	if err := l.scanGuard(); err != nil {
		return err
	}
	if err := l.be.Scan(l.img, l.reqs); err != nil {
		return l.fail(err)
	}
	return nil
}

// buildSymIndex maps output symbols back to their resolution records.
//
// A relocation carries an *image.Symbol, which knows its name and its address
// and nothing about how it was resolved. Asking whether a relocation target is
// an import means going the other way, and a linear search over two symbol
// tables per relocation is the kind of thing that turns a two-second link into
// a two-minute one.
func (l *Linker) buildSymIndex() {
	n := 0
	for _, tab := range l.tabs {
		n += len(tab.Symbols())
	}
	l.symOf = make(map[*image.Symbol]*Sym, n)
	for _, tab := range l.tabs {
		for _, s := range tab.Symbols() {
			l.symOf[s.Out] = s
		}
	}
}

// scanImports records which imports the image actually uses.
//
// Slot liveness and thunk liveness are tracked separately, and the separation
// is the entire reason Reqs has two methods rather than one. A program that
// only ever calls through __imp_foo — which is what __declspec(dllimport)
// generates, and the PE analogue of ELF's -fno-plt — needs the IAT entry and
// no thunk. One that calls the unprefixed foo needs both. Collapsing them
// emits a thunk per import in every dllimport-only program: dead code in the
// image, and a pointless entry in every table that walks .text.
//
// The walk is over live chunks rather than over the symbol table, so an import
// referenced only from a chunk /OPT:REF removed does not reach the IAT. A
// linker that sized the IAT from the symbol table would produce an import
// directory naming DLLs the program no longer touches, and the loader would
// dutifully load them.
func (l *Linker) scanImports() error {
	for _, c := range l.chunks {
		if !c.Live() {
			continue
		}
		for _, r := range c.Relocs() {
			if r.Sym == nil {
				continue
			}
			s := l.symOf[r.Sym]
			if s == nil || s.Kind != SymImport || s.imp == nil {
				continue
			}
			if isImpName(s.Name) {
				l.reqs.NeedIATSlot(r.Sym)
				continue
			}
			// The unprefixed name. The call lands in a thunk that
			// jumps through the slot, so this implies the slot too —
			// NeedImportThunk records both.
			s.imp.Thunks[s.Name] = true
			l.reqs.NeedImportThunk(r.Sym)
		}
	}
	return nil
}

const impPrefix = "__imp_"

func isImpName(name string) bool {
	return len(name) > len(impPrefix) && name[:len(impPrefix)] == impPrefix
}

// guardSections are the four the linker collects Control Flow Guard targets
// from.
//
// Each holds a run of RVAs, and an RVA in an object file is a relocation — so
// the targets are named by the relocations rather than by the bytes, and
// reading the bytes would read zeroes. The sections are $-suffixed so that the
// CRT's own start and end markers bracket them after merge.
var guardSections = []string{".gfids", ".giats", ".gljmp", ".gehcont"}

// scanGuard collects the indirect call targets the CFG tables will hold.
//
// The tables themselves are built during synth and sorted during fill, after
// addresses are final — the GFIDS table must be sorted by RVA or the image
// will not load at all, and no sort is possible before layout has run.
//
// Nothing is collected without /GUARD:CF. The sections are still present in
// the objects and still contribute their bytes; what changes is whether the
// load configuration describes them, and describing a table the image does not
// otherwise support is worse than omitting it.
func (l *Linker) scanGuard() error {
	if l.opt.Guard == GuardNone {
		return nil
	}
	for _, c := range l.chunks {
		if !c.Live() || !isGuardSection(c.GroupName()) {
			continue
		}
		for _, r := range c.Relocs() {
			if r.Sym == nil {
				continue
			}
			l.reqs.NeedGuardTarget(r.Sym)
		}
	}
	return nil
}

func isGuardSection(name string) bool {
	for _, g := range guardSections {
		if name == g {
			return true
		}
	}
	return false
}
