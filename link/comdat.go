package link

import (
	"bytes"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/coff"
	"github.com/vertex-language/pe/image"
)

// A COMDAT section is one whose duplicate definitions across objects are
// expected — an inline function, a template instantiation, a vtable — and
// whose Selection says how the linker picks a winner.
//
// Election is per name, not per section, and the name is the COMDAT symbol:
// the second symbol carrying the section's number, found by position and not
// by any marker in the file. The first is the section definition record.
//
// The losing section is discarded and its symbols never reach the table. That
// ordering matters: a loser whose symbols were defined first would collide
// with the winner's, so the election would have chosen which copy of the bytes
// to keep while leaving the names duplicated.

// comdatSym is the election terms attached to a winning definition, kept so a
// later candidate can be compared against it.
type comdatSym struct {
	selection pe.Selection
	chunk     *image.Chunk
	sec       *coff.Section
	obj       *Object
}

// elect runs the COMDAT election for every COMDAT section in an object.
//
// Associative sections are deliberately skipped. They are followers: their
// fate is their leader's, applied afterwards by applyAssociative. Electing one
// independently is a real bug in link.exe, which reports a duplicate symbol
// error for an external defined in an associative section even when that
// section would have been discarded once its leader lost.
func (l *Linker) elect(o *Object) error {
	for i, sec := range o.File.Sections {
		c := o.chunks[i]
		if c == nil || !sec.IsComdat() {
			continue
		}
		cd, err := sec.Comdat()
		if err != nil {
			return l.fail(&InputError{Name: o.Name, Err: err})
		}
		if cd == nil || cd.Selection.Associative() {
			continue
		}
		if cd.Leader.Class != pe.ClassExternal {
			// A key symbol with no external linkage names nothing
			// another object could be talking about, so there is no
			// duplicate to elect against and this section always
			// prevails. MSVC's string pooling depends on it: /GF puts
			// every literal in its own COMDAT keyed on a static $SG
			// symbol, and those numbers restart in every translation
			// unit, so electing them by name would discard one
			// object's literals in favour of another's unrelated ones
			// and leave the code that used them pointing at bytes
			// that are not in the image.
			continue
		}
		if err := l.electOne(o, sec, c, cd); err != nil {
			return l.fail(err)
		}
	}
	return nil
}

// electOne decides one candidate against whatever already holds the name.
//
// The selections divide into three behaviours. ANY and NEWEST keep the first
// seen — link.exe and lld both do exactly that, and NEWEST is documented but
// never meaningfully implemented anywhere. SAME_SIZE and EXACT_MATCH keep the
// first seen but turn a disagreement into a diagnostic. LARGEST can displace
// an earlier winner. NODUPLICATES elects nothing at all: it simply declines to
// deduplicate, and the duplicate that results falls out as an ordinary
// duplicate definition.
func (l *Linker) electOne(o *Object, sec *coff.Section, c *image.Chunk, cd *coff.Comdat) error {
	name := cd.Leader.Name
	s := o.tab.intern(name)

	prev := s.comdat
	if prev == nil {
		// First candidate. It wins by default; addSymbols will define
		// the section's symbols against it.
		s.comdat = &comdatSym{selection: cd.Selection, chunk: c, sec: sec, obj: o}
		return nil
	}

	if prev.selection != cd.Selection {
		// Two objects disagreeing about how a name should be
		// deduplicated is a one-definition-rule violation that the
		// format can express and the linker cannot resolve. link.exe
		// takes the first; this reports it, because the two copies were
		// compiled under different assumptions and one of them is
		// wrong.
		return &ComdatMismatchError{
			Name: name, First: prev.obj.Name, Second: o.Name,
			Reason: "selection " + prev.selection.String() + " and " + cd.Selection.String(),
		}
	}

	switch cd.Selection {
	case pe.SelectNoDuplicates:
		// No deduplication happens. The section is kept and its symbols
		// are defined, which is what makes the second one a duplicate.
		return nil

	case pe.SelectSameSize:
		if prev.sec.Size != sec.Size {
			return &ComdatMismatchError{
				Name: name, First: prev.obj.Name, Second: o.Name,
				Reason: "sizes differ",
			}
		}

	case pe.SelectExactMatch:
		same, err := sameContents(prev.sec, sec, prev.obj.Machine, o.Machine)
		if err != nil {
			return &InputError{Name: o.Name, Err: err}
		}
		if !same {
			return &ComdatMismatchError{
				Name: name, First: prev.obj.Name, Second: o.Name,
				Reason: "contents differ",
			}
		}

	case pe.SelectLargest:
		if sec.Size > prev.sec.Size {
			// The earlier winner loses. Its symbols were already
			// defined against it; Define replaces, so redefining them
			// against this chunk is enough, and addSymbols will do it
			// when it walks this object.
			prev.chunk.Discarded = true
			s.comdat = &comdatSym{selection: cd.Selection, chunk: c, sec: sec, obj: o}
			return nil
		}
	}

	c.Discarded = true
	return nil
}

// sameContents compares two candidate sections byte for byte and relocation
// for relocation, which is what EXACT_MATCH asks for.
//
// What "differ" means is the linker's business — the specification does not
// say — and this compares both halves because bytes alone are not enough: two
// sections can hold identical instructions and relocate them against different
// symbols, and folding those would bind half the program to the wrong
// definition.
//
// The symbol comparison is by name rather than by slot, since the two objects
// have unrelated symbol tables and identical slot numbers mean nothing.
func sameContents(a, b *coff.Section, ma, mb pe.Machine) (bool, error) {
	if a.Size != b.Size || a.Characteristics() != b.Characteristics() {
		return false, nil
	}
	da, err := a.Data()
	if err != nil {
		return false, err
	}
	db, err := b.Data()
	if err != nil {
		return false, err
	}
	if !bytes.Equal(da, db) {
		return false, nil
	}

	ra, err := a.Relocs()
	if err != nil {
		return false, err
	}
	rb, err := b.Relocs()
	if err != nil {
		return false, err
	}
	if len(ra) != len(rb) {
		return false, nil
	}
	for i := range ra {
		if ra[i].Address != rb[i].Address || ra[i].Type != rb[i].Type {
			return false, nil
		}
		if ra[i].IsPair(ma) != rb[i].IsPair(mb) {
			return false, nil
		}
		if ra[i].IsPair(ma) {
			if ra[i].SymIndex != rb[i].SymIndex {
				return false, nil
			}
			continue
		}
		na, okA := relocSymName(a, ra[i].SymIndex)
		nb, okB := relocSymName(b, rb[i].SymIndex)
		if !okA || !okB || na != nb {
			return false, nil
		}
	}
	return true, nil
}

// relocSymName resolves a relocation's symbol slot to a name within its own
// object.
func relocSymName(sec *coff.Section, slot uint32) (string, bool) {
	f := sec.File()
	if f == nil {
		return "", false
	}
	s := f.SymbolAt(slot)
	if s == nil {
		return "", false
	}
	return s.Name, true
}

// applyAssociative propagates each leader's fate to its followers.
//
// An associative COMDAT lives or dies with the section it names. It is how
// .pdata and .xdata stay attached to the function they describe, and how a
// discarded function takes its unwind data with it — without which the image
// carries exception records for code that is not there, and the runtime
// binary-searches its way to them.
//
// The walk is iterative and bounded by the chain length, which coff has
// already proved terminates: an associative chain that loops is checked for at
// parse time, in both the reader and the writer, precisely so that every
// consumer downstream can walk it without a visited set.
func (l *Linker) applyAssociative() error {
	for _, o := range l.objects {
		for i, sec := range o.File.Sections {
			c := o.chunks[i]
			if c == nil || !sec.IsComdat() {
				continue
			}
			cd, err := sec.Comdat()
			if err != nil {
				return l.fail(&InputError{Name: o.Name, Err: err})
			}
			if cd == nil || !cd.Selection.Associative() || cd.Associated == nil {
				continue
			}
			if leader := o.chunks[cd.Associated.Index()]; leader == nil || leader.Discarded {
				c.Discarded = true
			}
		}
	}
	return nil
}