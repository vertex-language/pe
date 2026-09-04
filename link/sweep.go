package link

import (
	"github.com/vertex-language/pe/image"
)

// Sweep is /OPT:REF: a mark-and-sweep collection over chunks, from the entry
// point, every /INCLUDE, and every export.
//
// One rule shapes the whole pass, and it is a limitation rather than a design:
// only a COMDAT section can be discarded. link.exe cannot collect a
// non-COMDAT section and lld reproduces that deliberately, so an object
// compiled without /Gy contributes one .text holding every function and none
// of it can be removed. That is why /Gy is not an optimization flag but the
// precondition for this pass doing anything at all, and it is why every
// non-COMDAT chunk below is a root rather than a candidate.
//
// The cost is real — measurements on profile-instrumented builds put it at
// something like 40% of the metadata sections that could be collected — and
// this tree pays it anyway, because collecting a non-COMDAT section means
// deciding that nothing outside the link references it, and nothing in the
// format supports that decision.

// sweep marks live chunks. It runs after split, so the dependency edges exist.
func (l *Linker) sweep() error {
	if !l.opt.OptRef {
		// Everything survives. The flag is still set on each chunk
		// rather than being consulted conditionally later, so that
		// Chunk.Live means one thing everywhere.
		for _, c := range l.chunks {
			c.Reachable = true
		}
		return nil
	}

	var work []*image.Chunk
	mark := func(c *image.Chunk) {
		if c == nil || c.Discarded || c.Reachable {
			return
		}
		c.Reachable = true
		work = append(work, c)
	}

	// Every chunk that is not a COMDAT is a root, for the reason above.
	// Except a follower: an unwind record this linker cut out of a
	// whole-file .pdata is not a section anyone else can reference, and
	// making it a root would keep every function in the object alive
	// through the record that describes it.
	for _, c := range l.chunks {
		if info := l.info[c]; info == nil || (!info.comdat && !info.follower) {
			mark(c)
		}
	}

	for _, tab := range l.tabs {
		for _, name := range l.roots() {
			if s := tab.Lookup(name); s != nil {
				mark(s.chunk)
			}
		}
	}

	// The transitive closure. A chunk's relocations name the symbols it
	// needs; its dependency edges name the things that must outlive it even
	// though nothing points at them — an associative COMDAT's followers,
	// and the unwind record split.go cut out of .pdata.
	for len(work) > 0 {
		c := work[len(work)-1]
		work = work[:len(work)-1]

		for _, r := range c.Relocs() {
			if r.Sym == nil {
				continue
			}
			mark(r.Sym.Chunk())
		}
		for _, d := range l.deps[c] {
			mark(d)
		}
	}
	return nil
}

// roots returns the names a sweep starts from.
//
// The entry point and /INCLUDE are the obvious two. Exports are the third and
// the one that is easy to forget: a DLL's exported functions are referenced by
// nothing inside the image, so a sweep that does not treat them as roots
// produces a DLL that exports names pointing at collected code.
//
// The CRT's linker-supplied symbols are not listed here. They are defined in
// non-COMDAT sections in every CRT anyone ships, so they are already roots by
// the rule above; naming them would be a second mechanism that agrees with the
// first until the day it does not.
func (l *Linker) roots() []string {
	out := make([]string, 0, len(l.opt.Includes)+len(l.opt.Exports)+1)
	if e := l.opt.EntryName(); e != "" {
		out = append(out, e)
	}
	out = append(out, l.opt.Includes...)
	for _, e := range l.opt.Exports {
		out = append(out, e.Name)
	}
	return out
}

// live returns the chunks that survived, in the order they were created.
//
// Order is preserved because it is the order contributions arrived, which is
// the order merge sorts within — and a map iteration here would make the
// output file differ between runs of a linker whose whole point is that it
// does not.
func (l *Linker) live() []*image.Chunk {
	out := make([]*image.Chunk, 0, len(l.chunks))
	for _, c := range l.chunks {
		if c.Live() {
			out = append(out, c)
		}
	}
	return out
}