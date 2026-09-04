package link

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/image"
)

// A range-extension thunk is a veneer: an unconditional branch to a target the
// original branch could not reach, placed close enough that the original can
// reach the veneer.
//
// Every veneer lands in the section holding the branch that needed it. That is
// the single-island model, and it is correct while a code section stays under
// the reach of the shortest branch into it — 128 MB for a BRANCH26 on AArch64.
// Above that the veneer itself is out of range and the backend reports it,
// which is the right failure: distributed islands are the next step and
// encoding silently is not.
//
// The rewrite is on the relocation, not on the instruction. A branch out of
// range keeps its opcode and its offset and has its target changed to the
// veneer's symbol, so apply writes an in-range displacement without knowing
// anything happened. Rewriting bytes here would mean doing it again on the
// next round, when layout moved everything.

// thunkRef is one veneer and the address it jumps to.
//
// The target is a symbol rather than an RVA because the veneer is created
// during layout, when addresses are still moving. The bytes are written during
// contents, when they are not.
type thunkRef struct {
	chunk  *image.Chunk
	target *image.Symbol
}

// thunkKey identifies a veneer: one per target per section, since a second
// branch in the same section to the same target can share the first's.
type thunkKey struct {
	sec    *image.Section
	target *image.Symbol
}

// growThunks adds the veneers this round's addresses turned out to need.
//
// It reports whether anything was added, which is the loop's termination
// condition. Adding nothing means every branch reaches, which means the
// addresses that produced that answer are the final ones.
func (l *Linker) growThunks(t backend.Thunker) (bool, error) {
	if l.thunkFor == nil {
		l.thunkFor = make(map[thunkKey]*Sym)
	}
	grew := false

	for _, c := range l.chunks {
		if !c.Live() {
			continue
		}
		from, err := c.RVA()
		if err != nil {
			// Not placed: a chunk in no section, which merge should
			// have made impossible.
			continue
		}
		sec := c.Section()
		if sec == nil {
			continue
		}

		var rewritten []image.Reloc
		changed := false
		for _, r := range c.Relocs() {
			if r.Sym == nil || !l.be.Classify(r.Type).Thunkable() {
				rewritten = append(rewritten, r)
				continue
			}
			to, err := r.Sym.RVA()
			if err != nil {
				rewritten = append(rewritten, r)
				continue
			}
			site := from.Add(r.Off)
			if t.InRange(r.Type, site, to) {
				rewritten = append(rewritten, r)
				continue
			}

			veneer, added, err := l.veneer(t, sec, r.Sym)
			if err != nil {
				return false, err
			}
			grew = grew || added
			changed = true
			r.Sym = veneer.Out
			rewritten = append(rewritten, r)
		}
		if changed {
			c.SetRelocs(rewritten)
		}
	}
	return grew, nil
}

// veneer returns the thunk in sec that jumps to target, creating it if this is
// the first branch that needed one.
//
// A veneer created on an earlier round is reused rather than duplicated. That
// is what makes the loop converge: without it, every round would add a fresh
// thunk for every out-of-range branch, every section would grow, and growth
// would put more branches out of range indefinitely.
func (l *Linker) veneer(t backend.Thunker, sec *image.Section, target *image.Symbol) (*Sym, bool, error) {
	key := thunkKey{sec: sec, target: target}
	if s, ok := l.thunkFor[key]; ok {
		return s, false, nil
	}

	size := t.ThunkSize()
	align := t.ThunkAlign()
	if size <= 0 {
		return nil, false, l.fail(&backend.RangeError{
			Reason: "backend reports a thunk size of zero but classifies a relocation as thunkable",
		})
	}

	c := image.NewChunk(sec.Name, "<thunk>", &thunkSource{size: uint32(size), align: align})
	c.Reachable = true
	if err := sec.Add(c); err != nil {
		return nil, false, l.fail(err)
	}
	l.chunks = append(l.chunks, c)

	// The name is decorated so it cannot collide with anything an input
	// could define, and carries the target's name so a map file or a
	// diagnostic says which branch it serves.
	name := "\x7fthunk." + target.Name + "." + sec.Name
	tab := l.tabs[0]
	s := tab.intern(name)
	s.Kind, s.chunk, s.off = SymDefined, c, 0
	tab.view.Symbols.Define(name, c, 0)

	l.thunkFor[key] = s
	l.thunks = append(l.thunks, thunkRef{chunk: c, target: target})
	return s, true, nil
}

// writeThunks emits every veneer's bytes. It runs during contents, when the
// image is frozen and every address it needs is final.
func (l *Linker) writeThunks(t backend.Thunker) error {
	for _, ref := range l.thunks {
		site, err := backend.NewSite(l.img, ref.chunk)
		if err != nil {
			return l.fail(err)
		}
		to, err := ref.target.RVA()
		if err != nil {
			return l.fail(err)
		}
		if err := t.WriteThunk(site, to); err != nil {
			return l.fail(&OverflowError{Input: ref.chunk.Input, Err: err})
		}
	}
	return nil
}

// thunkSource is a veneer's bytes: a fixed-size run the backend fills in
// during contents.
//
// It returns a zero slice rather than nil. Nil means a chunk that occupies
// address space and no file space, which is what a .bss becomes, and a veneer
// is the opposite of that — it is code, it must be in the file, and the bytes
// are simply not known until every address is.
type thunkSource struct {
	size  uint32
	align int
}

func (s *thunkSource) Size() uint32 { return s.size }
func (s *thunkSource) Align() int   { return s.align }

func (s *thunkSource) Bytes() ([]byte, error) { return make([]byte, s.size), nil }

// thunkProt is what a section holding veneers must permit. It is asserted
// rather than applied: a veneer placed in a section the loader will not
// execute is a crash at the first call through it, and the placement decision
// was made by whoever put the branch there.
const thunkProt = pe.SecExecute | pe.SecRead