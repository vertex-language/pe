package link

import (
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/image"
)

// Layout is the fixpoint. It assigns every RVA and file offset, grows
// range-extension thunks until every branch reaches, and freezes the image.
//
// On x64 it runs once. A REL32 displacement is signed and 32 bits, so a branch
// reaches ±2 GB — further than a PE32+ image can be — and no veneer is ever
// needed. The x64 backend therefore does not implement backend.Thunker and
// this loop assigns, sees no growth, and stops.
//
// On AArch64 it does not. A BRANCH26 reaches ±128 MB, a conditional BRANCH19
// far less, and a TBZ ±32 KB, so veneers are routine, veneers grow the
// sections they live in, and growth can put another branch out of range. The
// loop is the only thing that makes that terminate.

// maxLayoutRounds bounds the thunk-growth loop.
//
// It is a bound and not a proof. Growth is monotonic in practice — a thunk is
// added and never removed, and the sections only get larger — so the loop
// converges in two or three rounds on any real input. A link that reaches this
// many has either a pathological input or a backend whose InRange disagrees
// with what its WriteThunk emits, and the second is the one worth catching:
// a backend that reports a site out of range and then writes a veneer that is
// also out of range would otherwise spin forever.
const maxLayoutRounds = 16

// layout assigns addresses and freezes.
func (l *Linker) layout() error {
	thunker := backend.AsThunker(l.be)

	for round := 0; ; round++ {
		if err := l.img.Assign(); err != nil {
			return l.fail(err)
		}
		if thunker == nil {
			break
		}
		grew, err := l.growThunks(thunker)
		if err != nil {
			return err
		}
		if !grew {
			break
		}
		if round >= maxLayoutRounds {
			return l.fail(ErrLayoutDivergence)
		}
	}

	if err := l.img.Freeze(); err != nil {
		return l.fail(err)
	}
	return l.bind()
}

// bind verifies that every symbol the image will emit has an address.
//
// It is a verification pass rather than a copy, and that is deliberate: a
// symbol's address is derived from its chunk, never stored, so there is no
// second place for it to be wrong and nothing here to write. What is left is
// to confirm that nothing reached this point undefined, which check should
// already have guaranteed — so a failure here is a bug in check rather than a
// bad input, and it says so.
//
// Absolute symbols are skipped. They have no address by construction, which is
// a different fact from not having one yet, and image.Symbol.RVA reports the
// two separately for exactly this reason.
func (l *Linker) bind() error {
	for _, tab := range l.tabs {
		for _, s := range tab.Symbols() {
			if s.Kind == SymAbsolute || s.chunk == nil {
				continue
			}
			if !s.chunk.Live() {
				continue
			}
			if _, err := s.Out.RVA(); err != nil {
				return l.fail(&InputError{Name: s.Name, Err: err})
			}
		}
	}
	return nil
}

// SizeOfImage and SizeOfHeaders are the two figures the optional header needs
// that only layout can supply. They are exposed because emit is a separate
// step and asking the image twice is one place too many for them to differ.
func (l *Linker) sizes() (sizeOfImage, sizeOfHeaders uint32, err error) {
	sizeOfImage, err = l.img.SizeOfImage()
	if err != nil {
		return 0, 0, err
	}
	sizeOfHeaders, err = l.img.SizeOfHeaders()
	if err != nil {
		return 0, 0, err
	}
	return sizeOfImage, sizeOfHeaders, nil
}

// sizeOfCode sums the sections holding executable code, which is what
// SizeOfCode in the optional header reports.
//
// The field is advisory — nothing in the loader consults it — but dumpbin
// prints it and a diff against link.exe output that differs only here is a
// diff nobody can read past.
func (l *Linker) sizeOfCode() (uint32, error) {
	var total uint32
	for _, s := range l.img.Sections() {
		if !s.Code() {
			continue
		}
		n, err := s.SizeOfRawData()
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// sectionOf returns the output section a chunk landed in, or nil.
func sectionOf(c *image.Chunk) *image.Section { return c.Section() }