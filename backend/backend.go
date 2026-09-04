// Package backend is where every machine-specific decision in a link lives.
//
// link never imports x64 or aarch64. It calls For, gets a Backend, and asks
// it: how to classify a relocation, what base relocation a relocation needs,
// what an import thunk looks like, how wide an unwind entry is. Each of those
// answers differs per machine and each of them is silently wrong if guessed.
//
// The interface is deliberately narrow and the optional parts are separate
// interfaces rather than methods returning "unsupported". A backend that
// cannot reach every branch target implements Thunker; one for a hybrid target
// implements Hybrid. Discovering those with a type assertion means x64 — which
// needs neither — has no stubs to write and no way to accidentally half-write
// one.
package backend

import (
	"errors"
	"strconv"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
)

var (
	// ErrNoBackend means no backend is registered for a target's machine
	// and subarch pair. Importing the backend package for its side effect
	// is what registers one, and forgetting the blank import is the usual
	// cause.
	ErrNoBackend = errors.New("backend: no backend registered for this target")

	// ErrUnsupportedReloc means a relocation type this backend does not
	// implement. It is distinct from a type it classifies as ignored: one
	// is a relocation with no effect, the other a relocation whose effect
	// is unknown, and applying the second as though it were the first
	// produces an image that is quietly missing a fixup.
	ErrUnsupportedReloc = errors.New("backend: relocation type not implemented")
)

// Backend is everything link needs to know about a machine.
type Backend interface {
	// Machine and SubArch are the pair this backend is registered on. There
	// is no fallback from a specific subarch to a generic one: a backend
	// decides which ABI a call site speaks, and answering for the wrong ABI
	// produces code that links and crashes at the boundary.
	Machine() pe.Machine
	SubArch() pe.SubArch

	// Classify says what kind of thing a relocation type is, in terms link
	// can reason about without knowing the machine.
	Classify(typ uint16) Kind

	// Scan walks the image before layout and records what the link will
	// need: IAT slots, import thunks, base relocation sites, TLS fixups,
	// guard targets. It reads sizes and never addresses, because it runs
	// while the image is open.
	Scan(img *image.Image, reqs *Reqs) error

	// Apply writes one relocation into a chunk's bytes. It runs frozen, so
	// every address it needs is final.
	Apply(s *Site, r image.Reloc) error

	// BaseRelocKind returns the base relocation a relocation needs, and
	// false when it needs none.
	//
	// This is on the interface rather than a switch in link because the
	// mapping is not one-to-one and getting it wrong is silent. An ADDR64
	// becomes DIR64. An ADDR32 becomes HIGHLOW *even on a 64-bit machine* —
	// a case that has been an actual bug in shipping linkers, where an
	// ADDR32 on AMD64 produced no base relocation at all and the image ran
	// correctly at its preferred base and faulted the moment ASLR moved it.
	// A REL32 becomes nothing, because a displacement between two things in
	// the same image does not change when the image does.
	BaseRelocKind(r image.Reloc) (pe.BaseRelocKind, bool)

	// ImportThunk is the shape of the thunk that jumps through an IAT slot:
	// the code a call to an unprefixed imported name lands in when the
	// compiler was not told to use __declspec(dllimport).
	ImportThunk() ThunkShape

	// UnwindEntrySize is one .pdata record's width: 12 bytes on x64 and 8
	// on ARM64 and ARMNT. The sort in fill is over fixed-width records and
	// needs the width.
	UnwindEntrySize() int

	// WordSize is the machine's pointer size in bytes. Register checks it
	// against the machine's own width, since the two disagreeing is a
	// build-configuration mistake that would otherwise surface as a wrong
	// file much later.
	WordSize() int
}

// Thunker is implemented by a backend whose branches cannot always reach their
// target.
//
// The split is real work, not bookkeeping. On x64 a REL32 displacement is a
// signed 32-bit field, so a branch reaches ±2 GB — further than any image can
// be — and no veneer is ever needed, which keeps the layout fixpoint trivial:
// assign once and stop. On AArch64 a BRANCH26 reaches ±128 MB, a conditional
// BRANCH19 ±1 MB, and a TBZ ±32 KB, so veneers are routine, veneers grow the
// sections they live in, and growth can put another branch out of range. That
// backend must implement this and the fixpoint is not optional.
type Thunker interface {
	// ThunkSize is the bytes one range-extension thunk occupies.
	ThunkSize() int

	// ThunkAlign is the alignment a thunk requires.
	ThunkAlign() int

	// InRange reports whether a relocation of this type, applied at from,
	// can reach to.
	InRange(typ uint16, from, to pe.RVA) bool

	// WriteThunk emits a veneer at s that jumps to the target.
	WriteThunk(s *Site, to pe.RVA) error
}

// Hybrid is implemented by a backend for a target carrying two views.
type Hybrid interface {
	// EntryThunkOffset is where a function's entry-thunk pointer sits
	// relative to the function.
	//
	// On ARM64EC it is the four bytes *before* the function: the emulator
	// reads them, masks the low two bits, and adds. The linker writes those
	// bytes and the compiler supplies the thunks they point at.
	EntryThunkOffset() int
}

// AsThunker returns b as a Thunker, or nil.
func AsThunker(b Backend) Thunker {
	t, _ := b.(Thunker)
	return t
}

// AsHybrid returns b as a Hybrid, or nil.
func AsHybrid(b Backend) Hybrid {
	h, _ := b.(Hybrid)
	return h
}

// key is the pair a backend is registered on.
type key struct {
	machine pe.Machine
	sub     pe.SubArch
}

var registry = map[key]Backend{}

// Register records a backend. It is called from a backend package's init, so
// that a blank import is what makes a machine available.
//
// It panics on a duplicate pair, and on a WordSize that disagrees with the
// machine's own width. Both are build-configuration mistakes rather than
// runtime conditions: neither can be caused by an input file, neither has a
// sensible recovery, and both would otherwise surface as a wrong output file
// long after the cause.
func Register(b Backend) {
	k := key{b.Machine(), b.SubArch()}
	if _, dup := registry[k]; dup {
		panic("backend: duplicate registration for " + k.String())
	}
	if got, want := b.WordSize(), b.Machine().Width().Bytes(); got != want {
		panic("backend: " + k.String() + " reports WordSize " + strconv.Itoa(got) +
			" but its machine is " + strconv.Itoa(want*8) + "-bit")
	}
	if b.SubArch() != b.Machine().SubArch() {
		panic("backend: " + k.String() + " registers a subarch its machine does not require")
	}
	registry[k] = b
}

// For returns the backend for a target.
//
// The lookup is on the (machine, subarch) pair with no fallback. A target
// asking for the EC ABI and getting a generic ARM64 backend would link, and
// every call across the boundary would use the wrong convention.
func For(t pe.Target) (Backend, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	b, ok := registry[key{t.Machine, t.SubArch}]
	if !ok {
		return nil, &NoBackendError{Machine: t.Machine, SubArch: t.SubArch}
	}
	return b, nil
}

// Registered returns the machine/subarch pairs a backend exists for, for a
// diagnostic that can say what *is* available.
func Registered() []pe.Target {
	out := make([]pe.Target, 0, len(registry))
	for k := range registry {
		out = append(out, pe.Target{Machine: k.machine, SubArch: k.sub})
	}
	return out
}

func (k key) String() string { return k.machine.String() + "/" + k.sub.String() }

// NoBackendError names the target that had no backend.
type NoBackendError struct {
	Machine pe.Machine
	SubArch pe.SubArch
}

func (e *NoBackendError) Error() string {
	return "backend: no backend registered for " + e.Machine.String() + "/" + e.SubArch.String() +
		" (is the backend package imported?)"
}

func (e *NoBackendError) Unwrap() error { return ErrNoBackend }