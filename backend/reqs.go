package backend

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
)

// Reqs is what a backend's Scan tells link the image will need.
//
// It is filled while the image is open, so everything in it is a size or a
// count and nothing in it is an address. The tables it drives — the IAT,
// .reloc, the guard tables — must all be sized before layout and filled after
// it, which is the same two-step circularity image.Synthetic exists for.
type Reqs struct {
	iatSlots     []*image.Symbol
	importThunks []*image.Symbol
	baseRelocs   []BaseRelocSite
	guardTargets []*image.Symbol
	tlsFixups    []*image.Symbol

	iatSeen   map[*image.Symbol]bool
	thunkSeen map[*image.Symbol]bool
	guardSeen map[*image.Symbol]bool
	tlsSeen   map[*image.Symbol]bool
}

// NewReqs returns an empty Reqs.
func NewReqs() *Reqs {
	return &Reqs{
		iatSeen:   make(map[*image.Symbol]bool),
		thunkSeen: make(map[*image.Symbol]bool),
		guardSeen: make(map[*image.Symbol]bool),
		tlsSeen:   make(map[*image.Symbol]bool),
	}
}

// BaseRelocSite is one place an absolute pointer was written, and the kind of
// base relocation that fixes it.
//
// The address is not known when this is recorded — Scan runs open — so the
// site is a chunk and an offset, and .reloc resolves both to an RVA after
// Freeze. Recording an RVA here would record zero.
type BaseRelocSite struct {
	Chunk *image.Chunk
	Off   uint32
	Kind  pe.BaseRelocKind
}

// RVA returns the site's address, valid only after layout.
func (s BaseRelocSite) RVA() (pe.RVA, error) {
	r, err := s.Chunk.RVA()
	if err != nil {
		return 0, err
	}
	return r.Add(s.Off), nil
}

// NeedIATSlot records that an import needs an address-table entry.
//
// Slot liveness and thunk liveness are tracked separately, and that separation
// is the point of having two methods rather than one. A program that only ever
// calls through __imp_foo needs the slot and no thunk; one that calls the
// unprefixed name needs both. Collapsing them emits a thunk per import in
// every dllimport-only program, which is dead code in the image and a
// pointless entry in every table that walks .text.
func (r *Reqs) NeedIATSlot(sym *image.Symbol) {
	if sym == nil || r.iatSeen[sym] {
		return
	}
	r.iatSeen[sym] = true
	r.iatSlots = append(r.iatSlots, sym)
}

// NeedImportThunk records that an import is called by its unprefixed name and
// so needs a thunk jumping through its slot. It implies the slot.
func (r *Reqs) NeedImportThunk(sym *image.Symbol) {
	if sym == nil || r.thunkSeen[sym] {
		return
	}
	r.thunkSeen[sym] = true
	r.importThunks = append(r.importThunks, sym)
	r.NeedIATSlot(sym)
}

// NeedBaseReloc records an absolute pointer that must be fixed up if the image
// moves.
//
// Every one of these has to be recorded during Scan, not discovered during
// apply. Under /DYNAMICBASE an absolute pointer with no site is
// link.ErrUnrelocatable rather than an image that faults after ASLR moves it —
// but the check can only fire if .reloc knows what it should have contained,
// and by apply the table has already been sized.
func (r *Reqs) NeedBaseReloc(c *image.Chunk, off uint32, kind pe.BaseRelocKind) {
	if c == nil || kind == pe.BaseRelocAbsolute {
		return
	}
	r.baseRelocs = append(r.baseRelocs, BaseRelocSite{Chunk: c, Off: off, Kind: kind})
}

// NeedGuardTarget records an indirect call target for the CFG function table.
func (r *Reqs) NeedGuardTarget(sym *image.Symbol) {
	if sym == nil || r.guardSeen[sym] {
		return
	}
	r.guardSeen[sym] = true
	r.guardTargets = append(r.guardTargets, sym)
}

// NeedTLSFixup records a field of the TLS directory that holds a VA rather
// than an RVA.
//
// The TLS directory is the one place in an image where a stored address is a
// virtual address, so each of those fields needs a base relocation of its own.
// Forgetting them produces a binary that works at its preferred base and
// crashes under ASLR — the same failure as a missing ADDR32 fixup, from a
// different direction.
func (r *Reqs) NeedTLSFixup(sym *image.Symbol) {
	if sym == nil || r.tlsSeen[sym] {
		return
	}
	r.tlsSeen[sym] = true
	r.tlsFixups = append(r.tlsFixups, sym)
}

// Accessors. Each returns its slice in recording order, which for the IAT is
// the order slots are laid out and therefore the order the import name table
// must match.
func (r *Reqs) IATSlots() []*image.Symbol     { return r.iatSlots }
func (r *Reqs) ImportThunks() []*image.Symbol { return r.importThunks }
func (r *Reqs) BaseRelocs() []BaseRelocSite   { return r.baseRelocs }
func (r *Reqs) GuardTargets() []*image.Symbol { return r.guardTargets }
func (r *Reqs) TLSFixups() []*image.Symbol    { return r.tlsFixups }