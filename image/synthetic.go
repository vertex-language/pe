package image

// Synthetic is a chunk the linker generates rather than reads: .idata, .edata,
// .reloc, the load config's tables, the DVRT.
//
// It is a two-step interface, and the two steps exist because of a
// circularity. An IAT slot's *size* is known before layout — it is one pointer
// — while its *content* is an RVA that layout has not assigned yet. One-step
// generation cannot break that: producing the bytes requires addresses, and
// producing addresses requires the sizes.
//
//	Prepare  runs while the image is open. It settles Size and Align, and
//	         may create chunks and sections. It must not read an address.
//	Generate runs after Freeze. Every address is final; it fills the bytes.
//
// A synthetic whose size changes between Prepare and Generate breaks layout
// silently, which is why Size is fixed by the first and the second is handed
// a buffer rather than asked for one.
type Synthetic interface {
	ChunkSource

	// Prepare settles this synthetic's size. It runs in the open phase,
	// before Seal, and reading any RVA from it yields ErrNoRVA.
	Prepare(*Image) error

	// Generate fills the bytes. It runs frozen, so every address the
	// content needs is available.
	Generate(*Image) error
}

// Finalizer runs after every other byte of the image is final.
//
// Registration order is load-bearing rather than incidental. The .pdata sort
// and the guard-table sorts must both complete before the data directories are
// filled, because a directory's size covers a table whose extent the sort can
// change; and the header checksum must be computed after the directories,
// because it covers them. Running these in an arbitrary order produces an
// image that is wrong in a way only the loader notices.
type Finalizer interface {
	Finalize(*Image) error
}

// AddSynthetic registers a synthetic contribution. It is valid only while the
// image is open.
func (img *Image) AddSynthetic(s Synthetic) error {
	if img.phase != phaseOpen {
		return ErrPhase
	}
	img.synthetics = append(img.synthetics, s)
	return nil
}

// AddFinalizer registers a pass to run once every byte is final. Passes run in
// registration order.
func (img *Image) AddFinalizer(f Finalizer) error {
	if img.phase == phaseFrozen {
		return ErrPhase
	}
	img.finalizers = append(img.finalizers, f)
	return nil
}

// Prepare runs every registered synthetic's Prepare, in registration order.
//
// A synthetic may register another during its own Prepare — the delay-load
// tables register the descriptors they need — so the loop reads the slice by
// index and re-checks its length rather than ranging over a snapshot. It
// terminates because registration is monotonic and each synthetic prepares
// once.
func (img *Image) Prepare() error {
	if img.phase != phaseOpen {
		return ErrPhase
	}
	for i := 0; i < len(img.synthetics); i++ {
		if err := img.synthetics[i].Prepare(img); err != nil {
			return err
		}
	}
	return nil
}

// Generate runs every registered synthetic's Generate, in registration order.
// The image must be frozen.
func (img *Image) Generate() error {
	if img.phase != phaseFrozen {
		return ErrNotFrozen
	}
	for _, s := range img.synthetics {
		if err := s.Generate(img); err != nil {
			return err
		}
	}
	return nil
}

// Finalize runs every registered Finalizer, in registration order.
func (img *Image) Finalize() error {
	if img.phase != phaseFrozen {
		return ErrNotFrozen
	}
	for _, f := range img.finalizers {
		if err := f.Finalize(img); err != nil {
			return err
		}
	}
	return nil
}