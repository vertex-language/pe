package link

import (
	"sort"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/internal/format"
)

// The exception table is the one linker output that is neither built nor
// filled but *reordered*.
//
// .pdata and .xdata round-trip as opaque bytes. The linker does three things
// to them: relocates the RVAs inside, which apply does; drops the entries
// whose function was swept, which split and sweep did by making each record a
// chunk of its own tied to the function it describes; and sorts the survivors
// by function start RVA, which is this file. Nothing here understands an
// unwind code, and nothing needs to.
//
// The sort is a correctness requirement. The runtime binary searches .pdata to
// find the unwind data for a faulting address, so an out-of-order table does
// not degrade to a linear scan — it misses, and the process dies with an
// unhandled exception at an address that has perfectly good unwind data twenty
// records away.
//
// It has to run last, and that is why this is a Finalizer rather than a
// Synthetic. The records are input bytes whose first word is an RVA supplied
// by a relocation, and apply runs after the contents pass. A sort performed at
// Generate would sort a table of zeroes into a table of zeroes. The guard
// tables in loadcfg.go are the opposite case — linker-built bytes over
// addresses that are final at Freeze — which is why they sort in Generate and
// this does not.
//
// Sorting the bytes rather than the chunks is deliberate. Chunk placement was
// decided at Assign and re-deciding it here would move addresses after Freeze,
// which is the mistake the phases exist to prevent. The records are
// fixed-width and self-contained: every pointer *into* a record moves with it,
// and nothing points *at* one, so permuting the array in place is safe in a
// way that permuting almost anything else in an image would not be.

// exceptionSection is the output section the records land in. The $ suffixes
// are gone by now; merge discarded them and used them to order the
// contributions this array is made of.
const exceptionSection = ".pdata"

// unwind is the exception table pass.
type unwind struct {
	l *Linker

	sec   *image.Section
	width uint32
	count uint32
	rva   pe.RVA
}

// Finalize sorts the exception table.
//
// It runs after apply, in registration order among the finalizers, and before
// the data directories are filled — because the directory's size covers a
// table whose extent this can change, and because the header checksum covers
// the directory.
func (u *unwind) Finalize(img *image.Image) error {
	l := u.l
	u.sec = sectionNamed(img, exceptionSection)
	if u.sec == nil {
		return nil
	}

	// The record width is the backend's because it is 12 bytes on x64 — a
	// start RVA, an end RVA, and an RVA to the unwind information — and 8
	// on ARM64 and ARMNT, whose second word packs the function length and
	// the unwind data together when it can.
	u.width = uint32(l.be.UnwindEntrySize())
	if u.width == 0 {
		return nil
	}

	rva, err := u.sec.RVA()
	if err != nil {
		return l.fail(err)
	}
	vsize, err := u.sec.VirtualSize()
	if err != nil {
		return l.fail(err)
	}
	u.rva = rva
	if vsize == 0 {
		return nil
	}
	if vsize%u.width != 0 {
		// Something that is not a whole number of records reached
		// .pdata: a section named .pdata by hand, or a record width
		// that disagrees with the objects. Sorting it would shear every
		// record after the offending byte.
		return l.fail(&image.LayoutError{
			Section: exceptionSection,
			Reason: "section length " + itoa(int(vsize)) +
				" is not a multiple of the " + itoa(int(u.width)) + "-byte unwind record",
			RVA: rva,
		})
	}
	if !rva.Aligned(format.RuntimeFunctionAlign) {
		return l.fail(&image.LayoutError{
			Section: exceptionSection,
			Reason:  "exception table is not DWORD aligned",
			RVA:     rva,
		})
	}

	if err := u.checkNoInboundRefs(); err != nil {
		return l.fail(err)
	}

	data, err := img.AtRVA(rva, int(vsize))
	if err != nil {
		return l.fail(err)
	}
	if err := u.sortRecords(data); err != nil {
		return l.fail(err)
	}
	u.count = vsize / u.width
	return nil
}

// checkNoInboundRefs refuses a sort that would break a reference into the
// table.
//
// Sorting moves records, so any address anybody holds into the middle of
// .pdata becomes an address of a different function's record. Nothing in a
// normal link holds one — the table is reached only through the exception
// directory — but MinGW's runtime and hand-written startup code have both been
// known to bracket it with symbols, and a silently permuted table under a
// symbol that still names its old position is a fault at unwind time with
// nothing to point at.
//
// A reference to the table's first byte is fine: that address is stable under
// any permutation, and it is how a bracketing symbol is usually spelled.
func (u *unwind) checkNoInboundRefs() error {
	for _, c := range u.l.chunks {
		if !c.Live() {
			continue
		}
		for _, r := range c.Relocs() {
			if r.Sym == nil {
				continue
			}
			t := r.Sym.Chunk()
			if t == nil || t.Section() != u.sec {
				continue
			}
			tr, err := t.RVA()
			if err != nil {
				continue
			}
			if tr == u.rva && r.Sym.Offset() == 0 {
				continue
			}
			return &image.LayoutError{
				Section: exceptionSection,
				Reason: "symbol " + r.Sym.Name + " points inside the exception table, " +
					"which sorting would move",
				RVA: tr,
			}
		}
	}
	return nil
}

// sortRecords orders the array in place by function start RVA.
//
// The key is the record's first 32-bit word, which is where every architecture
// Microsoft has defined puts it — so the sort needs the width and nothing else
// about the machine. That is the only thing this tree knows about the contents
// of an unwind record, and it is enough.
//
// The sort is stable. Two records can legitimately share a start RVA after
// /OPT:ICF folds two identical functions into one, and an unstable sort would
// make the output depend on the input order in a build whose entire premise is
// that it does not.
func (u *unwind) sortRecords(data []byte) error {
	n := len(data) / int(u.width)
	idx := make([]int, n)
	keys := make([]uint32, n)
	for i := range idx {
		idx[i] = i
		k, ok := format.FunctionStart(data[i*int(u.width):])
		if !ok {
			return &image.LayoutError{
				Section: exceptionSection,
				Reason:  "unwind record shorter than its start RVA",
				RVA:     u.rva,
			}
		}
		if k == 0 {
			// A record whose function start relocated to nothing.
			// It sorts to the front and every binary search that
			// lands on it reads unwind data for an address that is
			// not in the image, so this is refused rather than
			// emitted — sweep should have taken the record with the
			// function.
			return &image.LayoutError{
				Section: exceptionSection,
				Reason:  "unwind record has a zero function start RVA",
				RVA:     u.rva.Add(uint32(i) * u.width),
			}
		}
		keys[i] = k
	}

	sort.SliceStable(idx, func(a, b int) bool { return keys[idx[a]] < keys[idx[b]] })

	// Permute through a copy. An in-place permutation by cycles would
	// avoid the allocation and is not worth the way it reads: this runs
	// once over a table that is a few hundred kilobytes in a large image.
	out := make([]byte, len(data))
	w := int(u.width)
	for pos, src := range idx {
		copy(out[pos*w:(pos+1)*w], data[src*w:(src+1)*w])
	}
	copy(data, out)
	return nil
}

// Dirs returns the exception data directory entry.
//
// Its size covers the records and nothing else. The directory is how the
// runtime finds the table at all — there is no symbol for it and no count
// stored anywhere else — so a size that included the section's alignment
// padding would present a run of zero records past the end of the real ones.
func (u *unwind) Dirs() []dirEntry {
	if u.count == 0 {
		return nil
	}
	return []dirEntry{{pe.DirException, u.rva, u.count * u.width}}
}

// Views records the exception directory on each view, for a hybrid image.
//
// An ARM64X image can legitimately have two exception tables — the native
// functions and the EC ones unwind differently — and where the two views
// disagree the difference is a dynamic value relocation over the directory's
// own bytes. This tree emits one table and gives both views the same answer,
// which is correct for a pure ARM64 or pure EC image and is the case arm64x.go
// has to revisit.
func (u *unwind) Views(img *image.Image) {
	if u.count == 0 {
		return
	}
	v := image.DirValue{RVA: u.rva, Size: u.count * u.width}
	for _, view := range img.Views() {
		view.Exception = v
	}
}