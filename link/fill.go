package link

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
)

// Fill is the last pass over the model and the first that treats the image as
// finished. It runs the finalizers and then writes the sixteen data
// directories from final RVAs.
//
// The directories are filled here, once, rather than by each synthetic as it
// generates. That is not tidiness. A directory's size covers a table whose
// extent a finalizer can change — the exception table is sorted in place after
// apply, and the guard tables were sorted before it — so a synthetic that
// recorded its own entry at Generate would be recording an extent a later pass
// moved. Collecting after every finalizer has run makes the ordering a
// property of this one function instead of an assumption spread across seven.
//
// Two directories are never written here. The certificate table holds a file
// offset rather than an RVA, names bytes that are not mapped, and is appended
// to a finished image by authenticode without disturbing a byte of layout — so
// link reserves nothing for it, and image.DataDir.Set refuses it by type
// rather than by convention. The architecture and reserved slots are refused
// the same way.
//
// The checksum is not run from here either, and that is the one ordering in
// the pipeline that a finalizer cannot express. It covers the whole file, the
// dynamic relocation table writes into the headers, and the headers do not
// exist until emit — so the checksum runs after both, as the literal last
// statement of Link.

// dirProvider is a pass that owns one or more data directory entries.
//
// Every table collects through this interface rather than by name, so that
// adding one is adding a method and a line in synth rather than editing a list
// that some other file also has to agree with.
type dirProvider interface {
	Dirs() []dirEntry
}

// fill runs the finalizers and writes the data directories.
func (l *Linker) fill() error {
	if err := l.img.Finalize(); err != nil {
		return l.fail(err)
	}

	// The order of l.dirs decides nothing: entries are indexed by
	// directory and no two providers may claim the same one, which is
	// checked rather than trusted.
	seen := make(map[pe.DataDirIndex]bool, pe.NumDataDirs)
	for _, p := range l.dirs {
		if p == nil {
			continue
		}
		for _, d := range p.Dirs() {
			if seen[d.Index] {
				// Two passes claiming one directory produces an
				// image describing whichever ran last, with
				// nothing anywhere to say the other table
				// exists. It is a linker bug and it is silent,
				// which is the combination worth a check.
				return l.fail(&image.LayoutError{
					Reason: "data directory " + d.Index.String() +
						" is claimed by two passes",
					RVA: d.RVA,
				})
			}
			seen[d.Index] = true
			if err := l.img.Dirs.Set(d.Index, d.RVA, d.Size); err != nil {
				return l.fail(err)
			}
		}
	}

	l.fillViews()
	return nil
}

// fillViews records the per-view answers for the three directories a hybrid
// image can disagree about.
//
// For a single-view image this copies what fill just wrote. For an ARM64X
// image a view may already carry its own answer, recorded during resolve or by
// a pass that built a second table — and where the two differ, arm64x.go turns
// the difference into a dynamic relocation over the directory's own bytes.
// That is why the values live on the View and why the array is not duplicated:
// the file has one of everything and a list of the words that would change.
func (l *Linker) fillViews() {
	get := func(i pe.DataDirIndex) image.DirValue {
		rva, size, err := l.img.Dirs.Dir(i)
		if err != nil {
			return image.DirValue{}
		}
		return image.DirValue{RVA: rva, Size: size}
	}
	export, exception, loadcfg := get(pe.DirExport), get(pe.DirException), get(pe.DirLoadConfig)

	for _, v := range l.img.Views() {
		// A view that already answered keeps its answer. Only a view
		// that has none inherits the file's, which for the native view
		// is always the same value and for the EC view is the case
		// where the two halves genuinely share a table.
		if v.Export.IsZero() {
			v.Export = export
		}
		if v.Exception.IsZero() {
			v.Exception = exception
		}
		if v.LoadConfig.IsZero() {
			v.LoadConfig = loadcfg
		}
	}
}

// Dirs returns the base relocation directory entry.
//
// It lives in this file rather than beside the rest of baseRelocs because the
// size it reports is the one Generate actually wrote and not the upper bound
// Prepare reserved, and fill is the only caller that can tell the difference.
//
// The slack at the end of the chunk is zeroes. The loader walks blocks until
// the directory's size runs out, so reporting the reserved size would send it
// into the padding, where it would read a page RVA of zero and a block size of
// zero and never advance.
func (b *baseRelocs) Dirs() []dirEntry {
	if b.chunk == nil || b.written == 0 {
		return nil
	}
	rva, err := b.chunk.RVA()
	if err != nil {
		return nil
	}
	return []dirEntry{{pe.DirBaseReloc, rva, b.written}}
}