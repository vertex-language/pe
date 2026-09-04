package image

import "github.com/vertex-language/pe"

// A View is one interpretation of an image.
//
// Every image has at least one. An ARM64X image has two — native and EC — and
// is one file that answers differently depending on who loaded it: the same
// bytes are an ARM64 module to a native process and an AMD64 module to an
// emulated one. The difference between the two views is not stored as two
// copies of anything; it is recorded as a dynamic value relocation table that
// the kernel applies while mapping, so the file still has one of everything.
//
// The mechanism is smaller than it sounds. The COFF header's Machine field
// sits at a fixed RVA, and a single DVRT entry overwrites those two bytes with
// 0x8664 when the image is loaded into an emulated process. The export and
// exception directories and the load config are patched the same way, which is
// why each of them is a field here rather than only on the Image.
type View struct {
	// Machine is the value this view's COFF header reports. For the native
	// view of an ARM64X image that is ARM64, which is what the file
	// literally contains; the EC view reports AMD64, which is what the DVRT
	// patches it to.
	Machine pe.Machine

	// Name is "native" or "ec", for diagnostics.
	Name string

	// Symbols is this view's namespace. The two views of a hybrid image are
	// resolved independently and against separate tables: the same name may
	// have a native definition and an EC one, which is exactly the case
	// ARM64EC's mangling exists to express.
	Symbols *SymbolTable

	// Entry is this view's entry point RVA, or zero for a DLL without one.
	// The two views may disagree, and when they do the EC answer reaches
	// the loader through the CHPE metadata's AlternateEntryPoint rather
	// than through the optional header.
	Entry pe.RVA

	// The three directories a view may answer differently for. Where the
	// views agree there is one value and no fixup; where they disagree the
	// difference becomes a DVRT entry over the directory's own bytes.
	Export    DirValue
	Exception DirValue
	LoadConfig DirValue
}

// DirValue is one data directory's answer for one view: an address and a size.
type DirValue struct {
	RVA  pe.RVA
	Size uint32
}

// IsZero reports whether the directory is absent.
func (d DirValue) IsZero() bool { return d.RVA == 0 && d.Size == 0 }

// newView returns a view with an empty symbol table.
func newView(name string, m pe.Machine) *View {
	return &View{Name: name, Machine: m, Symbols: NewSymbolTable()}
}

// Views returns the image's views: one, or two for a hybrid image, native
// first.
func (img *Image) Views() []*View { return img.views }

// Native returns the view a native process sees. For a non-hybrid image it is
// the only view.
func (img *Image) Native() *View { return img.views[0] }

// EC returns the view an emulated x64 process sees, or nil for a non-hybrid
// image.
//
// Callers check for nil rather than asking Hybrid first, because the two
// questions have the same answer and only one of them hands back the thing
// needed next.
func (img *Image) EC() *View {
	if len(img.views) < 2 {
		return nil
	}
	return img.views[1]
}

// Hybrid reports whether the image carries two views.
func (img *Image) Hybrid() bool { return len(img.views) > 1 }

// ViewFor returns the view an input of the given machine belongs to.
//
// Routing is by machine type and there is no per-input override, because an
// object's machine already says which view it belongs to and accepting a
// second answer only creates a way for the two to disagree. ARM64 goes native;
// ARM64EC and AMD64 go to the EC view, which is why an ordinary x64 object can
// be linked into a hybrid image at all.
//
// It reports false for a machine that fits neither view, which link turns into
// a *ViewError naming the input.
func (img *Image) ViewFor(m pe.Machine) (*View, bool) {
	if !img.Hybrid() {
		v := img.views[0]
		if m == v.Machine || m == img.Cfg.Target.Machine {
			return v, true
		}
		return nil, false
	}
	switch m {
	case pe.MachineARM64:
		return img.views[0], true
	case pe.MachineARM64EC, pe.MachineAMD64:
		return img.views[1], true
	}
	return nil, false
}

// initViews builds the view set for a target. It is called by New.
func initViews(t pe.Target) []*View {
	if !t.Hybrid() {
		return []*View{newView("native", t.Machine.ImageMachine())}
	}
	// The native view carries what the file literally holds; the EC view
	// carries what the DVRT patches it into. ImageMachine gives the first
	// directly and the second is AMD64 by the same rule that marks a pure
	// ARM64EC image.
	return []*View{
		newView("native", pe.MachineARM64),
		newView("ec", pe.MachineAMD64),
	}
}