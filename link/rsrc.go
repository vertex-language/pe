package link

import (
	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/image"
	"github.com/vertex-language/pe/internal/format"
	"github.com/vertex-language/pe/rsrc"
)

// Resources are the one synthesized table whose contents come from outside the
// link entirely. rsrc parses the .res, builds the whole tree, and hands back
// bytes plus a short list of the fields that need an address — so this pass is
// a placement and a patch rather than a construction.
//
// That shape is why rsrc is a package and not a file in here. Everything else
// link synthesizes is a function of the symbol table; a resource tree is a
// function of its input, and the only thing it needs from the link is where it
// landed.

// manifestResourceType is RT_MANIFEST.
const manifestResourceType = 24

// The manifest's resource name depends on what is being built: an executable's
// is 1 and a DLL's is 2. Getting it backwards produces an image whose manifest
// the activation context never finds, and the symptom is a program that runs
// with the wrong common-controls version rather than one that fails.
const (
	manifestNameEXE = 1
	manifestNameDLL = 2
)

// manifestLanguage is the language id the manifest resource carries. Zero is
// language-neutral and would be defensible; 1033 is what link.exe and lld both
// write, and a manifest is not a thing anyone localizes.
const manifestLanguage = 1033

// resources is the .rsrc synthetic.
type resources struct {
	l *Linker

	data   []byte
	fixups []rsrc.Fixup
	chunk  *image.Chunk
}

func (r *resources) Size() uint32 { return uint32(len(r.data)) }

// Align is four. The directory is an array of DWORD-keyed structures and the
// loader indexes it; the data blobs inside carry their own alignment, which
// rsrc applied when it laid them out.
func (r *resources) Align() int { return 4 }

// Bytes returns the tree with its RVA fields still zero. Generate patches them
// once the chunk has an address — which is the whole reason those fields came
// back as a list instead of being filled in rsrc.
func (r *resources) Bytes() ([]byte, error) { return r.data, nil }

// Prepare parses every .res, merges them into one tree, and reserves a chunk.
//
// The merge is why the tree is built here rather than once per input. A
// program's resources routinely arrive as several .res files — one from the
// build, one carrying the manifest, one carrying the version block — and the
// image has exactly one resource directory. Building a tree per file and
// concatenating them would produce several level-one directories, of which the
// loader would find the first.
func (r *resources) Prepare(img *image.Image) error {
	l := r.l
	if len(l.res) == 0 && l.opt.Manifest != ManifestEmbed {
		return nil
	}

	tree := rsrc.NewTree()
	for _, res := range l.res {
		parsed, err := rsrc.ParseRes(res.Data)
		if err != nil {
			return l.fail(&InputError{Name: res.Name, Err: err})
		}
		if err := tree.AddAll(parsed); err != nil {
			return l.fail(&InputError{Name: res.Name, Err: err})
		}
	}

	if l.opt.Manifest == ManifestEmbed {
		if err := r.addManifest(tree); err != nil {
			return err
		}
	}

	data, fixups, err := tree.Build()
	if err != nil {
		return l.fail(&InputError{Name: "<resources>", Err: err})
	}
	r.data, r.fixups = data, fixups

	// .rsrc is read-only and not discardable. The loader does not drop it
	// after load the way it drops .reloc: LoadString and FindResource read
	// it at any point in the process's life, so a discardable resource
	// section is a fault the first time a dialog opens.
	sec, err := l.section(".rsrc", pe.SecInitData, pe.SecRead)
	if err != nil {
		return err
	}
	r.chunk = image.NewChunk(".rsrc", "<link>", r)
	r.chunk.Reachable = true
	if err := sec.Add(r.chunk); err != nil {
		return l.fail(err)
	}
	l.chunks = append(l.chunks, r.chunk)
	return nil
}

// addManifest places the caller's manifest as an RT_MANIFEST resource.
//
// /MANIFEST:EMBED is the only mode that reaches here. The external mode writes
// a file beside the image, which this package cannot do — it returns an image
// rather than touching the filesystem — so that mode reserves the name and
// leaves the writing to the caller.
//
// A manifest already present in a .res wins. A build that supplies one both
// ways has said the same thing twice and the .res is the more specific answer;
// replacing it with the option's would discard a manifest someone compiled
// deliberately.
func (r *resources) addManifest(tree *rsrc.Tree) error {
	name := uint16(manifestNameEXE)
	if r.l.opt.Kind == OutputDLL {
		name = manifestNameDLL
	}
	err := tree.Add(rsrc.Resource{
		Type:     format.NewResOrdinal(manifestResourceType),
		Name:     format.NewResOrdinal(name),
		Language: manifestLanguage,
		Data:     r.l.opt.ManifestData,
	})
	if err != nil {
		r.l.warn("an RT_MANIFEST resource is already present; " +
			"/MANIFEST:EMBED did not replace it")
	}
	return nil
}

// Generate patches the one field per resource that holds an address.
//
// It runs frozen, so the chunk's RVA is final. Every other offset in the tree
// was final when rsrc.Build returned, because they are relative to the
// directory's own start — which is the property that let the tree be sized
// before it was placed.
func (r *resources) Generate(img *image.Image) error {
	if r.chunk == nil {
		return nil
	}
	rva, err := r.chunk.RVA()
	if err != nil {
		return err
	}
	out, err := img.AtRVA(rva, len(r.data))
	if err != nil {
		return err
	}
	copy(out, r.data)

	for _, f := range r.fixups {
		if uint64(f.Off)+4 > uint64(len(out)) {
			return r.l.fail(&image.LayoutError{
				Section: ".rsrc",
				Reason:  "resource fixup falls outside the directory",
				RVA:     rva,
			})
		}
		v := uint32(rva) + f.Rel
		out[f.Off+0] = byte(v)
		out[f.Off+1] = byte(v >> 8)
		out[f.Off+2] = byte(v >> 16)
		out[f.Off+3] = byte(v >> 24)
	}
	return nil
}

// Dirs returns the resource data directory entry.
//
// Its size covers the whole tree — directories, descriptors, names, and the
// data — rather than just the directory table. The loader bounds every offset
// it follows against this extent, so a size stopping at the tables makes every
// resource look like it points outside the directory.
func (r *resources) Dirs() []dirEntry {
	if r.chunk == nil {
		return nil
	}
	rva, err := r.chunk.RVA()
	if err != nil {
		return nil
	}
	return []dirEntry{{pe.DirResource, rva, uint32(len(r.data))}}
}