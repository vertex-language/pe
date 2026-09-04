package link

import (
	"github.com/vertex-language/pe/backend"
	"github.com/vertex-language/pe/image"
)

// Contents and apply are two passes over the same chunks, in that order, and
// the order is the whole design.
//
// Contents copies every live chunk's bytes into the output buffer and then
// lets the synthetics generate. Apply walks the relocations and patches what
// contents wrote. Splitting them matters because a relocation *adds* to the
// field it patches: COFF carries no addend, so the addend is whatever the
// compiler left in the bytes, and a pass that relocated a chunk before writing
// it would add to whatever the buffer happened to hold.
//
// It also matters for the synthetics. A synthetic's Generate runs inside the
// contents pass, which is why a synthetic writes finished bytes and never
// carries relocations: it already knows every address, so there is nothing for
// apply to do to it. The one apparent exception is the load config, whose
// fields are filled by the CRT's own relocations — but those belong to the
// CRT's chunk, which is an ordinary input, and apply patches it like any other.

// contents writes every live chunk and generates the synthetics.
//
// A chunk with no file content is skipped rather than zero-filled. The output
// buffer starts zeroed and a .bss can be megabytes; materializing it here
// would put in memory exactly the thing the format exists to keep out of the
// file.
func (l *Linker) contents() error {
	for _, c := range l.chunks {
		if !c.Live() || !c.HasContent() {
			continue
		}
		rva, err := c.RVA()
		if err != nil {
			return l.fail(&InputError{Name: c.Input, Err: err})
		}
		data, err := c.Bytes()
		if err != nil {
			return l.fail(&InputError{Name: c.Input, Err: err})
		}
		if data == nil {
			continue
		}
		if uint32(len(data)) != c.Size() {
			// The chunk was sized from a section header and the
			// bytes behind it disagree. Copying the short read
			// would leave the chunk's tail holding whatever the
			// buffer was initialized with, which is zeroes that
			// look exactly like legitimate padding.
			return l.fail(&InputError{
				Name: c.Input,
				Err: &image.LayoutError{
					Section: c.Name,
					Reason:  "chunk contents do not fill the size layout reserved",
					RVA:     rva,
				},
			})
		}
		out, err := l.img.AtRVA(rva, len(data))
		if err != nil {
			return l.fail(&InputError{Name: c.Input, Err: err})
		}
		copy(out, data)
	}

	if err := l.img.Generate(); err != nil {
		return l.fail(err)
	}

	// The veneers last, because a thunk's bytes are a function of the
	// addresses of everything else and the backend writes them directly
	// rather than through a ChunkSource.
	if t := backend.AsThunker(l.be); t != nil {
		if err := l.writeThunks(t); err != nil {
			return err
		}
	}
	return nil
}

// apply patches every relocation in every live chunk.
//
// One Site per chunk rather than one per relocation: a Site is a bounds-checked
// window on the chunk's output bytes, and building it costs an address lookup
// that would otherwise be repeated for every field in a section with ten
// thousand of them.
//
// The bounds are the chunk's and not the file's, which is the difference that
// matters. A relocation running past the end of its own chunk is a bug in the
// object or in the backend, and catching it at the file boundary would let it
// corrupt the neighbouring chunk first and fail only if it also ran off the
// end of the image.
func (l *Linker) apply() error {
	for _, c := range l.chunks {
		if !c.Live() || len(c.Relocs()) == 0 {
			continue
		}
		if !c.HasContent() {
			// A relocation against a chunk with no file content is
			// an object claiming .bss has contents to patch. There
			// is nothing there to write into, and NewSite would
			// fail with a less specific message.
			return l.fail(&InputError{
				Name: c.Input,
				Err: &image.LayoutError{
					Section: c.Name,
					Reason:  "relocations against a chunk with no file content",
				},
			})
		}
		site, err := backend.NewSite(l.img, c)
		if err != nil {
			return l.fail(&InputError{Name: c.Input, Err: err})
		}
		for _, r := range c.Relocs() {
			if err := l.applyOne(site, c, r); err != nil {
				return err
			}
		}
	}
	return l.applyEntryThunks()
}

// applyOne patches one relocation and gives the failure an input to name.
//
// The backend knows the chunk and the field; it does not know which object the
// chunk came from once merge has run. Adding that here is the difference
// between "a branch did not reach" and something a build can act on.
func (l *Linker) applyOne(site *backend.Site, c *image.Chunk, r image.Reloc) error {
	kind := l.be.Classify(r.Type)
	if kind.NeedsSymbol() && r.Sym == nil {
		return l.fail(&InputError{
			Name: c.Input,
			Err: &image.LayoutError{
				Section: c.Name,
				Reason:  "relocation of kind " + kind.String() + " names no symbol",
			},
		})
	}
	if err := l.be.Apply(site, r); err != nil {
		return l.fail(&OverflowError{Input: c.Input, Err: err})
	}
	return nil
}

// applyEntryThunks writes the four bytes before every ARM64EC function.
//
// Those bytes hold the relative address of the function's entry thunk: the
// emulator reads them, masks off the low two bits, and adds. The compiler
// supplies the thunks and places them in .wowthk$aa as discard COMDATs; what
// it cannot supply is the displacement, because neither address exists until
// now. The masking is why the value is stored relative rather than absolute
// and why it needs no base relocation.
//
// This is the only place in the pipeline where the linker writes code-adjacent
// bytes that no relocation named, which is why it is a step of its own rather
// than a case inside apply.
func (l *Linker) applyEntryThunks() error {
	h := backend.AsHybrid(l.be)
	if h == nil {
		return nil
	}
	return ErrUnimplemented
}