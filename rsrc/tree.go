package rsrc

import (
	"sort"
	"strings"

	"github.com/vertex-language/pe/internal/format"
)

// The resource tree is three levels deep and the depth is fixed by the format
// rather than by the data: type, then name, then language. A resource with no
// language still occupies a language level, with whatever id the .res carried,
// because FindResourceEx reaches the leaf by all three keys and a two-level
// tree has nowhere to put the third.
//
// Every directory's entries are two sorted runs — named first, then ordinal —
// and each run is sorted within itself. That is a load requirement and not a
// convention: the loader binary-searches each run using the counts in the
// directory header, so an unsorted run makes lookups miss resources that are
// present. Build sorts; it does not trust the order the .res arrived in.

// Tree is a resource directory under construction.
type Tree struct {
	root dirNode
}

// dirNode is one directory.
type dirNode struct {
	entries []*entryNode
}

// entryNode is one directory entry: an identifier and either a subdirectory or
// a leaf. Exactly one of dir and data is set.
type entryNode struct {
	id   format.ResID
	dir  *dirNode
	data *Data

	// nameOff is the string's position within the built blob, assigned by
	// Build and meaningless before it.
	nameOff uint32
}

// Data is a leaf: the bytes and the fields of its IMAGE_RESOURCE_DATA_ENTRY.
type Data struct {
	Bytes    []byte
	CodePage uint32

	// descOff and dataOff are positions within the built blob.
	descOff uint32
	dataOff uint32
}

// NewTree returns an empty tree.
func NewTree() *Tree { return &Tree{} }

// Add places one resource. It reports ErrDuplicateResource if the triple is
// already occupied.
func (t *Tree) Add(r Resource) error {
	typ := t.root.child(r.Type)
	name := typ.child(r.Name)
	lang := format.NewResOrdinal(r.Language)

	if e := name.find(lang); e != nil {
		return &ResourceError{
			Type: r.Type.String(), Name: r.Name.String(),
			Err: ErrDuplicateResource,
		}
	}
	name.entries = append(name.entries, &entryNode{
		id:   lang,
		data: &Data{Bytes: r.Bytes(), CodePage: r.CodePage},
	})
	return nil
}

// Bytes returns the resource's data. It exists so Add does not reach into the
// struct twice and so a future copy-on-add is one line.
func (r Resource) Bytes() []byte { return r.Data }

// AddAll places every resource in a .res.
func (t *Tree) AddAll(rs []Resource) error {
	for _, r := range rs {
		if err := t.Add(r); err != nil {
			return err
		}
	}
	return nil
}

// child returns the subdirectory under this identifier, creating it if this is
// the first resource to need it.
func (d *dirNode) child(id format.ResID) *dirNode {
	if e := d.find(id); e != nil {
		return e.dir
	}
	sub := &dirNode{}
	d.entries = append(d.entries, &entryNode{id: id, dir: sub})
	return sub
}

func (d *dirNode) find(id format.ResID) *entryNode {
	for _, e := range d.entries {
		if sameID(e.id, id) {
			return e
		}
	}
	return nil
}

// sameID compares two identifiers.
//
// A name and an ordinal are never equal, whatever they spell: a resource named
// "1" and one with ordinal 1 are different resources and live in different
// runs of the directory. Names compare case-insensitively, because that is how
// the loader compares them — FindResource("Foo") finds a resource stored as
// "FOO" — so treating them as distinct here would build a tree with two
// entries the loader cannot tell apart.
func sameID(a, b format.ResID) bool {
	if a.IsName != b.IsName {
		return false
	}
	if !a.IsName {
		return a.Ordinal == b.Ordinal
	}
	return strings.EqualFold(a.Name, b.Name)
}

// sortDir orders one directory's entries: named entries first, then ordinals,
// each run sorted.
//
// The named run's comparison is case-insensitive for the same reason the
// equality test is, and ties are impossible because sameID already rejected
// them at Add.
//
// UNVERIFIED: rc.exe and link.exe uppercase resource names before storing
// them, so a real image's named entries are all uppercase and the ordering
// question does not arise. This preserves the case it was given and sorts
// case-insensitively, which agrees with link.exe on every input link.exe can
// produce and differs on inputs only this tree can. It should be checked
// against a .res carrying mixed-case names before it is trusted.
func sortDir(d *dirNode) {
	sort.SliceStable(d.entries, func(i, j int) bool {
		a, b := d.entries[i].id, d.entries[j].id
		if a.IsName != b.IsName {
			return a.IsName
		}
		if a.IsName {
			return strings.ToUpper(a.Name) < strings.ToUpper(b.Name)
		}
		return a.Ordinal < b.Ordinal
	})
	for _, e := range d.entries {
		if e.dir != nil {
			sortDir(e.dir)
		}
	}
}

// counts returns the directory's named and ordinal entry counts, which the
// header states separately because the loader searches the two runs
// separately.
func (d *dirNode) counts() (named, ids uint16) {
	for _, e := range d.entries {
		if e.id.IsName {
			named++
			continue
		}
		ids++
	}
	return named, ids
}