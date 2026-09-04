package rsrc_test

import (
	"os"
	"testing"

	"github.com/vertex-language/pe/internal/format"
	"github.com/vertex-language/pe/rsrc"
)

func TestAddAndBuild(t *testing.T) {
	tree := rsrc.NewTree()
	res := []rsrc.Resource{
		{Type: format.NewResOrdinal(10) /* RT_RCDATA */, Name: format.NewResName("BLOB1"), Language: 0x409, Data: []byte("hello")},
		{Type: format.NewResOrdinal(10), Name: format.NewResName("BLOB2"), Language: 0x409, Data: []byte("world, a bit longer")},
	}
	if err := tree.AddAll(res); err != nil {
		t.Fatalf("AddAll: %v", err)
	}

	data, fixups, err := tree.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Build returned no bytes")
	}
	if len(fixups) != len(res) {
		t.Fatalf("got %d fixups, want %d (one per resource data entry)", len(fixups), len(res))
	}
	for _, f := range fixups {
		if f.Off >= uint32(len(data)) {
			t.Errorf("fixup offset %d is outside the %d-byte blob", f.Off, len(data))
		}
		if f.Rel >= uint32(len(data)) {
			t.Errorf("fixup target %d is outside the %d-byte blob", f.Rel, len(data))
		}
	}

	// Both resource payloads must appear somewhere in the built blob.
	if !contains(data, []byte("hello")) {
		t.Error("built blob does not contain the first resource's bytes")
	}
	if !contains(data, []byte("world, a bit longer")) {
		t.Error("built blob does not contain the second resource's bytes")
	}
}

func TestAddDuplicateRejected(t *testing.T) {
	tree := rsrc.NewTree()
	r := rsrc.Resource{Type: format.NewResOrdinal(10), Name: format.NewResName("BLOB"), Language: 0x409, Data: []byte("a")}
	if err := tree.Add(r); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := tree.Add(r); err == nil {
		t.Fatal("second Add with the same (type,name,language) succeeded, want ErrDuplicateResource")
	}
}

func TestBuildEmptyTreeRejected(t *testing.T) {
	tree := rsrc.NewTree()
	if _, _, err := tree.Build(); err == nil {
		t.Error("Build on a tree with no resources added should fail")
	}
}

func TestParseResRejectsGarbage(t *testing.T) {
	if _, err := rsrc.ParseRes([]byte{1, 2, 3}); err == nil {
		t.Error("ParseRes accepted a truncated/garbage buffer")
	}
}

// TestParseRealWindresOutput reads a .res file produced by the real
// mingw-w64 windres, if installed, and round-trips it through the tree
// builder.
func TestParseRealWindresOutput(t *testing.T) {
	data, err := os.ReadFile("/tmp/pesmoke/test.res")
	if err != nil {
		t.Skip("no windres-generated .res fixture available (see /tmp/pesmoke/test.res)")
	}

	resources, err := rsrc.ParseRes(data)
	if err != nil {
		t.Fatalf("ParseRes: %v", err)
	}
	if len(resources) == 0 {
		t.Fatal("ParseRes found no resources in windres output")
	}

	tree := rsrc.NewTree()
	if err := tree.AddAll(resources); err != nil {
		t.Fatalf("AddAll: %v", err)
	}
	built, fixups, err := tree.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(built) == 0 {
		t.Error("Build produced no bytes for real windres resources")
	}
	if len(fixups) != len(resources) {
		t.Errorf("got %d fixups, want %d (one per resource)", len(fixups), len(resources))
	}
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
