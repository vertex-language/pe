package pe

import "strings"

// Export is one exported name: what a .def EXPORTS definition, a /EXPORT
// option, and a __declspec(dllexport) directive all describe.
//
// It lives here rather than in def or implib because three packages need the
// same description and none of them owns it. def parses one, implib turns it
// into an import, and link places it in .edata — and a type defined in any of
// those would have to be converted at two of the three boundaries, which is
// two places for the Name/ExtName direction to get reversed.
//
// The zero value exports nothing: an Export with an empty Name is not a
// request to export the empty name, and consumers reject it.
type Export struct {
	// Name is the *internal* name: the symbol as the defining object spells
	// it. For an ordinary export this is also the name the DLL exports.
	//
	// The direction is worth stating because it reads backwards. In the
	// .def line `func2=func1` the DLL's own symbol is func1 and callers see
	// func2, so Name is func1 and ExtName is func2. The specification calls
	// the left side entryname and the right internal_name, and this field
	// is the right one.
	Name string

	// ExtName is the *exported* name when it differs from Name, and empty
	// when it does not. It is the left side of a .def alias.
	ExtName string

	// SymbolName overrides the symbol an importing object references, when
	// that differs from both names above. /EXPORT sets it; .def has no
	// syntax for it.
	SymbolName string

	// ImportName forces the name looked up in the exporting DLL. It comes
	// from the `==` form, which is an lld extension with no equivalent in
	// link.exe.
	ImportName string

	// ExportAs forces the exported name to be stored literally rather than
	// derived from the symbol by a prefix rule. It comes from EXPORTAS,
	// which is absent from the published specification and is how every
	// ARM64EC import library expresses the mangled/demangled pair.
	ExportAs string

	// Ordinal is the export ordinal, one-based, or zero for none. The space
	// is 16 bits and real projects have reached the end of it.
	Ordinal uint16

	// NoName exports by ordinal only, keeping the name out of the DLL's
	// export name table. GetProcAddress then works only by ordinal.
	NoName bool

	// Data marks an export that is data rather than code. It decides how
	// many symbols an import library member contributes, which is why
	// implib.Kind exists rather than a bool on the entry.
	Data bool

	// Constant marks an export as a constant. The specification documents
	// it as obsolete and link.exe warns (LNK4087); it is carried because
	// real .def files still contain it.
	Constant bool

	// Private keeps the export out of the import library generated
	// alongside the image. It does not affect the image's own export
	// directory.
	Private bool
}

// Forwarder reports whether this export forwards to another module, and
// returns the target if so.
//
// A forwarder is spelled as an alias whose internal name names another
// module: `func2=other.func1`, or `func2=other.#42` when that module exports
// by ordinal. The dot is the only marker the syntax provides, which is why
// this asks for an alias first — an unaliased name containing a dot is a
// symbol with a dot in it, not a forwarder.
//
// In the image the same ambiguity is resolved by position rather than by
// spelling: an export whose address RVA falls inside the export directory's
// own range is a forwarder, and the bytes there are this string.
func (e Export) Forwarder() (string, bool) {
	if e.ExtName == "" || !strings.Contains(e.Name, ".") {
		return "", false
	}
	return e.Name, true
}

// Exported returns the name this export presents to the outside: ExtName when
// an alias is present, Name otherwise.
func (e Export) Exported() string {
	if e.ExtName != "" {
		return e.ExtName
	}
	return e.Name
}