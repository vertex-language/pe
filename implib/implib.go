package implib

import "strings"

// Kind is what an import refers to, and it decides how many symbols the member
// contributes — which is the whole reason the type exists.
//
// A data import defines __imp_$sym and nothing else: the compiler must have
// been told, with __declspec(dllimport), to go through the slot. A code import
// defines __imp_$sym *and* $sym, where $sym is a thunk jumping through the
// slot — the PE equivalent of a PLT entry — so that code calling the
// unprefixed name still links.
//
// That asymmetry is why implib.Entry has no "is it a function" bool.
type Kind uint8

const (
	KindCode  Kind = 0
	KindData  Kind = 1
	KindConst Kind = 2
)

func (k Kind) String() string {
	switch k {
	case KindCode:
		return "code"
	case KindData:
		return "data"
	case KindConst:
		return "const"
	}
	return "kind(" + itoa(int(k)) + ")"
}

// NameKind is the rule relating the symbol name stored in the member to the
// name the DLL actually exports.
type NameKind uint8

const (
	// NameOrdinal means the import is by ordinal and there is no exported
	// name at all.
	NameOrdinal NameKind = 0
	// NameExact means the exported name is the symbol name.
	NameExact NameKind = 1
	// NameNoPrefix means the exported name is the symbol name with one
	// leading '?', '@', or '_' removed.
	NameNoPrefix NameKind = 2
	// NameUndecorate means NoPrefix, and then truncated at the first '@'.
	// This is how a __stdcall function exported without its decoration is
	// described.
	NameUndecorate NameKind = 3
	// NameExportAs means the exported name is stored as a third string in
	// the member, because no rule relates it to the symbol.
	//
	// It is absent from the published specification. It is also how every
	// ARM64EC import library works: the symbol is the mangled name and the
	// export is the demangled one, and no prefix rule can express that.
	NameExportAs NameKind = 4
)

func (n NameKind) String() string {
	switch n {
	case NameOrdinal:
		return "ordinal"
	case NameExact:
		return "name"
	case NameNoPrefix:
		return "noprefix"
	case NameUndecorate:
		return "undecorate"
	case NameExportAs:
		return "exportas"
	}
	return "namekind(" + itoa(int(n)) + ")"
}

// Apply derives the exported name from a symbol name under this rule.
//
// It is not defined for NameExportAs, whose answer is stored rather than
// derived, or for NameOrdinal, which has no name; both return s unchanged and
// the caller is expected to have handled them.
func (n NameKind) Apply(s string) string {
	switch n {
	case NameNoPrefix:
		return trimOne(s, "?@_")
	case NameUndecorate:
		s = trimOne(s, "?@_")
		if i := strings.IndexByte(s, '@'); i >= 0 {
			return s[:i]
		}
		return s
	}
	return s
}

// trimOne removes at most one leading byte, and only if it is in set.
func trimOne(s, set string) string {
	if s != "" && strings.IndexByte(set, s[0]) >= 0 {
		return s[1:]
	}
	return s
}

// The ARM64EC name mangling an import library has to undo.
//
// Two forms, and the '#' one is the one people forget: a C function foo
// compiled as ARM64EC is #foo, while a C++ name has $$h inserted after the
// qualification. coff.ECDemangle handles the second; the first lives here
// because only import libraries produce it.
const ecHashPrefix = "#"

// ECDemangle returns the name the x64 side would use for an ARM64EC symbol,
// and whether the input was mangled at all.
func ECDemangle(name string) (string, bool) {
	if rest, ok := strings.CutPrefix(name, ecHashPrefix); ok {
		return rest, true
	}
	before, after, found := strings.Cut(name, "$$h")
	if !found {
		return name, false
	}
	return before + after, true
}

// ECMangle returns the ARM64EC form of a name, and whether mangling applied.
// A name already carrying either mark is returned unchanged.
func ECMangle(name string) (string, bool) {
	if _, mangled := ECDemangle(name); mangled {
		return name, false
	}
	if name == "" {
		return name, false
	}
	if name[0] == '?' {
		// A C++ mangled name takes $$h after the qualification, which
		// this package does not parse. The caller supplies the mangled
		// form for those; only the C shape is derivable here.
		return name, false
	}
	return ecHashPrefix + name, true
}

// Entry is one import.
type Entry struct {
	// Symbol is the name as stored in the member: the name the importing
	// object references, before any prefix is added.
	Symbol string

	// DLL is the library the import comes from.
	DLL string

	Kind     Kind
	NameKind NameKind

	// Ordinal is the ordinal when NameKind is NameOrdinal, and a hint into
	// the exporting DLL's name table otherwise. The two share one wire
	// field and NameKind decides which it is.
	Ordinal uint16

	// ExportName is the third string, present only for NameExportAs.
	ExportName string

	// Machine is the member's machine type. It is per-member, not
	// per-archive: an ARM64EC import library holds ARM64EC members
	// alongside ARM64 ones.
	Machine uint16
}

// Exported returns the name the DLL exports for this entry, or "" for an
// ordinal-only import.
func (e Entry) Exported() string {
	switch e.NameKind {
	case NameOrdinal:
		return ""
	case NameExportAs:
		return e.ExportName
	}
	return e.NameKind.Apply(e.Symbol)
}

// Symbols returns the symbol names this member contributes to a link.
//
// A data or const import contributes one. A code import contributes two: the
// slot and a thunk through it. An ARM64EC code import contributes four — the
// slot, the thunk, an auxiliary slot for the x64 view, and the mangled thunk —
// because the EC and native namespaces are separate and the same import has to
// answer in both.
func (e Entry) Symbols(arm64ec bool) []string {
	base, _ := ECDemangle(e.Symbol)
	if !arm64ec {
		base = e.Symbol
	}
	out := []string{"__imp_" + base}
	if e.Kind != KindCode {
		return out
	}
	out = append(out, base)
	if arm64ec {
		out = append(out, "__imp_aux_"+base, e.Symbol)
	}
	return out
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}