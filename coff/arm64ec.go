package coff

import "strings"

// ARM64EC support at the object level is mostly a matter of recognizing three
// naming conventions. The code generation — entry thunks, exit thunks, the
// call-checker sequence — is the compiler's, and passes through this tree
// untouched.

// ThunkSection is where the compiler places entry and exit thunks. They arrive
// as discard COMDATs keyed on the thunk symbol itself, so an unreferenced
// thunk is swept like any other COMDAT loser.
const ThunkSection = ".wowthk$aa"

// Entry thunk symbols are named for the signature they adapt, not for the
// function they belong to, so one thunk serves every function with the same
// signature. The association from function to thunk is not in the name: it is
// the four bytes immediately *before* the ARM64EC function, which the linker
// writes and the emulator reads.
const EntryThunkPrefix = "$ientry_thunk$"

// The ARM64EC tag inserted into a mangled C++ name. A function compiled as
// ARM64EC carries it; the same function compiled for x64 does not, which is
// how the two can coexist in one symbol namespace.
const ECManglingTag = "$$h"

// MD5-mangled names use a different rule. MSVC hashes very long symbols into
// the form ??@<32 hex chars>@, and the ARM64EC variant appends $h@ rather than
// inserting $$h — a single dollar, and at the end. A demangler that applies
// the general rule to these produces a name that matches nothing.
const (
	md5ManglePrefix = "??@"
	md5ECSuffix     = "@$h@"
	md5PlainSuffix  = "@"
)

// IsEntryThunk reports whether a symbol name is a compiler-generated entry
// thunk.
func IsEntryThunk(name string) bool {
	return strings.HasPrefix(name, EntryThunkPrefix)
}

// IsECMangled reports whether a name carries the ARM64EC tag in either form.
func IsECMangled(name string) bool {
	if strings.HasPrefix(name, md5ManglePrefix) {
		return strings.HasSuffix(name, md5ECSuffix)
	}
	return strings.Contains(name, ECManglingTag)
}

// ECDemangle strips the ARM64EC tag, returning the name the x64 side would
// use. It reports false if the name carries no tag.
func ECDemangle(name string) (string, bool) {
	if strings.HasPrefix(name, md5ManglePrefix) {
		if base, ok := strings.CutSuffix(name, md5ECSuffix); ok {
			return base + md5PlainSuffix, true
		}
		return "", false
	}
	before, after, found := strings.Cut(name, ECManglingTag)
	if !found {
		return "", false
	}
	return before + after, true
}

// HasECSymbols reports whether the object contains any ARM64EC-tagged symbol
// or entry thunk.
//
// ar uses this to decide whether a member belongs in the /<ECSYMBOLS>/ index.
// The machine type is the primary signal and this is a secondary one: an
// AMD64 object may legitimately be linked into an ARM64EC image, and one that
// carries tagged names is doing so deliberately.
func (f *File) HasECSymbols() (bool, error) {
	syms, err := f.Symbols()
	if err != nil {
		return false, err
	}
	for _, s := range syms {
		if IsEntryThunk(s.Name) || IsECMangled(s.Name) {
			return true, nil
		}
	}
	return false, nil
}