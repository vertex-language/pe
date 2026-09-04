package def

import "github.com/vertex-language/pe"

// File is a parsed module-definition file.
//
// The Has* flags exist because zero is a legal value for every numeric field
// here. An image base of zero is not "unset", it is a request the linker will
// refuse; a stack reserve of zero is the same. Without the flags an emitter
// cannot tell a file that said nothing from one that said zero, and defaults
// would silently override explicit values.
type File struct {
	// Library is the LIBRARY statement's name: this module is a DLL. It is
	// recorded exactly as written — see DLLName for the extension rule.
	Library string

	// Name is the NAME statement's name: this module is an executable.
	// LIBRARY and NAME are mutually exclusive, and a file carrying both is
	// ErrDuplicateModule.
	Name string

	// ImageBase is the BASE= address on either statement.
	ImageBase    uint64
	HasImageBase bool

	// Stack and heap sizes, from STACKSIZE and HEAPSIZE. The commit is
	// optional; HasCommit says whether one was given.
	StackReserve, StackCommit uint64
	HasStack, HasStackCommit  bool
	HeapReserve, HeapCommit   uint64
	HasHeap, HasHeapCommit    bool

	// Version is the VERSION statement, which sets the image version fields
	// of the optional header.
	Version    pe.Version
	HasVersion bool

	// Exports accumulates every EXPORTS statement in the file, in order. A
	// .def may carry more than one.
	Exports []pe.Export
}

// IsDLL reports whether the file described a DLL rather than an executable.
func (f *File) IsDLL() bool { return f.Library != "" }

// Module returns whichever of Library and Name was given.
func (f *File) Module() string {
	if f.Library != "" {
		return f.Library
	}
	return f.Name
}

// DLLName returns the name of the DLL an import library should import from:
// Library, with ".dll" appended when it carries no extension.
//
// The extension is a real question and this is the one place it is answered.
// `LIBRARY kernel32` is ordinary — link.exe appends the extension when naming
// the output, and LLVM does the same for its output file while keeping the
// raw name for the import name. Parse records what the file said; a caller
// that needs a filename calls this. Passing Library straight to
// implib.Options.DLL instead produces a library whose members import from
// "kernel32", a module no loader will find.
//
// It returns "" for a file that declared NAME rather than LIBRARY, since an
// executable is not imported from.
func (f *File) DLLName() string {
	if f.Library == "" {
		return ""
	}
	if hasExtension(f.Library) {
		return f.Library
	}
	return f.Library + ".dll"
}

// hasExtension reports whether the last path component contains a dot.
func hasExtension(s string) bool {
	for i := len(s) - 1; i >= 0; i-- {
		switch s[i] {
		case '.':
			return true
		case '/', '\\':
			return false
		}
	}
	return false
}