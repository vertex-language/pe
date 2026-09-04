package implib

import (
	"io"
	"strings"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/ar"
	"github.com/vertex-language/pe/coff"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// An import library is four kinds of member. Three are fixed COFF objects that
// bracket the import tables, and the rest are one short-import member per
// import:
//
//	__IMPORT_DESCRIPTOR_<lib>   .idata$2 — the descriptor, plus the DLL name
//	                            in .idata$6, with three relocations that the
//	                            linker turns into the ILT, IAT, and name RVAs
//	__NULL_IMPORT_DESCRIPTOR    .idata$3 — the zero descriptor terminating
//	                            the directory
//	\x7f<lib>_NULL_THUNK_DATA   .idata$5 and .idata$4 — the zero entries
//	                            terminating the IAT and ILT
//
// The $-group ordering is what assembles them: every import's own .idata$4 and
// .idata$5 contributions sort between the descriptor and the terminators.
//
// The three objects here are built with coff.Writer rather than emitted as
// literal byte arrays. That is a deliberate difference from llvm-lib, which
// hand-assembles them: this way the object writer is exercised by its own
// tree, at the cost of not being byte-identical to llvm-lib output. The
// structural content is the same; a byte diff against llvm-lib will show the
// extra section-definition symbols coff.Writer emits.
//
// The export description itself is pe.Export, not a type of this package's
// own. def parses one, this turns it into an import, and link places it in
// .edata; a type owned by any of the three would need converting at two of the
// three boundaries, and each conversion is a place for the internal and
// exported names to swap.

// Symbol names the linker looks for. The null-thunk prefix is a literal DEL
// byte, which sorts the symbol out of the way of anything a user could write.
const (
	descriptorPrefix     = "__IMPORT_DESCRIPTOR_"
	nullDescriptorSymbol = "__NULL_IMPORT_DESCRIPTOR"
	nullThunkPrefix      = "\x7f"
	nullThunkSuffix      = "_NULL_THUNK_DATA"
)

// importDirectoryEntrySize is IMAGE_IMPORT_DESCRIPTOR: five 32-bit words.
const importDirectoryEntrySize = 20

// Field offsets within it. Three of the five need a relocation; the other two
// are the timestamp and the forwarder chain, both zero in an import library.
const (
	dirOffImportLookupTable  = 0
	dirOffName               = 12
	dirOffImportAddressTable = 16
)

// Options configures Write.
type Options struct {
	// Target decides the machine written into every member and the ABI
	// that decides the library's shape. Its ABI field is load-bearing:
	// MSVC gets short-import members, MinGW gets real COFF ones.
	Target pe.Target

	// DLL is the name of the library being imported from, with extension.
	// It is written into every member and is the name the loader resolves
	// at run time, so a name without its extension produces a library
	// importing from a module that does not exist. A caller holding a
	// parsed .def wants def.File.DLLName rather than def.File.Library.
	DLL string
}

// Write emits an import library for the given exports.
func Write(w io.Writer, opt Options, exports []pe.Export) error {
	if err := opt.Target.Validate(); err != nil {
		return err
	}
	if opt.DLL == "" {
		return ErrNoDLL
	}
	if opt.Target.ABI == pe.ABIMinGW {
		// The GNU shape emits real COFF members with .idata sections
		// rather than short-import pseudo-objects. It is a different
		// writer, not a flag on this one — see writegnu.go.
		return writeGNU(w, opt, exports)
	}

	machine := opt.Target.Machine
	native := machine
	if machine == pe.MachineARM64EC {
		// The head objects are native ARM64 even though the imports
		// they bracket are ARM64EC. An ARM64EC import library is one
		// library serving two namespaces, and the descriptor belongs to
		// the native one.
		native = pe.MachineARM64
	}

	lib := stem(opt.DLL)
	aw := ar.NewWriter(w, ar.Options{Deterministic: true})

	desc, err := buildDescriptor(opt, native, lib)
	if err != nil {
		return err
	}
	aw.Add(desc)

	nullDesc, err := buildNullDescriptor(opt, native, lib)
	if err != nil {
		return err
	}
	aw.Add(nullDesc)

	nullThunk, err := buildNullThunk(opt, native, lib)
	if err != nil {
		return err
	}
	aw.Add(nullThunk)

	arm64ec := machine == pe.MachineARM64EC
	for _, e := range exports {
		if e.Private {
			continue
		}
		entry, err := entryFor(e, opt, machine)
		if err != nil {
			return err
		}
		data, err := encodeEntry(entry)
		if err != nil {
			return err
		}
		aw.Add(ar.Input{
			Name:    opt.DLL,
			Data:    data,
			Symbols: entry.Symbols(arm64ec),
		})
	}
	return aw.Close()
}

// entryFor decides the name type for one export.
//
// The order of the tests is the rule. An explicit ExportAs or a NONAME ordinal
// settles it outright; otherwise the derivable rules are tried, and only a name
// no rule can produce falls back to storing it. Preferring a rule over EXPORTAS
// matters because the rules are what older linkers understand.
func entryFor(e pe.Export, opt Options, machine pe.Machine) (Entry, error) {
	kind := KindCode
	switch {
	case e.Constant:
		kind = KindConst
	case e.Data:
		kind = KindData
	}

	sym := e.SymbolName
	if sym == "" {
		sym = e.Name
	}
	name := sym
	if e.ExtName != "" {
		// Name is the internal symbol and ExtName the exported one, so
		// this rewrites the internal spelling into the external one
		// wherever it occurs — which for an ordinary alias is the whole
		// string, and for a decorated one is the undecorated part of it.
		replaced, ok := replace(sym, e.Name, e.ExtName)
		if !ok {
			return Entry{}, ErrBadExport
		}
		name = replaced
	}

	entry := Entry{
		Symbol:  name,
		DLL:     opt.DLL,
		Kind:    kind,
		Ordinal: e.Ordinal,
		Machine: uint16(machine),
	}

	switch {
	case e.NoName:
		if e.Ordinal == 0 {
			// An ordinal-only import with no ordinal names nothing.
			return Entry{}, ErrBadOrdinal
		}
		entry.NameKind = NameOrdinal

	case e.ExportAs != "":
		entry.NameKind, entry.ExportName = NameExportAs, e.ExportAs

	case e.ImportName != "":
		switch {
		case machine == pe.MachineI386 &&
			NameUndecorate.Apply(name) == e.ImportName:
			entry.NameKind = NameUndecorate
		case machine == pe.MachineI386 &&
			NameNoPrefix.Apply(name) == e.ImportName:
			entry.NameKind = NameNoPrefix
		case name == e.ImportName:
			entry.NameKind = NameExact
		default:
			entry.NameKind, entry.ExportName = NameExportAs, e.ImportName
		}

	default:
		entry.NameKind = inferNameKind(name, e.Exported(), machine, opt.Target.ABI)
	}

	if machine == pe.MachineARM64EC && kind == KindCode {
		mangled, changed := ECMangle(entry.Symbol)
		if changed && !e.NoName && entry.ExportName == "" {
			// The DLL exports the demangled name; the symbol in the
			// object is the mangled one, and no prefix rule relates
			// the two. EXPORTAS is the only way to say it.
			entry.NameKind, entry.ExportName = NameExportAs, entry.Symbol
			entry.Symbol = mangled
		}
	}

	if entry.NameKind != NameOrdinal && entry.Ordinal > 0 {
		// Legal: the field is a hint rather than the answer when a name
		// is present.
		_ = entry.Ordinal
	}
	return entry, nil
}

// inferNameKind picks the rule for an export with no explicit override.
//
// The i386 stdcall case is the one that differs between toolchains: MSVC
// exports a decorated __stdcall function with its leading underscore intact
// and so uses the exact name, while MinGW drops the underscore and uses
// NOPREFIX. Getting this backwards produces a library that links and a program
// that cannot find its imports.
func inferNameKind(sym, exported string, machine pe.Machine, abi pe.ABI) NameKind {
	if strings.HasPrefix(exported, "_") && strings.Contains(exported, "@") && abi != pe.ABIMinGW {
		return NameExact
	}
	if sym != exported {
		return NameUndecorate
	}
	if machine == pe.MachineI386 && strings.HasPrefix(sym, "_") {
		return NameNoPrefix
	}
	return NameExact
}

// replace rewrites the alias target inside a symbol name.
//
// The two may be mangled while the occurrence inside the symbol is not, which
// is why a failed match retries with a leading underscore stripped from both
// rather than giving up.
func replace(s, from, to string) (string, bool) {
	i := strings.Index(s, from)
	if i < 0 && strings.HasPrefix(from, "_") && strings.HasPrefix(to, "_") {
		from, to = from[1:], to[1:]
		i = strings.Index(s, from)
	}
	if i < 0 {
		return "", false
	}
	return s[:i] + to + s[i+len(from):], true
}

// encodeEntry writes one short-import member.
func encodeEntry(e Entry) ([]byte, error) {
	if e.NameKind == NameOrdinal && e.Ordinal == 0 {
		return nil, ErrBadOrdinal
	}
	size := len(e.Symbol) + 1 + len(e.DLL) + 1
	if e.NameKind == NameExportAs {
		size += len(e.ExportName) + 1
	}

	h := format.NewImportHeader(e.Machine)
	h.SizeOfData = uint32(size)
	h.OrdinalHint = e.Ordinal
	if !h.SetTypeInfo(uint8(e.Kind), uint8(e.NameKind)) {
		return nil, ErrBadMember
	}

	b := binio.NewBufSize(format.ImportHeaderSize + size)
	h.Encode(b)
	b.CStr(e.Symbol)
	b.CStr(e.DLL)
	if e.NameKind == NameExportAs {
		b.CStr(e.ExportName)
	}
	return b.Data()
}

// buildDescriptor emits __IMPORT_DESCRIPTOR_<lib>.
//
// The descriptor's five words are all zero on disk; three of them carry
// relocations, and the linker fills them from the final RVAs of the ILT, the
// IAT, and the DLL name. The name itself lives in .idata$6 in this same object,
// which is why the object has two sections rather than one.
func buildDescriptor(opt Options, machine pe.Machine, lib string) (ar.Input, error) {
	var buf writeBuf
	w := coff.NewWriter(&buf, coff.Options{Target: targetFor(opt, machine)})

	dir := w.Section(coff.SectionHeader{
		Name:  ".idata$2",
		Kind:  pe.SecInitData,
		Prot:  pe.SecRead | pe.SecWrite,
		Align: 4,
	})
	dir.Write(make([]byte, importDirectoryEntrySize))

	name := w.Section(coff.SectionHeader{
		Name:  ".idata$6",
		Kind:  pe.SecInitData,
		Prot:  pe.SecRead | pe.SecWrite,
		Align: 2,
	})
	name.Write(append([]byte(opt.DLL), 0))

	// The descriptor symbol itself, at the start of .idata$2.
	w.Symbol(coff.SymbolDef{
		Name:    descriptorPrefix + lib,
		Section: dir,
		Class:   pe.ClassExternal,
	})
	// The name blob, referenced by the NameRVA relocation.
	nameSym := w.Symbol(coff.SymbolDef{
		Name:    ".idata$6",
		Section: name,
		Class:   pe.ClassStatic,
	})
	// The ILT and IAT groups live in other objects; these are undefined
	// section symbols the linker resolves to the merged groups.
	iltSym := w.Symbol(coff.SymbolDef{Name: ".idata$4", Class: pe.ClassSection})
	iatSym := w.Symbol(coff.SymbolDef{Name: ".idata$5", Class: pe.ClassSection})

	// Referencing the terminators from here is what drags them into the
	// link, so the directory and both tables always get their zero entry.
	w.Symbol(coff.SymbolDef{Name: nullDescriptorSymbol, Class: pe.ClassExternal})
	w.Symbol(coff.SymbolDef{Name: nullThunkPrefix + lib + nullThunkSuffix, Class: pe.ClassExternal})

	rel, err := addr32NB(machine)
	if err != nil {
		return ar.Input{}, err
	}
	w.Reloc(dir, coff.RelocSpec{Address: dirOffName, Sym: nameSym, Type: rel})
	w.Reloc(dir, coff.RelocSpec{Address: dirOffImportLookupTable, Sym: iltSym, Type: rel})
	w.Reloc(dir, coff.RelocSpec{Address: dirOffImportAddressTable, Sym: iatSym, Type: rel})

	if err := w.Close(); err != nil {
		return ar.Input{}, err
	}
	return ar.Input{
		Name:    opt.DLL,
		Data:    buf.b,
		Symbols: []string{descriptorPrefix + lib},
	}, nil
}

// buildNullDescriptor emits __NULL_IMPORT_DESCRIPTOR: a zero descriptor in
// .idata$3, which sorts after every real one and terminates the directory.
func buildNullDescriptor(opt Options, machine pe.Machine, lib string) (ar.Input, error) {
	var buf writeBuf
	w := coff.NewWriter(&buf, coff.Options{Target: targetFor(opt, machine)})

	s := w.Section(coff.SectionHeader{
		Name:  ".idata$3",
		Kind:  pe.SecInitData,
		Prot:  pe.SecRead | pe.SecWrite,
		Align: 4,
	})
	s.Write(make([]byte, importDirectoryEntrySize))
	w.Symbol(coff.SymbolDef{Name: nullDescriptorSymbol, Section: s, Class: pe.ClassExternal})

	if err := w.Close(); err != nil {
		return ar.Input{}, err
	}
	return ar.Input{Name: opt.DLL, Data: buf.b, Symbols: []string{nullDescriptorSymbol}}, nil
}

// buildNullThunk emits the zero IAT and ILT entries.
//
// Both are one pointer wide, so this is the one head object whose size depends
// on the target's width — and the reason it asks the machine rather than
// carrying a constant.
func buildNullThunk(opt Options, machine pe.Machine, lib string) (ar.Input, error) {
	var buf writeBuf
	t := targetFor(opt, machine)
	w := coff.NewWriter(&buf, coff.Options{Target: t})

	word := t.Width().Bytes()
	align := word

	// .idata$5 first, matching llvm-lib. The order within the object does
	// not decide the order in the image — the $ groups do — but keeping it
	// makes a member-by-member diff readable.
	iat := w.Section(coff.SectionHeader{
		Name:  ".idata$5",
		Kind:  pe.SecInitData,
		Prot:  pe.SecRead | pe.SecWrite,
		Align: align,
	})
	iat.Write(make([]byte, word))

	ilt := w.Section(coff.SectionHeader{
		Name:  ".idata$4",
		Kind:  pe.SecInitData,
		Prot:  pe.SecRead | pe.SecWrite,
		Align: align,
	})
	ilt.Write(make([]byte, word))

	sym := nullThunkPrefix + lib + nullThunkSuffix
	w.Symbol(coff.SymbolDef{Name: sym, Section: iat, Class: pe.ClassExternal})

	if err := w.Close(); err != nil {
		return ar.Input{}, err
	}
	return ar.Input{Name: opt.DLL, Data: buf.b, Symbols: []string{sym}}, nil
}

// targetFor rebuilds the options' target for a possibly different machine,
// which the ARM64EC head objects need.
func targetFor(opt Options, machine pe.Machine) pe.Target {
	t := opt.Target
	t.Machine = machine
	t.SubArch = machine.SubArch()
	return t
}

// addr32NB returns the image-relative 32-bit relocation for a machine.
//
// Every address stored in a PE table is an RVA, so this is the relocation the
// descriptor's three fields want: image-relative, and therefore needing no base
// relocation of its own.
func addr32NB(m pe.Machine) (uint16, error) {
	switch m {
	case pe.MachineAMD64:
		return uint16(pe.IMAGE_REL_AMD64_ADDR32NB), nil
	case pe.MachineI386:
		return uint16(pe.IMAGE_REL_I386_DIR32NB), nil
	case pe.MachineARM64, pe.MachineARM64EC, pe.MachineARM64X:
		return uint16(pe.IMAGE_REL_ARM64_ADDR32NB), nil
	}
	return 0, pe.ErrUnsupportedMachine
}

// writeBuf collects a coff.Writer's output. coff.Writer takes an io.Writer and
// writes once at Close, so this is all the adapter needs to be.
type writeBuf struct{ b []byte }

func (w *writeBuf) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

// stem returns a DLL name without its directory or extension, which is what
// the descriptor and null-thunk symbol names are built from.
func stem(dll string) string {
	if i := strings.LastIndexAny(dll, `/\`); i >= 0 {
		dll = dll[i+1:]
	}
	if i := strings.LastIndexByte(dll, '.'); i > 0 {
		dll = dll[:i]
	}
	return dll
}