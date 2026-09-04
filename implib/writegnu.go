package implib

import (
	"fmt"
	"io"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/ar"
	"github.com/vertex-language/pe/coff"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
)

// The GNU shape has four kinds of member, and none of them is the
// short-import pseudo-object the MS shape uses — every one is a real COFF
// object contributing real .idata input sections, merged into the final
// image by the ordinary $-group pipeline in pe/link rather than by a
// synthetic that understands import libraries specifically. dlltool
// (binutils) is the shape's only writer and pe/link's only reader, so this
// writer follows dlltool's own object layout rather than the published
// specification, which does not cover it at all:
//
//	head object   .idata$2, the descriptor, plus empty .idata$4/.idata$5
//	              sections whose only job is to define the symbols the
//	              descriptor's own relocations point at — so that once
//	              merge has placed every contribution, those symbols name
//	              the start of the merged ILT and IAT rather than some
//	              real entry's address.
//	per-export    .idata$4 and .idata$5 (one thunk slot each, relocated
//	object        against a shared .idata$6 hint/name entry unless the
//	              export is by ordinal) and, for a code import, a two-
//	              instruction .text thunk jumping through the IAT slot.
//	              It also carries a relocation against the head object's
//	              own symbol that exists for no reason but to force the
//	              head into the link whenever this member is.
//	tail object   .idata$4 and .idata$5 zero entries terminating the ILT
//	              and IAT, plus .idata$7, the DLL name the head's
//	              descriptor names by forcing this object in the same way
//	              a per-export object forces the head.
//
// Nothing here is pulled in by being listed — an import library is searched
// like any other archive, and a member is only linked in if something
// references a symbol it defines. That is what the forcing relocations are
// for: a real per-export object is pulled in because the importing code
// references the symbol it defines, and it references the head, and the
// head references the tail, so requesting one import from a DLL brings in
// the whole DLL's descriptor and terminator and nothing from any other
// DLL's members.
//
// pe/link's merge phase has to place these three roles correctly within
// .idata$4 and .idata$5 without being able to trust the order they were
// resolved in — see chunkRank in pe/link/merge.go, which this writer's
// member shapes exist to be read by.

// writeGNU emits a dlltool-shaped import library.
//
// AMD64 is the only machine implemented. dlltool's i386 objects use a
// different internal symbol convention (a double-underscore head symbol, a
// thunk relocated directly against the IAT slot's section symbol rather
// than a separate __imp_ symbol) that this writer does not reproduce, and
// ARM64/ARM64EC have no GNU toolchain that consumes this shape at all — so
// getting either one wrong would be unverifiable against any real linker,
// the same reasoning that kept new architecture backends out of this pass.
func writeGNU(w io.Writer, opt Options, exports []pe.Export) error {
	if opt.Target.Machine != pe.MachineAMD64 {
		return &UnsupportedGNUMachineError{Machine: opt.Target.Machine}
	}

	lib := stem(opt.DLL)
	headSym := "_head_" + lib
	inameSym := "_iname_" + lib
	word := opt.Target.Width().Bytes()

	aw := ar.NewWriter(w, ar.Options{Deterministic: true})

	// Every member's ar_name must be distinct, not merely non-empty. This
	// package's own linker keys a COFF static symbol's local scope on
	// (member name, symbol name) — see symtab.local in pe/link/resolve.go
	// — because a real archive's members are ordinarily distinct object
	// files and nothing else identifies one. The head, tail, and every
	// per-export object here each define their own local ".idata$4" and
	// ".idata$5" section symbols, so giving them all the MS shape's
	// convention of naming every member after the DLL would silently
	// collide those symbols across members and resolve a relocation to
	// whichever one last claimed the name — which is exactly the shape
	// this bug took before this comment existed. dlltool avoids it the
	// same way: every member of a real .dll.a has a distinct filename.
	head, err := buildGNUHead(opt, lib+"_h.o", headSym, inameSym)
	if err != nil {
		return err
	}
	aw.Add(head)

	for i, e := range exports {
		if e.Private {
			continue
		}
		entry, err := entryFor(e, opt, opt.Target.Machine)
		if err != nil {
			return err
		}
		member, err := buildGNUEntry(opt, fmt.Sprintf("%s_s%05d.o", lib, i), entry, headSym, word)
		if err != nil {
			return err
		}
		aw.Add(member)
	}

	tail, err := buildGNUTail(opt, lib+"_t.o", inameSym, word)
	if err != nil {
		return err
	}
	aw.Add(tail)

	return aw.Close()
}

// buildGNUHead emits the descriptor and the symbols marking where the merged
// ILT and IAT begin.
func buildGNUHead(opt Options, memberName, headSym, inameSym string) (ar.Input, error) {
	var buf writeBuf
	w := coff.NewWriter(&buf, coff.Options{Target: opt.Target})

	dir := w.Section(coff.SectionHeader{
		Name:  ".idata$2",
		Kind:  pe.SecInitData,
		Prot:  pe.SecRead | pe.SecWrite,
		Align: 4,
	})
	dir.Write(make([]byte, importDirectoryEntrySize))

	// Empty: their only purpose is the symbols defined below, at their
	// (zero) start. chunkRank places a zero-size .idata$4/.idata$5 chunk
	// first among its peers precisely so that these resolve to the start
	// of the merged tables rather than to wherever they physically land.
	ilt := w.Section(coff.SectionHeader{Name: ".idata$4", Kind: pe.SecInitData, Prot: pe.SecRead | pe.SecWrite, Align: 4})
	iat := w.Section(coff.SectionHeader{Name: ".idata$5", Kind: pe.SecInitData, Prot: pe.SecRead | pe.SecWrite, Align: 4})

	w.Symbol(coff.SymbolDef{Name: headSym, Section: dir, Class: pe.ClassExternal})
	iltSym := w.Symbol(coff.SymbolDef{Name: ".idata$4", Section: ilt, Class: pe.ClassStatic})
	iatSym := w.Symbol(coff.SymbolDef{Name: ".idata$5", Section: iat, Class: pe.ClassStatic})
	// Undefined: referencing it is what drags the tail object, which
	// defines it, into the link.
	inameRef := w.Symbol(coff.SymbolDef{Name: inameSym, Class: pe.ClassExternal})

	rel, err := addr32NB(opt.Target.Machine)
	if err != nil {
		return ar.Input{}, err
	}
	w.Reloc(dir, coff.RelocSpec{Address: dirOffImportLookupTable, Sym: iltSym, Type: rel})
	w.Reloc(dir, coff.RelocSpec{Address: dirOffName, Sym: inameRef, Type: rel})
	w.Reloc(dir, coff.RelocSpec{Address: dirOffImportAddressTable, Sym: iatSym, Type: rel})

	if err := w.Close(); err != nil {
		return ar.Input{}, err
	}
	return ar.Input{Name: memberName, Data: buf.b, Symbols: []string{headSym}}, nil
}

// buildGNUTail emits the zero ILT/IAT terminators and the DLL's name.
func buildGNUTail(opt Options, memberName, inameSym string, word int) (ar.Input, error) {
	var buf writeBuf
	w := coff.NewWriter(&buf, coff.Options{Target: opt.Target})

	ilt := w.Section(coff.SectionHeader{Name: ".idata$4", Kind: pe.SecInitData, Prot: pe.SecRead | pe.SecWrite, Align: word})
	ilt.Write(make([]byte, word))
	iat := w.Section(coff.SectionHeader{Name: ".idata$5", Kind: pe.SecInitData, Prot: pe.SecRead | pe.SecWrite, Align: word})
	iat.Write(make([]byte, word))

	name := w.Section(coff.SectionHeader{Name: ".idata$7", Kind: pe.SecInitData, Prot: pe.SecRead | pe.SecWrite, Align: 4})
	name.Write(append([]byte(opt.DLL), 0))
	w.Symbol(coff.SymbolDef{Name: inameSym, Section: name, Class: pe.ClassExternal})

	if err := w.Close(); err != nil {
		return ar.Input{}, err
	}
	return ar.Input{Name: memberName, Data: buf.b, Symbols: []string{inameSym}}, nil
}

// buildGNUEntry emits one export's thunk slots, its hint/name entry (unless
// it is by ordinal), and — for a code import — the .text stub that lets code
// call the unprefixed name.
func buildGNUEntry(opt Options, memberName string, e Entry, headSym string, word int) (ar.Input, error) {
	var buf writeBuf
	w := coff.NewWriter(&buf, coff.Options{Target: opt.Target})

	ilt := w.Section(coff.SectionHeader{Name: ".idata$4", Kind: pe.SecInitData, Prot: pe.SecRead | pe.SecWrite, Align: word})
	iat := w.Section(coff.SectionHeader{Name: ".idata$5", Kind: pe.SecInitData, Prot: pe.SecRead | pe.SecWrite, Align: word})

	rel, err := addr32NB(opt.Target.Machine)
	if err != nil {
		return ar.Input{}, err
	}

	if e.NameKind == NameOrdinal {
		tb := binio.NewBufSize(word)
		(&format.ThunkData{ByOrdinal: true, Ordinal: e.Ordinal}).Encode(tb, opt.Target.Width())
		data, err := tb.Data()
		if err != nil {
			return ar.Input{}, err
		}
		ilt.Write(append([]byte(nil), data...))
		iat.Write(append([]byte(nil), data...))
	} else {
		ilt.Write(make([]byte, word))
		iat.Write(make([]byte, word))

		hint := w.Section(coff.SectionHeader{Name: ".idata$6", Kind: pe.SecInitData, Prot: pe.SecRead | pe.SecWrite, Align: 2})
		hb := binio.NewBufSize(format.HintSize + len(e.Exported()) + 2)
		(&format.HintName{Hint: e.Ordinal, Name: e.Exported()}).Encode(hb)
		data, err := hb.Data()
		if err != nil {
			return ar.Input{}, err
		}
		hint.Write(data)
		hintSym := w.Symbol(coff.SymbolDef{Name: ".idata$6", Section: hint, Class: pe.ClassStatic})
		w.Reloc(ilt, coff.RelocSpec{Address: 0, Sym: hintSym, Type: rel})
		w.Reloc(iat, coff.RelocSpec{Address: 0, Sym: hintSym, Type: rel})
	}

	// Forces the head object into the link whenever this member is —
	// see the package doc comment above writeGNU.
	forcing := w.Section(coff.SectionHeader{Name: ".idata$7", Kind: pe.SecInitData, Prot: pe.SecRead | pe.SecWrite, Align: 4})
	forcing.Write(make([]byte, 4))
	headRef := w.Symbol(coff.SymbolDef{Name: headSym, Class: pe.ClassExternal})
	w.Reloc(forcing, coff.RelocSpec{Address: 0, Sym: headRef, Type: rel})

	impSym := w.Symbol(coff.SymbolDef{Name: "__imp_" + e.Symbol, Section: iat, Class: pe.ClassExternal})

	syms := []string{"__imp_" + e.Symbol}
	if e.Kind == KindCode {
		text := w.Section(coff.SectionHeader{Name: ".text", Kind: pe.SecCode, Prot: pe.SecExecute | pe.SecRead, Align: 4})
		// jmp qword ptr [rip+__imp_<sym>] ; nop ; nop — the same
		// indirect-jump-through-the-slot shape as an ordinary
		// __declspec(dllimport) call thunk, padded to a 4-byte
		// boundary.
		text.Write([]byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90})
		w.Symbol(coff.SymbolDef{Name: e.Symbol, Section: text, Class: pe.ClassExternal})
		w.Reloc(text, coff.RelocSpec{
			Address: 2, Sym: impSym, Type: uint16(pe.IMAGE_REL_AMD64_REL32),
		})
		syms = append(syms, e.Symbol)
	}

	if err := w.Close(); err != nil {
		return ar.Input{}, err
	}
	return ar.Input{Name: memberName, Data: buf.b, Symbols: syms}, nil
}
