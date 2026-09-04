package coff

import (
	"strings"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/binio"
	"github.com/vertex-language/pe/internal/format"
	"github.com/vertex-language/pe/internal/strtab"
)

// Close is where every deferred decision is made at once, because they are not
// independent. The header family depends on the section count; the symbol
// slots depend on the header family; the relocations depend on the slots; the
// string table depends on every name; and the file offsets depend on all of it.
//
// The sequence below is the only order in which each step's inputs are final.

// relocOverflowBias is what the escape record's count field carries beyond the
// real count: the pseudo-record includes itself.
//
// UNVERIFIED against a real MSVC object. lld and llvm-objcopy both write the
// count plus one and read it back minus one, and this tree matches them on
// both sides, so it round-trips with itself and with LLVM. If an object from
// link.exe ever disagrees, this constant and Section.NumRelocs are the two
// places to change.
const relocOverflowBias = 1

// Close finishes the object and writes it.
//
// It is idempotent in the sense that a second call returns the same error and
// writes nothing further. A Writer cannot be reused.
func (w *Writer) Close() error {
	if w.closed {
		return w.err
	}
	if w.err != nil {
		w.closed = true
		return w.err
	}

	// synthDirectives calls w.Section, which refuses once w.closed is set, so
	// it has to run before that flag flips.
	w.synthDirectives()
	w.closed = true
	if len(w.secs) == 0 {
		return w.finish(ErrNoSections)
	}
	if err := w.checkComdats(); err != nil {
		return w.finish(err)
	}

	m := w.opt.Target.Machine
	for _, s := range w.secs {
		if err := s.checkRelocOrder(m); err != nil {
			return w.finish(err)
		}
	}

	bigObj, err := pickHeaderFamily(w.opt.BigObj, len(w.secs), w.opt.Characteristics)
	if err != nil {
		return w.finish(err)
	}

	order := w.assignSlots(bigObj)
	names, err := w.buildStrings(order)
	if err != nil {
		return w.finish(err)
	}

	buf, err := w.encode(bigObj, order, names)
	if err != nil {
		return w.finish(err)
	}
	if _, err := w.w.Write(buf); err != nil {
		return w.finish(err)
	}
	return nil
}

func (w *Writer) finish(err error) error {
	w.Fail(err)
	return w.err
}

// synthDirectives builds the .drectve section from the recorded options.
//
// It is created last so it does not shift the section numbers of anything the
// caller created, and it carries LNK_INFO plus LNK_REMOVE: the linker consumes
// it and it never reaches the image. It has no relocations, which the reader
// enforces and which is why nothing here can add any.
func (w *Writer) synthDirectives() {
	if len(w.directives) == 0 {
		return
	}
	var b strings.Builder
	for i, d := range w.directives {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('/')
		b.WriteString(d.Name)
		if d.Value == "" {
			continue
		}
		b.WriteByte(':')
		if strings.ContainsAny(d.Value, " \t") {
			b.WriteByte('"')
			b.WriteString(d.Value)
			b.WriteByte('"')
			continue
		}
		b.WriteString(d.Value)
	}
	s := w.Section(SectionHeader{
		Name:  DirectiveSection,
		Kind:  pe.SecLnkInfo | pe.SecLnkRemove,
		Align: 1,
	})
	s.data = []byte(b.String())
}

// checkComdats validates the election terms of every COMDAT section, including
// that associative chains terminate.
//
// The cycle check is the writer's twin of File.CheckComdatCycles, and it runs
// here for the same reason it runs at parse time there: a chain that loops is
// an infinite loop in every consumer, and the cheapest place to refuse it is
// before it exists.
func (w *Writer) checkComdats() error {
	const (
		white = 0
		grey  = 1
		black = 2
	)
	colour := make([]uint8, len(w.secs))
	for i, s := range w.secs {
		if s.kind.Has(pe.SecLnkComdat) && !s.comdat {
			// Flagged COMDAT with no key symbol. There is nothing to
			// elect on, and defaulting to the section name would
			// merge sections never meant to be equivalent.
			return ErrNoComdatLeader
		}
		if colour[i] != white {
			continue
		}
		var path []int
		cur := i
		for {
			if colour[cur] == grey {
				return ErrComdatCycle
			}
			if colour[cur] == black {
				break
			}
			colour[cur] = grey
			path = append(path, cur)
			nxt := w.secs[cur].assoc
			if nxt == nil {
				break
			}
			if !nxt.comdat {
				// An associative section must be associated with
				// a COMDAT section, or the chain has no terminus
				// that means anything.
				return ErrCorrupt
			}
			cur = nxt.index
		}
		for _, n := range path {
			colour[n] = black
		}
	}
	return nil
}

// assignSlots orders the symbol table and gives every symbol its physical slot.
//
// The order is not cosmetic. The specification requires that the first symbol
// carrying a COMDAT section's number be that section's definition record and
// the second be the COMDAT symbol, and nothing in the file marks which is
// which — the linker finds them by position. So the table is emitted as:
//
//	.file, if any
//	for each section: its definition record, then its COMDAT leader
//	every remaining symbol, in creation order
//
// Emitting the definition records first also matches what MSVC produces, which
// keeps a byte-level diff against cl output readable.
func (w *Writer) assignSlots(bigObj bool) []*SymbolRef {
	slotSize := format.SymbolSlotSize(bigObj)
	order := make([]*SymbolRef, 0, len(w.syms)+len(w.secs)+1)
	slot := 0

	add := func(s *SymbolRef, aux int) {
		s.slot = slot
		s.nslots = 1 + aux
		slot += s.nslots
		s.emitted = true
		order = append(order, s)
	}

	if w.hasFile {
		n := (len(w.file) + slotSize - 1) / slotSize
		if n == 0 {
			n = 1
		}
		f := &SymbolRef{
			w:    w,
			def:  SymbolDef{Name: ".file", Class: pe.ClassFile},
			sect: pe.SectionDebug,
			aux:  []auxRecord{{kind: pe.AuxFile, fileName: w.file}},
		}
		add(f, n)
	}

	for _, s := range w.secs {
		add(s.def, 1)
		if s.comdat && s.leader != nil && !s.leader.emitted {
			add(s.leader, len(s.leader.aux))
		}
	}
	for _, s := range w.syms {
		if s.emitted {
			continue
		}
		add(s, len(s.aux))
	}
	return order
}

// nameFields holds the eight-byte name field chosen for every section and
// symbol, plus the finished string table.
type nameFields struct {
	sections [][strtab.NameFieldLen]byte
	symbols  [][strtab.NameFieldLen]byte
	table    *strtab.Builder
}

// buildStrings routes long names through the string table.
//
// Section names go in first, deliberately. A long section name escapes as the
// decimal form "/N", which has seven digits to work with; a long symbol name
// has a full 32-bit offset. Adding sections first keeps their offsets small
// enough that the escape that can run out never does.
func (w *Writer) buildStrings(order []*SymbolRef) (*nameFields, error) {
	b := strtab.NewBuilder()
	nf := &nameFields{
		sections: make([][strtab.NameFieldLen]byte, len(w.secs)),
		symbols:  make([][strtab.NameFieldLen]byte, len(order)),
		table:    b,
	}
	for i, s := range w.secs {
		nf.sections[i] = b.SectionName(s.Name)
	}
	for i, s := range order {
		nf.symbols[i] = b.SymbolName(s.def.Name)
	}
	if err := b.Err(); err != nil {
		return nil, err
	}
	return nf, nil
}

// encode lays out and writes every byte of the object.
//
// Offsets are computed before anything is emitted, because the file header
// carries the symbol table pointer and each section header carries its own
// data and relocation offsets. Section contents are followed immediately by
// that section's relocations, which is llvm-objcopy's arrangement; MSVC groups
// all contents and then all relocations. Both are legal — nothing in the
// format requires either — and the choice is recorded here so a byte diff
// against cl output is not a surprise.
func (w *Writer) encode(bigObj bool, order []*SymbolRef, nf *nameFields) ([]byte, error) {
	slotSize := format.SymbolSlotSize(bigObj)
	hdrSize := format.FileHeaderSize
	if bigObj {
		hdrSize = format.BigObjHeaderSize
	}

	type placed struct {
		dataOff  uint32
		relocOff uint32
		nreloc   int
		overflow bool
	}
	place := make([]placed, len(w.secs))

	off := uint32(hdrSize + format.SectionHeaderSize*len(w.secs))
	for i, s := range w.secs {
		p := &place[i]
		p.nreloc = len(s.relocs)
		if !s.kind.Has(pe.SecUninitData) && len(s.data) > 0 {
			p.dataOff = off
			off += uint32(len(s.data))
		}
		if p.nreloc > 0 {
			p.relocOff = off
			// The escape triggers at 0xffff, not above it: the
			// count field would read 0xffff either way, and a
			// reader cannot tell a real 0xffff from the sentinel.
			if p.nreloc >= format.RelocOverflow {
				p.overflow = true
				off += format.RelocationSize
			}
			off += uint32(format.RelocationSize * p.nreloc)
		}
	}

	nslots := 0
	for _, s := range order {
		nslots += s.nslots
	}
	symOff := off
	off += uint32(slotSize * nslots)

	b := binio.NewBufSize(int(off) + nf.table.Len())

	machine := uint16(w.opt.Target.Machine)
	if bigObj {
		h := format.NewBigObjHeader(machine)
		h.TimeDateStamp = w.opt.TimeDateStamp
		h.NumberOfSections = uint32(len(w.secs))
		h.PointerToSymbolTable = symOff
		h.NumberOfSymbols = uint32(nslots)
		h.Encode(b)
	} else {
		h := format.FileHeader{
			Machine:              machine,
			NumberOfSections:     uint16(len(w.secs)),
			TimeDateStamp:        w.opt.TimeDateStamp,
			PointerToSymbolTable: symOff,
			NumberOfSymbols:      uint32(nslots),
			SizeOfOptionalHeader: 0,
			Characteristics:      uint16(w.opt.Characteristics),
		}
		h.Encode(b)
	}

	for i, s := range w.secs {
		p := place[i]
		char, err := pe.PackSecChar(s.kind, s.prot, s.align)
		if err != nil {
			return nil, err
		}
		nreloc := uint16(p.nreloc)
		if p.overflow {
			// The flag and the sentinel count go together; the
			// reader treats the flag alone as an ordinary count.
			char |= uint32(pe.SecLnkNRelocOvfl)
			nreloc = format.RelocOverflow
		}
		h := format.SectionHeader{
			Name:                 nf.sections[i],
			VirtualSize:          0, // meaningless in an object
			VirtualAddress:       0, // the specification says compilers set zero
			SizeOfRawData:        s.Size(),
			PointerToRawData:     p.dataOff,
			PointerToRelocations: p.relocOff,
			NumberOfRelocations:  nreloc,
			Characteristics:      char,
		}
		h.Encode(b)
	}

	m := w.opt.Target.Machine
	for i, s := range w.secs {
		p := place[i]
		if p.dataOff != 0 {
			b.Bytes(s.data)
		}
		if p.overflow {
			r := format.Relocation{
				VirtualAddress: uint32(p.nreloc + relocOverflowBias),
			}
			r.Encode(b)
		}
		for _, e := range s.relocs {
			idx := uint32(0)
			switch {
			case pe.RelocIsPair(m, e.spec.Type):
				// Not a symbol index. A reader that resolves
				// this field looks up an arbitrary symbol.
				idx = e.spec.Disp
			case e.spec.Sym != nil:
				idx = uint32(e.spec.Sym.slot)
			}
			r := format.Relocation{
				VirtualAddress:   e.spec.Address,
				SymbolTableIndex: idx,
				Type:             e.spec.Type,
			}
			r.Encode(b)
		}
	}

	for i, s := range order {
		raw := format.Symbol{
			NameInline:         nf.symbols[i],
			Value:              s.def.Value,
			SectionNumber:      int32(s.sect),
			Type:               uint16(s.def.Type),
			StorageClass:       uint8(s.def.Class),
			NumberOfAuxSymbols: uint8(s.nslots - 1),
		}
		raw.Encode(b, bigObj)
		w.encodeAux(b, s, bigObj)
	}

	nf.table.Encode(b)
	if err := nf.table.Err(); err != nil {
		return nil, err
	}
	return b.Data()
}

// encodeAux writes a symbol's auxiliary records.
//
// A .file record is the exception to one-record-per-slot: its name occupies
// every declared slot consecutively, NUL-padded, so it is written once across
// all of them rather than once per slot.
func (w *Writer) encodeAux(b *binio.Buf, s *SymbolRef, bigObj bool) {
	for _, a := range s.aux {
		switch a.kind {
		case pe.AuxFile:
			f := format.AuxFile{Name: a.fileName}
			f.Encode(b, bigObj)

		case pe.AuxWeakExternal:
			we := format.AuxWeakExternal{
				TagIndex:        uint32(a.weakTag.slot),
				Characteristics: uint32(a.weakKind),
			}
			we.Encode(b, bigObj)

		case pe.AuxSectionDef:
			sec := a.sectionDef
			sd := format.AuxSectionDef{
				Length:              sec.Size(),
				NumberOfRelocations: relocCountField(len(sec.relocs)),
				CheckSum:            sectionChecksum(sec),
				Selection:           uint8(sec.selection),
			}
			// The Number field names the associated section for an
			// associative COMDAT and the section itself otherwise,
			// which is what lld and llvm-objcopy both write.
			if sec.assoc != nil {
				sd.Number = uint32(sec.assoc.index + 1)
			} else {
				sd.Number = uint32(sec.index + 1)
			}
			sd.Encode(b, bigObj)

		default:
			b.Zero(format.SymbolSlotSize(bigObj))
		}
	}
}

// relocCountField narrows a relocation count for the aux record's 16-bit
// field. The aux record has no escape of its own, so a count that overflows is
// written as the sentinel and a reader is expected to prefer the header's
// resolution — which is exactly what AuxSectionDef.RelocCount reports.
func relocCountField(n int) uint16 {
	if n >= format.RelocOverflow {
		return format.RelocOverflow
	}
	return uint16(n)
}

// sectionChecksum computes the value link.exe expects in a section definition
// record, and warns about when it is wrong.
//
// It is a reflected CRC-32 over the section's contents with the register
// initialized to zero and no final inversion. That is *not* the CRC-32/JAMCRC
// of the CRC catalogue, which initializes the register to all ones — LLVM
// names its helper JamCRC but constructs it with an explicit init of zero for
// exactly this field, and the reverse-engineered MSVC routine is likewise
// described as a CRC-32 with the inversion omitted. Getting the init wrong
// produces a checksum that is stable, plausible, and rejected.
//
// A section with no contents has no checksum; zero is what MSVC writes.
func sectionChecksum(s *SectionBuilder) uint32 {
	if s.kind.Has(pe.SecUninitData) || len(s.data) == 0 {
		return 0
	}
	crc := uint32(0)
	for _, c := range s.data {
		crc = crcTable[byte(crc)^c] ^ (crc >> 8)
	}
	return crc
}

var crcTable = func() [256]uint32 {
	// The reflected form of the IEEE polynomial, which is the only form
	// this loop can use.
	const poly = 0xedb88320
	var t [256]uint32
	for i := range t {
		c := uint32(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = poly ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return t
}()