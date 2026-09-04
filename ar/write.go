package ar

import (
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/internal/binio"
)

// Writer builds an MSVC-layout archive.
//
// The layout is fixed and the order is not a choice: both index members must
// precede the content they name, and the "//" member must precede any member
// whose name escapes to it. Since every offset in the indices is an absolute
// file offset, the sizes of the index members are inputs to the values they
// contain — so Close computes all four member sizes, then the offsets, then
// writes. Sizes do not depend on the offsets, which is the only reason one
// pass of arithmetic suffices.
type Writer struct {
	w   io.Writer
	opt Options

	inputs []Input

	err    error
	closed bool
}

// Options configures a Writer.
type Options struct {
	// Deterministic writes zero for every timestamp, uid, gid, and mode.
	// It is the default this tree recommends and what /Brepro-style builds
	// require.
	Deterministic bool

	// Thin writes a thin archive, whose members are paths rather than
	// contents. Inputs must then carry no data.
	Thin bool

	// EC forces the /<ECSYMBOLS>/ member on or off. When nil, Close infers
	// it: the member is written when the archive contains both an ARM64
	// object of some flavour and an EC one, which is the case a single
	// static library serving native, EC, and hybrid links produces.
	EC *bool

	// Extract supplies a member's exported symbol names. AddFile runs it.
	// ar does not link against coff, so this is how the caller injects the
	// only COFF knowledge the writer needs.
	Extract func(name string, data []byte) ([]string, error)
}

// Input is one member to add.
type Input struct {
	// Name is the member name. A name of 16 bytes or more, or one
	// containing a slash, escapes to the "//" member.
	Name string

	// Data is the member's contents, empty for a thin archive.
	Data []byte

	// Symbols are the names this member defines. The caller supplies them;
	// nothing here parses Data to find out.
	Symbols []string

	ModTime int64
	UID     int
	GID     int
	Mode    uint32
}

// NewWriter returns a Writer that emits to w on Close.
func NewWriter(w io.Writer, opt Options) *Writer {
	return &Writer{w: w, opt: opt}
}

// Err returns the first error latched, or nil.
func (w *Writer) Err() error { return w.err }

// Fail latches err if no error is latched yet.
func (w *Writer) Fail(err error) {
	if w.err == nil && err != nil {
		w.err = err
	}
}

// Add appends a member.
func (w *Writer) Add(in Input) {
	if w.err != nil || w.closed {
		w.Fail(ErrClosed)
		return
	}
	if w.opt.Thin && len(in.Data) != 0 {
		w.Fail(ErrThinData)
		return
	}
	if w.opt.Deterministic {
		in.ModTime, in.UID, in.GID, in.Mode = 0, 0, 0, 0
	}
	w.inputs = append(w.inputs, in)
}

// AddFile reads a file and adds it, running Options.Extract for its symbols.
func (w *Writer) AddFile(path string) error {
	if w.err != nil || w.closed {
		w.Fail(ErrClosed)
		return w.err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		w.Fail(err)
		return err
	}
	name := path
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var syms []string
	if w.opt.Extract != nil {
		syms, err = w.opt.Extract(name, data)
		if err != nil {
			w.Fail(err)
			return err
		}
	}
	w.Add(Input{Name: name, Data: data, Symbols: syms})
	return nil
}

// symRef is one symbol bound to the member index that defines it.
type symRef struct {
	name string
	idx  uint16 // one-based index into the offset table
}

// Close writes the archive.
func (w *Writer) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if len(w.inputs) > 0xffff {
		// The second linker member names members with a 16-bit index.
		return w.finish(ErrTooManyMembers)
	}

	names, longNames := w.buildNames()
	native, ec := w.buildSymbols()

	b := binio.NewBuf()
	b.Bytes([]byte(w.magic()))

	// Sizes first. Every index offset is absolute, so the content cannot be
	// written until the four preceding members' sizes are known.
	firstSize := 4 + len(native)*4 + nameBytes(native)
	secondSize := 4 + len(w.inputs)*4 + 4 + len(native)*2 + nameBytes(native)
	ecSize := 0
	if len(ec) > 0 {
		ecSize = 4 + len(ec)*2 + nameBytes(ec)
	}

	pos := int64(MagicSize)
	pos += memberSpan(int64(firstSize))
	pos += memberSpan(int64(secondSize))
	if ecSize > 0 {
		pos += memberSpan(int64(ecSize))
	}
	if len(longNames) > 0 {
		pos += memberSpan(int64(len(longNames)))
	}

	offsets := make([]int64, len(w.inputs))
	for i, in := range w.inputs {
		offsets[i] = pos
		pos += memberSpan(int64(len(in.Data)))
	}

	w.writeHeader(b, LinkerMemberName, 0, 0, 0, 0, firstSize)
	writeFirstIndex(b, native, offsets)
	pad(b)

	w.writeHeader(b, LinkerMemberName, 0, 0, 0, 0, secondSize)
	writeSecondIndex(b, native, offsets)
	pad(b)

	if ecSize > 0 {
		w.writeHeader(b, ECSymbolsMemberName, 0, 0, 0, 0, ecSize)
		writeECIndex(b, ec)
		pad(b)
	}

	if len(longNames) > 0 {
		w.writeHeader(b, LongNamesMemberName, 0, 0, 0, 0, len(longNames))
		b.Bytes(longNames)
		pad(b)
	}

	for i, in := range w.inputs {
		w.writeHeader(b, names[i], in.ModTime, in.UID, in.GID, in.Mode, len(in.Data))
		b.Bytes(in.Data)
		pad(b)
	}

	data, err := b.Data()
	if err != nil {
		return w.finish(err)
	}
	if _, err := w.w.Write(data); err != nil {
		return w.finish(err)
	}
	return nil
}

func (w *Writer) finish(err error) error {
	w.Fail(err)
	return w.err
}

func (w *Writer) magic() string {
	if w.opt.Thin {
		return ThinMagic
	}
	return Magic
}

// memberSpan is a member's total footprint: header, data, and the pad that
// brings the next header back to an even offset.
func memberSpan(size int64) int64 {
	n := int64(MemberHeaderSize) + size
	if n%MemberAlign != 0 {
		n++
	}
	return n
}

func pad(b *binio.Buf) {
	if b.Len()%MemberAlign != 0 {
		b.Pad(MemberPadByte, 1)
	}
}

func nameBytes(syms []symRef) int {
	n := 0
	for _, s := range syms {
		n += len(s.name) + 1
	}
	return n
}

// buildNames chooses each member's 16-byte name field and builds the "//"
// member.
//
// A name that fits goes inline with a trailing slash, which is what terminates
// it — the field is not NUL-padded, so a 16-byte name and a 15-byte name plus
// slash are indistinguishable without one. A name containing a slash must
// escape regardless of length, since the slash would be read as the terminator.
//
// Entries in the table are NUL-terminated, which is the COFF shape. GNU
// archives end each with "/\n" instead; the reader takes either, the writer
// emits only this one.
func (w *Writer) buildNames() ([]string, []byte) {
	out := make([]string, len(w.inputs))
	var tab []byte
	seen := map[string]int{}

	for i, in := range w.inputs {
		if len(in.Name) < hdrNameLen-1 && !strings.Contains(in.Name, "/") && !w.opt.Thin {
			out[i] = in.Name + "/"
			continue
		}
		off, ok := seen[in.Name]
		if !ok {
			off = len(tab)
			seen[in.Name] = off
			tab = append(tab, in.Name...)
			tab = append(tab, 0)
		}
		out[i] = "/" + strconv.Itoa(off)
	}
	return out, tab
}

// buildSymbols bins every symbol into the native index or the EC one.
//
// The routing is by the member's machine type, read from its header — which is
// the only thing this package knows how to find inside a member, and the reason
// pe.MachineOf exists. A member whose machine cannot be read contributes to the
// native index, since an unrecognizable member is not an EC one.
//
// Both lists are deduplicated first-wins and sorted by name: the second linker
// member and the EC member are both binary-searched by the linker.
func (w *Writer) buildSymbols() (native, ec []symRef) {
	useEC := w.wantEC()
	seenN := map[string]bool{}
	seenE := map[string]bool{}

	for i, in := range w.inputs {
		idx := uint16(i + 1)
		toEC := useEC && isECMachine(machineOfBytes(in.Data))
		for _, s := range in.Symbols {
			if toEC {
				if !seenE[s] {
					seenE[s] = true
					ec = append(ec, symRef{s, idx})
				}
				continue
			}
			if !seenN[s] {
				seenN[s] = true
				native = append(native, symRef{s, idx})
			}
		}
	}
	sort.Slice(native, func(i, j int) bool { return native[i].name < native[j].name })
	sort.Slice(ec, func(i, j int) bool { return ec[i].name < ec[j].name })
	return native, ec
}

// wantEC decides whether to emit the /<ECSYMBOLS>/ member.
//
// The inferred rule is: emit when the archive holds both an ARM64-family object
// and an EC one. That is the case where one library has to serve a native
// ARM64 link, a pure ARM64EC link, and a hybrid ARM64X link, and the two symbol
// namespaces have to stay apart.
//
// This is narrower than llvm-lib's, which treats any machine that is not plain
// ARM64 as an EC object — including x86, which cannot participate in an EC link
// at all. The wider rule emits a spurious EC member for a library holding x86
// and ARM64 objects; harmless, but not something to reproduce deliberately.
func (w *Writer) wantEC() bool {
	if w.opt.EC != nil {
		return *w.opt.EC
	}
	var haveARM64, haveEC bool
	for _, in := range w.inputs {
		m := machineOfBytes(in.Data)
		switch m {
		case pe.MachineARM64, pe.MachineARM64EC, pe.MachineARM64X:
			haveARM64 = true
		}
		if isECMachine(m) {
			haveEC = true
		}
		if haveARM64 && haveEC {
			return true
		}
	}
	return false
}

func isECMachine(m pe.Machine) bool {
	switch m {
	case pe.MachineARM64EC, pe.MachineARM64X, pe.MachineAMD64:
		return true
	}
	return false
}

func machineOfBytes(data []byte) pe.Machine {
	n := pe.KindPrefix
	if len(data) < n {
		n = len(data)
	}
	m, ok := pe.MachineOf(data[:n])
	if !ok {
		return pe.MachineUnknown
	}
	return m
}

// writeFirstIndex emits the legacy big-endian index.
//
// This is the one big-endian structure in the module. It is written because
// some very old consumers read only this member; the reader here trusts the
// second one, and so does every linker anybody still uses.
func writeFirstIndex(b *binio.Buf, syms []symRef, offsets []int64) {
	beU32(b, uint32(len(syms)))
	for _, s := range syms {
		beU32(b, uint32(offsets[s.idx-1]))
	}
	for _, s := range syms {
		b.CStr(s.name)
	}
}

// writeSecondIndex emits the authoritative little-endian index: a member offset
// table, then one one-based index into it per symbol, then the sorted names.
func writeSecondIndex(b *binio.Buf, syms []symRef, offsets []int64) {
	b.U32(uint32(len(offsets)))
	for _, off := range offsets {
		b.U32(uint32(off))
	}
	b.U32(uint32(len(syms)))
	for _, s := range syms {
		b.U16(s.idx)
	}
	for _, s := range syms {
		b.CStr(s.name)
	}
}

// writeECIndex emits /<ECSYMBOLS>/, which has no offset table of its own and
// indexes the second linker member's.
func writeECIndex(b *binio.Buf, syms []symRef) {
	b.U32(uint32(len(syms)))
	for _, s := range syms {
		b.U16(s.idx)
	}
	for _, s := range syms {
		b.CStr(s.name)
	}
}

func beU32(b *binio.Buf, v uint32) {
	b.U8(byte(v >> 24))
	b.U8(byte(v >> 16))
	b.U8(byte(v >> 8))
	b.U8(byte(v))
}

// writeHeader emits one 60-byte member header. Every field is left-justified
// ASCII, space-padded, and unterminated.
func (w *Writer) writeHeader(b *binio.Buf, name string, modTime int64, uid, gid int, mode uint32, size int) {
	if len(name) > hdrNameLen {
		w.Fail(ErrBadHeader)
		return
	}
	padStr(b, name, hdrNameLen)
	padStr(b, strconv.FormatInt(modTime, 10), hdrDateLen)
	padStr(b, strconv.Itoa(uid), hdrUIDLen)
	padStr(b, strconv.Itoa(gid), hdrGIDLen)
	padStr(b, strconv.FormatUint(uint64(mode), 8), hdrModeLen)
	padStr(b, strconv.Itoa(size), hdrSizeLen)
	b.Bytes(hdrTerminator[:])
}

func padStr(b *binio.Buf, s string, n int) {
	b.Bytes([]byte(s))
	if len(s) < n {
		b.Pad(' ', n-len(s))
	}
}