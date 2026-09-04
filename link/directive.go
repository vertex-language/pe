package link

import (
	"strconv"
	"strings"

	"github.com/vertex-language/pe"
	"github.com/vertex-language/pe/coff"
)

// A .drectve section replays linker options from inside an object file. It is
// how __declspec(dllexport) becomes an export, how the CRT names the library
// it needs, and how #pragma comment(linker, ...) reaches the link at all.
//
// Three kinds of option arrive here and they need three different answers.
//
// Honoured — the option means the same thing here as on the command line, and
// is applied.
//
// Ignored — link.exe accepts it from a #pragma comment(linker, ...) and it
// affects something this tree does not implement. It is accepted and dropped,
// deliberately and by name. That list is a compatibility surface rather than a
// design: a new toolchain adds a flag, its standard library starts emitting
// it, and every build with a linker that rejects unknown options breaks at
// once. That has happened — /INFERASANLIBS appeared in the MSVC STL and broke
// every lld ASAN link until it was added to exactly this list.
//
// Refused — everything else. An option this linker does not recognize is an
// error rather than a warning, because a directive that silently does nothing
// is a build whose flags are not the flags it thinks it has.

// ignoredDirectives are accepted and dropped. Each is here because link.exe
// accepts it in a #pragma-generated directive section and it controls
// something outside this tree's scope.
var ignoredDirectives = map[string]bool{
	"EDITANDCONTINUE":  true, // incremental linking, which this tree does not do
	"GUARDSYM":         true, // a /GUARD:CF detail carried in the load config
	"THROWINGNEW":      true, // an MSVC allocator choice with no linker effect here
	"INFERASANLIBS":    true, // the sanitizer runtime selection; the driver picks it
	"INFERASANLIBS:NO": true,
	"DISABLEPHYSICALPAGERANDOMIZATION": true,
}

// applyDirectives replays every option in an object's .drectve section.
//
// It runs once per object, which the flag rather than a set enforces, because
// an object fetched twice from an archive would otherwise contribute its
// exports twice.
func (l *Linker) applyDirectives(o *Object) error {
	if o.directives {
		return nil
	}
	o.directives = true
	for _, d := range o.File.Directives() {
		if err := l.applyDirective(o, d); err != nil {
			return l.fail(err)
		}
	}
	return nil
}

// applyDirective applies one option.
//
// coff has already tokenized and normalized: the leading slash or hyphen is
// gone, the name is upper case, and the value keeps its case because library,
// symbol, and export names are case-sensitive to everything downstream.
func (l *Linker) applyDirective(o *Object, d coff.Directive) error {
	bad := func(reason string) error {
		return &DirectiveError{Input: o.Name, Name: d.Name, Value: d.Value,
			Reason: reason, Err: ErrDirectiveNotAllowed}
	}

	switch d.Name {
	case "DEFAULTLIB":
		l.needLibrary(d.Value)

	case "NODEFAULTLIB", "DISALLOWLIB":
		// DISALLOWLIB is the same exclusion under the name the MSVC CRT
		// uses for it. It is how libcmt.obj declares that it will not
		// share a link with msvcrt.lib, and lld-link resolves it to
		// /NODEFAULTLIB for exactly that reason. It is undocumented and
		// unavoidable: every static-CRT link on Windows carries several.
		//
		// An exclusion arriving from an object applies to libraries not
		// yet opened. One already open stays open: it may have supplied
		// definitions that are being used, and unwinding that is not
		// something the format lets a linker do halfway through.
		if d.Value == "" {
			l.opt.NoDefaultLibAll = true
			break
		}
		l.opt.NoDefaultLibs = append(l.opt.NoDefaultLibs, d.Value)

	case "EXPORT":
		e, err := parseExportDirective(d.Value)
		if err != nil {
			return &DirectiveError{Input: o.Name, Name: d.Name, Value: d.Value, Err: err}
		}
		l.opt.Exports = append(l.opt.Exports, e)

	case "INCLUDE":
		if d.Value == "" {
			return bad("no symbol name")
		}
		l.opt.Includes = append(l.opt.Includes, d.Value)

	case "ALTERNATENAME":
		from, to, ok := strings.Cut(d.Value, "=")
		if !ok || from == "" || to == "" {
			return bad("expected from=to")
		}
		l.opt.AlternateNames = append(l.opt.AlternateNames, AlternateName{from, to})

	case "FAILIFMISMATCH":
		if err := l.recordMismatch(o, d.Value); err != nil {
			return err
		}

	case "MERGE":
		from, to, ok := strings.Cut(d.Value, "=")
		if !ok || from == "" || to == "" {
			return bad("expected from=to")
		}
		l.opt.Merges = append(l.opt.Merges, Merge{from, to})

	case "SECTION":
		ov, err := parseSectionDirective(d.Value)
		if err != nil {
			return &DirectiveError{Input: o.Name, Name: d.Name, Value: d.Value, Err: err}
		}
		l.opt.Sections = append(l.opt.Sections, ov)

	case "STACK":
		reserve, commit, err := parseNumbers(d.Value)
		if err != nil {
			return &DirectiveError{Input: o.Name, Name: d.Name, Value: d.Value, Err: err}
		}
		l.opt.StackReserve, l.opt.StackCommit, l.opt.HasStack = reserve, commit, true

	case "HEAP":
		reserve, commit, err := parseNumbers(d.Value)
		if err != nil {
			return &DirectiveError{Input: o.Name, Name: d.Name, Value: d.Value, Err: err}
		}
		l.opt.HeapReserve, l.opt.HeapCommit, l.opt.HasHeap = reserve, commit, true

	case "SUBSYSTEM":
		sub, ver, hasVer, err := parseSubsystem(d.Value)
		if err != nil {
			return &DirectiveError{Input: o.Name, Name: d.Name, Value: d.Value, Err: err}
		}
		l.opt.Subsystem = sub
		if hasVer {
			// The subsystem version doubles as the OS version, which
			// is what link.exe does and what decides the lowest
			// Windows the image will load on.
			l.opt.SubsystemVersion, l.opt.OSVersion = ver, ver
		}

	case "ALIGNCOMM":
		sym, align, err := parseAlignComm(d.Value)
		if err != nil {
			return &DirectiveError{Input: o.Name, Name: d.Name, Value: d.Value, Err: err}
		}
		l.AlignComm(sym, align)

	case "MANIFESTDEPENDENCY":
		// Recorded rather than applied. It belongs in the manifest, and
		// this tree embeds a manifest the caller supplies rather than
		// composing one — so dropping it silently would lose a
		// dependency the build declared.
		if l.opt.Manifest == ManifestNone {
			return bad("manifest dependencies require /MANIFEST")
		}
		l.manifestDeps = append(l.manifestDeps, d.Value)

	default:
		if ignoredDirectives[d.Name] ||
			ignoredDirectives[d.Name+":"+strings.ToUpper(d.Value)] {
			break
		}
		return bad("")
	}
	return nil
}

// recordMismatch applies one /FAILIFMISMATCH:key=value.
//
// The directive comes from #pragma detect_mismatch, whose entire job is to
// turn an ABI incompatibility into a link failure instead of a crash: two
// objects built against different runtime libraries, or different compiler
// versions, or with and without a sanitizer. The comparison is exact and
// case-sensitive, because the values are opaque strings chosen by whoever
// wrote the pragma.
func (l *Linker) recordMismatch(o *Object, value string) error {
	key, val, ok := strings.Cut(value, "=")
	if !ok || key == "" {
		return &DirectiveError{Input: o.Name, Name: "FAILIFMISMATCH", Value: value,
			Reason: "expected key=value", Err: ErrDirectiveNotAllowed}
	}
	prev, seen := l.mismatch[key]
	if !seen {
		l.mismatch[key] = mismatch{value: val, input: o.Name}
		return nil
	}
	if prev.value == val {
		return nil
	}
	return &MismatchError{
		Key: key, Value: val, Input: o.Name,
		PrevValue: prev.value, PrevInput: prev.input,
	}
}

// mismatch is one recorded /FAILIFMISMATCH value and the first object that
// declared it. The input is kept because the answer to a mismatch is always
// "rebuild one of these two" and the useful question is which two.
type mismatch struct {
	value string
	input string
}

// parseExportDirective reads /EXPORT's value:
//
//	name[=internalname][,@ordinal][,NONAME][,DATA][,CONSTANT][,PRIVATE][,EXPORTAS:name]
//
// The comma separation is the difference from a .def EXPORTS line, which
// separates with spaces. Everything else — including which side of the '=' is
// which — is the same, and the direction reads backwards: the left side is the
// name the DLL presents and the right is the symbol inside it.
func parseExportDirective(s string) (pe.Export, error) {
	if s == "" {
		return pe.Export{}, ErrDirectiveNotAllowed
	}
	parts := strings.Split(s, ",")

	e := pe.Export{Name: strings.TrimSpace(parts[0])}
	if e.Name == "" {
		return pe.Export{}, ErrDirectiveNotAllowed
	}
	if ext, internal, ok := strings.Cut(e.Name, "="); ok {
		if ext == "" || internal == "" {
			return pe.Export{}, ErrDirectiveNotAllowed
		}
		// The exported name is the left side and the internal name the
		// right. Spelling the assignment out rather than doing it in a
		// literal is deliberate: reversing these produces a DLL that
		// links and exports the wrong names.
		e.ExtName = ext
		e.Name = internal
	}

	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(p, "@"); ok {
			n, err := strconv.ParseUint(rest, 10, 32)
			if err != nil || n == 0 || n > 65535 {
				return pe.Export{}, &OrdinalError{Name: e.Name, Ordinal: uint32(n)}
			}
			e.Ordinal = uint16(n)
			continue
		}
		if name, ok := cutFoldPrefix(p, "EXPORTAS:"); ok {
			if name == "" {
				return pe.Export{}, ErrDirectiveNotAllowed
			}
			e.ExportAs = name
			continue
		}
		switch strings.ToUpper(p) {
		case "NONAME":
			e.NoName = true
		case "DATA":
			e.Data = true
		case "CONSTANT":
			e.Constant = true
		case "PRIVATE":
			e.Private = true
		default:
			return pe.Export{}, ErrDirectiveNotAllowed
		}
	}

	if e.NoName && e.Ordinal == 0 {
		// Exporting by ordinal only, with no ordinal, names nothing.
		return pe.Export{}, &OrdinalError{Name: e.Name}
	}
	return e, nil
}

func cutFoldPrefix(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

// parseSectionDirective reads /SECTION's value: name,[!]attrs.
//
// The attributes are single letters and a leading '!' negates the ones that
// follow it, so ".data,!W" is a writable section made read-only. Only the
// memory half is settable: the content flags come from what the section holds,
// and letting a directive change those would change what the section is rather
// than how it may be touched.
func parseSectionDirective(s string) (SectionOverride, error) {
	name, attrs, ok := strings.Cut(s, ",")
	if !ok || name == "" {
		return SectionOverride{}, ErrDirectiveNotAllowed
	}

	var set, clear pe.SecProt
	negate := false
	for i := 0; i < len(attrs); i++ {
		c := attrs[i]
		if c == '!' {
			negate = true
			continue
		}
		var bit pe.SecProt
		switch c {
		case 'E', 'e':
			bit = pe.SecExecute
		case 'R', 'r':
			bit = pe.SecRead
		case 'W', 'w':
			bit = pe.SecWrite
		case 'S', 's':
			bit = pe.SecShared
		case 'D', 'd':
			bit = pe.SecDiscardable
		case 'K', 'k':
			bit = pe.SecNotCached
		case 'P', 'p':
			bit = pe.SecNotPaged
		case ' ':
			continue
		default:
			return SectionOverride{}, ErrDirectiveNotAllowed
		}
		if negate {
			clear |= bit
		} else {
			set |= bit
		}
	}
	// The cleared bits are recorded by their absence from Prot, which is
	// enough because an override replaces the section's protection outright
	// rather than amending it. Keeping both halves would only matter if
	// overrides composed, and link.exe's do not.
	return SectionOverride{Name: strings.TrimSpace(name), Prot: set &^ clear}, nil
}

// parseAlignComm reads /ALIGNCOMM's value: symbol,log2align.
//
// The alignment is a log2 exponent here, unlike everywhere else in this tree,
// because that is what the directive carries. It is converted immediately, so
// the exponent never leaves this function — the same rule the section
// alignment nibble follows.
func parseAlignComm(s string) (string, int, error) {
	sym, exp, ok := strings.Cut(s, ",")
	if !ok || sym == "" {
		return "", 0, ErrDirectiveNotAllowed
	}
	n, err := strconv.Atoi(strings.TrimSpace(exp))
	if err != nil || n < 0 || n > 13 {
		// Thirteen is log2(8192), the largest alignment a section can
		// express, and a common block cannot ask for more than the
		// section it lands in can provide.
		return "", 0, ErrDirectiveNotAllowed
	}
	return sym, 1 << n, nil
}