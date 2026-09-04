package def

import (
	"strconv"
	"strings"

	"github.com/vertex-language/pe"
)

// Statement tags. They are case-sensitive, which the trailing keywords of an
// export definition are not — LIB compares tags exactly and folds case on
// CONSTANT, PRIVATE, DATA, and NONAME. LLVM's parser matches every keyword
// case-sensitively and so rejects a lowercase `data` that link.exe accepts;
// this package follows link.exe.
const (
	tagLibrary   = "LIBRARY"
	tagName      = "NAME"
	tagExports   = "EXPORTS"
	tagHeapSize  = "HEAPSIZE"
	tagStackSize = "STACKSIZE"
	tagVersion   = "VERSION"
)

// unsupportedTags are statements LIB recognizes and this tree declines. They
// are listed rather than left to fall through to "unknown statement", because
// a .def carrying DESCRIPTION is a valid file that this package does not
// implement, and that is a different thing to tell someone than "syntax
// error".
//
// SEGMENTS is an alias of SECTIONS. CODE, DATA, IMPORTS, and PROTMODE are
// recognized but unsupported by LIB itself; DESCRIPTION, EXETYPE, STUB, and
// VXD join them outside a VxD build, which this tree never does.
var unsupportedTags = map[string]bool{
	"CODE":        true,
	"DATA":        true,
	"DESCRIPTION": true,
	"EXETYPE":     true,
	"IMPORTS":     true,
	"PROTMODE":    true,
	"SECTIONS":    true,
	"SEGMENTS":    true,
	"STUB":        true,
	"VXD":         true,
}

// isTag reports whether s begins a statement, supported or not.
//
// The EXPORTS block needs this: a definition ends the block if its first token
// is a tag, which is the only thing separating `EXPORTS\n foo\n VERSION 1.0`
// from an export named VERSION.
func isTag(s string) bool {
	switch s {
	case tagLibrary, tagName, tagExports, tagHeapSize, tagStackSize, tagVersion:
		return true
	}
	return unsupportedTags[s]
}

// Parse reads a module-definition file.
//
// An unrecognized statement is an error rather than a warning. LIB warns
// (LNK4017) and skips the line, which is the right behaviour for a tool that
// must keep building thirty-year-old projects and the wrong one here: a .def
// that silently loses half its exports produces a link that succeeds and a DLL
// that exports nothing.
func Parse(data []byte) (*File, error) {
	toks, err := lex(data)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, f: &File{}}
	if err := p.run(); err != nil {
		return nil, err
	}
	return p.f, nil
}

type parser struct {
	toks []token
	i    int
	f    *File
}

// peek returns the current token without consuming it. At the end of the
// input it returns the EOF token every time.
func (p *parser) peek() token { return p.toks[p.i] }

// advance consumes the current token, unless it is EOF.
func (p *parser) advance() {
	if p.toks[p.i].kind != tokEOF {
		p.i++
	}
}

func (p *parser) next() token {
	t := p.peek()
	p.advance()
	return t
}

func (p *parser) errorAt(t token, reason string) error {
	return &SyntaxError{Line: t.line, Col: t.col, Near: t.text, Reason: reason}
}

func (p *parser) run() error {
	for {
		t := p.next()
		if t.kind == tokEOF {
			return nil
		}
		if t.kind != tokIdent {
			return p.errorAt(t, "expected a statement")
		}
		if unsupportedTags[t.text] {
			return &UnsupportedError{Line: t.line, Directive: t.text}
		}
		var err error
		switch t.text {
		case tagLibrary, tagName:
			err = p.parseModule(t)
		case tagExports:
			err = p.parseExports()
		case tagHeapSize:
			err = p.parseSizes(t, &p.f.HeapReserve, &p.f.HeapCommit,
				&p.f.HasHeap, &p.f.HasHeapCommit)
		case tagStackSize:
			err = p.parseSizes(t, &p.f.StackReserve, &p.f.StackCommit,
				&p.f.HasStack, &p.f.HasStackCommit)
		case tagVersion:
			err = p.parseVersion(t)
		default:
			return p.errorAt(t, "unknown statement")
		}
		if err != nil {
			return err
		}
	}
}

// parseModule reads LIBRARY or NAME, each of which is a name and an optional
// base address:
//
//	LIBRARY [name] [BASE=address]
//	NAME    [name] [BASE=address]
//
// The name is optional in both. A bare LIBRARY is how a .def declares that the
// module is a DLL without naming it, leaving the name to the output file.
func (p *parser) parseModule(tag token) error {
	if p.f.Library != "" || p.f.Name != "" {
		return ErrDuplicateModule
	}

	name := ""
	if t := p.peek(); t.kind == tokIdent && t.line == tag.line && t.text != "BASE" {
		name = t.text
		p.advance()
	}
	// An empty name still records which statement was seen, so IsDLL can
	// answer. A DLL with no name is spelled with a single space rather than
	// left empty, because "" is also what NAME leaves behind.
	if name == "" {
		name = " "
	}
	if tag.text == tagLibrary {
		p.f.Library = name
	} else {
		p.f.Name = name
	}

	if t := p.peek(); t.kind == tokIdent && t.line == tag.line && t.text == "BASE" {
		p.advance()
		if e := p.next(); e.kind != tokEqual || e.line != tag.line {
			return p.errorAt(e, "expected '=' after BASE")
		}
		v, err := p.parseInt(tag.line)
		if err != nil {
			return err
		}
		p.f.ImageBase, p.f.HasImageBase = v, true
	}
	return p.endOfStatement(tag)
}

// parseSizes reads HEAPSIZE or STACKSIZE: reserve[,commit].
func (p *parser) parseSizes(tag token, reserve, commit *uint64, has, hasCommit *bool) error {
	v, err := p.parseInt(tag.line)
	if err != nil {
		return err
	}
	*reserve, *has = v, true

	if t := p.peek(); t.kind == tokComma && t.line == tag.line {
		p.advance()
		v, err := p.parseInt(tag.line)
		if err != nil {
			return err
		}
		*commit, *hasCommit = v, true
	}
	return p.endOfStatement(tag)
}

// parseVersion reads VERSION major[.minor].
//
// The lexer does not split on '.', so the whole version arrives as one token
// and pe.ParseVersion does the rest. The fields it feeds are 16-bit in the
// optional header, which is where the bound comes from.
func (p *parser) parseVersion(tag token) error {
	t := p.next()
	if t.kind != tokIdent || t.line != tag.line {
		return p.errorAt(t, "expected a version after VERSION")
	}
	v, err := pe.ParseVersion(t.text)
	if err != nil {
		return p.errorAt(t, "malformed version")
	}
	p.f.Version, p.f.HasVersion = v, true
	return p.endOfStatement(tag)
}

// parseInt reads one integer on the given line.
//
// The base is inferred from the literal, so 0x10000000 and 268435456 both
// work — which matters because BASE= is conventionally written in hex and
// STACKSIZE in decimal, in the same file.
func (p *parser) parseInt(line int) (uint64, error) {
	t := p.next()
	if t.kind != tokIdent || t.line != line {
		return 0, p.errorAt(t, "expected a number")
	}
	v, err := strconv.ParseUint(t.text, 0, 64)
	if err != nil {
		return 0, p.errorAt(t, "malformed number")
	}
	return v, nil
}

// endOfStatement rejects trailing text on a single-definition statement.
//
// LIB is stricter here than anywhere else in the grammar — additional text in
// a definition is a fatal error, not a warning — and it is worth matching,
// because the text is usually a second argument someone expected to work.
func (p *parser) endOfStatement(tag token) error {
	if t := p.peek(); t.kind != tokEOF && t.line == tag.line {
		return p.errorAt(t, "unexpected text after "+tag.text)
	}
	return nil
}

// parseExports reads an EXPORTS block.
//
// The block is a multi-definition statement: the first definition may share
// the tag's line and every later one begins its own. It ends where a
// definition could begin but a statement tag appears instead — including on
// the tag's own line, which is how an empty EXPORTS lets the next statement
// start mid-line.
func (p *parser) parseExports() error {
	for {
		t := p.peek()
		if t.kind == tokEOF {
			return nil
		}
		if t.kind != tokIdent {
			return p.errorAt(t, "expected an export definition")
		}
		if isTag(t.text) {
			// Not an entry name: the next statement. Leave it for run.
			return nil
		}
		p.advance()
		if err := p.parseExport(t); err != nil {
			return err
		}
	}
}

// parseExport reads one definition:
//
//	entryname [=internalname] [@ordinal [NONAME]] [CONSTANT|PRIVATE|DATA]
//	          [==importname] [EXPORTAS exportname]
//
// The last two forms are lld extensions absent from the published
// specification. EXPORTAS is the one that matters: it is how every ARM64EC
// import library relates a mangled symbol to a demangled export, which no
// prefix rule can express.
//
// Everything belonging to the definition is on entry's line. A token on a
// later line begins the next definition; an unrecognized token on this one is
// an error rather than the start of anything.
func (p *parser) parseExport(entry token) error {
	e := pe.Export{Name: entry.text}

	if t := p.peek(); t.kind == tokEqual && t.line == entry.line {
		p.advance()
		v := p.peek()
		if v.kind != tokIdent || v.line != entry.line {
			// LIB accepts a dangling '=' and takes the definition as
			// having ended with just the entry name. That is almost
			// always a truncated line, and accepting it exports a
			// name whose implementation was meant to be elsewhere,
			// so this follows lld and refuses.
			return p.errorAt(v, "expected an internal name after '='")
		}
		p.advance()
		// The exported name is the left side and the internal name the
		// right. Reversing these produces a library that builds and
		// exports the wrong names, which is why the assignment is
		// spelled out rather than done in the struct literal above.
		e.ExtName = e.Name
		e.Name = v.text
	}

	var hasOrdinal bool
	for {
		t := p.peek()
		if t.kind == tokEOF || t.line != entry.line {
			break
		}

		if t.kind == tokEqualEqual {
			p.advance()
			v := p.peek()
			if v.kind != tokIdent || v.line != entry.line {
				return p.errorAt(v, "expected a name after '=='")
			}
			p.advance()
			e.ImportName = v.text
			continue
		}

		if t.kind != tokIdent {
			return p.errorAt(t, "unexpected text in export definition")
		}

		// An ordinal is an '@' that stands apart from the preceding
		// token. One attached to it — _Func@8 — is part of a decorated
		// __stdcall name and never reaches here, because the lexer does
		// not break identifiers on '@'.
		if strings.HasPrefix(t.text, "@") {
			if hasOrdinal {
				return p.errorAt(t, "ordinal given twice")
			}
			p.advance()
			digits := t.text[1:]
			if digits == "" {
				v := p.peek()
				if v.kind != tokIdent || v.line != entry.line {
					return p.errorAt(v, "expected an ordinal after '@'")
				}
				p.advance()
				digits, t = v.text, v
			}
			n, err := parseOrdinal(digits)
			if err != nil {
				return p.errorAt(t, err.Error())
			}
			e.Ordinal, hasOrdinal = n, true
			continue
		}

		switch strings.ToUpper(t.text) {
		case "NONAME":
			if !hasOrdinal {
				// Exporting by ordinal only, with no ordinal,
				// names nothing at all.
				return p.errorAt(t, "NONAME without an ordinal")
			}
			p.advance()
			e.NoName = true
			continue
		case "DATA":
			p.advance()
			e.Data = true
			continue
		case "CONSTANT":
			p.advance()
			e.Constant = true
			continue
		case "PRIVATE":
			p.advance()
			e.Private = true
			continue
		case "EXPORTAS":
			p.advance()
			v := p.peek()
			if v.kind != tokIdent || v.line != entry.line {
				return p.errorAt(v, "expected a name after EXPORTAS")
			}
			p.advance()
			e.ExportAs = v.text
			// EXPORTAS ends the definition; anything after it on this
			// line is trailing text.
			if n := p.peek(); n.kind != tokEOF && n.line == entry.line {
				return p.errorAt(n, "unexpected text after EXPORTAS")
			}
			p.f.Exports = append(p.f.Exports, e)
			return nil
		}

		return p.errorAt(t, "unexpected text in export definition")
	}

	// LIB allows only one of CONSTANT, PRIVATE, and DATA, and warns that
	// CONSTANT is obsolete. This package accepts any combination: DATA and
	// PRIVATE say unrelated things — one is the kind of the export, the
	// other whether it reaches the import library — and refusing a pairing
	// that lld accepts would reject files that link today.

	p.f.Exports = append(p.f.Exports, e)
	return nil
}

// parseOrdinal validates an export ordinal.
//
// The space is one-based and 16 bits. LIB reads the leading digits and ignores
// whatever follows them, so "@12abc" is ordinal 12 there; this requires the
// whole token to be digits, because the ignored tail is how a typo becomes a
// silently different ordinal and the ordinal is what a NONAME export is found
// by.
func parseOrdinal(s string) (uint16, error) {
	if s == "" {
		return 0, errReason("empty ordinal")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errReason("ordinal is not a decimal number")
		}
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil || v == 0 || v > 65535 {
		return 0, errReason("ordinal outside 1..65535")
	}
	return uint16(v), nil
}

// errReason carries a parse reason up to the caller that knows the position.
type errReason string

func (e errReason) Error() string { return string(e) }