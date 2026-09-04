package coff

import (
	"strings"

	"github.com/vertex-language/pe"
)

// DirectiveSection is the name a directive section must have. The flag alone
// is not enough: the specification requires both LNK_INFO and this name.
const DirectiveSection = ".drectve"

// utf8BOM marks a directive string as UTF-8. Without it the string is ANSI.
//
// In practice this tree treats both as UTF-8, because every directive anyone
// emits is ASCII and the two encodings agree there. A non-ASCII ANSI byte
// would be misread, but it would have to appear in a library path, and a
// library path outside ASCII will already have failed elsewhere.
var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// Directive is one linker option from a .drectve section.
//
// Name is normalized: the leading / or - is stripped and the name is
// upper-cased, so the MSVC "/DEFAULTLIB:msvcrt" and the GNU "-defaultlib:msvcrt"
// both yield {Name: "DEFAULTLIB", Value: "msvcrt"}. The specification describes
// only the hyphen form, but MSVC — the dominant producer — emits the slash
// form, so both are accepted.
//
// Value keeps its case. Library names, symbol names, and export names are all
// case-sensitive to the things that consume them.
type Directive struct {
	Name  string
	Value string
}

// readDirectives finds the .drectve section and parses it.
func (f *File) readDirectives() error {
	for _, s := range f.Sections {
		if s.Name != DirectiveSection || !s.kind.Has(pe.SecLnkInfo) {
			continue
		}
		if s.hdr.NumberOfRelocations != 0 || s.hdr.NumberOfLinenumbers != 0 {
			return &SectionError{Index: s.index, Name: s.Name, Err: ErrDirectiveRelocs}
		}
		data, err := s.Data()
		if err != nil {
			return err
		}
		ds, err := ParseDirectives(data)
		if err != nil {
			return &SectionError{Index: s.index, Name: s.Name, Err: err}
		}
		f.directives = append(f.directives, ds...)
	}
	return nil
}

// ParseDirectives tokenizes a .drectve payload.
//
// The grammar is options separated by whitespace, where an option containing
// spaces is quoted. Quoting is the part that bites: a path with a space in it
// is the common case, and the quotes may wrap the whole option or only its
// value — both /DEFAULTLIB:"c:/program files/x.lib" and
// "/DEFAULTLIB:c:/program files/x.lib" occur, so the tokenizer tracks quoting
// across the whole option rather than splitting on the colon first.
func ParseDirectives(data []byte) ([]Directive, error) {
	s := string(data)
	s = strings.TrimPrefix(s, string(utf8BOM))

	var out []Directive
	i := 0
	for i < len(s) {
		for i < len(s) && isDirectiveSpace(s[i]) {
			i++
		}
		if i >= len(s) {
			break
		}
		tok, next, err := scanToken(s, i)
		if err != nil {
			return nil, err
		}
		i = next
		d, ok := parseOne(tok)
		if !ok {
			return nil, ErrBadDirective
		}
		out = append(out, d)
	}
	return out, nil
}

func isDirectiveSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// scanToken reads one whitespace-delimited option, honouring double quotes.
// Quotes are removed; the text inside them is taken verbatim.
func scanToken(s string, i int) (string, int, error) {
	var b strings.Builder
	inQuote := false
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case !inQuote && isDirectiveSpace(c):
			return b.String(), i, nil
		default:
			b.WriteByte(c)
		}
	}
	if inQuote {
		return "", i, ErrBadDirective
	}
	return b.String(), i, nil
}

// parseOne splits a normalized option into its name and value.
func parseOne(tok string) (Directive, bool) {
	if tok == "" {
		return Directive{}, false
	}
	if tok[0] != '/' && tok[0] != '-' {
		// Some producers emit a bare library name. link.exe rejects it,
		// and so does this: a directive with no option name cannot be
		// dispatched on, and guessing that it means /DEFAULTLIB would be
		// a guess about someone else's build.
		return Directive{}, false
	}
	body := tok[1:]
	if body == "" {
		return Directive{}, false
	}
	name, value, _ := strings.Cut(body, ":")
	if name == "" {
		return Directive{}, false
	}
	return Directive{Name: strings.ToUpper(name), Value: value}, true
}