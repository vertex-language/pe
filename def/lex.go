package def

// The lexer keeps line structure, because the grammar needs it: a statement
// tag is recognized only where a definition may begin, and where a definition
// may begin is decided by line breaks. Every token therefore records the line
// it came from and whether it was the first on that line.

type tokKind uint8

const (
	tokEOF tokKind = iota
	tokIdent
	tokEqual      // =
	tokEqualEqual // ==
	tokComma      // ,
)

type token struct {
	kind  tokKind
	text  string
	line  int
	col   int
	first bool // the first token on its line
}

// eofChar is Ctrl-Z. LIB reads a .def through the C runtime's text mode, in
// which this character ends the text before the end of the file. Files
// produced on MS-DOS-descended tooling still carry one, and honouring it costs
// one line.
const eofChar = 0x1a

// utf8BOM is stripped if present. Nothing in the format calls for one, but
// editors add them and a BOM would otherwise become part of the first tag,
// which fails as "unknown statement" a long way from the cause.
var utf8BOM = "\xef\xbb\xbf"

// lex tokenizes the whole file.
//
// A .def is a few hundred lines at most, so everything is tokenized up front
// and the parser indexes a slice. That is what makes lookahead free, and
// lookahead is what the export grammar needs: whether a token is an ordinal or
// the start of the next definition is decided by the line it sits on.
func lex(data []byte) ([]token, error) {
	s := string(data)
	if i := indexByte(s, eofChar); i >= 0 {
		s = s[:i]
	}
	if len(s) >= len(utf8BOM) && s[:len(utf8BOM)] == utf8BOM {
		s = s[len(utf8BOM):]
	}

	var toks []token
	line := 0
	for len(s) > 0 || line == 0 {
		line++
		var l string
		if i := indexByte(s, '\n'); i >= 0 {
			l, s = s[:i], s[i+1:]
		} else {
			l, s = s, ""
		}
		if n := len(l); n > 0 && l[n-1] == '\r' {
			l = l[:n-1]
		}
		var err error
		toks, err = lexLine(l, line, toks)
		if err != nil {
			return nil, err
		}
		if s == "" {
			break
		}
	}
	return append(toks, token{kind: tokEOF, line: line}), nil
}

// lexLine tokenizes one line, which has already had its terminator removed.
func lexLine(l string, line int, out []token) ([]token, error) {
	first := true
	for i := 0; i < len(l); {
		if isSpace(l[i]) {
			i++
			continue
		}
		col := i + 1
		switch c := l[i]; {
		case c == ';':
			// A semicolon outside quotes begins a comment that runs to
			// the end of the line.
			return out, nil

		case c == ',':
			out = append(out, token{tokComma, ",", line, col, first})
			i++

		case c == '=':
			if i+1 < len(l) && l[i+1] == '=' {
				out = append(out, token{tokEqualEqual, "==", line, col, first})
				i += 2
				break
			}
			out = append(out, token{tokEqual, "=", line, col, first})
			i++

		case c == '"':
			j := i + 1
			for j < len(l) && l[j] != '"' {
				j++
			}
			if j >= len(l) {
				return nil, &SyntaxError{
					Line: line, Col: col, Near: l[i:],
					Reason: "unterminated quoted name",
				}
			}
			// The quotes are removed and the text inside is taken
			// verbatim, semicolons included. Quoting is an lld
			// extension; link.exe would treat that semicolon as a
			// comment, but a file relying on the difference does not
			// exist and accepting both costs nothing.
			out = append(out, token{tokIdent, l[i+1 : j], line, col, first})
			i = j + 1

		default:
			j := i
			for j < len(l) && !isDelim(l[j]) {
				j++
			}
			out = append(out, token{tokIdent, l[i:j], line, col, first})
			i = j
		}
		first = false
	}
	return out, nil
}

// isSpace is the whitespace that separates tokens within a line.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\v' || c == '\f'
}

// isDelim reports whether c ends an identifier.
//
// '@' is deliberately absent. A decorated __stdcall name is _Func@8, and an
// ordinal is @8 — the two are told apart by whether the '@' is attached to the
// preceding text or stands on its own, so the lexer must not split on it and
// the parser decides by position. Splitting here is how "_Func@8" becomes a
// symbol named "_Func" at ordinal 8.
func isDelim(c byte) bool {
	return isSpace(c) || c == '=' || c == ',' || c == ';'
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}