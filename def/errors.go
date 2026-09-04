// Package def parses module-definition files: the .def files that name a
// module's exports and a few of its image parameters.
//
// It is a leaf. Nothing here does I/O beyond taking a byte slice, and the only
// package it imports from this tree is pe, for Export and Version.
//
// The grammar this package implements is link.exe's, which is line-oriented: a
// definition runs to the end of the line it starts on, and every definition
// after the first begins a new line. LLVM's parser is not — its lexer trims
// newlines like any other whitespace and then recovers the definition boundary
// with a heuristic, testing whether the text after an '@' parses as an integer
// so that "foo\n@bar" is two exports rather than one with an ordinal. Keeping
// the line structure makes that heuristic unnecessary, and this package
// accepts every file either tool accepts.
package def

import (
	"errors"
	"strconv"
)

var (
	// ErrSyntax means the file could not be parsed. The concrete error is a
	// *SyntaxError carrying the line and column.
	ErrSyntax = errors.New("def: malformed module-definition file")

	// ErrUnsupportedDirective means a statement this tree recognizes but
	// does not implement. The concrete error is an *UnsupportedError.
	//
	// The distinction from ErrSyntax is the whole point of having two: a
	// .def carrying DESCRIPTION is a valid file this package declines, and
	// telling its author it is malformed sends them looking for a typo that
	// is not there.
	ErrUnsupportedDirective = errors.New("def: recognized but unimplemented statement")

	// ErrDuplicateModule means both LIBRARY and NAME appeared, or one of
	// them appeared twice. A file that names the module twice does not say
	// which name wins, and guessing produces a DLL whose import library
	// points at a different file than the one built.
	ErrDuplicateModule = errors.New("def: module named more than once")
)

// SyntaxError is a parse failure at a position.
//
// Line and Col are one-based, and Col counts bytes rather than runes: a .def
// is ASCII in every case anyone has produced, and a byte column is what an
// editor's "go to column" agrees with for one.
type SyntaxError struct {
	Line   int
	Col    int
	Near   string // the offending token, or the text that could not be tokenized
	Reason string
}

func (e *SyntaxError) Error() string {
	s := "def: " + strconv.Itoa(e.Line) + ":" + strconv.Itoa(e.Col) + ": " + e.Reason
	if e.Near != "" {
		s += " near " + strconv.Quote(e.Near)
	}
	return s
}

func (e *SyntaxError) Unwrap() error { return ErrSyntax }

// UnsupportedError names a statement this tree recognizes and declines.
type UnsupportedError struct {
	Line      int
	Directive string
}

func (e *UnsupportedError) Error() string {
	return "def: " + strconv.Itoa(e.Line) + ": " + e.Directive +
		" is a recognized statement this tree does not implement"
}

func (e *UnsupportedError) Unwrap() error { return ErrUnsupportedDirective }