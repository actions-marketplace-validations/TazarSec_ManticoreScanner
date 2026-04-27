package parser

import "io"

type Package struct {
	Name      string
	Version   string
	Ecosystem string
	Integrity string
}

type ParseOptions struct {
	IncludeDev        bool
	IncludeTransitive bool
}

type Parser interface {
	Parse(r io.Reader, opts ParseOptions) ([]Package, error)
	Ecosystem() string
}
