package formatter

import "github.com/TazarSec/ManticoreScanner/pkg/api"

type Options struct {
	InputFile string
}

type Formatter interface {
	Format(results []api.BatchResultItem, opts Options) ([]byte, error)
}

func Get(name string) Formatter {
	switch name {
	case "json":
		return &JSONFormatter{}
	case "sarif":
		return &SARIFFormatter{}
	case "table":
		return &TableFormatter{}
	default:
		return &TableFormatter{}
	}
}
