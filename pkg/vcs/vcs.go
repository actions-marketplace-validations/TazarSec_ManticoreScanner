package vcs

import (
	"context"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
)

type Context struct {
	Provider   string
	Repository string
	PRNumber   int
	CommitSHA  string
	Token      string
}

type Provider interface {
	Name() string
	Detect() (*Context, error)
	PostResults(ctx context.Context, vcsCtx *Context, results []api.BatchResultItem, scanErr error) error
}
