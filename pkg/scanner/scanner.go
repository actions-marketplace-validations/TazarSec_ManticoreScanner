package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
	"github.com/TazarSec/ManticoreScanner/pkg/parser"
	"github.com/TazarSec/ManticoreScanner/pkg/parser/npm"
)

const maxBatchSize = 50

type Result struct {
	Items     []api.BatchResultItem
	InputFile string
}

func Run(ctx context.Context, cfg Config, onProgress func(completed, total int)) (*Result, error) {
	packages, inputFile, err := npm.DetectAndParse(cfg.InputPath, parser.ParseOptions{
		IncludeDev:        !cfg.Production,
		IncludeTransitive: cfg.IncludeTransitive,
	})
	if err != nil {
		return nil, fmt.Errorf("parsing dependencies: %w", err)
	}

	packages = filterIgnored(packages, cfg.IgnoreList)

	if len(packages) == 0 {
		return &Result{InputFile: inputFile}, nil
	}

	items := make([]api.ScanRequestItem, len(packages))
	for i, pkg := range packages {
		items[i] = api.ScanRequestItem{
			Package:   pkg.Name,
			Version:   pkg.Version,
			Ecosystem: api.Ecosystem(pkg.Ecosystem),
			Hash:      pkg.Integrity,
		}
	}

	httpClient := api.NewHTTPClient(time.Duration(cfg.HTTPTimeoutSec) * time.Second)
	client := api.NewClient(cfg.APIBaseURL, cfg.Auth, httpClient)

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	deadline := time.Now().Add(timeout)

	pollerCfg := api.DefaultPollerConfig()

	totalItems := len(items)
	batches := api.ChunkItems(items, maxBatchSize)
	allResults := make([]api.BatchResultItem, 0, totalItems)
	doneSoFar := 0

	for _, batch := range batches {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			allResults = append(allResults, pendingItems(batch)...)
			continue
		}

		batchCfg := pollerCfg
		batchCfg.Timeout = remaining
		if onProgress != nil {
			offset := doneSoFar
			batchCfg.OnProgress = func(completed, _ int) {
				onProgress(offset+completed, totalItems)
			}
		}

		batchResults, batchErr := api.PollUntilComplete(ctx, client, batch, batchCfg)
		allResults = append(allResults, batchResults...)
		doneSoFar += countResolved(batchResults)

		if batchErr != nil {
			return &Result{Items: allResults, InputFile: inputFile}, batchErr
		}
		if hasPending(batchResults) {
			return &Result{Items: allResults, InputFile: inputFile}, nil
		}
	}

	return &Result{Items: allResults, InputFile: inputFile}, nil
}

func pendingItems(batch []api.ScanRequestItem) []api.BatchResultItem {
	out := make([]api.BatchResultItem, len(batch))
	for i, item := range batch {
		out[i] = api.BatchResultItem{
			Package:   item.Package,
			Version:   item.Version,
			Ecosystem: string(item.Ecosystem),
			Hash:      item.Hash,
			Status:    api.StatusInProgress,
		}
	}
	return out
}

func isResolved(item api.BatchResultItem) bool {
	return item.Status == api.StatusCompleted || item.Error != ""
}

func countResolved(items []api.BatchResultItem) int {
	n := 0
	for _, item := range items {
		if isResolved(item) {
			n++
		}
	}
	return n
}

func hasPending(items []api.BatchResultItem) bool {
	for _, item := range items {
		if !isResolved(item) {
			return true
		}
	}
	return false
}

func filterIgnored(packages []parser.Package, ignoreList []string) []parser.Package {
	if len(ignoreList) == 0 {
		return packages
	}
	versionPins := make(map[string]struct{}, len(ignoreList))
	hashPins := make(map[string]struct{}, len(ignoreList))
	for _, entry := range ignoreList {
		if strings.HasPrefix(entry, "sha") {
			hashPins[entry] = struct{}{}
			continue
		}
		versionPins[entry] = struct{}{}
	}
	kept := packages[:0]
	for _, pkg := range packages {
		if _, skip := versionPins[pkg.Name+"@"+pkg.Version]; skip {
			continue
		}
		if pkg.Integrity != "" {
			if _, skip := hashPins[pkg.Integrity]; skip {
				continue
			}
		}
		kept = append(kept, pkg)
	}
	return kept
}
