package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"time"
)

type PollerConfig struct {
	Timeout           time.Duration
	InitialInterval   time.Duration
	MaxInterval       time.Duration
	BackoffMultiplier float64
	OnProgress        func(completed, total int)
}

func DefaultPollerConfig() PollerConfig {
	return PollerConfig{
		Timeout:           5 * time.Minute,
		InitialInterval:   2 * time.Second,
		MaxInterval:       30 * time.Second,
		BackoffMultiplier: 1.5,
	}
}

func PollUntilComplete(ctx context.Context, client *Client, items []ScanRequestItem, cfg PollerConfig) ([]BatchResultItem, error) {
	if len(items) == 0 {
		return nil, nil
	}

	completed := make(map[string]BatchResultItem)
	pending := items
	interval := cfg.InitialInterval
	deadline := time.Now().Add(cfg.Timeout)

	for {
		resp, _, err := client.ScanBatch(ctx, pending)
		if err != nil {
			var rlErr *RateLimitError
			if errors.As(err, &rlErr) {
				wait := time.Duration(rlErr.RetryAfterSec) * time.Second
				if wait == 0 {
					wait = 60 * time.Second
				}

				deadline = deadline.Add(wait)
				if err := sleep(ctx, wait); err != nil {
					return collectResults(completed, pending), err
				}
				continue
			}
			return collectResults(completed, pending), fmt.Errorf("scan request failed: %w", err)
		}

		var stillPending []ScanRequestItem
		for _, result := range resp.Results {
			key := resultKey(result)
			if result.Status == StatusCompleted || result.Error != "" {
				completed[key] = result
			} else {
				stillPending = append(stillPending, ScanRequestItem{
					Package:   result.Package,
					Version:   result.Version,
					Ecosystem: Ecosystem(result.Ecosystem),
					Hash:      result.Hash,
				})
			}
		}

		total := len(completed) + len(stillPending)
		if cfg.OnProgress != nil {
			cfg.OnProgress(len(completed), total)
		}

		if len(stillPending) == 0 {
			return collectResults(completed, nil), nil
		}

		if time.Now().After(deadline) {
			return collectResults(completed, stillPending), nil
		}

		jittered := applyJitter(interval)
		if err := sleep(ctx, jittered); err != nil {
			return collectResults(completed, stillPending), err
		}

		interval = time.Duration(float64(interval) * cfg.BackoffMultiplier)
		if interval > cfg.MaxInterval {
			interval = cfg.MaxInterval
		}

		pending = stillPending
	}
}

func resultKey(r BatchResultItem) string {
	if r.Hash != "" {
		return "hash:" + r.Hash
	}
	return r.Package + "@" + r.Version
}

func applyJitter(d time.Duration) time.Duration {
	jitter := 0.8 + rand.Float64()*0.4
	return time.Duration(float64(d) * jitter)
}

func collectResults(completed map[string]BatchResultItem, pending []ScanRequestItem) []BatchResultItem {
	results := make([]BatchResultItem, 0, len(completed)+len(pending))
	for _, r := range completed {
		results = append(results, r)
	}
	for _, p := range pending {
		results = append(results, BatchResultItem{
			Package:   p.Package,
			Version:   p.Version,
			Ecosystem: string(p.Ecosystem),
			Hash:      p.Hash,
			Status:    StatusInProgress,
		})
	}
	return results
}

func sleep(ctx context.Context, d time.Duration) error {
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func ChunkItems(items []ScanRequestItem, chunkSize int) [][]ScanRequestItem {
	if chunkSize <= 0 {
		chunkSize = 50
	}
	n := int(math.Ceil(float64(len(items)) / float64(chunkSize)))
	chunks := make([][]ScanRequestItem, 0, n)
	for i := 0; i < len(items); i += chunkSize {
		end := i + chunkSize
		if end > len(items) {
			end = len(items)
		}
		chunks = append(chunks, items[i:end])
	}
	return chunks
}
