package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TazarSec/ManticoreScanner/pkg/auth"
)

func TestPollUntilComplete_ImmediateCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(BatchResponse{
			Results: []BatchResultItem{
				{Package: "lodash", Version: "4.17.21", Status: StatusCompleted, Profile: &Profile{SuspicionScore: 0}},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, auth.NewAPIKeyAuthenticator("key"), server.Client())
	cfg := DefaultPollerConfig()
	cfg.Timeout = 5 * time.Second

	results, err := PollUntilComplete(context.Background(), client, []ScanRequestItem{
		{Package: "lodash", Version: "4.17.21"},
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusCompleted {
		t.Errorf("expected completed, got %s", results[0].Status)
	}
}

func TestPollUntilComplete_EventualCompletion(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(BatchResponse{
				Results: []BatchResultItem{
					{Package: "lodash", Version: "4.17.21", Status: StatusInProgress},
				},
			})
			return
		}
		json.NewEncoder(w).Encode(BatchResponse{
			Results: []BatchResultItem{
				{Package: "lodash", Version: "4.17.21", Status: StatusCompleted, Profile: &Profile{SuspicionScore: 42}},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, auth.NewAPIKeyAuthenticator("key"), server.Client())
	cfg := DefaultPollerConfig()
	cfg.Timeout = 30 * time.Second
	cfg.InitialInterval = 100 * time.Millisecond
	cfg.MaxInterval = 500 * time.Millisecond

	results, err := PollUntilComplete(context.Background(), client, []ScanRequestItem{
		{Package: "lodash", Version: "4.17.21"},
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Profile == nil || results[0].Profile.SuspicionScore != 42 {
		t.Error("expected suspicion score 42")
	}
}

func TestPollUntilComplete_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(BatchResponse{
			Results: []BatchResultItem{
				{Package: "lodash", Version: "4.17.21", Status: StatusInProgress},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, auth.NewAPIKeyAuthenticator("key"), server.Client())
	cfg := DefaultPollerConfig()
	cfg.Timeout = 500 * time.Millisecond
	cfg.InitialInterval = 100 * time.Millisecond

	results, err := PollUntilComplete(context.Background(), client, []ScanRequestItem{
		{Package: "lodash", Version: "4.17.21"},
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Should return the pending item as in_progress.
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusInProgress {
		t.Errorf("expected in_progress on timeout, got %s", results[0].Status)
	}
}

func TestPollUntilComplete_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(BatchResponse{
			Results: []BatchResultItem{
				{Package: "lodash", Version: "4.17.21", Status: StatusInProgress},
			},
		})
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	client := NewClient(server.URL, auth.NewAPIKeyAuthenticator("key"), server.Client())
	cfg := DefaultPollerConfig()
	cfg.Timeout = 10 * time.Second
	cfg.InitialInterval = 100 * time.Millisecond

	results, err := PollUntilComplete(ctx, client, []ScanRequestItem{
		{Package: "lodash", Version: "4.17.21"},
	}, cfg)
	if err == nil {
		t.Fatal("expected context error")
	}
	// Should still return partial results.
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestPollUntilComplete_EmptyItems(t *testing.T) {
	results, err := PollUntilComplete(context.Background(), nil, nil, DefaultPollerConfig())
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Errorf("expected nil, got %v", results)
	}
}

func TestChunkItems(t *testing.T) {
	items := make([]ScanRequestItem, 120)
	for i := range items {
		items[i] = ScanRequestItem{Package: "pkg"}
	}

	chunks := ChunkItems(items, 50)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}
	if len(chunks[0]) != 50 {
		t.Errorf("first chunk: expected 50, got %d", len(chunks[0]))
	}
	if len(chunks[1]) != 50 {
		t.Errorf("second chunk: expected 50, got %d", len(chunks[1]))
	}
	if len(chunks[2]) != 20 {
		t.Errorf("third chunk: expected 20, got %d", len(chunks[2]))
	}
}
