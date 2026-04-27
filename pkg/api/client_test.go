package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanBatch_Success(t *testing.T) {
	expected := BatchResponse{
		Results: []BatchResultItem{
			{
				Package:   "lodash",
				Version:   "4.17.21",
				Ecosystem: "npm",
				Status:    StatusCompleted,
				Profile: &Profile{
					PackageName:    "lodash",
					Version:        "4.17.21",
					Ecosystem:      "npm",
					SuspicionScore: 0,
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/scan" {
			t.Errorf("expected /v1/scan, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Bearer test-key, got %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
		}

		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if len(req.Packages) != 1 || req.Packages[0].Package != "lodash" {
			t.Errorf("unexpected request: %+v", req)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(expected)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", server.Client())
	resp, status, err := client.ScanBatch(context.Background(), []ScanRequestItem{
		{Package: "lodash", Version: "4.17.21", Ecosystem: EcosystemNPM},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
	if resp.Results[0].Package != "lodash" {
		t.Errorf("expected lodash, got %s", resp.Results[0].Package)
	}
	if resp.Results[0].Status != StatusCompleted {
		t.Errorf("expected completed, got %s", resp.Results[0].Status)
	}
}

func TestScanBatch_Accepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := BatchResponse{
			Results: []BatchResultItem{
				{Package: "lodash", Version: "4.17.21", Status: StatusInProgress},
			},
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", server.Client())
	resp, status, err := client.ScanBatch(context.Background(), []ScanRequestItem{
		{Package: "lodash", Version: "4.17.21"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusAccepted {
		t.Errorf("expected 202, got %d", status)
	}
	if resp.Results[0].Status != StatusInProgress {
		t.Errorf("expected in_progress, got %s", resp.Results[0].Status)
	}
}

func TestScanBatch_AuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(APIError{Error: "invalid api key"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "bad-key", server.Client())
	_, _, err := client.ScanBatch(context.Background(), []ScanRequestItem{
		{Package: "lodash", Version: "4.17.21"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	authErr, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if authErr.Message != "invalid api key" {
		t.Errorf("expected 'invalid api key', got %q", authErr.Message)
	}
}

func TestScanBatch_RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(APIError{Error: "rate limit exceeded"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", server.Client())
	_, _, err := client.ScanBatch(context.Background(), []ScanRequestItem{
		{Package: "lodash", Version: "4.17.21"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	rlErr, ok := err.(*RateLimitError)
	if !ok {
		t.Fatalf("expected *RateLimitError, got %T", err)
	}
	if rlErr.RetryAfterSec != 30 {
		t.Errorf("expected RetryAfter 30, got %d", rlErr.RetryAfterSec)
	}
}

func TestScanBatch_ValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIError{Error: "invalid request"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", server.Client())
	_, _, err := client.ScanBatch(context.Background(), []ScanRequestItem{})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*ValidationError); !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
}
