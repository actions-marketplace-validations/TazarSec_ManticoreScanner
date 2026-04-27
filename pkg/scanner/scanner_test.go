package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
	"github.com/TazarSec/ManticoreScanner/pkg/auth"
	"github.com/TazarSec/ManticoreScanner/pkg/parser"
)

func TestRun_ForwardsIntegrityAsHash(t *testing.T) {
	var received []api.ScanRequestItem

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		received = append(received, req.Packages...)

		results := make([]api.BatchResultItem, len(req.Packages))
		for i, p := range req.Packages {
			results[i] = api.BatchResultItem{
				Package:   p.Package,
				Version:   p.Version,
				Ecosystem: string(p.Ecosystem),
				Hash:      p.Hash,
				Status:    api.StatusCompleted,
				Profile:   &api.Profile{SuspicionScore: 0},
			}
		}
		_ = json.NewEncoder(w).Encode(api.BatchResponse{Results: results})
	}))
	defer server.Close()

	cfg := Config{
		Auth:       auth.NewAPIKeyAuthenticator("test-key"),
		APIBaseURL: server.URL,
		InputPath:  "../../testdata/package-lock-v3.json",
		TimeoutSec: 5,
	}

	result, err := Run(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}

	hashByName := make(map[string]string, len(received))
	for _, item := range received {
		hashByName[item.Package] = item.Hash
	}
	if hashByName["lodash"] != "sha512-lodash-hash==" {
		t.Errorf("lodash hash = %q, want sha512-lodash-hash==", hashByName["lodash"])
	}
	if hashByName["express"] != "sha512-express-hash==" {
		t.Errorf("express hash = %q, want sha512-express-hash==", hashByName["express"])
	}
}

func TestFilterIgnoredEmptyList(t *testing.T) {
	pkgs := []parser.Package{
		{Name: "lodash", Version: "1.0.0"},
		{Name: "express", Version: "4.0.0"},
	}
	got := filterIgnored(pkgs, nil)
	if !reflect.DeepEqual(got, pkgs) {
		t.Fatalf("expected packages unchanged, got %v", got)
	}
}

func TestFilterIgnoredDropsVersionMatch(t *testing.T) {
	pkgs := []parser.Package{
		{Name: "lodash", Version: "1.0.0"},
		{Name: "express", Version: "4.0.0"},
		{Name: "@scope/pkg", Version: "2.0.0"},
	}
	got := filterIgnored(pkgs, []string{"express@4.0.0", "@scope/pkg@2.0.0"})
	want := []parser.Package{{Name: "lodash", Version: "1.0.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFilterIgnoredKeepsOtherVersions(t *testing.T) {
	pkgs := []parser.Package{
		{Name: "express", Version: "4.0.0"},
		{Name: "express", Version: "4.1.0"},
	}
	got := filterIgnored(pkgs, []string{"express@4.0.0"})
	want := []parser.Package{{Name: "express", Version: "4.1.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFilterIgnoredDropsHashMatch(t *testing.T) {
	pkgs := []parser.Package{
		{Name: "lodash", Version: "1.0.0", Integrity: "sha512-aaa=="},
		{Name: "express", Version: "4.0.0", Integrity: "sha512-bbb=="},
	}
	got := filterIgnored(pkgs, []string{"sha512-bbb=="})
	want := []parser.Package{{Name: "lodash", Version: "1.0.0", Integrity: "sha512-aaa=="}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFilterIgnoredHashIgnoredWhenPackageHasNoIntegrity(t *testing.T) {
	pkgs := []parser.Package{
		{Name: "lodash", Version: "1.0.0"},
	}
	got := filterIgnored(pkgs, []string{"sha512-aaa=="})
	if !reflect.DeepEqual(got, pkgs) {
		t.Fatalf("expected packages unchanged, got %v", got)
	}
}
