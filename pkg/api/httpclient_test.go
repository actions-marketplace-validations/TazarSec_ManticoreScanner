package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TazarSec/ManticoreScanner/pkg/auth"
)

func TestValidateBackendURL_HTTPSAllowed(t *testing.T) {
	if err := ValidateBackendURL("https://api.example.com", false); err != nil {
		t.Errorf("https should be allowed without --insecure, got %v", err)
	}
}

func TestValidateBackendURL_HTTPRejectedByDefault(t *testing.T) {
	err := ValidateBackendURL("http://api.example.com", false)
	if err == nil {
		t.Fatal("http should be rejected without --insecure")
	}
	if !strings.Contains(err.Error(), "--insecure") {
		t.Errorf("error should mention --insecure, got %v", err)
	}
}

func TestValidateBackendURL_HTTPAllowedWithInsecure(t *testing.T) {
	if err := ValidateBackendURL("http://localhost:8080", true); err != nil {
		t.Errorf("http should be allowed with --insecure, got %v", err)
	}
}

func TestValidateBackendURL_RejectsNonHTTPSchemes(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd",
		"ftp://example.com",
		"javascript:alert(1)",
		"gopher://example.com",
	} {
		if err := ValidateBackendURL(raw, true); err == nil {
			t.Errorf("scheme in %q should be rejected even with --insecure", raw)
		}
	}
}

func TestValidateBackendURL_RejectsEmpty(t *testing.T) {
	if err := ValidateBackendURL("", false); err == nil {
		t.Error("empty URL should be rejected")
	}
}

func TestNewHTTPClient_TLSMinVersion(t *testing.T) {
	c := NewHTTPClient(0)
	uat, ok := c.Transport.(*userAgentTransport)
	if !ok {
		t.Fatalf("expected *userAgentTransport, got %T", c.Transport)
	}
	tr, ok := uat.base.(*http.Transport)
	if !ok {
		t.Fatalf("expected wrapped *http.Transport, got %T", uat.base)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS MinVersion 1.2 (%d), got %d",
			tls.VersionTLS12, tr.TLSClientConfig.MinVersion)
	}
	if c.Timeout != DefaultHTTPTimeout {
		t.Errorf("expected default timeout %v, got %v", DefaultHTTPTimeout, c.Timeout)
	}
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("transport must set TLSHandshakeTimeout")
	}
	if tr.ResponseHeaderTimeout == 0 {
		t.Error("transport must set ResponseHeaderTimeout")
	}
}

func TestNewHTTPClient_SetsUserAgent(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := NewHTTPClient(0)
	c.Transport.(*userAgentTransport).base = server.Client().Transport

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if !strings.HasPrefix(got, "manticorescanner/") {
		t.Errorf("expected User-Agent to start with %q, got %q", "manticorescanner/", got)
	}
}

func TestNewHTTPClient_HonorsCustomTimeout(t *testing.T) {
	c := NewHTTPClient(45 * time.Second)
	if c.Timeout != 45*time.Second {
		t.Errorf("expected 45s timeout, got %v", c.Timeout)
	}
}

func TestReadBounded_AcceptsSmallBody(t *testing.T) {
	body, err := readBounded(bytes.NewReader([]byte("hello")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("got %q, want %q", body, "hello")
	}
}

func TestReadBounded_RejectsOversizedBody(t *testing.T) {
	huge := bytes.Repeat([]byte{'x'}, MaxResponseBytes+10)
	_, err := readBounded(bytes.NewReader(huge))
	if err == nil {
		t.Fatal("expected error for oversized body")
	}
}

// TestScanBatch_RejectsHugeResponse verifies the bound is enforced over a
// real HTTP round-trip, not just on a synthetic reader.
func TestScanBatch_RejectsHugeResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Stream more than MaxResponseBytes; the client must abort.
		buf := bytes.Repeat([]byte{'x'}, 1<<20) // 1 MiB chunks
		for written := 0; written < MaxResponseBytes+(2<<20); written += len(buf) {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, auth.NewAPIKeyAuthenticator("test-key"), server.Client())
	_, _, err := client.ScanBatch(context.Background(), []ScanRequestItem{
		{Package: "x", Version: "1"},
	})
	if err == nil {
		t.Fatal("expected error for oversized response body")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("expected size-cap error, got %v", err)
	}
}

// Compile-time guard that we don't accidentally hand http.DefaultClient
// to NewClient, which would bypass our timeouts and TLS minimum.
func TestNewClient_DefaultIsHardened(t *testing.T) {
	c := NewClient("https://example.com", auth.NewAPIKeyAuthenticator("k"), nil)
	if c.httpClient == http.DefaultClient {
		t.Fatal("NewClient must not fall back to http.DefaultClient")
	}
	if c.httpClient.Timeout == 0 {
		t.Fatal("default client must have a timeout")
	}
}

// Sanity-check that JSON encoding of the bounded reader works end-to-end.
func TestReadBounded_DecodesJSON(t *testing.T) {
	payload := BatchResponse{Results: []BatchResultItem{{Package: "p", Version: "1"}}}
	raw, _ := json.Marshal(payload)
	r := io.NopCloser(bytes.NewReader(raw))
	got, err := readBounded(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded BatchResponse
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Results) != 1 || decoded.Results[0].Package != "p" {
		t.Errorf("round-trip mismatch: %+v", decoded)
	}
}
