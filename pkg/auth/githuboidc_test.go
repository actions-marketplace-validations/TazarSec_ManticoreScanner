package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestGitHubOIDC_FetchAndCache(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got, want := r.URL.Query().Get("audience"), GitHubOIDCAudience; got != want {
			t.Errorf("audience: got %q, want %q", got, want)
		}
		if got := r.Header.Get("Authorization"); got != "bearer rt" {
			t.Errorf("authorization: got %q, want %q", got, "bearer rt")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":"jwt-abc"}`))
	}))
	defer server.Close()

	a, err := NewGitHubOIDCAuthenticator(GitHubOIDCConfig{
		RequestURL:   server.URL,
		RequestToken: "rt",
		HTTPClient:   server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		got, err := a.AuthorizationHeader(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if want := "GithubOIDC jwt-abc"; got != want {
			t.Errorf("header: got %q, want %q", got, want)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("expected token fetched once, got %d calls", calls.Load())
	}
}

func TestGitHubOIDC_PreservesExistingQueryParams(t *testing.T) {
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"value":"jwt"}`))
	}))
	defer server.Close()

	a, err := NewGitHubOIDCAuthenticator(GitHubOIDCConfig{
		RequestURL:   server.URL + "/?token_id=xyz",
		RequestToken: "rt",
		HTTPClient:   server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AuthorizationHeader(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seen == "" {
		t.Fatal("server saw no query string")
	}
	// Both keys must be present; ordering is map-defined.
	if !contains(seen, "token_id=xyz") || !contains(seen, "audience="+GitHubOIDCAudience) {
		t.Errorf("query string should retain both params, got %q", seen)
	}
}

func TestGitHubOIDC_MissingEnv(t *testing.T) {
	_, err := NewGitHubOIDCAuthenticator(GitHubOIDCConfig{})
	if !errors.Is(err, ErrMissingGitHubOIDCEnv) {
		t.Errorf("expected ErrMissingGitHubOIDCEnv, got %v", err)
	}
}

func TestGitHubOIDC_NonOKReturnsFetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("nope"))
	}))
	defer server.Close()

	a, err := NewGitHubOIDCAuthenticator(GitHubOIDCConfig{
		RequestURL:   server.URL,
		RequestToken: "rt",
		HTTPClient:   server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.AuthorizationHeader(context.Background())
	var fetchErr *OIDCFetchError
	if !errors.As(err, &fetchErr) {
		t.Fatalf("expected *OIDCFetchError, got %T (%v)", err, err)
	}
	if fetchErr.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", fetchErr.StatusCode, http.StatusForbidden)
	}
}

func TestAPIKey_Header(t *testing.T) {
	a := NewAPIKeyAuthenticator("sekret")
	got, err := a.AuthorizationHeader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := "Bearer sekret"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
