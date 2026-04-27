package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Env vars exposed by GitHub Actions runners when the workflow has
// `permissions: id-token: write`.
const (
	EnvGitHubOIDCRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	EnvGitHubOIDCRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

// maxOIDCResponseBytes caps the response we read from the GitHub token
// endpoint. Real responses are a few KiB; anything larger is hostile or
// broken.
const maxOIDCResponseBytes = 64 << 10

// ErrMissingGitHubOIDCEnv is returned when github-oidc auth is requested
// but the runner has not exposed the OIDC request env vars.
var ErrMissingGitHubOIDCEnv = fmt.Errorf(
	"GitHub OIDC auth requires %s and %s; ensure the workflow grants `permissions: id-token: write`",
	EnvGitHubOIDCRequestURL, EnvGitHubOIDCRequestToken,
)

type OIDCFetchError struct {
	StatusCode int
	Body       string
}

func (e *OIDCFetchError) Error() string {
	return fmt.Sprintf("failed to mint GitHub OIDC token (HTTP %d): %s", e.StatusCode, e.Body)
}

type GitHubOIDCAuthenticator struct {
	requestURL   string
	requestToken string
	audience     string
	httpClient   *http.Client

	mu     sync.Mutex
	cached string
}

type GitHubOIDCConfig struct {
	RequestURL   string
	RequestToken string
	Audience     string
	HTTPClient   *http.Client
}

func NewGitHubOIDCAuthenticator(cfg GitHubOIDCConfig) (*GitHubOIDCAuthenticator, error) {
	if cfg.RequestURL == "" || cfg.RequestToken == "" {
		return nil, ErrMissingGitHubOIDCEnv
	}
	if cfg.Audience == "" {
		cfg.Audience = GitHubOIDCAudience
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	return &GitHubOIDCAuthenticator{
		requestURL:   cfg.RequestURL,
		requestToken: cfg.RequestToken,
		audience:     cfg.Audience,
		httpClient:   cfg.HTTPClient,
	}, nil
}

func (a *GitHubOIDCAuthenticator) AuthorizationHeader(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cached != "" {
		return "GithubOIDC " + a.cached, nil
	}

	token, err := a.fetch(ctx)
	if err != nil {
		return "", err
	}
	a.cached = token
	return "GithubOIDC " + token, nil
}

func (a *GitHubOIDCAuthenticator) fetch(ctx context.Context) (string, error) {
	u, err := url.Parse(a.requestURL)
	if err != nil {
		return "", fmt.Errorf("parsing %s: %w", EnvGitHubOIDCRequestURL, err)
	}
	q := u.Query()
	q.Set("audience", a.audience)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("building OIDC token request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+a.requestToken)
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting GitHub OIDC token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOIDCResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading OIDC token response: %w", err)
	}
	if int64(len(body)) > maxOIDCResponseBytes {
		return "", fmt.Errorf("OIDC token response exceeds %d bytes", maxOIDCResponseBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &OIDCFetchError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}

	var parsed struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decoding OIDC token response: %w", err)
	}
	if parsed.Value == "" {
		return "", fmt.Errorf("OIDC token response missing 'value' field")
	}
	return parsed.Value, nil
}
