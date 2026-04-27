package api

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TazarSec/ManticoreScanner/internal/buildinfo"
)

const MaxResponseBytes = 32 << 20 // 32 MiB

const DefaultHTTPTimeout = 2 * time.Minute

func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &userAgentTransport{base: transport, userAgent: buildinfo.UserAgent()},
	}
}

type userAgentTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", t.userAgent)
	}
	return t.base.RoundTrip(req)
}

func ValidateBackendURL(raw string, insecure bool) error {
	if raw == "" {
		return fmt.Errorf("API URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid API URL %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
		return nil
	case "http":
		if insecure {
			return nil
		}
		return fmt.Errorf("API URL must use HTTPS (got %q); pass --insecure or set MANTICORE_INSECURE=true to allow plaintext http://", raw)
	default:
		return fmt.Errorf("unsupported scheme %q in API URL %q (only http/https are supported)", u.Scheme, raw)
	}
}