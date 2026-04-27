package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/TazarSec/ManticoreScanner/pkg/auth"
)

type AuthError struct {
	Message string
}

func (e *AuthError) Error() string { return fmt.Sprintf("authentication failed: %s", e.Message) }

type RateLimitError struct {
	Message       string
	RetryAfterSec int
}

func (e *RateLimitError) Error() string { return fmt.Sprintf("rate limited: %s", e.Message) }

type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return fmt.Sprintf("validation error: %s", e.Message) }

type ServerError struct {
	StatusCode int
	Message    string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("server error (%d): %s", e.StatusCode, e.Message)
}

type Client struct {
	baseURL    string
	auth       auth.Authenticator
	httpClient *http.Client
}

func NewClient(baseURL string, authenticator auth.Authenticator, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = NewHTTPClient(0)
	}
	return &Client{
		baseURL:    baseURL,
		auth:       authenticator,
		httpClient: httpClient,
	}
}

// readBounded reads up to MaxResponseBytes from r and returns an error if
// the body is larger. This protects callers from OOM via a hostile or
// buggy backend.
func readBounded(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, MaxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > MaxResponseBytes {
		return body[:MaxResponseBytes], errors.New("response body exceeds maximum allowed size")
	}
	return body, nil
}

func (c *Client) ScanBatch(ctx context.Context, items []ScanRequestItem) (*BatchResponse, int, error) {
	reqBody := ScanRequest{Packages: items}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/scan", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	authHeader, err := c.auth.AuthorizationHeader(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("building Authorization header: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readBounded(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		var batch BatchResponse
		if err := json.Unmarshal(respBody, &batch); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("decoding response: %w", err)
		}
		return &batch, resp.StatusCode, nil

	case http.StatusBadRequest:
		var apiErr APIError
		_ = json.Unmarshal(respBody, &apiErr)
		return nil, resp.StatusCode, &ValidationError{Message: apiErr.Error}

	case http.StatusUnauthorized:
		var apiErr APIError
		_ = json.Unmarshal(respBody, &apiErr)
		return nil, resp.StatusCode, &AuthError{Message: apiErr.Error}

	case http.StatusTooManyRequests:
		var apiErr APIError
		_ = json.Unmarshal(respBody, &apiErr)
		retryAfter := 0
		if val := resp.Header.Get("Retry-After"); val != "" {
			retryAfter, _ = strconv.Atoi(val)
		}
		return nil, resp.StatusCode, &RateLimitError{
			Message:       apiErr.Error,
			RetryAfterSec: retryAfter,
		}

	default:
		var apiErr APIError
		_ = json.Unmarshal(respBody, &apiErr)
		return nil, resp.StatusCode, &ServerError{
			StatusCode: resp.StatusCode,
			Message:    apiErr.Error,
		}
	}
}
