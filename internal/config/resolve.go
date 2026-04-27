package config

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
	"github.com/TazarSec/ManticoreScanner/pkg/auth"
	"github.com/TazarSec/ManticoreScanner/pkg/scanner"
)

const (
	defaultAPIURL           = "https://tazarsec.dev"
	defaultTimeout          = 300
	defaultHTTPTimeout      = 120
	defaultFormat           = "table"
	defaultFailureThreshold = 1
	defaultOnError          = OnErrorFail
	defaultAuthMode         = auth.ModeAPIKey
)

const (
	OnErrorFail     = "fail"
	OnErrorContinue = "continue"
)

type CLIFlags struct {
	APIKey               string
	APIURL               string
	AuthMode             string
	File                 string
	Format               string
	Output               string
	IgnoreListFile       string
	FailOn               float64
	FailOnSet            bool
	Timeout              int
	HTTPTimeout          int
	OnError              string
	Production           bool
	VCSComment           bool
	Quiet                bool
	Verbose              bool
	Insecure             bool
	InsecureSet          bool
	IncludeTransitive    bool
	IncludeTransitiveSet bool
}

// Resolve merges CLI flags, environment variables, and defaults into a
// scanner.Config. Warnings (e.g. unused MANTICORE_API_KEY in OIDC mode)
// are written to warnW; pass io.Discard to silence them.
func Resolve(flags CLIFlags, warnW io.Writer) (scanner.Config, error) {
	if warnW == nil {
		warnW = io.Discard
	}

	apiKey := envOrDefault("MANTICORE_API_KEY", "")
	if flags.APIKey != "" {
		apiKey = flags.APIKey
	}

	authMode := envOrDefault("MANTICORE_AUTH_MODE", defaultAuthMode)
	if flags.AuthMode != "" {
		authMode = flags.AuthMode
	}

	cfg := scanner.Config{
		APIBaseURL:        envOrDefault("MANTICORE_API_URL", defaultAPIURL),
		TimeoutSec:        envIntOrDefault("MANTICORE_TIMEOUT", defaultTimeout),
		HTTPTimeoutSec:    envIntOrDefault("MANTICORE_HTTP_TIMEOUT", defaultHTTPTimeout),
		Format:            envOrDefault("MANTICORE_FORMAT", defaultFormat),
		FailOn:            envFloatOrDefault("MANTICORE_FAILURE_THRESHOLD", defaultFailureThreshold),
		OnError:           envOrDefault("MANTICORE_ON_ERROR", defaultOnError),
		InputPath:         ".",
		Production:        false,
		PostToVCS:         false,
		Quiet:             false,
		Verbose:           false,
		Insecure:          envBoolOrDefault("MANTICORE_INSECURE", false),
		IncludeTransitive: envBoolOrDefault("MANTICORE_INCLUDE_TRANSITIVE", false),
	}

	if flags.APIURL != "" {
		cfg.APIBaseURL = flags.APIURL
	}
	if flags.File != "" {
		cfg.InputPath = flags.File
	}
	if flags.Format != "" {
		cfg.Format = flags.Format
	}
	if flags.Output != "" {
		cfg.OutputPath = flags.Output
	}
	if flags.FailOnSet {
		cfg.FailOn = flags.FailOn
	}
	if flags.Timeout > 0 {
		cfg.TimeoutSec = flags.Timeout
	}
	if flags.HTTPTimeout > 0 {
		cfg.HTTPTimeoutSec = flags.HTTPTimeout
	}
	if flags.OnError != "" {
		cfg.OnError = flags.OnError
	}
	if flags.Production {
		cfg.Production = true
	}
	if flags.VCSComment {
		cfg.PostToVCS = true
	}
	if flags.Quiet {
		cfg.Quiet = true
	}
	if flags.Verbose {
		cfg.Verbose = true
	}
	if flags.InsecureSet {
		cfg.Insecure = flags.Insecure
	}
	if flags.IncludeTransitiveSet {
		cfg.IncludeTransitive = flags.IncludeTransitive
	}

	if err := api.ValidateBackendURL(cfg.APIBaseURL, cfg.Insecure); err != nil {
		return scanner.Config{}, err
	}

	switch cfg.OnError {
	case OnErrorFail, OnErrorContinue:
	default:
		return scanner.Config{}, fmt.Errorf("invalid --on-error value %q (must be %q or %q)", cfg.OnError, OnErrorFail, OnErrorContinue)
	}

	if cfg.HTTPTimeoutSec < 0 {
		return scanner.Config{}, fmt.Errorf("--http-timeout must be >= 0 (got %d)", cfg.HTTPTimeoutSec)
	}

	authenticator, err := buildAuthenticator(authMode, apiKey, warnW)
	if err != nil {
		return scanner.Config{}, err
	}
	cfg.Auth = authenticator

	ignoreListPath := flags.IgnoreListFile
	if ignoreListPath == "" {
		ignoreListPath = os.Getenv("MANTICORE_IGNORE_LIST")
	}
	if ignoreListPath != "" {
		names, err := LoadIgnoreList(ignoreListPath)
		if err != nil {
			return scanner.Config{}, err
		}
		cfg.IgnoreList = names
	}

	return cfg, nil
}

func buildAuthenticator(mode, apiKey string, warnW io.Writer) (auth.Authenticator, error) {
	switch mode {
	case auth.ModeAPIKey:
		if apiKey == "" {
			return nil, fmt.Errorf("API key is required for --auth-mode=%s. Set --api-key or MANTICORE_API_KEY environment variable", auth.ModeAPIKey)
		}
		return auth.NewAPIKeyAuthenticator(apiKey), nil
	case auth.ModeGitHubOIDC:
		if apiKey != "" {
			fmt.Fprintf(warnW, "Warning: ignoring MANTICORE_API_KEY/--api-key because --auth-mode=%s is set\n", auth.ModeGitHubOIDC)
		}
		return auth.NewGitHubOIDCAuthenticator(auth.GitHubOIDCConfig{
			RequestURL:   os.Getenv(auth.EnvGitHubOIDCRequestURL),
			RequestToken: os.Getenv(auth.EnvGitHubOIDCRequestToken),
		})
	default:
		return nil, fmt.Errorf("invalid --auth-mode value %q (must be %q or %q)", mode, auth.ModeAPIKey, auth.ModeGitHubOIDC)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envFloatOrDefault(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func envBoolOrDefault(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
