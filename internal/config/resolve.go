package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
	"github.com/TazarSec/ManticoreScanner/pkg/scanner"
)

const (
	defaultAPIURL           = "https://tazarsec.dev"
	defaultTimeout          = 300
	defaultHTTPTimeout      = 120
	defaultFormat           = "table"
	defaultFailureThreshold = 1
	defaultOnError          = OnErrorFail
)

const (
	OnErrorFail     = "fail"
	OnErrorContinue = "continue"
)

type CLIFlags struct {
	APIKey               string
	APIURL               string
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

func Resolve(flags CLIFlags) (scanner.Config, error) {
	cfg := scanner.Config{
		APIKey:            envOrDefault("MANTICORE_API_KEY", ""),
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

	if flags.APIKey != "" {
		cfg.APIKey = flags.APIKey
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
