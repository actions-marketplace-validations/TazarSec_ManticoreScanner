package config

import (
	"strings"
	"testing"
)

// envVars Resolve reads — clear all of them so tests are deterministic
// regardless of caller environment.
var envVarsToClear = []string{
	"MANTICORE_API_KEY",
	"MANTICORE_API_URL",
	"MANTICORE_TIMEOUT",
	"MANTICORE_HTTP_TIMEOUT",
	"MANTICORE_ON_ERROR",
	"MANTICORE_FORMAT",
	"MANTICORE_FAILURE_THRESHOLD",
	"MANTICORE_INSECURE",
	"MANTICORE_IGNORE_LIST",
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range envVarsToClear {
		t.Setenv(k, "")
	}
}

func TestResolve_RejectsHTTPByDefault(t *testing.T) {
	clearEnv(t)
	_, err := Resolve(CLIFlags{
		APIKey: "k",
		APIURL: "http://example.com",
	})
	if err == nil {
		t.Fatal("expected error for plaintext http:// without --insecure")
	}
	if !strings.Contains(err.Error(), "--insecure") {
		t.Errorf("error should mention --insecure, got %v", err)
	}
}

func TestResolve_AllowsHTTPWithInsecureFlag(t *testing.T) {
	clearEnv(t)
	cfg, err := Resolve(CLIFlags{
		APIKey:      "k",
		APIURL:      "http://localhost:8080",
		Insecure:    true,
		InsecureSet: true,
	})
	if err != nil {
		t.Fatalf("expected http:// to be allowed with --insecure, got %v", err)
	}
	if !cfg.Insecure {
		t.Error("cfg.Insecure should be true")
	}
}

func TestResolve_AllowsHTTPWithEnvVar(t *testing.T) {
	clearEnv(t)
	t.Setenv("MANTICORE_INSECURE", "true")
	if _, err := Resolve(CLIFlags{
		APIKey: "k",
		APIURL: "http://api.example.com",
	}); err != nil {
		t.Fatalf("expected MANTICORE_INSECURE=true to allow http://, got %v", err)
	}
}

func TestResolve_FlagOverridesEnvForInsecure(t *testing.T) {
	clearEnv(t)
	t.Setenv("MANTICORE_INSECURE", "true")
	// --insecure=false explicitly should win over env=true.
	_, err := Resolve(CLIFlags{
		APIKey:      "k",
		APIURL:      "http://api.example.com",
		Insecure:    false,
		InsecureSet: true,
	})
	if err == nil {
		t.Fatal("--insecure=false should override env and reject http://")
	}
}

func TestResolve_HTTPSAlwaysAllowed(t *testing.T) {
	clearEnv(t)
	if _, err := Resolve(CLIFlags{
		APIKey: "k",
		APIURL: "https://api.example.com",
	}); err != nil {
		t.Fatalf("https:// should always be allowed, got %v", err)
	}
}

func TestResolve_RejectsBogusScheme(t *testing.T) {
	clearEnv(t)
	if _, err := Resolve(CLIFlags{
		APIKey:      "k",
		APIURL:      "file:///etc/passwd",
		Insecure:    true,
		InsecureSet: true,
	}); err == nil {
		t.Error("file:// scheme should be rejected even with --insecure")
	}
}

func TestResolve_HTTPTimeoutDefault(t *testing.T) {
	clearEnv(t)
	cfg, err := Resolve(CLIFlags{APIKey: "k", APIURL: "https://api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPTimeoutSec != defaultHTTPTimeout {
		t.Errorf("expected default HTTP timeout %d, got %d", defaultHTTPTimeout, cfg.HTTPTimeoutSec)
	}
}

func TestResolve_HTTPTimeoutFlagOverridesEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("MANTICORE_HTTP_TIMEOUT", "60")
	cfg, err := Resolve(CLIFlags{
		APIKey:      "k",
		APIURL:      "https://api.example.com",
		HTTPTimeout: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPTimeoutSec != 200 {
		t.Errorf("flag should override env: got %d, want 200", cfg.HTTPTimeoutSec)
	}
}

func TestResolve_HTTPTimeoutEnvUsedWhenNoFlag(t *testing.T) {
	clearEnv(t)
	t.Setenv("MANTICORE_HTTP_TIMEOUT", "75")
	cfg, err := Resolve(CLIFlags{APIKey: "k", APIURL: "https://api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPTimeoutSec != 75 {
		t.Errorf("env should be honored: got %d, want 75", cfg.HTTPTimeoutSec)
	}
}

func TestResolve_OnErrorDefaultsToFail(t *testing.T) {
	clearEnv(t)
	cfg, err := Resolve(CLIFlags{APIKey: "k", APIURL: "https://api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OnError != OnErrorFail {
		t.Errorf("default OnError should be %q, got %q", OnErrorFail, cfg.OnError)
	}
}

func TestResolve_OnErrorContinueAccepted(t *testing.T) {
	clearEnv(t)
	cfg, err := Resolve(CLIFlags{
		APIKey:  "k",
		APIURL:  "https://api.example.com",
		OnError: OnErrorContinue,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OnError != OnErrorContinue {
		t.Errorf("OnError should be %q, got %q", OnErrorContinue, cfg.OnError)
	}
}

func TestResolve_OnErrorFlagOverridesEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("MANTICORE_ON_ERROR", "continue")
	cfg, err := Resolve(CLIFlags{
		APIKey:  "k",
		APIURL:  "https://api.example.com",
		OnError: "fail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OnError != OnErrorFail {
		t.Errorf("flag should override env: got %q", cfg.OnError)
	}
}

func TestResolve_OnErrorRejectsInvalid(t *testing.T) {
	clearEnv(t)
	_, err := Resolve(CLIFlags{
		APIKey:  "k",
		APIURL:  "https://api.example.com",
		OnError: "panic",
	})
	if err == nil {
		t.Fatal("expected error for invalid --on-error value")
	}
	if !strings.Contains(err.Error(), "on-error") {
		t.Errorf("error should reference on-error, got %v", err)
	}
}

func TestResolve_HTTPTimeoutRejectsNegative(t *testing.T) {
	clearEnv(t)
	t.Setenv("MANTICORE_HTTP_TIMEOUT", "-5")
	_, err := Resolve(CLIFlags{APIKey: "k", APIURL: "https://api.example.com"})
	if err == nil {
		t.Fatal("expected error for negative http-timeout")
	}
}
