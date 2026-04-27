package formatter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
)

var testResults = []api.BatchResultItem{
	{
		Package:   "lodash",
		Version:   "4.17.21",
		Ecosystem: "npm",
		Status:    api.StatusCompleted,
		Profile: &api.Profile{
			PackageName:    "lodash",
			Version:        "4.17.21",
			SuspicionScore: 0,
		},
	},
	{
		Package:   "evil-pkg",
		Version:   "1.0.0",
		Ecosystem: "npm",
		Status:    api.StatusCompleted,
		Profile: &api.Profile{
			PackageName:       "evil-pkg",
			Version:           "1.0.0",
			SuspicionScore:    85.5,
			HasUnknownNetwork: true,
			SuspicionReasons: []api.SuspicionReason{
				{Type: "new_network", Detail: "Connects to unknown host", Severity: api.SeverityHigh, Phase: api.PhaseInstall},
			},
		},
	},
}

func TestJSONFormatter(t *testing.T) {
	f := &JSONFormatter{}
	out, err := f.Format(testResults, Options{})
	if err != nil {
		t.Fatal(err)
	}

	var parsed []api.BatchResultItem
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 results, got %d", len(parsed))
	}
}

func TestTableFormatter(t *testing.T) {
	f := &TableFormatter{}
	out, err := f.Format(testResults, Options{})
	if err != nil {
		t.Fatal(err)
	}

	s := string(out)
	if !strings.Contains(s, "lodash") {
		t.Error("expected table to contain 'lodash'")
	}
	if !strings.Contains(s, "evil-pkg") {
		t.Error("expected table to contain 'evil-pkg'")
	}
	if !strings.Contains(s, "85.5") {
		t.Error("expected table to contain score '85.5'")
	}
	if !strings.Contains(s, "NET") {
		t.Error("expected table to contain 'NET' flag")
	}
	if !strings.Contains(s, "1 suspicious") {
		t.Error("expected summary to mention 1 suspicious")
	}
}

func TestTableFormatter_Empty(t *testing.T) {
	f := &TableFormatter{}
	out, err := f.Format(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "No packages") {
		t.Error("expected empty message")
	}
}

func TestSARIFFormatter(t *testing.T) {
	f := &SARIFFormatter{}
	out, err := f.Format(testResults, Options{InputFile: "package-lock.json"})
	if err != nil {
		t.Fatal(err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if sarif["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", sarif["version"])
	}

	runs := sarif["runs"].([]interface{})
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}

	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	// Only evil-pkg should produce results (lodash has score 0).
	if len(results) != 1 {
		t.Fatalf("expected 1 SARIF result, got %d", len(results))
	}

	result := results[0].(map[string]interface{})
	if result["level"] != "error" {
		t.Errorf("expected level 'error' for high severity, got %v", result["level"])
	}
}

func TestSARIFFormatter_NoSuspicious(t *testing.T) {
	f := &SARIFFormatter{}
	clean := []api.BatchResultItem{
		{
			Package: "lodash",
			Status:  api.StatusCompleted,
			Profile: &api.Profile{SuspicionScore: 0},
		},
	}
	out, err := f.Format(clean, Options{})
	if err != nil {
		t.Fatal(err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatal(err)
	}
	runs := sarif["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	// Results should be null/nil when no suspicious packages.
	if results, ok := run["results"]; ok && results != nil {
		arr := results.([]interface{})
		if len(arr) != 0 {
			t.Errorf("expected 0 results, got %d", len(arr))
		}
	}
}

func TestTableFormatter_StripsControlChars(t *testing.T) {
	hostile := []api.BatchResultItem{{
		Package: "evil\x1b[31mpkg\x1b[0m",
		Version: "1.0\r0",
		Status:  api.ScanStatus("ok\x07"),
		Profile: &api.Profile{SuspicionScore: 0},
	}}
	f := &TableFormatter{}
	out, err := f.Format(hostile, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// The hostile ESC and BEL bytes must be gone. CR must be gone. The
	// remaining bracket-letter sequences (e.g. "[31m") are inert without
	// the leading ESC. We deliberately do NOT assert "\x1b" is absent
	// outright, because the formatter emits its own colour-reset escape
	// after the score column — that one is intentional.
	for _, bad := range []string{"\r", "\x07"} {
		if strings.Contains(s, bad) {
			t.Errorf("output leaked control char %q", bad)
		}
	}
	// The hostile ESC bytes belonged to "evil\x1b[31mpkg\x1b[0m"; that
	// specific sequence must not appear.
	if strings.Contains(s, "\x1b[31m") {
		t.Errorf("hostile ANSI sequence survived sanitization")
	}
	// The package name should still be visible as readable text. After
	// stripping the two ESC bytes, the value reads as "evil[31mpkg[0m".
	if !strings.Contains(s, "evil[31mpkg[0m") {
		t.Errorf("expected sanitized package name to remain readable, got:\n%s", s)
	}
}

func TestSARIFFormatter_StripsControlChars(t *testing.T) {
	hostile := []api.BatchResultItem{{
		Package: "evil\x1b[31mpkg",
		Version: "1.0\n.0",
		Status:  api.StatusCompleted,
		Profile: &api.Profile{
			SuspicionScore: 50,
			SuspicionReasons: []api.SuspicionReason{
				{Type: "x", Detail: "boom\x1b[0m\nclear", Severity: api.SeverityHigh, Phase: api.PhaseInstall},
			},
		},
	}}
	f := &SARIFFormatter{}
	out, err := f.Format(hostile, Options{InputFile: "pkg-lock.json"})
	if err != nil {
		t.Fatal(err)
	}
	// JSON-encode the output and look for raw escapes — they must not
	// appear, even though SARIF JSON escapes them, because we stripped them
	// before formatting.
	var sarif map[string]interface{}
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatal(err)
	}
	runs := sarif["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	msg := results[0].(map[string]interface{})["message"].(map[string]interface{})["text"].(string)
	for _, bad := range []string{"\x1b", "\n"} {
		if strings.Contains(msg, bad) {
			t.Errorf("SARIF message leaked %q: %q", bad, msg)
		}
	}
}

func TestGet(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"json", "*formatter.JSONFormatter"},
		{"table", "*formatter.TableFormatter"},
		{"sarif", "*formatter.SARIFFormatter"},
		{"unknown", "*formatter.TableFormatter"},
	}

	for _, tt := range tests {
		f := Get(tt.name)
		if f == nil {
			t.Errorf("Get(%q) returned nil", tt.name)
		}
	}
}
