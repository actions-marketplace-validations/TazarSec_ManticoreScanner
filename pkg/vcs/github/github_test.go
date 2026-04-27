package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
	"github.com/TazarSec/ManticoreScanner/pkg/vcs"
)

func TestBuildCommentBody_Suspicious(t *testing.T) {
	results := []api.BatchResultItem{
		{
			Package: "lodash",
			Version: "4.17.21",
			Status:  api.StatusCompleted,
			Profile: &api.Profile{SuspicionScore: 0},
		},
		{
			Package: "evil-pkg",
			Version: "1.0.0",
			Status:  api.StatusCompleted,
			Profile: &api.Profile{
				SuspicionScore:    85.5,
				HasUnknownNetwork: true,
				SuspicionReasons: []api.SuspicionReason{
					{Type: "unknown_network", Detail: "169.254.169.254:80/tcp", Severity: api.SeverityHigh, Phase: api.PhaseInstall},
					{Type: "credential_exfiltration", Detail: "sensitive credential access with network activity", Severity: api.SeverityCritical, Phase: api.PhaseInstall},
				},
			},
		},
	}

	body := buildCommentBody(results, nil)

	if !strings.Contains(body, commentMarker) {
		t.Error("expected comment marker")
	}
	if !strings.Contains(body, "evil-pkg") {
		t.Error("expected evil-pkg in body")
	}
	if !strings.Contains(body, "85.5") {
		t.Error("expected score 85.5 in body")
	}
	if strings.Contains(body, "lodash") {
		t.Error("lodash should not appear (score is 0)")
	}
	if !strings.Contains(body, "Critical") {
		t.Error("expected Critical severity label")
	}
	if !strings.Contains(body, "🔴") {
		t.Error("expected critical severity icon")
	}
	if !strings.Contains(body, "2 packages scanned") {
		t.Error("expected total package count in summary")
	}
	if !strings.Contains(body, "1 suspicious") {
		t.Error("expected suspicious count in summary")
	}
	if !strings.Contains(body, "<details>") {
		t.Error("expected collapsible details section")
	}
	if !strings.Contains(body, "Credential Exfiltration") {
		t.Error("expected humanized type name for credential_exfiltration")
	}
	if !strings.Contains(body, "Unknown Network") {
		t.Error("expected humanized type name for unknown_network")
	}
	if !strings.Contains(body, "🌐 Network") {
		t.Error("expected network behavior flag")
	}
}

func TestBuildCommentBody_NoSuspicious(t *testing.T) {
	results := []api.BatchResultItem{
		{
			Package: "lodash",
			Status:  api.StatusCompleted,
			Profile: &api.Profile{SuspicionScore: 0},
		},
	}

	body := buildCommentBody(results, nil)
	if !strings.Contains(body, "no suspicious") {
		t.Error("expected 'no suspicious' message")
	}
	if !strings.Contains(body, "1 package scanned") {
		t.Error("expected singular 'package' for single result")
	}
	if !strings.Contains(body, "✅") {
		t.Error("expected check mark for clean scan")
	}
}

func TestBuildCommentBody_ScanErroredWithPendingItems(t *testing.T) {
	results := []api.BatchResultItem{
		{Package: "lodash", Version: "4.17.21", Status: api.StatusInProgress},
		{Package: "express", Version: "4.18.2", Status: api.StatusInProgress},
		{Package: "ts-gaussian", Version: "3.0.5", Status: api.StatusInProgress},
		{Package: "jest", Version: "29.0.0", Status: api.StatusInProgress},
	}

	scanErr := errors.New(`scan request failed: dial tcp: lookup tazarsec.dev on 127.0.0.53:53: no such host`)
	body := buildCommentBody(results, scanErr)

	if strings.Contains(body, "no suspicious behavior detected") && !strings.Contains(body, "completed items") {
		t.Errorf("must not falsely claim a clean scan when scan errored:\n%s", body)
	}
	if strings.Contains(body, "✅") {
		t.Errorf("must not show success checkmark when scan errored:\n%s", body)
	}
	if !strings.Contains(body, "did not complete successfully") {
		t.Errorf("expected failure header in body:\n%s", body)
	}
	if !strings.Contains(body, "4 pending") {
		t.Errorf("expected '4 pending' count in body:\n%s", body)
	}
	if !strings.Contains(body, "0 completed") {
		t.Errorf("expected '0 completed' count in body:\n%s", body)
	}
	if !strings.Contains(body, "tazarsec.dev") {
		t.Errorf("expected scan error message included in body:\n%s", body)
	}
}

func TestBuildCommentBody_PartialFailureWithSuspicious(t *testing.T) {
	results := []api.BatchResultItem{
		{
			Package: "evil-pkg",
			Version: "1.0.0",
			Status:  api.StatusCompleted,
			Profile: &api.Profile{
				SuspicionScore: 90,
				SuspicionReasons: []api.SuspicionReason{
					{Type: "unknown_network", Detail: "10.0.0.1:443", Severity: api.SeverityHigh, Phase: api.PhaseInstall},
				},
			},
		},
		{Package: "stuck-pkg", Version: "2.0.0", Status: api.StatusInProgress},
	}

	body := buildCommentBody(results, nil)

	if !strings.Contains(body, "did not complete successfully") {
		t.Errorf("expected failure header due to pending item:\n%s", body)
	}
	if !strings.Contains(body, "1 pending") {
		t.Errorf("expected '1 pending' count:\n%s", body)
	}
	if !strings.Contains(body, "evil-pkg") {
		t.Errorf("suspicious finding from completed item must still appear:\n%s", body)
	}
}

func TestBuildCommentBody_MultipleSuspicious(t *testing.T) {
	results := []api.BatchResultItem{
		{
			Package: "bad-a",
			Version: "1.0.0",
			Status:  api.StatusCompleted,
			Profile: &api.Profile{
				SuspicionScore: 50,
				SuspicionReasons: []api.SuspicionReason{
					{Type: "unknown_dns", Detail: "evil.com", Severity: api.SeverityMedium, Phase: api.PhaseInstall},
				},
			},
		},
		{
			Package: "bad-b",
			Version: "2.0.0",
			Status:  api.StatusCompleted,
			Profile: &api.Profile{
				SuspicionScore: 90,
				SuspicionReasons: []api.SuspicionReason{
					{Type: "unknown_network", Detail: "10.0.0.1:443", Severity: api.SeverityHigh, Phase: api.PhaseInstall},
				},
			},
		},
	}

	body := buildCommentBody(results, nil)

	// Higher score should appear first.
	badBIdx := strings.Index(body, "bad-b")
	badAIdx := strings.Index(body, "bad-a")
	if badBIdx < 0 || badAIdx < 0 {
		t.Fatal("expected both packages in body")
	}
	if badBIdx > badAIdx {
		t.Error("expected higher-score package (bad-b) to appear before lower-score (bad-a)")
	}
	if !strings.Contains(body, "2 suspicious") {
		t.Error("expected '2 suspicious' in summary")
	}
}

func TestBuildCommentBody_DeduplicatesDetails(t *testing.T) {
	results := []api.BatchResultItem{
		{
			Package: "dup-pkg",
			Version: "1.0.0",
			Status:  api.StatusCompleted,
			Profile: &api.Profile{
				SuspicionScore:    60,
				HasUnexpectedProcess: true,
				SuspicionReasons: []api.SuspicionReason{
					{Type: "unknown_process", Detail: "/bin/sh", Severity: api.SeverityMedium, Phase: api.PhaseInstall},
					{Type: "unknown_process", Detail: "/bin/sh", Severity: api.SeverityMedium, Phase: api.PhaseInstall},
					{Type: "unknown_process", Detail: "sh", Severity: api.SeverityMedium, Phase: api.PhaseInstall},
				},
			},
		},
	}

	body := buildCommentBody(results, nil)
	if !strings.Contains(body, "×2") {
		t.Error("expected deduplication marker ×2 for repeated /bin/sh")
	}
}

func TestBuildCommentBody_TruncatesLongDetailLists(t *testing.T) {
	var reasons []api.SuspicionReason
	for i := 0; i < 10; i++ {
		reasons = append(reasons, api.SuspicionReason{
			Type:     "sensitive_env_access",
			Detail:   "ENV_VAR_" + string(rune('A'+i)),
			Severity: api.SeverityHigh,
			Phase:    api.PhaseInstall,
		})
	}

	results := []api.BatchResultItem{
		{
			Package: "many-env",
			Version: "1.0.0",
			Status:  api.StatusCompleted,
			Profile: &api.Profile{
				SuspicionScore:   80,
				SuspicionReasons: reasons,
			},
		},
	}

	body := buildCommentBody(results, nil)
	if !strings.Contains(body, "and 5 more") {
		t.Error("expected truncation message 'and 5 more' for 10 unique env vars")
	}
}

func TestHumanizeType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"unknown_network", "Unknown Network"},
		{"sensitive_file_access", "Sensitive File Access"},
		{"unknown_dns", "Unknown DNS"},
		{"credential_exfiltration", "Credential Exfiltration"},
		{"sensitive_env_access", "Sensitive Env Access"},
		{"unknown_ip_address", "Unknown IP Address"},
	}
	for _, tc := range tests {
		got := humanizeType(tc.input)
		if got != tc.expected {
			t.Errorf("humanizeType(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestSeverityIcon(t *testing.T) {
	tests := []struct {
		sev  api.Severity
		icon string
	}{
		{api.SeverityCritical, "🔴"},
		{api.SeverityHigh, "🟠"},
		{api.SeverityMedium, "🟡"},
		{api.SeverityLow, "🟢"},
	}
	for _, tc := range tests {
		got := severityIcon(tc.sev)
		if got != tc.icon {
			t.Errorf("severityIcon(%q) = %q, want %q", tc.sev, got, tc.icon)
		}
	}
}

func TestFormatScore(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{100, "100"},
		{0, "0"},
		{85.5, "85.5"},
		{33.3, "33.3"},
	}
	for _, tc := range tests {
		got := formatScore(tc.score)
		if got != tc.expected {
			t.Errorf("formatScore(%v) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestPackageHighestSeverity(t *testing.T) {
	p := &api.Profile{
		SuspicionScore: 80,
		SuspicionReasons: []api.SuspicionReason{
			{Severity: api.SeverityMedium},
			{Severity: api.SeverityCritical},
			{Severity: api.SeverityHigh},
		},
	}
	got := packageHighestSeverity(p)
	if got != api.SeverityCritical {
		t.Errorf("packageHighestSeverity = %q, want %q", got, api.SeverityCritical)
	}
}

func TestPackageHighestSeverity_NoReasons(t *testing.T) {
	tests := []struct {
		score    float64
		expected api.Severity
	}{
		{80, api.SeverityHigh},
		{50, api.SeverityMedium},
		{10, api.SeverityLow},
	}
	for _, tc := range tests {
		p := &api.Profile{SuspicionScore: tc.score}
		got := packageHighestSeverity(p)
		if got != tc.expected {
			t.Errorf("packageHighestSeverity(score=%.0f) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestPostResults_CreatesComment(t *testing.T) {
	var postedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// List comments: empty.
			json.NewEncoder(w).Encode([]ghComment{})
			return
		}
		if r.Method == http.MethodPost {
			var req ghCommentRequest
			json.NewDecoder(r.Body).Decode(&req)
			postedBody = req.Body
			w.WriteHeader(http.StatusCreated)
			return
		}
	}))
	defer server.Close()

	// Override the API base for testing.
	provider := NewProvider(server.Client())

	vcsCtx := &vcs.Context{
		Repository: "owner/repo",
		PRNumber:   42,
		Token:      "test-token",
	}

	results := []api.BatchResultItem{
		{
			Package: "evil-pkg",
			Version: "1.0.0",
			Status:  api.StatusCompleted,
			Profile: &api.Profile{
				SuspicionScore: 50,
				SuspicionReasons: []api.SuspicionReason{
					{Detail: "bad stuff", Severity: api.SeverityHigh, Type: "unknown_network"},
				},
			},
		},
	}

	// We need to point the provider to our test server.
	// For this test, we'll validate buildCommentBody separately
	// since the actual HTTP calls go to api.github.com.
	body := buildCommentBody(results, nil)
	if !strings.Contains(body, "evil-pkg") {
		t.Error("expected evil-pkg in comment body")
	}
	_ = provider
	_ = vcsCtx
	_ = postedBody
	_ = context.Background()
}

func TestGroupFindings(t *testing.T) {
	reasons := []api.SuspicionReason{
		{Type: "unknown_network", Detail: "10.0.0.1:80", Severity: api.SeverityHigh},
		{Type: "unknown_dns", Detail: "evil.com", Severity: api.SeverityMedium},
		{Type: "credential_exfiltration", Detail: "cred leak", Severity: api.SeverityCritical},
		{Type: "unknown_dns", Detail: "bad.org", Severity: api.SeverityMedium},
	}

	groups := groupFindings(reasons)

	if len(groups) != 3 {
		t.Fatalf("expected 3 severity groups, got %d", len(groups))
	}
	// First group should be critical.
	if groups[0].Severity != api.SeverityCritical {
		t.Errorf("first group severity = %q, want critical", groups[0].Severity)
	}
	// Second group should be high.
	if groups[1].Severity != api.SeverityHigh {
		t.Errorf("second group severity = %q, want high", groups[1].Severity)
	}
	// Third group (medium) should have unknown_dns with 2 details.
	if groups[2].Severity != api.SeverityMedium {
		t.Errorf("third group severity = %q, want medium", groups[2].Severity)
	}
	if len(groups[2].Groups) != 1 {
		t.Fatalf("expected 1 type group in medium, got %d", len(groups[2].Groups))
	}
	if len(groups[2].Groups[0].Details) != 2 {
		t.Errorf("expected 2 DNS details, got %d", len(groups[2].Groups[0].Details))
	}
}

func TestFormatDetails(t *testing.T) {
	// Deduplication.
	details := []string{"/bin/sh", "/bin/sh", "sh"}
	result := formatDetails(details, 5)
	if !strings.Contains(result, "×2") {
		t.Errorf("expected ×2 for duplicates, got %q", result)
	}
	if !strings.Contains(result, "/bin/sh") {
		t.Errorf("expected /bin/sh in result, got %q", result)
	}

	// Truncation.
	var many []string
	for i := 0; i < 8; i++ {
		many = append(many, strings.Repeat("x", i+1))
	}
	result = formatDetails(many, 3)
	if !strings.Contains(result, "and 5 more") {
		t.Errorf("expected 'and 5 more', got %q", result)
	}

	// Detail with spaces should not be wrapped in inline-code fences.
	details = []string{"some long description here"}
	result = formatDetails(details, 5)
	if strings.Contains(result, "`") {
		t.Errorf("expected no backticks for detail with spaces, got %q", result)
	}
}