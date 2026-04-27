package github

import (
	"strings"
	"testing"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
)

func TestSanitizeText_StripsControlAndNewlines(t *testing.T) {
	got := sanitizeText("evil\n# FAKE\r\x1b[31mansi\x07")
	// Newlines and control chars must be gone. The `#` itself is harmless
	// inline (only a heading at line start), and we just stripped the line
	// break, so it can remain as literal text.
	for _, bad := range []string{"\n", "\r", "\x1b", "\x07"} {
		if strings.Contains(got, bad) {
			t.Errorf("sanitizeText leaked %q in %q", bad, got)
		}
	}
}

func TestSanitizeText_EscapesMarkdownAndHTML(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"a*b", `a\*b`},
		{"a_b", `a\_b`},
		{"a`b", "a\\`b"},
		{"a|b", `a\|b`},
		{"a[b]", `a\[b\]`},
		{"a~b", `a\~b`},
		{"a<b", "a&lt;b"},
		{"a>b", "a&gt;b"},
		{"a&b", "a&amp;b"},
		{`a"b`, "a&quot;b"},
		{"a'b", "a&#39;b"},
		{"a\\b", `a\\b`},
	}
	for _, c := range cases {
		got := sanitizeText(c.in)
		if got != c.want {
			t.Errorf("sanitizeText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeText_PreservesBenignChars(t *testing.T) {
	// Hyphens, dots, slashes are inert inline (we strip newlines) and would
	// produce ugly output if escaped. Make sure they pass through unchanged.
	got := sanitizeText("evil-pkg/sub.0.1")
	if got != "evil-pkg/sub.0.1" {
		t.Errorf("sanitizeText over-escaped: %q", got)
	}
}

func TestSanitizeInlineCode_FenceBeatsBacktickRun(t *testing.T) {
	got := sanitizeInlineCode("a``b```c")
	// Longest run is 3, so fence must be 4.
	if !strings.HasPrefix(got, "```` ") || !strings.HasSuffix(got, " ````") {
		t.Errorf("expected 4-tick fence wrapping, got %q", got)
	}
	if !strings.Contains(got, "a``b```c") {
		t.Errorf("inner value missing: %q", got)
	}
}

func TestSanitizeInlineCode_StripsControl(t *testing.T) {
	got := sanitizeInlineCode("ver\nsion\x1b[0m")
	for _, bad := range []string{"\n", "\x1b"} {
		if strings.Contains(got, bad) {
			t.Errorf("sanitizeInlineCode leaked %q in %q", bad, got)
		}
	}
}

func TestSanitizeText_TruncatesLongValue(t *testing.T) {
	in := strings.Repeat("a", maxFieldLen+50)
	got := sanitizeText(in)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("expected truncation marker, got %q", got)
	}
}

func TestBuildCommentBody_HostileInputsAreSanitized(t *testing.T) {
	results := []api.BatchResultItem{{
		Package: "evil\n# FAKE HEADING\n",
		Version: "1.0.0` payload `1.0.0",
		Status:  api.StatusCompleted,
		Profile: &api.Profile{
			SuspicionScore: 80,
			SuspicionReasons: []api.SuspicionReason{
				{Type: "x", Detail: "</details><img src=x>", Severity: api.SeverityHigh, Phase: api.PhaseInstall},
				{Type: "x", Detail: "row1\nrow2|piped", Severity: api.SeverityHigh, Phase: api.PhaseInstall},
				{Type: "x", Detail: "back`tick`s", Severity: api.SeverityHigh, Phase: api.PhaseInstall},
				{Type: "x", Detail: "ansi\x1b[31mboom\x1b[0m", Severity: api.SeverityHigh, Phase: api.PhaseInstall},
			},
		},
	}}

	body := buildCommentBody(results, nil)

	// Substring checks for purely-injected structures (the formatter never
	// emits these itself).
	for _, bad := range []string{
		"\n# ",   // newline-prefixed heading injection
		"<img",   // raw <img> element
		"<script", // raw script
		"\x1b",   // ANSI escape sequence
		"\r",     // CR
	} {
		if strings.Contains(body, bad) {
			t.Errorf("body contains forbidden %q\n--- body ---\n%s", bad, body)
		}
	}

	// The formatter legitimately emits one <details>…</details> per
	// suspicious package, and one <summary>…</summary> inside it. With one
	// suspicious package, the count of each open/close tag must be exactly
	// one — anything more would mean the hostile Detail re-introduced them.
	for _, tag := range []string{"<details>", "</details>", "<summary>", "</summary>"} {
		if got := strings.Count(body, tag); got != 1 {
			t.Errorf("expected exactly 1 occurrence of %q (formatter-emitted), got %d\n--- body ---\n%s", tag, got, body)
		}
	}

	// The hostile "</details><img src=x>" Detail must appear in *escaped*
	// form, proving sanitization ran rather than dropping the value.
	if !strings.Contains(body, "&lt;/details&gt;&lt;img src=x&gt;") {
		t.Errorf("expected escaped form of hostile Detail in body:\n%s", body)
	}

	// The Detail "row1\nrow2|piped" gets rendered inside an inline-code span
	// (no spaces in the value). Markdown does NOT interpret `|` inside a code
	// span as a table separator, so the substring "row1row2|piped" is safe
	// and *must* appear (otherwise the value was lost). What must NOT appear
	// is a literal newline keeping the two halves on separate lines.
	if !strings.Contains(body, "row1row2") {
		t.Errorf("expected sanitized concatenation 'row1row2' in body")
	}
	if strings.Contains(body, "row1\nrow2") {
		t.Errorf("newline inside Detail leaked into body")
	}

	// The version field has internal backticks. sanitizeInlineCode wraps it
	// in a longer fence rather than escaping. Verify the wrapping fence is
	// at least 2 backticks long (longer than the longest internal run = 1).
	if !strings.Contains(body, "`` 1.0.0` payload `1.0.0 ``") {
		t.Errorf("expected version wrapped in a longer backtick fence, got:\n%s", body)
	}
}

func TestTruncateComment_UnderLimitUnchanged(t *testing.T) {
	in := strings.Repeat("a", 100)
	if got := truncateComment(in); got != in {
		t.Errorf("truncateComment modified short input")
	}
}

func TestTruncateComment_OverLimitTrimmed(t *testing.T) {
	in := strings.Repeat("a", maxCommentLen+1000)
	got := truncateComment(in)
	if len(got) > maxCommentLen+64 {
		t.Errorf("truncateComment produced %d bytes, want ≤ %d", len(got), maxCommentLen+64)
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("expected truncation marker in output")
	}
}