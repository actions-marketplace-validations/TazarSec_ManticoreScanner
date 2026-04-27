package github

import "strings"

const (
	maxFieldLen   = 256
	maxCommentLen = 60_000
)

func stripControl(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			continue
		case r == 0x2028, r == 0x2029:
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	count := 0
	for i := range s {
		if count == max {
			return s[:i] + "…"
		}
		count++
	}
	return s
}

func sanitizeText(s string) string {
	s = truncateRunes(stripControl(s), maxFieldLen)
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\', '`', '*', '_', '[', ']', '|', '~':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '&':
			b.WriteString("&amp;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sanitizeInlineCode(s string) string {
	s = truncateRunes(stripControl(s), maxFieldLen)
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	return fence + " " + s + " " + fence
}

func truncateComment(body string) string {
	if len(body) <= maxCommentLen {
		return body
	}
	return body[:maxCommentLen] + "\n\n_… output truncated_\n"
}
