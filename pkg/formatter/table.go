package formatter

import (
	"fmt"
	"strings"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorBold   = "\033[1m"
)

type TableFormatter struct{}

// stripControl drops C0/C1 control characters so a hostile backend cannot
// inject ANSI escapes, BEL, OSC 8 hyperlinks, or carriage returns into the
// rendered table. Tabs become spaces. The colour escapes emitted by this
// formatter are added after sanitization, so they are unaffected.
func stripControl(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (f *TableFormatter) Format(results []api.BatchResultItem, opts Options) ([]byte, error) {
	if len(results) == 0 {
		return []byte("No packages scanned.\n"), nil
	}

	type cleanRow struct {
		pkg, version, status string
	}
	cleaned := make([]cleanRow, len(results))
	nameW, versionW, statusW, scoreW := 7, 7, 6, 5
	for i, r := range results {
		cleaned[i] = cleanRow{
			pkg:     stripControl(r.Package),
			version: stripControl(r.Version),
			status:  stripControl(string(r.Status)),
		}
		if l := len(cleaned[i].pkg); l > nameW {
			nameW = l
		}
		if l := len(cleaned[i].version); l > versionW {
			versionW = l
		}
		if l := len(cleaned[i].status); l > statusW {
			statusW = l
		}
	}

	var sb strings.Builder

	header := fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %s\n",
		nameW, "PACKAGE",
		versionW, "VERSION",
		statusW, "STATUS",
		scoreW, "SCORE",
		"FLAGS",
	)
	sb.WriteString(colorBold + header + colorReset)
	sb.WriteString(strings.Repeat("-", len(header)+10) + "\n")

	for i, r := range results {
		score := "-"
		scoreColor := colorReset
		flags := ""

		if r.Profile != nil {
			score = fmt.Sprintf("%.1f", r.Profile.SuspicionScore)
			scoreColor = scoreColorFor(r.Profile.SuspicionScore)

			var flagParts []string
			if r.Profile.HasUnknownNetwork {
				flagParts = append(flagParts, "NET")
			}
			if r.Profile.HasSensitiveFileAccess {
				flagParts = append(flagParts, "FILE")
			}
			if r.Profile.HasUnexpectedProcess {
				flagParts = append(flagParts, "PROC")
			}
			flags = strings.Join(flagParts, ",")
		}

		line := fmt.Sprintf("%-*s  %-*s  %-*s  %s%-*s%s  %s\n",
			nameW, cleaned[i].pkg,
			versionW, cleaned[i].version,
			statusW, cleaned[i].status,
			scoreColor, scoreW, score, colorReset,
			flags,
		)
		sb.WriteString(line)
	}

	completed := 0
	suspicious := 0
	for _, r := range results {
		if r.Status == api.StatusCompleted {
			completed++
		}
		if r.Profile != nil && r.Profile.SuspicionScore > 0 {
			suspicious++
		}
	}
	sb.WriteString(fmt.Sprintf("\n%d packages scanned, %d completed, %d suspicious\n", len(results), completed, suspicious))

	return []byte(sb.String()), nil
}

func scoreColorFor(score float64) string {
	switch {
	case score >= 70:
		return colorRed
	case score >= 30:
		return colorYellow
	default:
		return colorGreen
	}
}
