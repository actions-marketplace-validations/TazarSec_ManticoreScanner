package github

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
)

var severityOrder = []api.Severity{
	api.SeverityCritical,
	api.SeverityHigh,
	api.SeverityMedium,
	api.SeverityLow,
}

var typeAbbreviations = map[string]string{
	"dns":  "DNS",
	"ip":   "IP",
	"http": "HTTP",
	"tcp":  "TCP",
	"url":  "URL",
	"env":  "Env",
}

func severityRank(s api.Severity) int {
	switch s {
	case api.SeverityCritical:
		return 0
	case api.SeverityHigh:
		return 1
	case api.SeverityMedium:
		return 2
	case api.SeverityLow:
		return 3
	default:
		return 4
	}
}

func severityIcon(s api.Severity) string {
	switch s {
	case api.SeverityCritical:
		return "🔴"
	case api.SeverityHigh:
		return "🟠"
	case api.SeverityMedium:
		return "🟡"
	case api.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

func severityLabel(s api.Severity) string {
	switch s {
	case api.SeverityCritical:
		return "Critical"
	case api.SeverityHigh:
		return "High"
	case api.SeverityMedium:
		return "Medium"
	case api.SeverityLow:
		return "Low"
	default:
		return "Unknown"
	}
}

func humanizeType(t string) string {
	words := strings.Split(t, "_")
	for i, w := range words {
		lower := strings.ToLower(w)
		if replacement, ok := typeAbbreviations[lower]; ok {
			words[i] = replacement
		} else if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

func formatScore(score float64) string {
	if score == float64(int(score)) {
		return fmt.Sprintf("%d", int(score))
	}
	return fmt.Sprintf("%.1f", score)
}

func packageHighestSeverity(p *api.Profile) api.Severity {
	if len(p.SuspicionReasons) == 0 {
		if p.SuspicionScore >= 70 {
			return api.SeverityHigh
		}
		if p.SuspicionScore >= 30 {
			return api.SeverityMedium
		}
		return api.SeverityLow
	}
	best := api.Severity("")
	for _, r := range p.SuspicionReasons {
		if best == "" || severityRank(r.Severity) < severityRank(best) {
			best = r.Severity
		}
	}
	return best
}

func overallHighestSeverity(suspicious []api.BatchResultItem) api.Severity {
	best := api.Severity("")
	for _, r := range suspicious {
		if r.Profile == nil {
			continue
		}
		s := packageHighestSeverity(r.Profile)
		if best == "" || severityRank(s) < severityRank(best) {
			best = s
		}
	}
	if best == "" {
		return api.SeverityLow
	}
	return best
}

type findingGroup struct {
	Type    string
	Details []string
}

type severityGroup struct {
	Severity api.Severity
	Groups   []findingGroup
}

func groupFindings(reasons []api.SuspicionReason) []severityGroup {
	m := make(map[api.Severity]map[string][]string)
	for _, r := range reasons {
		if m[r.Severity] == nil {
			m[r.Severity] = make(map[string][]string)
		}
		m[r.Severity][string(r.Type)] = append(m[r.Severity][string(r.Type)], r.Detail)
	}

	var result []severityGroup
	for _, sev := range severityOrder {
		types, ok := m[sev]
		if !ok {
			continue
		}
		var typeNames []string
		for t := range types {
			typeNames = append(typeNames, t)
		}
		sort.Strings(typeNames)

		var groups []findingGroup
		for _, t := range typeNames {
			groups = append(groups, findingGroup{Type: t, Details: types[t]})
		}
		result = append(result, severityGroup{Severity: sev, Groups: groups})
	}
	return result
}

func countBySeverity(reasons []api.SuspicionReason) map[api.Severity]int {
	counts := make(map[api.Severity]int)
	for _, r := range reasons {
		counts[r.Severity]++
	}
	return counts
}

func formatDetails(details []string, maxShow int) string {
	if maxShow <= 0 {
		maxShow = 5
	}

	type entry struct {
		detail string
		count  int
	}
	seen := make(map[string]*entry)
	var unique []*entry
	for _, d := range details {
		if e, ok := seen[d]; ok {
			e.count++
		} else {
			e = &entry{detail: d, count: 1}
			seen[d] = e
			unique = append(unique, e)
		}
	}

	var parts []string
	for _, e := range unique {
		var s string
		if strings.Contains(e.detail, " ") {
			s = sanitizeText(e.detail)
		} else {
			s = sanitizeInlineCode(e.detail)
		}
		if e.count > 1 {
			s += fmt.Sprintf(" ×%d", e.count)
		}
		parts = append(parts, s)
	}

	if len(parts) <= maxShow {
		return strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(parts[:maxShow], ", "), len(parts)-maxShow)
}

func buildFlagLabels(p *api.Profile) string {
	var flags []string
	if p.HasUnknownNetwork {
		flags = append(flags, "🌐 Network")
	}
	if p.HasSensitiveFileAccess {
		flags = append(flags, "📁 File Access")
	}
	if p.HasUnexpectedProcess {
		flags = append(flags, "⚙️ Processes")
	}
	return strings.Join(flags, " · ")
}

func writePackageSection(sb *strings.Builder, r api.BatchResultItem) {
	p := r.Profile
	highest := packageHighestSeverity(p)

	sb.WriteString(fmt.Sprintf("### %s %s %s\n",
		severityIcon(highest),
		sanitizeText(r.Package),
		sanitizeInlineCode(r.Version),
	))
	sb.WriteString(fmt.Sprintf("**Score:** %s / 100 · **Severity:** %s\n\n",
		formatScore(p.SuspicionScore), severityLabel(highest)))

	if len(p.SuspicionReasons) == 0 {
		return
	}

	counts := countBySeverity(p.SuspicionReasons)
	var summaryParts []string
	for _, sev := range severityOrder {
		if c, ok := counts[sev]; ok && c > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf(
				"%s <strong>%d %s</strong>", severityIcon(sev), c, severityLabel(sev)))
		}
	}

	sb.WriteString(fmt.Sprintf("<details>\n<summary>%s findings</summary>\n\n",
		strings.Join(summaryParts, " · ")))

	grouped := groupFindings(p.SuspicionReasons)
	for _, sg := range grouped {
		sb.WriteString(fmt.Sprintf("#### %s %s\n", severityIcon(sg.Severity), severityLabel(sg.Severity)))
		sb.WriteString("| Type | Detail |\n|------|--------|\n")
		for _, fg := range sg.Groups {
			sb.WriteString(fmt.Sprintf("| %s | %s |\n",
				sanitizeText(humanizeType(fg.Type)),
				formatDetails(fg.Details, 5),
			))
		}
		sb.WriteString("\n")
	}

	flags := buildFlagLabels(p)
	if flags != "" {
		sb.WriteString(fmt.Sprintf("**Behavior:** %s\n\n", flags))
	}

	sb.WriteString("</details>\n\n")
}

func buildCommentBody(results []api.BatchResultItem) string {
	var sb strings.Builder
	sb.WriteString(commentMarker + "\n")
	sb.WriteString("## Manticore Security Scan Results\n\n")

	var suspicious []api.BatchResultItem
	for _, r := range results {
		if r.Profile != nil && r.Profile.SuspicionScore > 0 {
			suspicious = append(suspicious, r)
		}
	}

	if len(suspicious) == 0 {
		pkg := "packages"
		if len(results) == 1 {
			pkg = "package"
		}
		sb.WriteString(fmt.Sprintf("✅ **%d %s scanned** — no suspicious behavior detected.\n", len(results), pkg))
		return sb.String()
	}

	highest := overallHighestSeverity(suspicious)
	pkgWord := "packages"
	if len(results) == 1 {
		pkgWord = "package"
	}
	sb.WriteString(fmt.Sprintf("**%d %s scanned** · **%d suspicious** · Highest severity: %s **%s**\n\n",
		len(results), pkgWord,
		len(suspicious),
		severityIcon(highest), severityLabel(highest),
	))
	sb.WriteString("---\n\n")

	sort.Slice(suspicious, func(i, j int) bool {
		return suspicious[i].Profile.SuspicionScore > suspicious[j].Profile.SuspicionScore
	})

	for _, r := range suspicious {
		writePackageSection(&sb, r)
	}

	sb.WriteString("\n---\n")
	sb.WriteString("<sub>Scanned by Manticore Engine</sub>\n")

	return truncateComment(sb.String())
}
