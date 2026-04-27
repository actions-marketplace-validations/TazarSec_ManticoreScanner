package formatter

import (
	"encoding/json"
	"fmt"

	"github.com/TazarSec/ManticoreScanner/internal/buildinfo"
	"github.com/TazarSec/ManticoreScanner/pkg/api"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type SARIFFormatter struct{}

const sarifMaxMessageLen = 1024

func capLen(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func (f *SARIFFormatter) Format(results []api.BatchResultItem, opts Options) ([]byte, error) {
	ruleMap := make(map[string]sarifRule)
	var sarifResults []sarifResult

	inputFile := stripControl(opts.InputFile)
	if inputFile == "" {
		inputFile = "package-lock.json"
	}

	for _, r := range results {
		if r.Profile == nil || r.Profile.SuspicionScore <= 0 {
			continue
		}

		pkg := stripControl(r.Package)
		ver := stripControl(r.Version)

		for _, reason := range r.Profile.SuspicionReasons {
			ruleID := stripControl(string(reason.Type))
			level := severityToLevel(reason.Severity)

			if _, exists := ruleMap[ruleID]; !exists {
				ruleMap[ruleID] = sarifRule{
					ID:               ruleID,
					ShortDescription: sarifMessage{Text: ruleID},
					DefaultConfig:    sarifRuleConfig{Level: level},
				}
			}

			msg := fmt.Sprintf("%s@%s (score: %.1f): %s [%s phase]",
				pkg, ver,
				r.Profile.SuspicionScore,
				stripControl(reason.Detail),
				stripControl(string(reason.Phase)),
			)
			msg = capLen(msg, sarifMaxMessageLen)

			sarifResults = append(sarifResults, sarifResult{
				RuleID:  ruleID,
				Level:   level,
				Message: sarifMessage{Text: msg},
				Locations: []sarifLocation{
					{
						PhysicalLocation: sarifPhysicalLocation{
							ArtifactLocation: sarifArtifactLocation{URI: inputFile},
							Region:           sarifRegion{StartLine: 1},
						},
					},
				},
			})
		}
	}

	rules := make([]sarifRule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		rules = append(rules, rule)
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "ManticoreScanner",
						InformationURI: "https://github.com/TazarSec/ManticoreScanner",
						Version:        buildinfo.Version,
						Rules:          rules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	return json.MarshalIndent(log, "", "  ")
}

func severityToLevel(s api.Severity) string {
	switch s {
	case api.SeverityLow:
		return "note"
	case api.SeverityMedium:
		return "warning"
	case api.SeverityHigh, api.SeverityCritical:
		return "error"
	default:
		return "warning"
	}
}
