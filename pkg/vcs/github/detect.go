package github

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/TazarSec/ManticoreScanner/pkg/vcs"
)

type eventPayload struct {
	PullRequest *struct {
		Number int `json:"number"`
	} `json:"pull_request"`
	Number int `json:"number"`
}

func Detect() (*vcs.Context, error) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return nil, fmt.Errorf("not running in GitHub Actions")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN not set")
	}

	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		return nil, fmt.Errorf("GITHUB_REPOSITORY not set")
	}

	sha := os.Getenv("GITHUB_SHA")

	prNumber, err := detectPRNumber()
	if err != nil {
		return nil, fmt.Errorf("detecting PR number: %w", err)
	}

	return &vcs.Context{
		Provider:   "github",
		Repository: repo,
		PRNumber:   prNumber,
		CommitSHA:  sha,
		Token:      token,
	}, nil
}

func detectPRNumber() (int, error) {
	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath == "" {
		return 0, fmt.Errorf("GITHUB_EVENT_PATH not set")
	}

	data, err := os.ReadFile(eventPath)
	if err != nil {
		return 0, fmt.Errorf("reading event file: %w", err)
	}

	var event eventPayload
	if err := json.Unmarshal(data, &event); err != nil {
		return 0, fmt.Errorf("parsing event file: %w", err)
	}

	if event.PullRequest != nil && event.PullRequest.Number > 0 {
		return event.PullRequest.Number, nil
	}
	if event.Number > 0 {
		return event.Number, nil
	}

	return 0, fmt.Errorf("could not determine PR number from event payload")
}
