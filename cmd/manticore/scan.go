package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/TazarSec/ManticoreScanner/internal/config"
	"github.com/TazarSec/ManticoreScanner/pkg/api"
	"github.com/TazarSec/ManticoreScanner/pkg/formatter"
	"github.com/TazarSec/ManticoreScanner/pkg/scanner"
	"github.com/TazarSec/ManticoreScanner/pkg/vcs/github"
)

var flags config.CLIFlags

// errFailOnTriggered is returned when --fail-on detects a suspicious package.
// The user-facing FAIL message is printed inline; the sentinel only carries
// the non-zero exit code up to cobra.
var errFailOnTriggered = errors.New("suspicious package threshold exceeded")

var scanCmd = &cobra.Command{
	Use:           "scan",
	Short:         "Scan packages from package.json / package-lock.json",
	Long:          "Parse npm dependency files, submit packages to Manticore backend for behavioral analysis, and report findings.",
	RunE:          runScan,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	f := scanCmd.Flags()
	f.StringVar(&flags.APIKey, "api-key", "", "API key (or set MANTICORE_API_KEY). Used when --auth-mode=api-key (default).")
	f.StringVar(&flags.APIURL, "api-url", "", "API base URL (or set MANTICORE_API_URL)")
	f.StringVar(&flags.AuthMode, "auth-mode", "", "Authentication mode: api-key (default) or github-oidc. github-oidc requires the workflow to grant `permissions: id-token: write`. (or set MANTICORE_AUTH_MODE)")
	f.StringVar(&flags.File, "file", "", "Path to package.json or package-lock.json (default: auto-detect in cwd)")
	f.StringVar(&flags.Format, "format", "", "Output format: table, json, sarif (default: table)")
	f.StringVar(&flags.Output, "output", "", "Write output to file (default: stdout)")
	f.StringVar(&flags.IgnoreListFile, "ignore-list", "", "Path to a file with packages to skip (one per line; each entry must be name@version or an integrity hash like sha512-...; '#' starts a comment)")
	f.Float64Var(&flags.FailOn, "fail-on", 0, "Exit code 1 if any suspicion_score >= this value")
	f.IntVar(&flags.Timeout, "timeout", 0, "Polling timeout in seconds (default: 300)")
	f.IntVar(&flags.HTTPTimeout, "http-timeout", 0, "Per-request HTTP timeout in seconds (default: 120)")
	f.StringVar(&flags.OnError, "on-error", "", "What to do on backend errors or polling deadline exceeded with pending items: fail (exit non-zero) or continue (exit 0). Default: fail")
	f.BoolVar(&flags.Production, "production", false, "Skip devDependencies")
	f.BoolVar(&flags.VCSComment, "vcs-comment", false, "Post results to VCS PR/MR (requires GITHUB_TOKEN)")
	f.BoolVar(&flags.Quiet, "quiet", false, "Suppress progress output")
	f.BoolVar(&flags.Verbose, "verbose", false, "Verbose logging")
	f.BoolVar(&flags.Insecure, "insecure", false, "Allow plaintext http:// API URLs (TLS still required by default)")
	f.BoolVar(&flags.IncludeTransitive, "include-transitive", false, "Submit transitive dependencies (defaults to direct deps only; backend behavioral analysis already exercises transitive code on install)")
}

func runScan(cmd *cobra.Command, args []string) error {
	flags.FailOnSet = cmd.Flags().Changed("fail-on")
	flags.InsecureSet = cmd.Flags().Changed("insecure")
	flags.IncludeTransitiveSet = cmd.Flags().Changed("include-transitive")

	cfg, err := config.Resolve(flags, os.Stderr)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var onProgress func(completed, total int)
	if !cfg.Quiet {
		onProgress = func(completed, total int) {
			fmt.Fprintf(os.Stderr, "\rScanning: %d/%d packages completed", completed, total)
		}
	}

	result, scanErr := scanner.Run(ctx, cfg, onProgress)

	if !cfg.Quiet && onProgress != nil {
		fmt.Fprintln(os.Stderr)
	}

	if result == nil {
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	if len(result.Items) == 0 {
		if scanErr != nil {
			return handleScanError(cfg, scanErr, 0)
		}
		if !cfg.Quiet {
			fmt.Fprintln(os.Stderr, "No packages found to scan.")
		}
		return nil
	}

	f := formatter.Get(cfg.Format)
	output, err := f.Format(result.Items, formatter.Options{
		InputFile: result.InputFile,
	})
	if err != nil {
		return fmt.Errorf("formatting output: %w", err)
	}

	if cfg.OutputPath != "" {
		if err := os.WriteFile(cfg.OutputPath, output, 0644); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
		if !cfg.Quiet {
			fmt.Fprintf(os.Stderr, "Results written to %s\n", cfg.OutputPath)
		}
	} else {
		fmt.Print(string(output))
	}

	if cfg.PostToVCS {
		if err := postToVCS(ctx, result); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to post VCS comment: %v\n", err)
		} else if !cfg.Quiet {
			fmt.Fprintln(os.Stderr, "Results posted to PR.")
		}
	}

	pending := countPending(result.Items)
	if scanErr != nil || pending > 0 {
		return handleScanError(cfg, scanErr, pending)
	}

	if cfg.FailOn != -1 {
		for _, item := range result.Items {
			if item.Profile != nil && item.Profile.SuspicionScore >= cfg.FailOn {
				fmt.Fprintf(os.Stderr, "FAIL: %s@%s has suspicion score %.1f (threshold: %.1f)\n",
					item.Package, item.Version,
					item.Profile.SuspicionScore, cfg.FailOn,
				)
				return errFailOnTriggered
			}
		}
	}

	return nil
}

func countPending(items []api.BatchResultItem) int {
	n := 0
	for _, item := range items {
		if item.Status == api.StatusInProgress || item.Status == api.StatusQueued {
			n++
		}
	}
	return n
}

func handleScanError(cfg scanner.Config, scanErr error, pending int) error {
	switch cfg.OnError {
	case config.OnErrorContinue:
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: scan error suppressed by --on-error=continue: %v\n", scanErr)
		}
		if pending > 0 {
			fmt.Fprintf(os.Stderr, "Warning: %d package(s) still pending at deadline; suppressed by --on-error=continue\n", pending)
		}
		return nil
	default:
		if scanErr != nil {
			return fmt.Errorf("scan failed: %w", scanErr)
		}
		return fmt.Errorf("scan timed out with %d package(s) still pending (use --on-error=continue to ignore)", pending)
	}
}

func postToVCS(ctx context.Context, result *scanner.Result) error {
	provider := github.NewProvider(nil)
	vcsCtx, err := provider.Detect()
	if err != nil {
		return fmt.Errorf("detecting VCS environment: %w", err)
	}
	return provider.PostResults(ctx, vcsCtx, result.Items)
}
