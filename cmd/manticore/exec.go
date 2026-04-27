package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/TazarSec/ManticoreScanner/internal/config"
	execpkg "github.com/TazarSec/ManticoreScanner/pkg/exec"
)

var execCmd = &cobra.Command{
	Use:   "exec [flags] -- <command> [args...]",
	Short: "Wrap a package manager command with pre-install security scanning",
	Long: `Wrap a package manager install command with pre-install security scanning.

The exec command intercepts package manager install operations, generates a
lockfile without installing packages or running lifecycle scripts, scans all
dependencies for security risks, and only proceeds with the actual installation
if the scan passes.

This prevents malicious packages from executing postinstall hooks before they
have been scanned.

Supported package managers: npm

Examples:
  manticore exec -- npm install
  manticore exec -- npm ci
  manticore exec -- npm install lodash
  manticore exec --fail-on 50 -- npm install`,
	Args:          cobra.MinimumNArgs(1),
	RunE:          runExec,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	f := execCmd.Flags()
	f.String("api-key", "", "API key (or set MANTICORE_API_KEY)")
	f.String("api-url", "", "Backend API base URL (or set MANTICORE_API_URL)")
	f.String("format", "", "Output format for scan results: table, json, sarif (default: table)")
	f.String("ignore-list", "", "Path to a file with packages to skip (one per line; each entry must be name@version or an integrity hash like sha512-...; '#' starts a comment)")
	f.String("on-error", "", "What to do on backend errors or polling deadline exceeded with pending items: fail (block install) or continue (proceed with install). Default: fail")
	f.Float64("fail-on", 0, "Block install if any package suspicion score >= threshold (or set MANTICORE_FAILURE_THRESHOLD; default: 1, any non-zero score)")
	f.Int("timeout", 0, "Scan polling timeout in seconds (default: 300)")
	f.Int("http-timeout", 0, "Per-request HTTP timeout in seconds (default: 120)")
	f.Bool("production", false, "Skip devDependencies")
	f.Bool("quiet", false, "Suppress manticore progress output")
	f.Bool("verbose", false, "Verbose logging")
	f.Bool("insecure", false, "Allow plaintext http:// API URLs (TLS still required by default)")
}

func runExec(cmd *cobra.Command, args []string) error {
	f := cmd.Flags()

	apiKey, _ := f.GetString("api-key")
	apiURL, _ := f.GetString("api-url")
	format, _ := f.GetString("format")
	ignoreList, _ := f.GetString("ignore-list")
	onError, _ := f.GetString("on-error")
	failOn, _ := f.GetFloat64("fail-on")
	timeout, _ := f.GetInt("timeout")
	httpTimeout, _ := f.GetInt("http-timeout")
	production, _ := f.GetBool("production")
	quiet, _ := f.GetBool("quiet")
	verbose, _ := f.GetBool("verbose")
	insecure, _ := f.GetBool("insecure")

	cliFlags := config.CLIFlags{
		APIKey:         apiKey,
		APIURL:         apiURL,
		Format:         format,
		IgnoreListFile: ignoreList,
		OnError:        onError,
		FailOn:         failOn,
		FailOnSet:      f.Changed("fail-on"),
		Timeout:        timeout,
		HTTPTimeout:    httpTimeout,
		Production:     production,
		Quiet:          quiet,
		Verbose:        verbose,
		Insecure:       insecure,
		InsecureSet:    f.Changed("insecure"),
	}
	scanCfg, err := config.Resolve(cliFlags)
	if err != nil {
		return err
	}

	if scanCfg.APIKey == "" {
		return fmt.Errorf("API key required: set --api-key or MANTICORE_API_KEY environment variable")
	}

	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	exitCode, err := execpkg.Run(ctx, execpkg.Config{
		Command:    args,
		Dir:        dir,
		ScanConfig: scanCfg,
		FailOn:     scanCfg.FailOn,
		Quiet:      quiet,
	})

	if err != nil {
		return err
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}
