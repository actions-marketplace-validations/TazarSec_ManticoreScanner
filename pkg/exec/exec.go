package exec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
	"github.com/TazarSec/ManticoreScanner/pkg/formatter"
	"github.com/TazarSec/ManticoreScanner/pkg/scanner"
)

const onErrorContinue = "continue"

type Config struct {
	Command    []string
	Dir        string
	ScanConfig scanner.Config
	FailOn     float64
	Quiet      bool
}

func Run(ctx context.Context, cfg Config) (int, error) {
	log := func(format string, args ...any) {
		if !cfg.Quiet {
			fmt.Fprintf(os.Stderr, "[manticore] "+format+"\n", args...)
		}
	}

	if len(cfg.Command) == 0 {
		return 1, fmt.Errorf("no command specified")
	}

	pm := Detect(cfg.Command[0])
	if pm == nil {
		return 1, fmt.Errorf("unsupported package manager: %s (supported: npm)", cfg.Command[0])
	}

	pmArgs := cfg.Command[1:]
	strategy := pm.Plan(pmArgs, cfg.Dir)
	if strategy == nil {
		log("Not an install command, running directly without scanning")
		return runPassthrough(ctx, cfg.Command, cfg.Dir)
	}

	log("Detected package manager: %s", pm.Name())

	if strategy.LockfileCmd != nil {
		log("Resolving dependencies (lockfile-only)...")
		exitCode, err := runPassthrough(ctx, strategy.LockfileCmd, cfg.Dir)
		if err != nil {
			return exitCode, fmt.Errorf("failed to resolve dependencies: %w", err)
		}
		if exitCode != 0 {
			return exitCode, fmt.Errorf("dependency resolution exited with code %d", exitCode)
		}
	}

	if _, err := os.Stat(strategy.LockfilePath); os.IsNotExist(err) {
		return 1, fmt.Errorf("lockfile not found at %s — cannot scan dependencies", strategy.LockfilePath)
	}

	log("Scanning dependencies...")
	scanCfg := cfg.ScanConfig
	scanCfg.InputPath = strategy.LockfilePath

	var progressFn func(completed, total int)
	if !cfg.Quiet {
		progressFn = func(completed, total int) {
			fmt.Fprintf(os.Stderr, "\r[manticore] Scanning: %d/%d packages completed", completed, total)
		}
	}

	result, err := scanner.Run(ctx, scanCfg, progressFn)

	if !cfg.Quiet && progressFn != nil {
		fmt.Fprintln(os.Stderr)
	}

	if err != nil {
		if scanCfg.OnError == onErrorContinue {
			log("Scan error suppressed by --on-error=continue: %v", err)
			log("Proceeding with install without security gate.")
			log("Running: %s", strings.Join(strategy.InstallCmd, " "))
			return runPassthrough(ctx, strategy.InstallCmd, cfg.Dir)
		}
		return 1, fmt.Errorf("scan failed: %w", err)
	}

	if len(result.Items) == 0 {
		log("No packages found to scan")
		log("Running: %s", strings.Join(strategy.InstallCmd, " "))
		return runPassthrough(ctx, strategy.InstallCmd, cfg.Dir)
	}

	pending := countPending(result.Items)
	if pending > 0 {
		if scanCfg.OnError == onErrorContinue {
			log("%d package(s) still pending at deadline; suppressed by --on-error=continue", pending)
			log("Proceeding with install without security gate for pending packages.")
			log("Running: %s", strings.Join(strategy.InstallCmd, " "))
			return runPassthrough(ctx, strategy.InstallCmd, cfg.Dir)
		}
		log("Scan timed out with %d package(s) still pending — blocking install (use --on-error=continue to override)", pending)
		return 1, nil
	}

	var blocked []api.BatchResultItem
	for _, item := range result.Items {
		if item.Profile != nil && item.Profile.SuspicionScore >= cfg.FailOn {
			blocked = append(blocked, item)
		}
	}

	if len(blocked) > 0 {
		fmtr := formatter.Get(scanCfg.Format)
		output, fmtErr := fmtr.Format(result.Items, formatter.Options{InputFile: result.InputFile})
		if fmtErr == nil {
			fmt.Fprintln(os.Stderr)
			os.Stdout.Write(output)
		}
		fmt.Fprintln(os.Stderr)
		log("Blocked %d package(s) exceeding suspicion threshold (%.0f)", len(blocked), cfg.FailOn)
		log("Aborting install. Review the packages above before proceeding.")
		return 1, nil
	}

	log("All %d packages passed security scan (threshold: %.0f)", len(result.Items), cfg.FailOn)

	fmt.Fprintln(os.Stderr)
	log("Running: %s", strings.Join(strategy.InstallCmd, " "))
	return runPassthrough(ctx, strategy.InstallCmd, cfg.Dir)
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

func runPassthrough(ctx context.Context, args []string, dir string) (int, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}
