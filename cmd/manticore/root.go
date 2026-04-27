package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/TazarSec/ManticoreScanner/internal/buildinfo"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "manticore",
	Short: "Scan npm packages for malicious behavior using Manticore intelligence backend.",
	Long:  "ManticoreScanner scans npm dependencies for suspicious behavior by submitting them to the Manticore analysis backend.",
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("manticore %s\n", buildinfo.Version)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if !errors.Is(err, errFailOnTriggered) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}
