// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"slices"

	"github.com/spf13/cobra"
)

// defaultGateFailOn is gate's threshold when neither --fail-on nor a config
// file sets one. scan alone fails only on CRITICAL, which lets HIGH findings
// such as RSA-2048 key generation through a build.
const defaultGateFailOn = "high"

// gateFormats are the reports gate prints.
var gateFormats = []string{"text", "json", "sarif"}

// gateFailOn has its own variable because its default differs from scan's.
var gateFailOn string

var gateCmd = &cobra.Command{
	Use:   "gate [path or URL]",
	Short: "Fail a build when findings reach a severity (equivalent to scan --fail-on high)",
	Long: `Scan a local directory or Git repository, print the report, and exit 1
when any finding is at or above the --fail-on severity. The default is high.

This runs the same scan as "cryptoscan scan --fail-on high". The one
difference from scan is that default: scan on its own fails only on CRITICAL
findings, which lets HIGH findings such as RSA-2048 key generation pass a
build. gate fails on HIGH and CRITICAL unless you choose another level. A
failOn set in a config file is used when --fail-on is not given.

Exit codes:
  0  no finding at or above the threshold
  1  at least one finding at or above the threshold, or the scan failed

Examples:
  cryptoscan gate .
  cryptoscan gate . --fail-on critical
  cryptoscan gate . --baseline baseline.json
  cryptoscan gate . --format sarif > results.sarif
  cryptoscan gate https://github.com/org/repo`,
	Args: cobra.ExactArgs(1),
	RunE: runGate,
}

func init() {
	gateCmd.Flags().StringVar(&gateFailOn, "fail-on", defaultGateFailOn, "Exit 1 if findings at this severity or higher (info, low, medium, high, critical)")
	// The remaining flags are bound to the variables scan uses for them, with
	// the same defaults, so the pipeline reads them unchanged.
	gateCmd.Flags().StringVar(&baselineFile, "baseline", "", "Baseline JSON file - only report new findings")
	gateCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text, json, sarif")
	gateCmd.Flags().StringVar(&ignorePatterns, "ignore", "", "Pattern IDs to ignore (comma-separated, e.g., \"RSA-001,CERT-*\")")
	gateCmd.Flags().StringVar(&ignoreCategories, "ignore-category", "", "Categories to ignore (comma-separated, e.g., \"Certificate,Library Import\")")
	gateCmd.Flags().StringVar(&configFile, "config", "", "Config file path (default: auto-detect .cryptoscan.yaml)")
}

func runGate(cmd *cobra.Command, args []string) error {
	return exitWith(gateTarget(cmd, args[0]))
}

// gateTarget scans target, prints the report, and returns 1 when a finding is
// at or above the threshold.
func gateTarget(cmd *cobra.Command, target string) (int, error) {
	if !slices.Contains(gateFormats, outputFormat) {
		return 0, fmt.Errorf("gate prints text, json or sarif, not %q; for a CBOM, use cryptoscan cbom", outputFormat)
	}
	given := ""
	if cmd.Flags().Changed("fail-on") {
		given = gateFailOn
	}
	results, threshold, err := scanPipeline(cmd, target, pipelineOptions{
		failOn:  given,
		formats: gateFormats,
	})
	if err != nil {
		return 0, err
	}
	if threshold == "" {
		threshold = defaultGateFailOn
	}
	return exitCode(results, threshold, true), nil
}
