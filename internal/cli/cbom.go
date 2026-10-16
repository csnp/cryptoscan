// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/spf13/cobra"
)

var cbomCmd = &cobra.Command{
	Use:   "cbom [path or URL]",
	Short: "Write a CycloneDX 1.6 Cryptographic Bill of Materials (equivalent to scan --format cbom)",
	Long: `Write a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) for a local
directory or Git repository.

This runs the same scan as "cryptoscan scan --format cbom", with the format
fixed. The CBOM is written as JSON to standard output, or to the file named
by --output, and nothing else is printed to standard output.

A CBOM is an inventory, not a verdict, so cbom exits 0 whatever it finds. It
exits non-zero only when the scan or the write fails. A baseline or minimum
severity set in a config file does not filter the CBOM; ignore rules still
apply. To fail a build on findings, use cryptoscan gate.

Examples:
  cryptoscan cbom .
  cryptoscan cbom . -o crypto-bom.json
  cryptoscan cbom https://github.com/org/repo -o crypto-bom.json
  cryptoscan cbom . --exclude "test/*" --ignore-category "Library Import"`,
	Args: cobra.ExactArgs(1),
	RunE: runCbom,
}

func init() {
	// Each flag is bound to the variable scan uses for it, with the same
	// default, so the pipeline reads it unchanged.
	cbomCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	cbomCmd.Flags().StringVarP(&includeGlobs, "include", "i", "", "File patterns to include (comma-separated)")
	cbomCmd.Flags().StringVarP(&excludeGlobs, "exclude", "e", "", "File patterns to exclude (comma-separated)")
	cbomCmd.Flags().StringVar(&ignorePatterns, "ignore", "", "Pattern IDs to ignore (comma-separated, e.g., \"RSA-001,CERT-*\")")
	cbomCmd.Flags().StringVar(&ignoreCategories, "ignore-category", "", "Categories to ignore (comma-separated, e.g., \"Certificate,Library Import\")")
	cbomCmd.Flags().StringVar(&configFile, "config", "", "Config file path (default: auto-detect .cryptoscan.yaml)")
}

func runCbom(cmd *cobra.Command, args []string) error {
	return exitWith(cbomTarget(cmd, args[0]))
}

// cbomTarget writes the CBOM for target and returns the exit code, which is
// 0 unless the scan or the write fails.
func cbomTarget(cmd *cobra.Command, target string) (int, error) {
	outputFormat = "cbom"
	results, _, err := scanPipeline(cmd, target, pipelineOptions{
		formats:   []string{"cbom"},
		inventory: true,
	})
	if err != nil {
		return 0, err
	}
	return exitCode(results, "", false), nil
}
