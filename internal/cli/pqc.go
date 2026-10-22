// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/csnp/cryptoscan/pkg/reporter"
	"github.com/csnp/cryptoscan/pkg/scanner"
)

// pqcFormats are the views pqc prints.
var pqcFormats = []string{"text", "json"}

var pqcCmd = &cobra.Command{
	Use:   "pqc [path or URL]",
	Short: "Show post-quantum readiness: PQC and hybrid usage found, quantum-vulnerable usage, and the QRAMM Dimension 1 levels",
	Long: `Show how far a local directory or Git repository has moved to
post-quantum cryptography.

The view lists, in this order:
  - Post-quantum algorithms found: ML-KEM, ML-DSA, SLH-DSA, FN-DSA, XMSS,
    LMS and post-quantum library imports, each with a count and up to three
    file:line locations
  - Hybrid constructions found, such as X25519 combined with ML-KEM
  - Quantum-vulnerable algorithms, each with a count
  - The migration readiness score and the QRAMM Dimension 1 practice levels,
    as the scan report prints them

pqc always includes the SHA-2 and AES findings, classed PARTIAL, that scan
leaves out unless you pass --include-quantum-safe. Its score counts them, so
it can differ from the score a default scan prints.

A readiness view is information, not a verdict, so pqc exits 0 whatever it
finds. It exits non-zero only when the scan fails. A baseline or minimum
severity set in a config file does not filter the view; ignore rules still
apply. To fail a build on findings, use cryptoscan gate.

Examples:
  cryptoscan pqc .
  cryptoscan pqc . --format json
  cryptoscan pqc https://github.com/org/repo
  cryptoscan pqc . --exclude "test/*"`,
	Args: cobra.ExactArgs(1),
	RunE: runPqc,
}

func init() {
	// Each flag is bound to the variable scan uses for it, with the same
	// default, so the pipeline reads it unchanged.
	pqcCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text, json")
	pqcCmd.Flags().StringVarP(&includeGlobs, "include", "i", "", "File patterns to include (comma-separated)")
	pqcCmd.Flags().StringVarP(&excludeGlobs, "exclude", "e", "", "File patterns to exclude (comma-separated)")
	pqcCmd.Flags().StringVar(&ignorePatterns, "ignore", "", "Pattern IDs to ignore (comma-separated, e.g., \"RSA-001,CERT-*\")")
	pqcCmd.Flags().StringVar(&configFile, "config", "", "Config file path (default: auto-detect .cryptoscan.yaml)")
	pqcCmd.Flags().BoolVar(&includeSkipped, "include-skipped", false, includeSkippedUsage)
	pqcCmd.Flags().BoolVar(&includeReports, "include-reports", false, includeReportsUsage)
	pqcCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
}

func runPqc(cmd *cobra.Command, args []string) error {
	return exitWith(pqcTarget(cmd, args[0]))
}

// pqcTarget prints the post-quantum readiness view for target and returns
// the exit code, which is 0 unless the scan fails.
func pqcTarget(cmd *cobra.Command, target string) (int, error) {
	if !slices.Contains(pqcFormats, outputFormat) {
		return 0, fmt.Errorf("pqc prints text or json, not %q; for other formats, use cryptoscan scan", outputFormat)
	}
	results, _, err := scanPipeline(cmd, target, pipelineOptions{
		formats:     pqcFormats,
		inventory:   true,
		quantumSafe: true,
		view:        pqcView,
	})
	if err != nil {
		return 0, err
	}
	return exitCode(results, "", false), nil
}

// pqcView builds the pqc report for format, which is text or json.
func pqcView(format string) reporter.Reporter {
	if format == "json" {
		return pqcJSONReporter{}
	}
	return reporter.NewPQCReporter(!noColor)
}

// pqcJSONReporter writes the pqc view as JSON: the tool, the filesScanned
// count and the migration score object scan reports, and the post-quantum and
// hybrid findings. filesScanned is 0 when the scan read no files, which the
// text view reports as nothing checked.
type pqcJSONReporter struct{}

func (pqcJSONReporter) Generate(results *scanner.Results) (string, error) {
	data, err := json.Marshal(struct {
		Tool           scanner.ToolInfo        `json:"tool"`
		FilesScanned   int                     `json:"filesScanned"`
		MigrationScore *scanner.MigrationScore `json:"migrationScore"`
		PQCFindings    []scanner.Finding       `json:"pqcFindings"`
	}{
		Tool:           results.Tool,
		FilesScanned:   results.FilesScanned,
		MigrationScore: results.MigrationScore,
		PQCFindings:    reporter.PQCFindings(results.Findings),
	})
	if err != nil {
		return "", err
	}
	return string(data), nil
}
