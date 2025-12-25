// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/csnp/qramm-cryptoscan/pkg/reporter"
	"github.com/csnp/qramm-cryptoscan/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	outputFormat  string
	outputFile    string
	includeGlobs  string
	excludeGlobs  string
	maxDepth      int
	showProgress  bool
	minSeverity   string
	noColor       bool
	jsonPretty    bool
	scanGitHistory bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path or URL]",
	Short: "Scan a directory or repository for cryptographic usage",
	Long: `Scan a local directory or Git repository for cryptographic patterns.

The scanner detects:
  - Asymmetric algorithms: RSA, DSA, ECDSA, Ed25519, DH, ECDH
  - Symmetric algorithms: AES, DES, 3DES, Blowfish, ChaCha20, RC4
  - Hash functions: MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA-3
  - Key sizes and configurations
  - TLS/SSL settings
  - Crypto library imports

Output formats:
  - text:  Human-readable console output (default)
  - json:  JSON format for programmatic processing
  - sarif: SARIF format for security tool integration
  - cbom:  Cryptographic Bill of Materials

Examples:
  cryptoscan scan .
  cryptoscan scan /path/to/project
  cryptoscan scan https://github.com/org/repo
  cryptoscan scan . --format json --output findings.json
  cryptoscan scan . --include "*.java,*.py" --exclude "vendor/*,test/*"`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text, json, csv, sarif, cbom")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	scanCmd.Flags().StringVarP(&includeGlobs, "include", "i", "", "File patterns to include (comma-separated)")
	scanCmd.Flags().StringVarP(&excludeGlobs, "exclude", "e", "", "File patterns to exclude (comma-separated)")
	scanCmd.Flags().IntVarP(&maxDepth, "max-depth", "d", 0, "Maximum directory depth (0 = unlimited)")
	scanCmd.Flags().BoolVarP(&showProgress, "progress", "p", false, "Show scan progress")
	scanCmd.Flags().StringVar(&minSeverity, "min-severity", "info", "Minimum severity to report: info, low, medium, high, critical")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	scanCmd.Flags().BoolVar(&jsonPretty, "pretty", false, "Pretty print JSON output")
	scanCmd.Flags().BoolVar(&scanGitHistory, "git-history", false, "Scan Git history (slower)")
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Parse include/exclude patterns
	var includes, excludes []string
	if includeGlobs != "" {
		includes = strings.Split(includeGlobs, ",")
		for i := range includes {
			includes[i] = strings.TrimSpace(includes[i])
		}
	}
	if excludeGlobs != "" {
		excludes = strings.Split(excludeGlobs, ",")
		for i := range excludes {
			excludes[i] = strings.TrimSpace(excludes[i])
		}
	}

	// Add default excludes
	defaultExcludes := []string{
		".git/*", ".svn/*", ".hg/*",
		"node_modules/*", "vendor/*", "venv/*", ".venv/*",
		"__pycache__/*", "*.pyc",
		"dist/*", "build/*", "target/*",
		"*.min.js", "*.min.css",
		"*.lock", "package-lock.json", "yarn.lock",
	}
	excludes = append(excludes, defaultExcludes...)

	// Create scanner config
	cfg := scanner.Config{
		Target:         target,
		IncludeGlobs:   includes,
		ExcludeGlobs:   excludes,
		MaxDepth:       maxDepth,
		ShowProgress:   showProgress,
		ScanGitHistory: scanGitHistory,
		MinSeverity:    parseSeverity(minSeverity),
	}

	// Resolve target path
	if !isURL(target) {
		absPath, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}
		cfg.Target = absPath
	}

	// Print banner
	if outputFormat == "text" && !noColor {
		printBanner()
	}

	// Run scanner
	startTime := time.Now()
	s := scanner.New(cfg)
	results, err := s.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	duration := time.Since(startTime)

	// Create reporter
	var rep reporter.Reporter
	switch outputFormat {
	case "json":
		rep = reporter.NewJSONReporter(jsonPretty)
	case "csv":
		rep = reporter.NewCSVReporter()
	case "sarif":
		rep = reporter.NewSARIFReporter()
	case "cbom":
		rep = reporter.NewCBOMReporter()
	default:
		rep = reporter.NewTextReporter(!noColor)
	}

	// Add metadata
	results.ScanDuration = duration
	results.ScanTarget = target
	results.ScanTime = startTime

	// Generate report
	report, err := rep.Generate(results)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Output
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(report), 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		if outputFormat == "text" {
			fmt.Printf("\nReport written to: %s\n", outputFile)
		}
	} else {
		fmt.Println(report)
	}

	// Exit with non-zero if critical findings
	if results.HasCritical() {
		os.Exit(1)
	}

	return nil
}

func printBanner() {
	const (
		colorCyan   = "\033[36m"
		colorBlue   = "\033[34m"
		colorGreen  = "\033[32m"
		colorYellow = "\033[33m"
		colorReset  = "\033[0m"
		colorBold   = "\033[1m"
		colorDim    = "\033[2m"
	)

	fmt.Println()
	fmt.Println(colorCyan + colorBold + "  ╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("  ║                                                                 ║")
	fmt.Println("  ║   ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ███████╗   ║")
	fmt.Println("  ║  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██╔════╝   ║")
	fmt.Println("  ║  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║███████╗   ║")
	fmt.Println("  ║  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║╚════██║   ║")
	fmt.Println("  ║  ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝███████║   ║")
	fmt.Println("  ║   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚══════╝   ║")
	fmt.Println("  ║                     ███████╗ ██████╗ █████╗ ███╗   ██╗         ║")
	fmt.Println("  ║                     ██╔════╝██╔════╝██╔══██╗████╗  ██║         ║")
	fmt.Println("  ║                     ███████╗██║     ███████║██╔██╗ ██║         ║")
	fmt.Println("  ║                     ╚════██║██║     ██╔══██║██║╚██╗██║         ║")
	fmt.Println("  ║                     ███████║╚██████╗██║  ██║██║ ╚████║         ║")
	fmt.Println("  ║                     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝         ║")
	fmt.Println("  ║                                                                 ║")
	fmt.Println("  ╚═══════════════════════════════════════════════════════════════╝" + colorReset)
	fmt.Println()
	fmt.Println(colorBlue + "  QRAMM Cryptographic Discovery Scanner" + colorReset)
	fmt.Println(colorDim + "  Quantum Readiness Assurance & Migration Tool" + colorReset)
	fmt.Println()
	fmt.Println(colorGreen + "  ┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("  │" + colorReset + colorBold + "  CSNP Mission:" + colorReset + colorGreen + "                                               │")
	fmt.Println("  │" + colorReset + "  Advancing cybersecurity through education, research, and    " + colorGreen + "│")
	fmt.Println("  │" + colorReset + "  open-source tools that empower organizations worldwide.     " + colorGreen + "│")
	fmt.Println("  └─────────────────────────────────────────────────────────────┘" + colorReset)
	fmt.Println()
	fmt.Println(colorDim + "  https://qramm.org  •  https://csnp.org  •  Apache-2.0 License" + colorReset)
	fmt.Println()
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "git@")
}

func parseSeverity(s string) scanner.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return scanner.SeverityCritical
	case "high":
		return scanner.SeverityHigh
	case "medium":
		return scanner.SeverityMedium
	case "low":
		return scanner.SeverityLow
	default:
		return scanner.SeverityInfo
	}
}
