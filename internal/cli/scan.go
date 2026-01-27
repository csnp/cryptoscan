// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/csnp/cryptoscan/pkg/reporter"
	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	outputFormat       string
	outputFile         string
	includeGlobs       string
	excludeGlobs       string
	maxDepth           int
	showProgress       bool
	minSeverity        string
	noColor            bool
	jsonPretty         bool
	scanGitHistory     bool
	groupBy            string
	contextLines       int
	streamFindings     bool
	includeImports     bool
	includeQuantumSafe bool
	verbose            bool
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
	scanCmd.Flags().StringVarP(&groupBy, "group-by", "g", "", "Group output by: file, severity, category, quantum")
	scanCmd.Flags().IntVarP(&contextLines, "context", "c", 3, "Number of context lines to show around findings")
	scanCmd.Flags().BoolVar(&streamFindings, "stream", true, "Show findings as they are discovered")
	scanCmd.Flags().BoolVar(&includeImports, "include-imports", false, "Include library import findings (normally suppressed as low-value)")
	scanCmd.Flags().BoolVar(&includeQuantumSafe, "include-quantum-safe", false, "Include quantum-safe algorithm findings (SHA-256, AES-256)")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show all findings including imports and quantum-safe algorithms")
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
		Target:             target,
		IncludeGlobs:       includes,
		ExcludeGlobs:       excludes,
		MaxDepth:           maxDepth,
		ShowProgress:       showProgress,
		ScanGitHistory:     scanGitHistory,
		MinSeverity:        parseSeverity(minSeverity),
		IncludeImports:     includeImports || verbose,     // Include if explicitly set or verbose mode
		IncludeQuantumSafe: includeQuantumSafe || verbose, // Include if explicitly set or verbose mode
	}

	// Setup streaming output for text format (thread-safe for parallel scanning)
	findingCount := 0
	fileCount := 0
	var outputMu sync.Mutex
	if streamFindings && outputFormat == "text" {
		cfg.OnFinding = func(f scanner.Finding) {
			outputMu.Lock()
			findingCount++
			num := findingCount
			// Clear the progress line before printing finding
			fmt.Print("\r\033[K")
			printStreamFinding(f, num, !noColor)
			outputMu.Unlock()
		}
		cfg.OnFileScanned = func(path string) {
			outputMu.Lock()
			fileCount++
			count := fileCount
			outputMu.Unlock()
			// Show progress every 50 files (less frequent for parallel scanning)
			if count%50 == 0 {
				shortPath := path
				if len(shortPath) > 50 {
					shortPath = "..." + shortPath[len(shortPath)-47:]
				}
				outputMu.Lock()
				fmt.Printf("\r\033[K  \033[2m📂 %d files scanned | %s\033[0m", count, shortPath)
				outputMu.Unlock()
			}
		}
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

	// Print streaming header
	if streamFindings && outputFormat == "text" {
		printScanningHeader(!noColor)
	}

	// Run scanner
	startTime := time.Now()
	s := scanner.New(cfg)
	results, err := s.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	duration := time.Since(startTime)

	// Print streaming footer with summary
	if streamFindings && outputFormat == "text" {
		// Clear any remaining progress line
		fmt.Print("\r\033[K")
		printScanningFooter(findingCount, fileCount, duration, !noColor)
	}

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
		textRep := reporter.NewTextReporter(!noColor)
		textRep.SetGroupBy(groupBy)
		rep = textRep
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
	fmt.Println("  ║    ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗            ║")
	fmt.Println("  ║   ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗           ║")
	fmt.Println("  ║   ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║           ║")
	fmt.Println("  ║   ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║           ║")
	fmt.Println("  ║   ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝           ║")
	fmt.Println("  ║    ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝            ║")
	fmt.Println("  ║                                                                 ║")
	fmt.Println("  ║    ███████╗ ██████╗ █████╗ ███╗   ██╗                           ║")
	fmt.Println("  ║    ██╔════╝██╔════╝██╔══██╗████╗  ██║                           ║")
	fmt.Println("  ║    ███████╗██║     ███████║██╔██╗ ██║                           ║")
	fmt.Println("  ║    ╚════██║██║     ██╔══██║██║╚██╗██║                           ║")
	fmt.Println("  ║    ███████║╚██████╗██║  ██║██║ ╚████║                           ║")
	fmt.Println("  ║    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                           ║")
	fmt.Println("  ║                                                                 ║")
	fmt.Println("  ╚═══════════════════════════════════════════════════════════════╝" + colorReset)
	fmt.Println()
	fmt.Println(colorBlue + "  Crypto Scan — QRAMM Cryptographic Discovery" + colorReset)
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

func printScanningHeader(useColor bool) {
	const (
		colorCyan  = "\033[36m"
		colorBold  = "\033[1m"
		colorReset = "\033[0m"
		colorDim   = "\033[2m"
	)

	if useColor {
		fmt.Printf("%s%s  ⏳ Scanning...%s %s(findings appear as discovered)%s\n\n",
			colorCyan, colorBold, colorReset, colorDim, colorReset)
	} else {
		fmt.Println("  Scanning... (findings appear as discovered)")
		fmt.Println()
	}
}

func printScanningFooter(findingCount, fileCount int, duration time.Duration, useColor bool) {
	const (
		colorGreen = "\033[32m"
		colorBold  = "\033[1m"
		colorReset = "\033[0m"
		colorDim   = "\033[2m"
	)

	fmt.Println()
	if useColor {
		fmt.Printf("%s%s  ✓ Scan complete%s — %d findings in %d files (%s)\n\n",
			colorGreen, colorBold, colorReset, findingCount, fileCount, duration.Round(time.Millisecond))
	} else {
		fmt.Printf("  Scan complete — %d findings in %d files (%s)\n\n", findingCount, fileCount, duration.Round(time.Millisecond))
	}
}

// printStreamFinding prints a compact finding line during scanning
func printStreamFinding(f scanner.Finding, num int, useColor bool) {
	const (
		colorReset   = "\033[0m"
		colorRed     = "\033[31m"
		colorYellow  = "\033[33m"
		colorBlue    = "\033[34m"
		colorCyan    = "\033[36m"
		colorMagenta = "\033[35m"
		colorBold    = "\033[1m"
		colorDim     = "\033[2m"
	)

	// Severity icon and color
	var sevIcon, sevColor string
	switch f.Severity {
	case scanner.SeverityCritical:
		sevIcon, sevColor = "🔴", colorRed+colorBold
	case scanner.SeverityHigh:
		sevIcon, sevColor = "🟠", colorRed
	case scanner.SeverityMedium:
		sevIcon, sevColor = "🟡", colorYellow
	case scanner.SeverityLow:
		sevIcon, sevColor = "🔵", colorBlue
	default:
		sevIcon, sevColor = "⚪", colorCyan
	}

	// Quantum risk indicator
	var qIcon string
	switch f.Quantum {
	case scanner.QuantumVulnerable:
		qIcon = "⚠️ "
	case scanner.QuantumPartial:
		qIcon = "⚡"
	default:
		qIcon = "  "
	}

	// Truncate file path for display
	file := f.File
	if len(file) > 40 {
		file = "..." + file[len(file)-37:]
	}

	// Format output
	if useColor {
		fmt.Printf("  %s %s%-8s%s %s#%-3d%s %-22s %s%s:%d%s %s\n",
			sevIcon,
			sevColor, f.Severity.String(), colorReset,
			colorDim, num, colorReset,
			truncate(f.Type, 22),
			colorMagenta, file, f.Line, colorReset,
			qIcon)
	} else {
		fmt.Printf("  [%s] #%-3d %-22s %s:%d %s\n",
			f.Severity.String(),
			num,
			truncate(f.Type, 22),
			file, f.Line,
			qIcon)
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
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
