// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/config"
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

	// CI/CD flexibility flags
	ignorePatterns   string // --ignore "RSA-001,DES-001"
	ignoreCategories string // --ignore-category "Certificate"
	failOn           string // --fail-on "high"
	baselineFile     string // --baseline "baseline.json"
	configFile       string // --config ".cryptoscan.yaml"
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

CI/CD Integration:
  --ignore              Suppress specific pattern IDs (e.g., "RSA-001,CERT-*")
  --ignore-category     Suppress entire categories (e.g., "Certificate,Library Import")
  --fail-on             Exit non-zero if findings at this severity or higher
  --baseline            Only report new findings compared to baseline JSON
  --config              Path to .cryptoscan.yaml config file

Inline Suppression:
  // cryptoscan:ignore                  Ignore all findings on this line
  // cryptoscan:ignore RSA-001          Ignore specific pattern
  // cryptoscan:ignore RSA-*            Ignore pattern family

Examples:
  cryptoscan scan .
  cryptoscan scan /path/to/project
  cryptoscan scan https://github.com/org/repo
  cryptoscan scan . --format json --output findings.json
  cryptoscan scan . --include "*.java,*.py" --exclude "vendor/*,test/*"

  # CI/CD examples
  cryptoscan scan . --ignore "RSA-001,CERT-SELFSIGNED-001"
  cryptoscan scan . --ignore-category "Certificate,Library Import"
  cryptoscan scan . --fail-on high  # Exit 1 if HIGH or CRITICAL findings
  cryptoscan scan . --baseline baseline.json  # Only show new findings`,
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

	// CI/CD flexibility flags
	scanCmd.Flags().StringVar(&ignorePatterns, "ignore", "", "Pattern IDs to ignore (comma-separated, e.g., \"RSA-001,CERT-*\")")
	scanCmd.Flags().StringVar(&ignoreCategories, "ignore-category", "", "Categories to ignore (comma-separated, e.g., \"Certificate,Library Import\")")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "Exit non-zero if findings at this severity or higher (info, low, medium, high, critical)")
	scanCmd.Flags().StringVar(&baselineFile, "baseline", "", "Baseline JSON file - only report new findings")
	scanCmd.Flags().StringVar(&configFile, "config", "", "Config file path (default: auto-detect .cryptoscan.yaml)")
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Load config file (explicit or auto-detected)
	var cfgFile *config.Config
	cfgPath := configFile
	if cfgPath == "" {
		// Auto-detect config file starting from target directory
		startDir := target
		if isURL(target) {
			startDir = "."
		}
		if absPath, err := filepath.Abs(startDir); err == nil {
			cfgPath = config.FindConfigFile(absPath)
		}
	}
	if cfgPath != "" {
		if loaded, err := config.Load(cfgPath); err == nil {
			cfgFile = loaded
		} else if configFile != "" {
			// Only error if explicitly specified
			return fmt.Errorf("failed to load config file %s: %w", cfgPath, err)
		}
	}

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

	// Parse ignore patterns from CLI flags
	var ignoreIDs, ignoreCats []string
	if ignorePatterns != "" {
		for _, p := range strings.Split(ignorePatterns, ",") {
			if p = strings.TrimSpace(p); p != "" {
				ignoreIDs = append(ignoreIDs, p)
			}
		}
	}
	if ignoreCategories != "" {
		for _, c := range strings.Split(ignoreCategories, ",") {
			if c = strings.TrimSpace(c); c != "" {
				ignoreCats = append(ignoreCats, c)
			}
		}
	}

	// Merge config file settings (CLI flags take precedence)
	effectiveMinSeverity := minSeverity
	effectiveFailOn := failOn
	effectiveBaseline := baselineFile
	if cfgFile != nil {
		// Add config file ignore patterns (CLI patterns take precedence)
		ignoreIDs = append(ignoreIDs, cfgFile.Ignore.Patterns...)
		ignoreCats = append(ignoreCats, cfgFile.Ignore.Categories...)
		excludes = append(excludes, cfgFile.Ignore.Files...)

		// Use config file settings if CLI flags not set
		if effectiveMinSeverity == "info" && cfgFile.MinSeverity != "" {
			effectiveMinSeverity = cfgFile.MinSeverity
		}
		if effectiveFailOn == "" && cfgFile.FailOn != "" {
			effectiveFailOn = cfgFile.FailOn
		}
		if effectiveBaseline == "" && cfgFile.Baseline != "" {
			effectiveBaseline = cfgFile.Baseline
		}
		if outputFormat == "text" && cfgFile.Format != "" {
			outputFormat = cfgFile.Format
		}
	}

	// Create scanner config
	cfg := scanner.Config{
		Target:             target,
		IncludeGlobs:       includes,
		ExcludeGlobs:       excludes,
		MaxDepth:           maxDepth,
		ShowProgress:       showProgress,
		ScanGitHistory:     scanGitHistory,
		MinSeverity:        parseSeverity(effectiveMinSeverity),
		IncludeImports:     includeImports || verbose,     // Include if explicitly set or verbose mode
		IncludeQuantumSafe: includeQuantumSafe || verbose, // Include if explicitly set or verbose mode
		IgnoreIDs:          ignoreIDs,
		IgnoreCategories:   ignoreCats,
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

	// Apply baseline comparison if specified
	if effectiveBaseline != "" {
		baseline, err := loadBaseline(effectiveBaseline)
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}
		results.Findings = filterNewFindings(results.Findings, baseline)
		// Recalculate summary and migration score after filtering
		results.Summary = calculateSummary(results.Findings)
		results.MigrationScore = analyzer.CalculateMigrationScore(results.Findings)
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

	// Exit code control based on --fail-on flag
	if effectiveFailOn != "" {
		failSeverity := parseSeverity(effectiveFailOn)
		if results.HasFindingsAtOrAbove(failSeverity) {
			os.Exit(1)
		}
	} else {
		// Default: exit non-zero only for critical findings
		if results.HasCritical() {
			os.Exit(1)
		}
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

// baselineResults is used for loading baseline JSON files
type baselineResults struct {
	Findings []scanner.Finding `json:"findings"`
}

// loadBaseline loads a baseline JSON file containing previous scan results
func loadBaseline(path string) ([]scanner.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var results baselineResults
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}

	return results.Findings, nil
}

// filterNewFindings removes findings that already exist in the baseline
// Comparison is based on file + line + pattern ID prefix
func filterNewFindings(findings []scanner.Finding, baseline []scanner.Finding) []scanner.Finding {
	baselineSet := make(map[string]bool)
	for _, f := range baseline {
		// Key: file + line + patternID prefix (ignoring column for minor shifts)
		key := fmt.Sprintf("%s:%d:%s", f.File, f.Line, extractPatternPrefix(f.ID))
		baselineSet[key] = true
	}

	var newFindings []scanner.Finding
	for _, f := range findings {
		key := fmt.Sprintf("%s:%d:%s", f.File, f.Line, extractPatternPrefix(f.ID))
		if !baselineSet[key] {
			newFindings = append(newFindings, f)
		}
	}
	return newFindings
}

// extractPatternPrefix extracts the pattern family prefix from a finding ID
// e.g., "RSA-001-a1b2c3d4" -> "RSA-001", "CERT-SELFSIGNED-001" -> "CERT-SELFSIGNED-001"
func extractPatternPrefix(id string) string {
	// If ID contains a hash suffix (pattern-NNN-HASH), remove it
	parts := strings.Split(id, "-")
	if len(parts) >= 3 {
		// Check if last part looks like a hash (lowercase hex)
		last := parts[len(parts)-1]
		if len(last) >= 6 && isHexString(last) {
			return strings.Join(parts[:len(parts)-1], "-")
		}
	}
	return id
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// calculateSummary recalculates the summary after filtering findings
func calculateSummary(findings []scanner.Finding) scanner.Summary {
	summary := scanner.Summary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByCategory:    make(map[string]int),
		ByQuantumRisk: make(map[string]int),
		ByConfidence:  make(map[string]int),
		ByFileType:    make(map[string]int),
		ByLanguage:    make(map[string]int),
	}

	for _, f := range findings {
		summary.BySeverity[f.Severity.String()]++
		summary.ByCategory[f.Category]++
		summary.ByQuantumRisk[string(f.Quantum)]++
		summary.ByConfidence[string(f.Confidence)]++
		if f.FileType != "" {
			summary.ByFileType[f.FileType]++
		}
		if f.Language != "" {
			summary.ByLanguage[f.Language]++
		}

		if f.Quantum == scanner.QuantumVulnerable {
			summary.QuantumVulnCount++
		}
		if f.Confidence == "HIGH" {
			summary.HighConfidence++
		}
		if f.Confidence == "HIGH" && f.FileType == "code" {
			summary.ActionableCount++
		}
	}

	return summary
}
