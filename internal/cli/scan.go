// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	includeNarrative   bool
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
  - Asymmetric algorithms: RSA, ECDSA, Ed25519, ECDH (the elliptic-curve
    ones are reported as ECC)
  - Symmetric algorithms: AES, DES, 3DES, Blowfish, ChaCha20, RC4
  - Hash functions: MD5, SHA-1, SHA-2, SHA-3
  - Key sizes and configurations
  - TLS/SSL settings
  - Crypto library imports

Quantum-safe algorithms, including AES and the SHA-2 family, are detected but
withheld from the default report because they need no migration. Pass
--include-quantum-safe to see them.

Not detected: DSA. Standalone DSA key generation is not matched by any
pattern, so a codebase using it will not be told that it is quantum
vulnerable. Detection is matched on whole words, so a compound identifier
such as RSAPrivateKey or AESCipher is not matched either.

Output formats:
  - text:  Human-readable console output (default)
  - json:  JSON format for programmatic processing
  - sarif: SARIF format for security tool integration
  - cbom:  Cryptographic Bill of Materials

CI/CD Integration:
  --ignore              Suppress specific pattern IDs (e.g., "RSA-001,CERT-*")
  --ignore-category     Suppress entire categories (e.g., "Certificate,Library Import")
  --fail-on             Exit non-zero if findings at this severity or higher,
                        or if any file could not be analyzed
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
	scanCmd.Flags().IntVarP(&maxDepth, "max-depth", "d", 0, "Maximum directory depth (0 = unlimited). NOT YET IMPLEMENTED: the value is accepted and ignored")
	scanCmd.Flags().BoolVarP(&showProgress, "progress", "p", false, "Show scan progress")
	scanCmd.Flags().StringVar(&minSeverity, "min-severity", "info", "Minimum severity to report: info, low, medium, high, critical")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	scanCmd.Flags().BoolVar(&jsonPretty, "pretty", false, "Pretty print JSON output")
	scanCmd.Flags().BoolVar(&scanGitHistory, "git-history", false, "Scan Git history (slower). NOT YET IMPLEMENTED: only the working tree is scanned")
	scanCmd.Flags().StringVarP(&groupBy, "group-by", "g", "", "Group output by: file. NOT YET IMPLEMENTED: severity, category and quantum are accepted and ignored")
	scanCmd.Flags().IntVarP(&contextLines, "context", "c", 3, "Number of context lines to show around findings. NOT YET IMPLEMENTED: the report always shows 3")
	scanCmd.Flags().BoolVar(&streamFindings, "stream", true, "Show findings as they are discovered")
	scanCmd.Flags().BoolVar(&includeImports, "include-imports", false, "Include library import findings (normally suppressed as low-value)")
	scanCmd.Flags().BoolVar(&includeQuantumSafe, "include-quantum-safe", false, "Include quantum-safe algorithm findings (SHA-256, AES-256)")
	scanCmd.Flags().BoolVar(&includeNarrative, "include-narrative", false, "Include algorithms named in prose, log messages, documentation and config keys")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show all findings including imports, quantum-safe algorithms and narrative mentions")

	// CI/CD flexibility flags
	scanCmd.Flags().StringVar(&ignorePatterns, "ignore", "", "Pattern IDs to ignore (comma-separated, e.g., \"RSA-001,CERT-*\")")
	scanCmd.Flags().StringVar(&ignoreCategories, "ignore-category", "", "Categories to ignore (comma-separated, e.g., \"Certificate,Library Import\")")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "Exit non-zero if findings at this severity or higher (info, low, medium, high, critical), or if any file could not be analyzed")
	scanCmd.Flags().StringVar(&baselineFile, "baseline", "", "Baseline JSON file - only report new findings")
	scanCmd.Flags().StringVar(&configFile, "config", "", "Config file path (default: auto-detect .cryptoscan.yaml)")
}

func runScan(cmd *cobra.Command, args []string) error {
	return exitWith(scanTarget(cmd, args[0]))
}

// scanTarget runs the scan command and returns the exit code it ends with.
func scanTarget(cmd *cobra.Command, target string) (int, error) {
	results, threshold, err := scanPipeline(cmd, target, pipelineOptions{failOn: failOn})
	if err != nil {
		return 0, err
	}
	return exitCode(results, threshold, true), nil
}

// pipelineOptions is what a command presets before the scan pipeline runs.
// scan, cbom and gate are one pipeline with three entry points; they differ
// only in these fields and in the flags they offer.
type pipelineOptions struct {
	// failOn is the threshold given on the command line, or empty when none
	// was given. A failOn in the config file applies only when it is empty.
	failOn string
	// formats lists the output formats the command writes. A config file
	// format outside it is ignored. Nil accepts every format.
	formats []string
	// inventory marks a report that lists everything found. A baseline or a
	// minimum severity from the config file does not filter it.
	inventory bool
	// quantumSafe includes the quantum-safe findings whatever
	// --include-quantum-safe says.
	quantumSafe bool
	// view, when set, builds the report for the output format in place of the
	// scan reports. A view is printed alone: no banner, and no findings
	// streamed while the scan runs.
	view func(format string) reporter.Reporter
}

// scanPipeline scans target, writes the report, and returns the results with
// the fail-on threshold that the command line and config file settled on.
func scanPipeline(cmd *cobra.Command, target string, opts pipelineOptions) (*scanner.Results, string, error) {
	// Cobra has parsed the arguments and flags by the time RunE runs, so an
	// error from here on is a runtime failure. The usage block would bury the
	// message and does not help fix it.
	cmd.SilenceUsage = true

	// Disable colour when the output is not a terminal, so that redirecting to
	// a file or piping into another tool produces clean text rather than ANSI
	// escape sequences. An explicit --no-color still wins, and NO_COLOR is
	// honoured per https://no-color.org.
	if !cmd.Flags().Changed("no-color") {
		if os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stdout) {
			noColor = true
		}
	}

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
			return nil, "", withHint(fmt.Errorf("failed to load config file %s: %w", cfgPath, err),
				"Check the --config path, or leave out --config to look for .cryptoscan.yaml automatically.")
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
	effectiveFailOn := opts.failOn
	effectiveBaseline := baselineFile
	if cfgFile != nil {
		// Add config file ignore patterns (CLI patterns take precedence)
		ignoreIDs = append(ignoreIDs, cfgFile.Ignore.Patterns...)
		ignoreCats = append(ignoreCats, cfgFile.Ignore.Categories...)
		excludes = append(excludes, cfgFile.Ignore.Files...)

		// Use config file settings if CLI flags not set
		if effectiveMinSeverity == "info" && cfgFile.MinSeverity != "" && !opts.inventory {
			effectiveMinSeverity = cfgFile.MinSeverity
		}
		if effectiveFailOn == "" && cfgFile.FailOn != "" {
			effectiveFailOn = cfgFile.FailOn
		}
		if effectiveBaseline == "" && cfgFile.Baseline != "" && !opts.inventory {
			effectiveBaseline = cfgFile.Baseline
		}
		if outputFormat == "text" && cfgFile.Format != "" &&
			(opts.formats == nil || slices.Contains(opts.formats, cfgFile.Format)) {
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
		IncludeImports:     includeImports || verbose,                         // Include if explicitly set or verbose mode
		IncludeQuantumSafe: includeQuantumSafe || verbose || opts.quantumSafe, // Include if explicitly set, verbose mode, or forced by the command
		IncludeNarrative:   includeNarrative || verbose,                       // Include if explicitly set or verbose mode
		IgnoreIDs:          ignoreIDs,
		IgnoreCategories:   ignoreCats,
	}

	// The banner and streamed findings belong to the scan's text report, not
	// to a view.
	textReport := outputFormat == "text" && opts.view == nil

	// Setup streaming output for text format (thread-safe for parallel scanning)
	findingCount := 0
	fileCount := 0
	var outputMu sync.Mutex
	if streamFindings && textReport {
		cfg.OnFinding = func(f scanner.Finding) {
			outputMu.Lock()
			findingCount++
			num := findingCount
			// Clear the progress line before printing finding
			clearProgressLine()
			printStreamFinding(f, num, !noColor)
			outputMu.Unlock()
		}
		cfg.OnFileScanned = func(path string) {
			outputMu.Lock()
			fileCount++
			count := fileCount
			outputMu.Unlock()
			// Show progress every 50 files (less frequent for parallel scanning)
			// The progress line rewrites itself in place, which only makes
			// sense on a terminal. Piped output would otherwise collect a
			// carriage return and an erase-line sequence per update.
			if count%50 == 0 && !noColor {
				shortPath := path
				if len(shortPath) > 50 {
					shortPath = "..." + shortPath[len(shortPath)-47:]
				}
				outputMu.Lock()
				fmt.Printf("\r\033[K  \033[2m%d files scanned | %s\033[0m", count, shortPath)
				outputMu.Unlock()
			}
		}
	}

	// Resolve target path
	if !isURL(target) {
		absPath, err := filepath.Abs(target)
		if err != nil {
			return nil, "", fmt.Errorf("invalid path: %w", err)
		}
		cfg.Target = absPath
	}

	// Print banner
	if textReport && !noColor {
		printBanner()
	}

	// Print streaming header
	if streamFindings && textReport {
		printScanningHeader(!noColor)
	}

	// Run scanner
	startTime := time.Now()
	s := scanner.New(cfg)
	results, err := s.Scan()
	if err != nil {
		return nil, "", withHint(fmt.Errorf("scan failed: %w", err), scanErrorHint(err))
	}
	duration := time.Since(startTime)

	// Print streaming footer with summary
	if streamFindings && textReport {
		// Clear any remaining progress line
		clearProgressLine()
		printScanningFooter(findingCount, fileCount, duration, !noColor)
	}

	// Apply baseline comparison if specified
	if effectiveBaseline != "" {
		baseline, err := loadBaseline(effectiveBaseline)
		if err != nil {
			return nil, "", withHint(fmt.Errorf("failed to load baseline: %w", err),
				"Check the --baseline path. To create a baseline: cryptoscan scan . --format json --output baseline.json")
		}
		results.Findings = filterNewFindings(results.Findings, results.Metadata[scanner.MetadataScanRoot], baseline)
		// Recalculate summary and migration score after filtering
		results.Summary = calculateSummary(results.Findings)
		results.MigrationScore = analyzer.CalculateMigrationScore(results.Findings)
	}

	// Create reporter
	var rep reporter.Reporter
	switch {
	case opts.view != nil:
		rep = opts.view(outputFormat)
	case outputFormat == "json":
		rep = reporter.NewJSONReporter(jsonPretty)
	case outputFormat == "csv":
		rep = reporter.NewCSVReporter()
	case outputFormat == "sarif":
		rep = reporter.NewSARIFReporter()
	case outputFormat == "cbom":
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
		return nil, "", fmt.Errorf("failed to generate report: %w", err)
	}

	// Output
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(report), 0644); err != nil {
			return nil, "", withHint(fmt.Errorf("failed to write output: %w", err),
				"Check that the folder for --output exists and that you can write to it.")
		}
		if outputFormat == "text" {
			fmt.Printf("\nReport written to: %s\n", outputFile)
		}
	} else {
		fmt.Println(report)
	}

	writeUnanalyzedNotice(os.Stderr, outputFormat, results.UnanalyzedFiles)

	return results, effectiveFailOn, nil
}

// exitCode decides the code a command ends with once its report is written.
// When gateFindings is false the report is an inventory, not a verdict, and
// the code is 0 whatever was found. Otherwise the code is 1 when a finding is
// at or above failOn; with failOn empty, only a CRITICAL finding fails.
func exitCode(results *scanner.Results, failOn string, gateFindings bool) int {
	if !gateFindings {
		return 0
	}
	// With --fail-on set, the run also fails when any file could not be
	// analyzed: that file is a coverage gap, and a gate that passes over it
	// would be passing on a partial scan.
	if failOn != "" {
		if results.HasFindingsAtOrAbove(parseSeverity(failOn)) || len(results.UnanalyzedFiles) > 0 {
			return 1
		}
		return 0
	}
	if results.HasCritical() {
		return 1
	}
	return 0
}

// exitWith ends the process with code once a command has finished. Commands
// return their code instead of exiting, so tests can check the decision.
func exitWith(code int, err error) error {
	if err != nil {
		return err
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

// writeUnanalyzedNotice names the files the scanner could not analyze. The
// text report lists them itself. CSV and CBOM have no place for them, and a
// JSON or SARIF report written to a file is not read on the console, so every
// other format gets the list on w.
func writeUnanalyzedNotice(w io.Writer, format string, files []scanner.UnanalyzedFile) {
	if format == "text" || len(files) == 0 {
		return
	}
	fmt.Fprintf(w, "cryptoscan: %d file(s) could not be analyzed, so findings for them may be incomplete:\n", len(files))
	for _, u := range files {
		location := u.File
		if u.Line > 0 {
			location = fmt.Sprintf("%s:%d", u.File, u.Line)
		}
		fmt.Fprintf(w, "  %s  %s\n", location, u.Reason)
	}
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
	fmt.Println(colorBlue + "  Crypto Scan: QRAMM Cryptographic Discovery" + colorReset)
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

// scanErrorHint names the next step for a scan that could not run, or returns
// "" when there is no specific step to suggest.
func scanErrorHint(err error) string {
	switch {
	case errors.Is(err, scanner.ErrCloneFailed):
		return "Check the URL. For a private repository, check that git clone works for it in this shell, or clone it yourself and scan the local folder."
	case errors.Is(err, exec.ErrNotFound):
		return "Install git, or clone the repository yourself and scan the local folder."
	case errors.Is(err, fs.ErrNotExist):
		return "Check the path, or pass a repository URL such as https://github.com/org/repo."
	case errors.Is(err, fs.ErrPermission):
		return "Check that you have permission to read the path."
	}
	return ""
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
		fmt.Printf("%s%s  \u2713 Scan complete%s: %d findings in %d files (%s)\n\n",
			colorGreen, colorBold, colorReset, findingCount, fileCount, duration.Round(time.Millisecond))
	} else {
		fmt.Printf("  Scan complete: %d findings in %d files (%s)\n\n", findingCount, fileCount, duration.Round(time.Millisecond))
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
		sevIcon, sevColor = "●", colorRed+colorBold
	case scanner.SeverityHigh:
		sevIcon, sevColor = "●", colorRed
	case scanner.SeverityMedium:
		sevIcon, sevColor = "●", colorYellow
	case scanner.SeverityLow:
		sevIcon, sevColor = "●", colorBlue
	default:
		sevIcon, sevColor = "●", colorCyan
	}

	// Quantum risk indicator
	var qIcon string
	switch f.Quantum {
	case scanner.QuantumVulnerable:
		qIcon = "[!]"
	case scanner.QuantumPartial:
		qIcon = "[~]"
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

// clearProgressLine erases the in-place progress line. It is a no-op when
// colour is off, since a redirected stream has no cursor to move.
func clearProgressLine() {
	if noColor {
		return
	}
	fmt.Print("\r\033[K")
}

// isTerminal reports whether f is attached to a terminal. A redirected or
// piped stream is a character device only when it is a terminal, so this
// distinguishes interactive output from output being captured.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
