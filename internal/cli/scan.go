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
	"strconv"
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
	groupBy            string
	contextLines       int
	streamFindings     bool
	includeImports     bool
	includeQuantumSafe bool
	includeNarrative   bool
	includeSkipped     bool
	includeReports     bool
	verbose            bool

	// CI/CD flexibility flags
	ignorePatterns   string // --ignore "RSA-001,DES-001"
	ignoreCategories string // --ignore-category "Certificate"
	failOn           string // --fail-on "high"
	baselineFile     string // --baseline "baseline.json"
	configFile       string // --config ".cryptoscan.yaml"
	noConfig         bool   // --no-config
)

// formatNames lists the values --format accepts, severityNames the values
// --min-severity and --fail-on accept, lowest first, and groupByNames the
// values --group-by accepts. The flag help and the error for an unknown value
// are both built from these lists.
var (
	formatNames   = []string{"text", "json", "csv", "sarif", "cbom"}
	severityNames = []string{"info", "low", "medium", "high", "critical"}
	groupByNames  = []string{"file"}
)

// includeSkippedUsage is the --include-skipped help of every command that
// scans, so that the flag reads the same wherever the report suggests it.
const includeSkippedUsage = "Scan the directories left out by default, such as .git, node_modules, vendor, dist, build, examples and testdata"

// includeReportsUsage is the --include-reports help of every command that
// scans, for the same reason. The file --output names is left out for being
// that file, not for how it starts, so the flag does not read it.
const includeReportsUsage = "Scan as source the files left out because they start like a CryptoScan report"

// progressShown records whether the running scan prints the in-place
// progress line, so that the line is cleared before anything else is printed
// and only then: a stream that never carried the line has no cursor to move.
var progressShown bool

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

The report classes SHA-2 and AES as PARTIAL: a quantum computer weakens them
but does not break them, so they need no post-quantum migration. SHA-2
findings, and AES findings at INFO severity other than AES-GCM and AES-ECB,
are left out of the default report; pass --include-quantum-safe to list
them. Post-quantum algorithms such as ML-KEM are classed SAFE and are
reported without that flag.

Not detected: DSA. Standalone DSA key generation is not matched by any
pattern, so a codebase using it will not be told that it is quantum
vulnerable. Detection is matched on whole words, so a compound identifier
such as RSAPrivateKey or AESCipher is not matched either.

Output formats:
  - text:  Human-readable console output (default)
  - json:  JSON format for programmatic processing
  - csv:   Comma-separated values, one finding per row
  - sarif: SARIF format for security tool integration
  - cbom:  Cryptographic Bill of Materials

CI/CD Integration:
  --ignore              Suppress specific pattern IDs (e.g., "RSA-001,CERT-*")
  --ignore-category     Suppress entire categories (e.g., "Certificate,Library Import")
  --fail-on             Exit non-zero if findings at this severity or higher,
                        or if any file could not be analyzed. Without it,
                        the scan exits 1 when any finding is CRITICAL
  --baseline            Only report new findings compared to baseline JSON
  --config              Path to .cryptoscan.yaml config file
  --no-config           Do not read a config file; use only command-line options

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
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: "+strings.Join(formatNames, ", "))
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	scanCmd.Flags().StringVarP(&includeGlobs, "include", "i", "", "File patterns to include (comma-separated)")
	scanCmd.Flags().StringVarP(&excludeGlobs, "exclude", "e", "", "File and directory patterns to exclude (comma-separated): a pattern without / matches a name at any depth (vendor, *_test.go), a pattern ending in /* or /** skips that directory and everything in it (vendor/*), and any other pattern is matched against the path from the scan root (src/*.pb.go)")
	scanCmd.Flags().IntVarP(&maxDepth, "max-depth", "d", 0, "Maximum directory depth (0 = unlimited): 1 scans only the files directly in the target, 2 adds the files in its subdirectories, and so on")
	scanCmd.Flags().BoolVarP(&showProgress, "progress", "p", false, "Show scan progress: the number of files scanned so far, updated in place (text output on a terminal)")
	scanCmd.Flags().StringVar(&minSeverity, "min-severity", "info", "Minimum severity to report: "+strings.Join(severityNames, ", "))
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	scanCmd.Flags().BoolVar(&jsonPretty, "pretty", false, "Pretty print JSON output")
	scanCmd.Flags().StringVarP(&groupBy, "group-by", "g", "", "Group the text report by: "+strings.Join(groupByNames, ", "))
	scanCmd.Flags().IntVarP(&contextLines, "context", "c", 3, "Lines of source to show before and after each finding")
	scanCmd.Flags().BoolVar(&streamFindings, "stream", true, "Show findings as they are discovered, up to the first "+strconv.Itoa(maxStreamedMatches)+" matches")
	scanCmd.Flags().BoolVar(&includeImports, "include-imports", false, "Include library import findings (normally suppressed as low-value)")
	scanCmd.Flags().BoolVar(&includeQuantumSafe, "include-quantum-safe", false, "Include the SHA-2 and AES findings left out by default, which the report classes as PARTIAL")
	scanCmd.Flags().BoolVar(&includeNarrative, "include-narrative", false, "Include algorithms named in prose, log messages, documentation and config keys")
	scanCmd.Flags().BoolVar(&includeSkipped, "include-skipped", false, includeSkippedUsage)
	scanCmd.Flags().BoolVar(&includeReports, "include-reports", false, includeReportsUsage)
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show all findings including imports, the SHA-2 and AES findings left out by default, and narrative mentions")

	// CI/CD flexibility flags
	scanCmd.Flags().StringVar(&ignorePatterns, "ignore", "", "Pattern IDs to ignore (comma-separated, e.g., \"RSA-001,CERT-*\")")
	scanCmd.Flags().StringVar(&ignoreCategories, "ignore-category", "", "Categories to ignore (comma-separated, e.g., \"Certificate,Library Import\")")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "Exit non-zero if findings at this severity or higher ("+strings.Join(severityNames, ", ")+"), or if any file could not be analyzed. When neither this flag nor failOn in the config file is set, the scan exits 1 when any finding is CRITICAL")
	scanCmd.Flags().StringVar(&baselineFile, "baseline", "", "Baseline JSON file - only report new findings")
	scanCmd.Flags().StringVar(&configFile, "config", "", "Config file path (default: auto-detect .cryptoscan.yaml)")
	scanCmd.Flags().BoolVar(&noConfig, "no-config", false, "Do not read a config file; use only command-line options")
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

	if noConfig && configFile != "" {
		return nil, "", fmt.Errorf("--config and --no-config cannot be used together")
	}

	// Load config file (explicit or auto-detected)
	var cfgFile *config.Config
	cfgPath := configFile
	cfgSource := scanner.ConfigSourceFlag
	if cfgPath == "" && !noConfig {
		// Auto-detect config file starting from target directory
		startDir := target
		if isURL(target) {
			startDir = "."
		}
		if absPath, err := filepath.Abs(startDir); err == nil {
			cfgPath = config.FindConfigFile(absPath)
			cfgSource = autoConfigSource(cfgPath, absPath, isURL(target))
		}
	}
	if cfgPath != "" {
		if loaded, err := config.Load(cfgPath); err == nil {
			cfgFile = loaded
		} else if configFile != "" {
			// Only error if explicitly specified
			return nil, "", withHint(fmt.Errorf("failed to load config file %s: %w", cfgPath, err),
				"Check the --config path, or leave out --config to look for .cryptoscan.yaml automatically.")
		} else {
			// The user may believe this file's rules are active, so say that
			// they are not.
			fmt.Fprintf(os.Stderr, "Warning: config file %s could not be parsed and was not applied: %v\n", cfgPath, err)
		}
		if absCfg, err := filepath.Abs(cfgPath); err == nil {
			cfgPath = absCfg
		}
	}

	// Reject an unknown format or severity, from a flag or the config file,
	// before anything is scanned or printed.
	if err := checkOptionValues(cfgFile, cfgPath); err != nil {
		return nil, "", err
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

	// Merge config file settings (CLI flags take precedence). The file's
	// suppression rules go to the scanner separately from the command-line
	// ones, so that what each removes can be counted in the report.
	effectiveFailOn := opts.failOn
	effectiveBaseline := baselineFile
	baselineFromConfig := false
	var cfgRules *scanner.ConfigFileRules
	if cfgFile != nil {
		cfgRules = &scanner.ConfigFileRules{
			Path:             cfgPath,
			Source:           cfgSource,
			IgnoreIDs:        cfgFile.Ignore.Patterns,
			IgnoreCategories: cfgFile.Ignore.Categories,
			IgnoreFiles:      cfgFile.Ignore.Files,
		}

		// Use config file settings if CLI flags not set
		if minSeverity == "info" && cfgFile.MinSeverity != "" && !opts.inventory {
			sev, err := parseSeverity(cfgFile.MinSeverity)
			if err != nil {
				return nil, "", err
			}
			cfgRules.MinSeverity = sev
			cfgRules.HasMinSeverity = true
		}
		if effectiveFailOn == "" && cfgFile.FailOn != "" {
			effectiveFailOn = cfgFile.FailOn
		}
		if effectiveBaseline == "" && cfgFile.Baseline != "" && !opts.inventory {
			effectiveBaseline = cfgFile.Baseline
			baselineFromConfig = true
		}
		if outputFormat == "text" && cfgFile.Format != "" &&
			(opts.formats == nil || slices.Contains(opts.formats, cfgFile.Format)) {
			outputFormat = cfgFile.Format
		}
	}
	outputFormat = strings.ToLower(outputFormat)
	minSev, err := parseSeverity(minSeverity)
	if err != nil {
		return nil, "", err
	}
	if _, err := parseSeverity(effectiveFailOn); err != nil {
		return nil, "", err
	}

	// A repository URL can carry a user name and password for the clone. The
	// scanner is given the target as it was typed; every copy the program
	// prints or saves is shownTarget, which leaves them out.
	shownTarget := displayTarget(target)

	// Create scanner config
	cfg := scanner.Config{
		Target:             target,
		IncludeGlobs:       includes,
		ExcludeGlobs:       excludes,
		MaxDepth:           maxDepth,
		ShowProgress:       showProgress,
		ContextLines:       contextLines,
		MinSeverity:        minSev,
		IncludeImports:     includeImports || verbose,                         // Include if explicitly set or verbose mode
		IncludeQuantumSafe: includeQuantumSafe || verbose || opts.quantumSafe, // Include if explicitly set, verbose mode, or forced by the command
		IncludeNarrative:   includeNarrative || verbose,                       // Include if explicitly set or verbose mode
		IgnoreIDs:          ignoreIDs,
		IgnoreCategories:   ignoreCats,
		ConfigFile:         cfgRules,
		// The default excludes are passed apart from --exclude, so that the
		// directories they keep out are counted in the report and
		// --include-skipped can walk them.
		DefaultExcludes: scanner.DefaultExcludeGlobs,
		IncludeSkipped:  includeSkipped,
		IncludeReports:  includeReports,
	}

	// The file --output names holds an earlier report, if anything, and this
	// run replaces it, so the scan does not read it.
	cfg.ReportFile = outputFile

	// The banner and streamed findings belong to the scan's text report, not
	// to a view.
	textReport := outputFormat == "text" && opts.view == nil

	// Setup streaming output for text format (thread-safe for parallel scanning)
	listedCount := 0
	fileCount := 0
	var outputMu sync.Mutex
	if streamFindings && textReport {
		cfg.OnFinding = func(f scanner.Finding) {
			outputMu.Lock()
			listedCount++
			num := listedCount
			// Print the first matches, then one line saying the rest are in
			// the report. Listing every match put the summary below all of
			// them, however many a large tree gave. The progress line is
			// cleared before either is printed.
			switch {
			case num <= maxStreamedMatches:
				clearProgressLine()
				printStreamFinding(f, num, !noColor)
			case num == maxStreamedMatches+1:
				clearProgressLine()
				printStreamCapNotice(!noColor)
			}
			outputMu.Unlock()
		}
	}

	// The progress line rewrites itself in place, which only makes sense on
	// a terminal. Piped output would otherwise collect a carriage return and
	// an erase-line sequence per update.
	progressShown = showProgress && textReport && isTerminal(os.Stdout)
	if progressShown {
		cfg.OnFileScanned = func(path string) {
			outputMu.Lock()
			fileCount++
			count := fileCount
			outputMu.Unlock()
			// The first file shows that the scan has started; after that the
			// count is refreshed every 50 files, since the workers scan in
			// parallel and a line per file would be mostly rewriting.
			if count != 1 && count%50 != 0 {
				return
			}
			shortPath := path
			if len(shortPath) > 50 {
				shortPath = "..." + shortPath[len(shortPath)-47:]
			}
			line := fmt.Sprintf("  %d %s scanned | %s", count, plural(count, "file", "files"), shortPath)
			if !noColor {
				line = "\033[2m" + line + "\033[0m"
			}
			outputMu.Lock()
			fmt.Print("\r\033[K" + line)
			outputMu.Unlock()
		}
	}

	// Resolve target path. shownPath is cfg.Target as the program prints it.
	shownPath := shownTarget
	if !isURL(target) {
		absPath, err := filepath.Abs(target)
		if err != nil {
			return nil, "", fmt.Errorf("invalid path: %w", err)
		}
		cfg.Target = absPath
		if shownPath, err = filepath.Abs(shownTarget); err != nil {
			return nil, "", fmt.Errorf("invalid path: %w", err)
		}
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
		err = fmt.Errorf("scan failed: %w", err)
		if shownPath != cfg.Target {
			// A URL with a scheme the scanner does not clone, such as
			// ssh://, is read as a local path, and the error for that path
			// quotes it.
			err = &shownError{err: err, message: strings.ReplaceAll(err.Error(), cfg.Target, shownPath)}
		}
		return nil, "", withHint(err, scanErrorHint(err))
	}
	duration := time.Since(startTime)

	// Matches are listed as they are found, before deduplication and before
	// any baseline is applied, so the footer is printed once the report's own
	// count is known.
	uniqueCount := len(results.Findings)

	// Apply baseline comparison if specified
	if effectiveBaseline != "" {
		baseline, err := loadBaseline(effectiveBaseline)
		if err != nil {
			return nil, "", withHint(fmt.Errorf("failed to load baseline: %w", err),
				"Check the --baseline path. To create a baseline: cryptoscan scan . --format json --output baseline.json")
		}
		before := len(results.Findings)
		results.Findings = filterNewFindings(results.Findings, results.Metadata[scanner.MetadataScanRoot], baseline)
		if baselineFromConfig && results.Config != nil {
			removed := before - len(results.Findings)
			results.Config.FindingsRemoved.Baseline = removed
			results.Config.FindingsRemoved.Total += removed
		}
		// Recalculate summary and migration score after filtering
		results.Summary = calculateSummary(results.Findings)
		results.MigrationScore = analyzer.CalculateMigrationScoreForRoot(results.Findings, results.ScanRoot)
	}

	// Clear any remaining progress line before the footer or the report.
	clearProgressLine()

	// Print streaming footer with summary
	if streamFindings && textReport {
		printScanningFooter(streamTally{
			listed:   listedCount,
			hidden:   max(listedCount-maxStreamedMatches, 0),
			unique:   uniqueCount,
			reported: len(results.Findings),
			files:    results.FilesScanned,
			target:   shownTarget,
		}, duration, !noColor)
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
	case outputFormat == "text":
		textRep := reporter.NewTextReporter(!noColor)
		textRep.SetGroupBy(groupBy)
		rep = textRep
	default:
		// checkOptionValues accepts only formatNames, so this is reached only
		// when a name is added to that list without a reporter here.
		return nil, "", fmt.Errorf("no reporter for format %q", outputFormat)
	}

	// Add metadata
	results.ScanDuration = duration
	results.ScanTarget = shownTarget
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
	writeSkippedNotice(os.Stderr, outputFormat, results.SkippedFiles)
	writeSkippedDependencyNotice(os.Stderr, outputFormat, results.SkippedDependencyDirs)
	writeSkippedDirectoriesNotice(os.Stderr, outputFormat, results.Skipped)

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
		// The threshold was checked before the scan ran, so an unknown name
		// cannot reach this point.
		threshold, _ := parseSeverity(failOn)
		if results.HasFindingsAtOrAbove(threshold) || len(results.UnanalyzedFiles) > 0 {
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

// maxSkippedNamed is the number of skipped files writeSkippedNotice names.
const maxSkippedNamed = 10

// writeSkippedNotice names the files the scan left out as minified or
// generated, as dependency manifests it has no reader for, or as reports
// CryptoScan wrote, for the same formats and reasons as writeUnanalyzedNotice.
// The exit code does not depend on them. When one of them was left out for
// how it starts, the notice ends with the flag that scans it.
func writeSkippedNotice(w io.Writer, format string, files []scanner.SkippedFile) {
	if format == "text" || len(files) == 0 {
		return
	}
	fmt.Fprintf(w, "cryptoscan: %d file(s) were not scanned, so cryptography in them is not in this report:\n", len(files))
	for i, sk := range files {
		if i == maxSkippedNamed {
			fmt.Fprintf(w, "  and %d more, listed under skippedFiles in --format json\n", len(files)-maxSkippedNamed)
			break
		}
		fmt.Fprintf(w, "  %s  %s\n", sk.File, sk.Reason)
	}
	if slices.ContainsFunc(files, scanner.SkippedFile.IsRecognizedReport) {
		fmt.Fprintf(w, "cryptoscan: %s\n", reporter.IncludeReportsHint)
	}
}

// writeSkippedDependencyNotice names the node_modules directories the scan
// did not enter, for the same formats as writeUnanalyzedNotice. The text
// report lists them itself.
func writeSkippedDependencyNotice(w io.Writer, format string, dirs []string) {
	if format == "text" || len(dirs) == 0 {
		return
	}
	head := fmt.Sprintf("%d dependency directories were", len(dirs))
	if len(dirs) == 1 {
		head = "1 dependency directory was"
	}
	fmt.Fprintf(w, "cryptoscan: %s not scanned, so the packages installed there are not in this report:\n", head)
	for i, d := range dirs {
		if i == maxSkippedNamed {
			fmt.Fprintf(w, "  and %d more, listed under skippedDependencyDirs in --format json\n", len(dirs)-maxSkippedNamed)
			break
		}
		fmt.Fprintf(w, "  %s\n", d)
	}
}

// writeSkippedDirectoriesNotice says how many files the directories the
// default rules left out hold, for the same formats as writeUnanalyzedNotice.
// The text report and the pqc text view say it themselves, and the JSON
// report carries the counts as well, under skipped.
func writeSkippedDirectoriesNotice(w io.Writer, format string, skipped scanner.SkippedDirectories) {
	if format == "text" || skipped.Files == 0 {
		return
	}
	fmt.Fprintf(w, "cryptoscan: %s %s\n", reporter.SkippedDirectoriesSummary(skipped), reporter.IncludeSkippedHint)
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

// shownError is a scan error whose message quotes the target as the program
// prints it. Unwrap returns the error underneath, so scanErrorHint chooses the
// next step for it the same way.
type shownError struct {
	err     error
	message string
}

func (e *shownError) Error() string { return e.message }
func (e *shownError) Unwrap() error { return e.err }

// autoConfigSource says where an auto-detected config file was found relative
// to the scan target. The search walks up from the target, so a file in any
// directory above it applies to the scan without being part of what is
// scanned, and the report has to say so.
func autoConfigSource(cfgPath, absStart string, targetIsURL bool) string {
	switch {
	case targetIsURL:
		return scanner.ConfigSourceWorkingDirectory
	case filepath.Dir(cfgPath) == absStart:
		return scanner.ConfigSourceScanTarget
	default:
		return scanner.ConfigSourceParentDirectory
	}
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

// streamTally holds the counts the stream footer reports. The streamed list
// shows every match as it is found, which is more than the report counts:
// matches of the same category on the same line are merged into one finding,
// and a baseline removes findings that were already known.
type streamTally struct {
	listed   int    // matches found while scanning
	hidden   int    // matches found after the first maxStreamedMatches, not printed
	unique   int    // findings left after deduplication
	reported int    // findings the report counts as Total Findings
	files    int    // files scanned
	target   string // the scan target as given, named when no file was scanned
}

func printScanningFooter(tally streamTally, duration time.Duration, useColor bool) {
	const (
		colorGreen  = "\033[32m"
		colorYellow = "\033[33m"
		colorBold   = "\033[1m"
		colorReset  = "\033[0m"
		colorDim    = "\033[2m"
	)

	counts := fmt.Sprintf("%d %s in %d %s (%s)",
		tally.reported, plural(tally.reported, "finding", "findings"),
		tally.files, plural(tally.files, "file", "files"),
		duration.Round(time.Millisecond))

	fmt.Println()
	switch {
	case tally.files == 0:
		// A scan that read no files checked nothing, so it gets no check mark
		// and says so in the words the text report uses.
		nothing := reporter.NothingScanned(tally.target)
		if useColor {
			nothing = colorYellow + nothing + colorReset
		}
		fmt.Printf("  Scan complete: %s\n  %s\n", counts, nothing)
	case useColor:
		fmt.Printf("%s%s  \u2713 Scan complete%s: %s\n", colorGreen, colorBold, colorReset, counts)
	default:
		fmt.Printf("  Scan complete: %s\n", counts)
	}

	// The listed matches are numbered, so when their count differs from the
	// report's, say where the difference went.
	var notes []string
	if tally.hidden > 0 {
		notes = append(notes, fmt.Sprintf("The scan found %d matches; the list above shows the first %d.",
			tally.listed, tally.listed-tally.hidden))
	}
	if tally.listed != tally.reported {
		if tally.hidden == 0 {
			notes = append(notes, fmt.Sprintf("The list above has %d %s.",
				tally.listed, plural(tally.listed, "match", "matches")))
		}
		if merged := tally.listed - tally.unique; merged > 0 {
			notes = append(notes, fmt.Sprintf("%d %s a match of the same kind on the same line and %s counted with it.",
				merged, plural(merged, "repeats", "repeat"), plural(merged, "is", "are")))
		}
		if known := tally.unique - tally.reported; known > 0 {
			notes = append(notes, fmt.Sprintf("%d %s already in the baseline and %s not counted.",
				known, plural(known, "is", "are"), plural(known, "is", "are")))
		}
	}
	for _, note := range notes {
		if useColor {
			fmt.Printf("%s  %s%s\n", colorDim, note, colorReset)
		} else {
			fmt.Printf("  %s\n", note)
		}
	}
	fmt.Println()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// maxStreamedMatches is the number of matches the text report lists while
// the scan runs. The report after the stream lists every finding.
const maxStreamedMatches = 200

// printStreamCapNotice prints the line that ends the streamed list once
// maxStreamedMatches matches have been printed.
func printStreamCapNotice(useColor bool) {
	line := fmt.Sprintf("  Matches after the first %d are not listed while the scan runs; the report lists every finding.", maxStreamedMatches)
	if useColor {
		line = "\033[2m" + line + "\033[0m"
	}
	fmt.Println(line)
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

// parseSeverity maps a severity name to its level, ignoring case. An empty
// string means the option was not set and maps to info. Any other name is an
// error rather than a silent info, which would make --fail-on fail on every
// finding and --min-severity report all of them.
func parseSeverity(s string) (scanner.Severity, error) {
	switch strings.ToLower(s) {
	case "critical":
		return scanner.SeverityCritical, nil
	case "high":
		return scanner.SeverityHigh, nil
	case "medium":
		return scanner.SeverityMedium, nil
	case "low":
		return scanner.SeverityLow, nil
	case "info", "":
		return scanner.SeverityInfo, nil
	default:
		return scanner.SeverityInfo, fmt.Errorf("unknown severity %q (valid: %s)", s, strings.Join(severityNames, ", "))
	}
}

// checkOptionValues checks --format, --min-severity, --fail-on and
// --group-by, then the format, minSeverity and failOn settings of the config
// file at cfgPath, and returns an error for the first value that is not one of
// the accepted names. It also rejects a negative --max-depth or --context.
func checkOptionValues(cfgFile *config.Config, cfgPath string) error {
	if maxDepth < 0 {
		return fmt.Errorf("--max-depth must be 0 (unlimited) or a positive number, not %d", maxDepth)
	}
	if contextLines < 0 {
		return fmt.Errorf("--context must be 0 or a positive number, not %d", contextLines)
	}

	type option struct {
		name, value, source string
		valid               []string
		emptyIsUnset        bool
	}
	// --format defaults to text, so an empty value was typed on purpose. For
	// the other options an empty value means the option was not set.
	options := []option{
		{"--format", outputFormat, "", formatNames, false},
		{"--min-severity", minSeverity, "", severityNames, true},
		{"--fail-on", failOn, "", severityNames, true},
		{"--group-by", groupBy, "", groupByNames, true},
	}
	if cfgFile != nil {
		// Named by their keys in the config file.
		options = append(options,
			option{"format", cfgFile.Format, cfgPath, formatNames, true},
			option{"minSeverity", cfgFile.MinSeverity, cfgPath, severityNames, true},
			option{"failOn", cfgFile.FailOn, cfgPath, severityNames, true},
		)
	}

	for _, o := range options {
		if (o.value == "" && o.emptyIsUnset) || containsFold(o.valid, o.value) {
			continue
		}
		where := ""
		if o.source != "" {
			where = " in " + o.source
		}
		return fmt.Errorf("unknown %s %q%s (valid: %s)", o.name, o.value, where, strings.Join(o.valid, ", "))
	}
	return nil
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
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

// clearProgressLine erases the in-place progress line. It prints nothing
// when no progress line is shown, since a redirected stream has no cursor to
// move.
func clearProgressLine() {
	if !progressShown {
		return
	}
	fmt.Print("\r\033[K")
}

// isTerminal reports whether f is attached to a terminal. A redirected or
// piped stream is a character device only when it is a terminal, so this
// distinguishes interactive output from output being captured. It is a
// variable so that a test can stand in for a terminal.
var isTerminal = func(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
