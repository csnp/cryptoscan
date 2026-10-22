// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/cryptoscan/pkg/reporter"
	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/version"
	"github.com/spf13/cobra"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input   string
		want    scanner.Severity
		wantErr bool
	}{
		{"critical", scanner.SeverityCritical, false},
		{"CRITICAL", scanner.SeverityCritical, false},
		{"Critical", scanner.SeverityCritical, false},
		{"high", scanner.SeverityHigh, false},
		{"HIGH", scanner.SeverityHigh, false},
		{"medium", scanner.SeverityMedium, false},
		{"MEDIUM", scanner.SeverityMedium, false},
		{"low", scanner.SeverityLow, false},
		{"LOW", scanner.SeverityLow, false},
		{"info", scanner.SeverityInfo, false},
		{"INFO", scanner.SeverityInfo, false},
		{"", scanner.SeverityInfo, false},
		{"invalid", scanner.SeverityInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseSeverity(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSeverity(%q) = %v, want an error", tt.input, got)
				}
				want := `unknown severity "` + tt.input + `" (valid: info, low, medium, high, critical)`
				if err.Error() != want {
					t.Errorf("parseSeverity(%q) error = %q, want %q", tt.input, err.Error(), want)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSeverity(%q) returned error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("parseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// The accepted values are listed once. The flag help, the error for an unknown
// value and the code that acts on the value must all agree with that list.
func TestOptionValueListsMatchHelpAndCode(t *testing.T) {
	for _, name := range severityNames {
		if _, err := parseSeverity(name); err != nil {
			t.Errorf("severity %q is listed as valid but parseSeverity rejects it: %v", name, err)
		}
	}

	helpWants := map[string]string{
		"format":       strings.Join(formatNames, ", "),
		"min-severity": strings.Join(severityNames, ", "),
		"fail-on":      strings.Join(severityNames, ", "),
		"group-by":     strings.Join(groupByNames, ", "),
	}
	for flag, list := range helpWants {
		usage := scanCmd.Flags().Lookup(flag).Usage
		if !strings.Contains(usage, list) {
			t.Errorf("--%s help %q does not list %q", flag, usage, list)
		}
	}

	_, formatSection, _ := strings.Cut(scanCmd.Long, "Output formats:")
	formatSection, _, _ = strings.Cut(formatSection, "\n\n")
	for _, name := range formatNames {
		if !strings.Contains(formatSection, "  - "+name+":") {
			t.Errorf("scan help's Output formats section does not describe %q", name)
		}
	}

	// Every listed format must reach a reporter rather than an error.
	for _, name := range formatNames {
		dir := t.TempDir()
		if _, _, err := executeScan(t, dir, "--format", name); err != nil {
			t.Errorf("scan --format %s: %v", name, err)
		}
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://github.com/org/repo", true},
		{"http://github.com/org/repo", true},
		{"git@github.com:org/repo.git", true},
		{"/path/to/local/dir", false},
		{"./relative/path", false},
		{".", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isURL(tt.input)
			if got != tt.want {
				t.Errorf("isURL(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestScanCmdExists(t *testing.T) {
	if scanCmd == nil {
		t.Error("scanCmd should not be nil")
	}
	if scanCmd.Use != "scan [path or URL]" {
		t.Errorf("scanCmd.Use = %q, want %q", scanCmd.Use, "scan [path or URL]")
	}
}

func TestRootCmdExists(t *testing.T) {
	if rootCmd == nil {
		t.Error("rootCmd should not be nil")
	}
	if rootCmd.Use != "cryptoscan" {
		t.Errorf("rootCmd.Use = %q, want %q", rootCmd.Use, "cryptoscan")
	}
}

func TestSetVersionInfo(t *testing.T) {
	SetVersionInfo("1.0.0", "abc123", "2025-01-01")
	if got := version.Get(); got != "1.0.0" {
		t.Errorf("version.Get() = %q, want %q", got, "1.0.0")
	}
	if commit != "abc123" {
		t.Errorf("commit = %q, want %q", commit, "abc123")
	}
	if buildDate != "2025-01-01" {
		t.Errorf("buildDate = %q, want %q", buildDate, "2025-01-01")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a longer string", 10, "this is..."},
		{"hello", 5, "hello"},
		{"hello world", 8, "hello..."},
		{"", 5, ""},
		{"abc", 3, "abc"},
		{"abcd", 3, "..."},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := truncate(tt.input, tt.max)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
			}
		})
	}
}

func TestScanCmdFlags(t *testing.T) {
	// Test that all expected flags exist on scanCmd
	expectedFlags := []string{
		"format",
		"output",
		"include",
		"exclude",
		"max-depth",
		"group-by",
		"context",
		"progress",
		"min-severity",
		"no-color",
		"pretty",
		"config",
		"no-config",
	}

	for _, flag := range expectedFlags {
		if scanCmd.Flags().Lookup(flag) == nil {
			t.Errorf("scanCmd missing expected flag: %s", flag)
		}
	}
}

func TestScanCmdShortFlags(t *testing.T) {
	// Test short flag variants
	shortFlags := map[string]string{
		"f": "format",
		"o": "output",
		"i": "include",
		"e": "exclude",
		"d": "max-depth",
		"g": "group-by",
		"c": "context",
		"p": "progress",
	}

	for short, long := range shortFlags {
		flag := scanCmd.Flags().ShorthandLookup(short)
		if flag == nil {
			t.Errorf("scanCmd missing short flag: -%s", short)
			continue
		}
		if flag.Name != long {
			t.Errorf("short flag -%s should map to --%s, got --%s", short, long, flag.Name)
		}
	}
}

// captureStdout captures stdout during function execution. The pipe is
// drained while f runs, so that output larger than the pipe buffer does not
// block f.
func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	f()

	w.Close()
	os.Stdout = old
	return <-done
}

func TestPrintBanner(t *testing.T) {
	output := captureStdout(func() {
		printBanner()
	})

	// Should contain key elements (banner uses ASCII art, so check for parts)
	checks := []string{
		"CSNP",
		"qramm.org",
		"csnp.org",
		"Apache-2.0",
	}

	for _, check := range checks {
		if !bytes.Contains([]byte(output), []byte(check)) {
			t.Errorf("Banner missing expected text: %s", check)
		}
	}

	// Banner should not be empty
	if len(output) < 100 {
		t.Error("Banner output too short")
	}
}

func TestPrintScanningHeader(t *testing.T) {
	// Test with color
	output := captureStdout(func() {
		printScanningHeader(true)
	})
	if output == "" {
		t.Error("printScanningHeader with color produced empty output")
	}

	// Test without color
	output = captureStdout(func() {
		printScanningHeader(false)
	})
	if output == "" {
		t.Error("printScanningHeader without color produced empty output")
	}
	if !bytes.Contains([]byte(output), []byte("Scanning")) {
		t.Error("printScanningHeader should contain 'Scanning'")
	}
}

func TestPrintScanningFooter(t *testing.T) {
	// Test with color
	output := captureStdout(func() {
		printScanningFooter(streamTally{listed: 10, unique: 10, reported: 10, files: 5}, 100*time.Millisecond, true)
	})
	if !bytes.Contains([]byte(output), []byte("10")) {
		t.Error("printScanningFooter should contain finding count")
	}

	// Test without color
	output = captureStdout(func() {
		printScanningFooter(streamTally{listed: 25, unique: 25, reported: 25, files: 10}, 500*time.Millisecond, false)
	})
	if !bytes.Contains([]byte(output), []byte("25")) {
		t.Error("printScanningFooter should contain finding count")
	}
	if !bytes.Contains([]byte(output), []byte("Scan complete")) {
		t.Error("printScanningFooter should contain 'Scan complete'")
	}
}

// TestPrintScanningFooterCountsReportedFindings uses the counts from a scan of
// crypto-samples, where 121 matches are listed and 110 findings remain after
// deduplication. The footer leads with the number the report prints as Total
// Findings and accounts for every listed match.
func TestPrintScanningFooterCountsReportedFindings(t *testing.T) {
	tests := []struct {
		name  string
		tally streamTally
		want  []string
		never []string
	}{
		{
			name:  "duplicates merged",
			tally: streamTally{listed: 121, unique: 110, reported: 110, files: 6},
			want: []string{
				"Scan complete: 110 findings in 6 files",
				"The list above has 121 matches.",
				"11 repeat a match of the same kind on the same line and are counted with it.",
			},
			never: []string{"121 findings", "baseline"},
		},
		{
			name:  "duplicates and baseline",
			tally: streamTally{listed: 16, unique: 13, reported: 12, files: 37},
			want: []string{
				"Scan complete: 12 findings in 37 files",
				"The list above has 16 matches.",
				"3 repeat a match of the same kind on the same line and are counted with it.",
				"1 is already in the baseline and is not counted.",
			},
			never: []string{"16 findings", "13 findings"},
		},
		{
			name:  "nothing merged",
			tally: streamTally{listed: 1, unique: 1, reported: 1, files: 1},
			want:  []string{"Scan complete: 1 finding in 1 file ("},
			never: []string{"The list above"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output := captureStdout(func() {
				printScanningFooter(tc.tally, 16*time.Millisecond, false)
			})
			for _, s := range tc.want {
				if !strings.Contains(output, s) {
					t.Errorf("footer should contain %q, got:\n%s", s, output)
				}
			}
			for _, s := range tc.never {
				if strings.Contains(output, s) {
					t.Errorf("footer should not contain %q, got:\n%s", s, output)
				}
			}
		})
	}
}

// TestPrintScanningFooterSaysNothingWasScanned checks the footer of a scan
// that read no files: it says that nothing was checked, in the words of the
// text report, and has no check mark in color either. A scan that read a file
// keeps its check mark.
func TestPrintScanningFooterSaysNothingWasScanned(t *testing.T) {
	const nothing = "Nothing was checked: no files were scanned under /repo/empty"
	for _, useColor := range []bool{false, true} {
		output := captureStdout(func() {
			printScanningFooter(streamTally{target: "/repo/empty"}, 16*time.Millisecond, useColor)
		})
		if !strings.Contains(output, "Scan complete") || !strings.Contains(output, "0 findings in 0 files (") {
			t.Errorf("color %v: footer lacks its counts, got:\n%s", useColor, output)
		}
		if !strings.Contains(output, nothing) {
			t.Errorf("color %v: footer should contain %q, got:\n%s", useColor, nothing, output)
		}
		if strings.Contains(output, "✓") {
			t.Errorf("color %v: footer of a scan with 0 files scanned has a check mark, got:\n%s", useColor, output)
		}
	}

	output := captureStdout(func() {
		printScanningFooter(streamTally{files: 1, target: "/repo/app"}, 16*time.Millisecond, true)
	})
	if !strings.Contains(output, "✓ Scan complete") {
		t.Errorf("footer of a scan with 1 file scanned lost its check mark, got:\n%s", output)
	}
	if strings.Contains(output, "Nothing was checked") {
		t.Errorf("footer of a scan with 1 file scanned says nothing was checked, got:\n%s", output)
	}
}

// TestRunScanOfEmptyDirectorySaysNothingWasScanned runs the scan command on an
// empty directory with findings streamed. The footer and the report both say
// that nothing was checked, and neither prints a check mark.
func TestRunScanOfEmptyDirectorySaysNothingWasScanned(t *testing.T) {
	dir := t.TempDir()
	resetConfigScanFlags()
	defer resetConfigScanFlags()
	noConfig = true
	streamFindings = true

	output := captureStdout(func() {
		if err := runScan(&cobra.Command{}, []string{dir}); err != nil {
			t.Errorf("runScan failed: %v", err)
		}
	})

	nothing := "Nothing was checked: no files were scanned under " + dir
	if n := strings.Count(output, nothing); n != 2 {
		t.Errorf("output has %q %d times, want 2 (stream footer and report):\n%s", nothing, n, output)
	}
	for _, line := range []string{"No cryptographic findings detected", "\u2713 Scan complete"} {
		if strings.Contains(output, line) {
			t.Errorf("output of a scan with 0 files scanned prints %q:\n%s", line, output)
		}
	}
}

func TestPrintStreamFinding(t *testing.T) {
	findings := []scanner.Finding{
		{ID: "1", Type: "RSA Key", Severity: scanner.SeverityCritical, Quantum: scanner.QuantumVulnerable, File: "/test.go", Line: 10},
		{ID: "2", Type: "AES Cipher", Severity: scanner.SeverityHigh, Quantum: scanner.QuantumPartial, File: "/test.go", Line: 20},
		{ID: "3", Type: "SHA-256", Severity: scanner.SeverityMedium, Quantum: scanner.QuantumSafe, File: "/test.go", Line: 30},
		{ID: "4", Type: "MD5 Hash", Severity: scanner.SeverityLow, Quantum: scanner.QuantumUnknown, File: "/test.go", Line: 40},
		{ID: "5", Type: "Info Finding", Severity: scanner.SeverityInfo, File: "/test.go", Line: 50},
	}

	// Test with color
	for i, f := range findings {
		output := captureStdout(func() {
			printStreamFinding(f, i+1, true)
		})
		if output == "" {
			t.Errorf("printStreamFinding with color produced empty output for finding %d", i+1)
		}
	}

	// Test without color
	for i, f := range findings {
		output := captureStdout(func() {
			printStreamFinding(f, i+1, false)
		})
		if output == "" {
			t.Errorf("printStreamFinding without color produced empty output for finding %d", i+1)
		}
	}
}

func TestRunScanWithTempDir(t *testing.T) {
	// Create temp directory with a test file
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a simple Go file with crypto usage (use low severity pattern)
	testFile := filepath.Join(tmpDir, "test.go")
	content := `package main
import "crypto/sha256"
func hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Reset flags to defaults
	outputFormat = "text"
	outputFile = ""
	minSeverity = ""
	noColor = true
	showProgress = false

	// Capture stdout and run scan
	output := captureStdout(func() {
		cmd := &cobra.Command{}
		err := runScan(cmd, []string{tmpDir})
		if err != nil {
			t.Errorf("runScan failed: %v", err)
		}
	})

	// Output should contain scan results
	if len(output) == 0 {
		t.Error("Scan should produce output")
	}
}

func TestRunScanWithJSONFormat(t *testing.T) {
	// Create temp directory with a test file
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a simple file (use low severity pattern)
	testFile := filepath.Join(tmpDir, "test.py")
	content := `import hashlib
def hash(data):
    return hashlib.sha256(data).hexdigest()
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Set JSON format
	outputFormat = "json"
	outputFile = ""
	minSeverity = ""
	noColor = true
	jsonPretty = false
	showProgress = false

	// Capture stdout and run scan
	output := captureStdout(func() {
		cmd := &cobra.Command{}
		err := runScan(cmd, []string{tmpDir})
		if err != nil {
			t.Errorf("runScan failed: %v", err)
		}
	})

	// Reset format
	outputFormat = "text"

	// Should be valid JSON structure
	if !bytes.Contains([]byte(output), []byte("{")) {
		t.Error("JSON output should start with {")
	}
}

func TestRunScanWithOutputFile(t *testing.T) {
	// Create temp directories
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a simple file (use low severity pattern - just an import)
	testFile := filepath.Join(tmpDir, "test.go")
	content := `package main
import "crypto/sha512"
var _ = sha512.Sum512
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Create output file path
	outFile := filepath.Join(tmpDir, "output.txt")

	// Set output file
	outputFormat = "text"
	outputFile = outFile
	minSeverity = ""
	noColor = true
	showProgress = false

	// Run scan
	cmd := &cobra.Command{}
	err = runScan(cmd, []string{tmpDir})
	if err != nil {
		t.Errorf("runScan failed: %v", err)
	}

	// Reset
	outputFile = ""

	// Check output file exists and has content
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Errorf("Failed to read output file: %v", err)
	}
	if len(data) == 0 {
		t.Error("Output file should not be empty")
	}
}

func TestRunScanEmptyDir(t *testing.T) {
	// Create empty temp directory
	tmpDir, err := os.MkdirTemp("", "cryptoscan-empty-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Reset flags
	outputFormat = "text"
	outputFile = ""
	minSeverity = ""
	noColor = true
	showProgress = false

	// Should succeed even with no files
	cmd := &cobra.Command{}
	err = runScan(cmd, []string{tmpDir})
	if err != nil {
		t.Errorf("runScan on empty dir failed: %v", err)
	}
}

// resetPipelineFlags sets the flag variables below to their defaults, with
// colour off, now and when the test ends, so a test neither inherits another
// test's values for them nor leaves its own to the next one.
func resetPipelineFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		outputFormat = "text"
		outputFile = ""
		includeGlobs = ""
		excludeGlobs = ""
		includeSkipped = false
		minSeverity = "info"
		noColor = true
		showProgress = false
		ignorePatterns = ""
		ignoreCategories = ""
		failOn = ""
		baselineFile = ""
		configFile = ""
		gateFailOn = "high"
	}
	reset()
	t.Cleanup(reset)
}

// A flag variable a test changes after calling resetPipelineFlags is back
// where resetPipelineFlags put it when that test ends. The skipped-file tests
// set failOn to "low" this way; TestRunScanExcludesFromFlagConfigAndDefaults,
// which does not set failOn, then ran with that threshold, and its runScan
// call ended the test binary with exit code 1.
func TestResetPipelineFlagsPutsTheDefaultsBackWhenTheTestEnds(t *testing.T) {
	t.Run("earlier test", func(t *testing.T) {
		resetPipelineFlags(t)
		failOn = "low"
		minSeverity = "high"
		excludeGlobs = "test/*"
		configFile = "other.yaml"
		gateFailOn = "critical"
		includeSkipped = true
	})
	for _, v := range []struct{ name, got, want string }{
		{"failOn", failOn, ""},
		{"minSeverity", minSeverity, "info"},
		{"excludeGlobs", excludeGlobs, ""},
		{"configFile", configFile, ""},
		{"gateFailOn", gateFailOn, "high"},
	} {
		if v.got != v.want {
			t.Errorf("%s = %q after the earlier test ended, want the default %q", v.name, v.got, v.want)
		}
	}
	if includeSkipped {
		t.Error("includeSkipped = true after the earlier test ended, want the default false")
	}
}

func TestExitCode(t *testing.T) {
	results := func(sevs ...scanner.Severity) *scanner.Results {
		var findings []scanner.Finding
		for _, s := range sevs {
			findings = append(findings, scanner.Finding{Severity: s})
		}
		return &scanner.Results{Findings: findings, Summary: calculateSummary(findings)}
	}

	tests := []struct {
		name         string
		results      *scanner.Results
		failOn       string
		gateFindings bool
		want         int
	}{
		{"no findings", results(), "", true, 0},
		{"default fails on critical", results(scanner.SeverityCritical), "", true, 1},
		{"default passes high", results(scanner.SeverityHigh), "", true, 0},
		{"high threshold fails high", results(scanner.SeverityHigh), "high", true, 1},
		{"high threshold fails critical", results(scanner.SeverityCritical), "high", true, 1},
		{"high threshold passes medium", results(scanner.SeverityMedium, scanner.SeverityLow), "high", true, 0},
		{"critical threshold passes high", results(scanner.SeverityHigh), "critical", true, 0},
		{"inventory passes critical", results(scanner.SeverityCritical), "", false, 0},
		{"inventory ignores a threshold", results(scanner.SeverityCritical), "info", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.results, tt.failOn, tt.gateFindings); got != tt.want {
				t.Errorf("exitCode(%s, %q, %v) = %d, want %d", tt.name, tt.failOn, tt.gateFindings, got, tt.want)
			}
		})
	}
}

// captureStderr captures stderr during function execution
func captureStderr(f func()) string {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	f()

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// configScanDir writes the tree from the issue: one Python file calling
// rsa.generate_private_key, and a .cryptoscan.yaml with the given content.
func configScanDir(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	code := "from cryptography.hazmat.primitives.asymmetric import rsa\n\n" +
		"key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cryptoscan.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func resetConfigScanFlags() {
	outputFormat = "text"
	outputFile = ""
	minSeverity = "info"
	failOn = ""
	baselineFile = ""
	configFile = ""
	noConfig = false
	noColor = true
	showProgress = false
}

// TestRunScanReportsAutoDetectedConfigFile is the reproduction from the issue:
// a .cryptoscan.yaml that ignores every pattern used to leave the report with
// a check mark and no mention of the file.
func TestRunScanReportsAutoDetectedConfigFile(t *testing.T) {
	dir := configScanDir(t, "ignore:\n  patterns: [\"*\"]\n")
	resetConfigScanFlags()
	defer resetConfigScanFlags()

	output := captureStdout(func() {
		if err := runScan(&cobra.Command{}, []string{dir}); err != nil {
			t.Errorf("runScan failed: %v", err)
		}
	})

	for _, want := range []string{
		"Config file applied: " + filepath.Join(dir, ".cryptoscan.yaml"),
		"(found in the scan target)",
		"ignore.patterns removed",
		"No findings reported: the config file removed",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if strings.Contains(output, "No cryptographic findings detected") {
		t.Error("report claims nothing was detected although the config file removed every finding")
	}
}

func TestRunScanNoConfigIgnoresTheFile(t *testing.T) {
	dir := configScanDir(t, "ignore:\n  patterns: [\"*\"]\n")
	resetConfigScanFlags()
	defer resetConfigScanFlags()
	outputFormat = "json"
	noConfig = true

	output := captureStdout(func() {
		if err := runScan(&cobra.Command{}, []string{dir}); err != nil {
			t.Errorf("runScan failed: %v", err)
		}
	})

	var report struct {
		Findings []scanner.Finding `json:"findings"`
		Config   *json.RawMessage  `json:"config"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if report.Config != nil {
		t.Errorf("--no-config still applied a config file: %s", *report.Config)
	}
	if len(report.Findings) == 0 {
		t.Error("--no-config scan reported no findings; the file's ignore rule was applied")
	}
}

// TestRunScanCountsBaselineFromConfigFile checks that a baseline named in the
// config file is counted against the file, since it removes findings the same
// way the ignore rules do.
func TestRunScanCountsBaselineFromConfigFile(t *testing.T) {
	dir := configScanDir(t, "")
	resetConfigScanFlags()
	defer resetConfigScanFlags()
	outputFormat = "json"
	noConfig = true

	first := captureStdout(func() {
		if err := runScan(&cobra.Command{}, []string{dir}); err != nil {
			t.Errorf("runScan failed: %v", err)
		}
	})
	var prior struct {
		Findings []scanner.Finding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(first), &prior); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(prior.Findings) == 0 {
		t.Fatal("fixture produced no findings to put in a baseline")
	}

	// The baseline lives outside the scanned tree so it is not scanned itself.
	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(baselinePath, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cryptoscan.yaml"), []byte("baseline: "+baselinePath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	noConfig = false
	second := captureStdout(func() {
		if err := runScan(&cobra.Command{}, []string{dir}); err != nil {
			t.Errorf("runScan failed: %v", err)
		}
	})
	var report struct {
		Findings []scanner.Finding     `json:"findings"`
		Config   *scanner.ConfigReport `json:"config"`
	}
	if err := json.Unmarshal([]byte(second), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if report.Config == nil {
		t.Fatal("JSON report has no config object")
	}
	if len(report.Findings) != 0 {
		t.Errorf("baseline left %d findings, want 0", len(report.Findings))
	}
	removed := report.Config.FindingsRemoved
	if removed.Baseline != len(prior.Findings) || removed.Total != len(prior.Findings) {
		t.Errorf("baseline removed %d (total %d), want %d", removed.Baseline, removed.Total, len(prior.Findings))
	}
}

func TestRunScanRejectsConfigWithNoConfig(t *testing.T) {
	dir := configScanDir(t, "minSeverity: high\n")
	resetConfigScanFlags()
	defer resetConfigScanFlags()
	configFile = filepath.Join(dir, ".cryptoscan.yaml")
	noConfig = true

	err := runScan(&cobra.Command{}, []string{dir})
	if err == nil || !strings.Contains(err.Error(), "--no-config") {
		t.Errorf("want an error naming --no-config, got %v", err)
	}
}

// TestRunScanWarnsAboutUnparsableConfigFile covers an auto-detected file that
// is not valid YAML, which used to be dropped without any output.
func TestRunScanWarnsAboutUnparsableConfigFile(t *testing.T) {
	dir := configScanDir(t, "ignore: [unclosed\n")
	resetConfigScanFlags()
	defer resetConfigScanFlags()
	outputFormat = "json"

	var stderr string
	captureStdout(func() {
		stderr = captureStderr(func() {
			if err := runScan(&cobra.Command{}, []string{dir}); err != nil {
				t.Errorf("runScan failed: %v", err)
			}
		})
	})

	want := "Warning: config file " + filepath.Join(dir, ".cryptoscan.yaml") + " could not be parsed and was not applied"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
}

func TestAutoConfigSource(t *testing.T) {
	tests := []struct {
		name     string
		cfgPath  string
		start    string
		isURL    bool
		expected string
	}{
		{"in the target", "/repo/.cryptoscan.yaml", "/repo", false, scanner.ConfigSourceScanTarget},
		{"above the target", "/repo/.cryptoscan.yaml", "/repo/service", false, scanner.ConfigSourceParentDirectory},
		{"above a file target", "/repo/.cryptoscan.yaml", "/repo/app.py", false, scanner.ConfigSourceParentDirectory},
		{"repository URL", "/work/.cryptoscan.yaml", "/work", true, scanner.ConfigSourceWorkingDirectory},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := autoConfigSource(tt.cfgPath, tt.start, tt.isURL); got != tt.expected {
				t.Errorf("autoConfigSource(%q, %q, %v) = %q, want %q", tt.cfgPath, tt.start, tt.isURL, got, tt.expected)
			}
		})
	}
}

func TestRunScanInvalidPath(t *testing.T) {
	// Reset flags
	outputFormat = "text"
	outputFile = ""
	noColor = true

	cmd := &cobra.Command{}
	err := runScan(cmd, []string{"/nonexistent/path/that/does/not/exist"})
	if err == nil {
		t.Error("runScan should fail with invalid path")
	}
}

// TestRunScanExcludesFromFlagConfigAndDefaults checks that the --exclude flag,
// the config file ignore.files list and the default excludes all skip the
// directories they name.
func TestRunScanExcludesFromFlagConfigAndDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	content := "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
	for _, dir := range []string{"vendor", "venv", "test", "generated", "src"} {
		if err := os.MkdirAll(filepath.Join(tmpDir, dir), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, dir, "keys.py"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := "ignore:\n  files:\n    - \"generated/*\"\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".cryptoscan.yaml"), []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()

	outputFormat = "json"
	outputFile = filepath.Join(outDir, "findings.json")
	excludeGlobs = "test/*"
	minSeverity = ""
	noColor = true
	showProgress = false
	t.Cleanup(func() {
		outputFormat = "text"
		outputFile = ""
		excludeGlobs = ""
	})

	if err := runScan(&cobra.Command{}, []string{tmpDir}); err != nil {
		t.Fatalf("runScan failed: %v", err)
	}
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Findings []struct {
			File string `json:"file"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}

	byDir := make(map[string]int)
	for _, f := range report.Findings {
		rel, err := filepath.Rel(tmpDir, f.File)
		if err != nil {
			t.Fatal(err)
		}
		byDir[strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]]++
	}
	for _, dir := range []string{"vendor", "venv", "test", "generated"} {
		if byDir[dir] != 0 {
			t.Errorf("%s/ has %d finding(s); it should be excluded", dir, byDir[dir])
		}
	}
	if byDir["src"] == 0 {
		t.Error("src/ has no findings; nothing excludes it")
	}
}

// TestStreamFooterMatchesReportTotal scans a line that two detection patterns
// match with the same category. Both matches are listed as they are found,
// and deduplication then keeps one of them. The footer used to print the
// number of listed matches, so it said "2 findings" above a report that says
// "Total Findings: 1".
func TestStreamFooterMatchesReportTotal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-dedup-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := "from cryptography.hazmat.primitives.kdf.hkdf import HKDF\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "kdf.py"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	outputFormat = "text"
	outputFile = ""
	minSeverity = ""
	noColor = true
	showProgress = false
	streamFindings = true
	baselineFile = ""
	failOn = ""

	output := captureStdout(func() {
		if err := runScan(&cobra.Command{}, []string{tmpDir}); err != nil {
			t.Errorf("runScan failed: %v", err)
		}
	})

	listed := regexp.MustCompile(`(?m)^\s+\[\w+\] #\d+`).FindAllString(output, -1)
	if len(listed) < 2 {
		t.Fatalf("fixture should list at least two matches on one line, listed %d:\n%s", len(listed), output)
	}

	footer := regexp.MustCompile(`Scan complete: (\d+) findings? in`).FindStringSubmatch(output)
	if footer == nil {
		t.Fatalf("no stream footer in output:\n%s", output)
	}
	total := regexp.MustCompile(`Total Findings: (\d+)`).FindStringSubmatch(output)
	if total == nil {
		t.Fatalf("no Total Findings line in output:\n%s", output)
	}
	if footer[1] != total[1] {
		t.Errorf("stream footer says %s findings, report says Total Findings: %s", footer[1], total[1])
	}
	if total[1] == strconv.Itoa(len(listed)) {
		t.Fatalf("fixture no longer produces a duplicate match: %d listed, %s reported", len(listed), total[1])
	}

	// The listed matches are numbered, so the footer has to account for them.
	wantListed := fmt.Sprintf("The list above has %d matches.", len(listed))
	if !strings.Contains(output, wantListed) {
		t.Errorf("footer should say %q, got:\n%s", wantListed, output)
	}
}

// executeScan runs "cryptoscan scan <args>" through the root command, the way
// the binary does. It returns what the scan wrote to stdout, what cobra printed
// (the error line and usage), and the error. The flag variables it can change
// are restored afterwards, and the usage block the scan turns off is turned
// back on, so later tests start from the same state.
func executeScan(t *testing.T, args ...string) (stdout, cobraOutput string, err error) {
	t.Helper()
	savedFormat, savedMinSeverity, savedFailOn, savedConfig := outputFormat, minSeverity, failOn, configFile
	t.Cleanup(func() {
		outputFormat, minSeverity, failOn, configFile = savedFormat, savedMinSeverity, savedFailOn, savedConfig
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		scanCmd.SilenceUsage = false
	})
	// Start where the binary starts, with the usage block on; see executeRoot.
	scanCmd.SilenceUsage = false

	var cobraBuf bytes.Buffer
	rootCmd.SetOut(&cobraBuf)
	rootCmd.SetErr(&cobraBuf)
	rootCmd.SetArgs(append([]string{"scan"}, args...))
	stdout = captureStdout(func() {
		err = rootCmd.Execute()
	})
	return stdout, cobraBuf.String(), err
}

func TestScanRejectsUnknownFormat(t *testing.T) {
	dir := t.TempDir()

	stdout, cobraOutput, err := executeScan(t, dir, "--format", "xml")
	if err == nil {
		t.Fatalf("scan --format xml returned no error; stdout began %q", firstLine(stdout))
	}
	want := `unknown --format "xml" (valid: text, json, csv, sarif, cbom)`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if !strings.Contains(cobraOutput, "Error: "+want) {
		t.Errorf("cobra output does not carry the error line; got %q", firstLine(cobraOutput))
	}
	if stdout != "" {
		t.Errorf("scan wrote to stdout before rejecting --format: %q", firstLine(stdout))
	}
}

// --format defaults to text, so an empty value (an unset CI variable, say) is a
// mistake to report, not a reason to scan and then fail to pick a reporter.
func TestScanRejectsEmptyFormat(t *testing.T) {
	dir := t.TempDir()

	stdout, _, err := executeScan(t, dir, "--format", "")
	if err == nil {
		t.Fatalf("scan --format \"\" returned no error; stdout began %q", firstLine(stdout))
	}
	want := `unknown --format "" (valid: text, json, csv, sarif, cbom)`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if stdout != "" {
		t.Errorf("scan wrote output before rejecting --format: %q", firstLine(stdout))
	}
}

func TestScanRejectsUnknownFailOnBeforeAnyOutput(t *testing.T) {
	dir := t.TempDir()

	stdout, _, err := executeScan(t, dir, "--fail-on", "extreme", "--format", "json")
	if err == nil {
		t.Fatalf("scan --fail-on extreme returned no error; stdout began %q", firstLine(stdout))
	}
	want := `unknown --fail-on "extreme" (valid: info, low, medium, high, critical)`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if stdout != "" {
		t.Errorf("scan wrote output before rejecting --fail-on: %q", firstLine(stdout))
	}
}

func TestScanRejectsUnknownMinSeverity(t *testing.T) {
	dir := t.TempDir()

	stdout, _, err := executeScan(t, dir, "--min-severity", "extreme", "--format", "json")
	if err == nil {
		t.Fatalf("scan --min-severity extreme returned no error; stdout began %q", firstLine(stdout))
	}
	want := `unknown --min-severity "extreme" (valid: info, low, medium, high, critical)`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if stdout != "" {
		t.Errorf("scan wrote output before rejecting --min-severity: %q", firstLine(stdout))
	}
}

func TestScanRejectsUnknownConfigFileValues(t *testing.T) {
	tests := []struct {
		yaml string
		want string // the error, with %s standing for the config file path
	}{
		{"failOn: extreme\n", `unknown failOn "extreme" in %s (valid: info, low, medium, high, critical)`},
		{"minSeverity: extreme\n", `unknown minSeverity "extreme" in %s (valid: info, low, medium, high, critical)`},
		{"format: xml\n", `unknown format "xml" in %s (valid: text, json, csv, sarif, cbom)`},
	}

	for _, tt := range tests {
		t.Run(tt.yaml, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, ".cryptoscan.yaml")
			if err := os.WriteFile(cfgPath, []byte(tt.yaml), 0644); err != nil {
				t.Fatal(err)
			}

			stdout, _, err := executeScan(t, dir)
			if err == nil {
				t.Fatalf("scan with %q in the config file returned no error; stdout began %q", tt.yaml, firstLine(stdout))
			}
			want := fmt.Sprintf(tt.want, cfgPath)
			if err.Error() != want {
				t.Errorf("error = %q, want %q", err.Error(), want)
			}
			if stdout != "" {
				t.Errorf("scan wrote output before rejecting the config file: %q", firstLine(stdout))
			}
		})
	}
}

func TestScanAcceptsValuesInAnyCase(t *testing.T) {
	dir := t.TempDir()

	stdout, _, err := executeScan(t, dir, "--fail-on", "HIGH", "--min-severity", "Low", "--format", "JSON")
	if err != nil {
		t.Fatalf("scan --fail-on HIGH --min-severity Low --format JSON: %v", err)
	}
	if !strings.HasPrefix(stdout, "{") {
		t.Errorf("--format JSON did not produce JSON; stdout began %q", firstLine(stdout))
	}
}

// firstLine shortens output for a failure message.
func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	if len(line) > 80 {
		line = line[:80] + "..."
	}
	return line
}

// userinfoTarget returns a repository URL that carries a user name and a
// password, joined from fragments at run time, along with those two parts.
// Port 1 on the loopback address refuses a connection, so a clone of the URL
// fails at once unless git has been told to clone a local repository for it.
func userinfoTarget() (target, user, password string) {
	user = strings.Join([]string{"scan", "user"}, "")
	password = strings.Join([]string{"fragment", "pass"}, "")
	target = strings.Join([]string{"http", "://", user, ":", password, "@", "127.0.0.1:1", "/repo.git"}, "")
	return target, user, password
}

// shownUserinfoTarget is the URL from userinfoTarget without its user
// information.
const shownUserinfoTarget = "http://127.0.0.1:1/repo.git"

// isolateGit runs git for the rest of the test with no system or user
// configuration and no proxy, so that git settings on the machine, such as a
// URL rewrite or a proxy, do not change what a clone in the test does.
func isolateGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	global := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(global, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_COUNT", "0")
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
	for _, name := range []string{"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

// cloneLocally commits the reviewed tree to a new local repository and has git
// clone that repository whenever it is asked to clone one of urls, so that a
// scan of any of them runs without reaching the network. Call isolateGit
// first.
func cloneLocally(t *testing.T, urls ...string) {
	t.Helper()
	repo := t.TempDir()
	writeReviewedTree(t, repo, reviewedApp)
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"add", "."},
		{"-c", "user.name=CryptoScan test", "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "fixture"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	t.Setenv("GIT_CONFIG_COUNT", strconv.Itoa(len(urls)))
	for i, url := range urls {
		t.Setenv("GIT_CONFIG_KEY_"+strconv.Itoa(i), "url."+repo+".insteadOf")
		t.Setenv("GIT_CONFIG_VALUE_"+strconv.Itoa(i), url)
	}
}

// runCLI runs cryptoscan with args the way main does and returns everything it
// printed: stdout, stderr, and cobra's error line with the hint after it.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var printed string
	var err error
	stderr := captureStderr(func() {
		printed, err = executeRoot(t, args...)
	})
	return printed + stderr, err
}

// reportScanTarget returns the scanTarget of the JSON report at path.
func reportScanTarget(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		ScanTarget string `json:"scanTarget"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	return report.ScanTarget
}

// assertHoldsNone fails the test when text holds any of parts.
func assertHoldsNone(t *testing.T, what, text string, parts ...string) {
	t.Helper()
	for _, part := range parts {
		if strings.Contains(text, part) {
			t.Errorf("%s holds %q:\n%s", what, part, text)
		}
	}
}

// A repository URL can carry a user name and a password for git to clone
// with. The report's scanTarget, a baseline saved from that report, and the
// text and pqc reports name the repository without them.
func TestScanOfAURLWithUserInformationNamesTheRepositoryWithoutIt(t *testing.T) {
	isolateGit(t)
	target, user, password := userinfoTarget()
	cloneLocally(t, target)
	baseline := filepath.Join(t.TempDir(), "baseline.json")

	t.Run("json report saved as a baseline", func(t *testing.T) {
		resetPipelineFlags(t)
		out, err := runCLI(t, "scan", target, "--no-color", "--format", "json", "--output", baseline)
		if err != nil {
			t.Fatalf("scan: %v\n%s", err, out)
		}
		assertHoldsNone(t, "the scan's output", out, user, password)
		data, err := os.ReadFile(baseline)
		if err != nil {
			t.Fatal(err)
		}
		assertHoldsNone(t, "the report", string(data), user, password)
		if got := reportScanTarget(t, baseline); got != shownUserinfoTarget {
			t.Errorf("report scanTarget = %q, want %q", got, shownUserinfoTarget)
		}
		b, err := loadBaseline(baseline)
		if err != nil {
			t.Fatal(err)
		}
		if b.ScanTarget != shownUserinfoTarget {
			t.Errorf("baseline scanTarget = %q, want %q", b.ScanTarget, shownUserinfoTarget)
		}
	})

	t.Run("text report", func(t *testing.T) {
		resetPipelineFlags(t)
		out, err := runCLI(t, "scan", target, "--no-color")
		if err != nil {
			t.Fatalf("scan: %v\n%s", err, out)
		}
		assertHoldsNone(t, "the text report", out, user, password)
		if !strings.Contains(out, shownUserinfoTarget) {
			t.Errorf("the text report does not name %s:\n%s", shownUserinfoTarget, out)
		}
	})

	t.Run("pqc report", func(t *testing.T) {
		resetPipelineFlags(t)
		out, err := runCLI(t, "pqc", target, "--no-color")
		if err != nil {
			t.Fatalf("pqc: %v\n%s", err, out)
		}
		assertHoldsNone(t, "the pqc report", out, user, password)
		if !strings.Contains(out, shownUserinfoTarget) {
			t.Errorf("the pqc report does not name %s:\n%s", shownUserinfoTarget, out)
		}
	})

	t.Run("nothing scanned", func(t *testing.T) {
		resetPipelineFlags(t)
		out, err := runCLI(t, "scan", target, "--no-color", "--stream", "--exclude", "*.py")
		if err != nil {
			t.Fatalf("scan: %v\n%s", err, out)
		}
		assertHoldsNone(t, "the output", out, user, password)
		nothing := reporter.NothingScanned(shownUserinfoTarget)
		if n := strings.Count(out, nothing); n != 2 {
			t.Errorf("the stream footer and the report should each say %q; it appears %d times in:\n%s", nothing, n, out)
		}
	})
}

// A clone that is refused leaves neither the user nor the password of its URL
// on any output stream or in any file the scan writes.
func TestRefusedCloneOfAURLWithUserInformationPrintsAndSavesNeitherPart(t *testing.T) {
	isolateGit(t)
	resetPipelineFlags(t)
	scratch := t.TempDir()
	// The scan makes its clone directory under TMPDIR.
	t.Setenv("TMPDIR", scratch)
	target, user, password := userinfoTarget()

	out, err := runCLI(t, "scan", target, "--no-color", "--format", "json", "--output", filepath.Join(scratch, "report.json"))
	if err == nil {
		t.Fatalf("the clone of %s should be refused; output:\n%s", shownUserinfoTarget, out)
	}
	if !strings.Contains(out, "repository not found or not accessible") {
		t.Errorf("the output does not say the clone failed:\n%s", out)
	}
	assertHoldsNone(t, "the output", out, user, password)
	err = filepath.Walk(scratch, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		assertHoldsNone(t, path, string(data), user, password)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A URL with a scheme the scanner does not clone, such as ssh://, is read as a
// local path. The error for that path names it without the URL's user
// information, and the next step for a missing path still follows it.
func TestScanOfAnUnclonedURLWithUserInformationNamesItWithoutIt(t *testing.T) {
	resetPipelineFlags(t)
	_, user, password := userinfoTarget()
	target := strings.Join([]string{"ssh", "://", user, ":", password, "@", "127.0.0.1:1", "/repo.git"}, "")
	shownPath, err := filepath.Abs("ssh://127.0.0.1:1/repo.git")
	if err != nil {
		t.Fatal(err)
	}

	out, err := runCLI(t, "scan", target, "--no-color")
	if err == nil {
		t.Fatalf("the scan should fail; output:\n%s", out)
	}
	assertHoldsNone(t, "the output", out, user, password)
	if !strings.Contains(out, "cannot access target") || !strings.Contains(out, shownPath) {
		t.Errorf("the error does not say it cannot access %s:\n%s", shownPath, out)
	}
	if !strings.Contains(out, "Check the path") {
		t.Errorf("the output does not give the next step for a missing path:\n%s", out)
	}
}

// A target with no user information is reported exactly as it was typed: a
// URL without it, the user@host:path form, which has no place for a password,
// and a local path holding "@".
func TestScanTargetWithoutUserInformationIsReportedAsTyped(t *testing.T) {
	isolateGit(t)
	url := strings.Join([]string{"http", "://", "127.0.0.1:1", "/repo.git"}, "")
	scp := strings.Join([]string{"git", "@", "127.0.0.1", ":", "repo.git"}, "")
	cloneLocally(t, url, scp)
	local := filepath.Join(t.TempDir(), "build@2")
	writeReviewedTree(t, local, reviewedApp)

	tests := []struct {
		name   string
		target string
	}{
		{"url without user information", url},
		{"user@host:path", scp},
		{"local path holding @", local},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetPipelineFlags(t)
			report := filepath.Join(t.TempDir(), "report.json")
			out, err := runCLI(t, "scan", tt.target, "--no-color", "--format", "json", "--output", report)
			if err != nil {
				t.Fatalf("scan: %v\n%s", err, out)
			}
			if got := reportScanTarget(t, report); got != tt.target {
				t.Errorf("scanTarget = %q, want %q", got, tt.target)
			}
		})
	}
}
