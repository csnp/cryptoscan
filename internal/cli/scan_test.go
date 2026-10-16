// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/version"
	"github.com/spf13/cobra"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  scanner.Severity
	}{
		{"critical", scanner.SeverityCritical},
		{"CRITICAL", scanner.SeverityCritical},
		{"Critical", scanner.SeverityCritical},
		{"high", scanner.SeverityHigh},
		{"HIGH", scanner.SeverityHigh},
		{"medium", scanner.SeverityMedium},
		{"MEDIUM", scanner.SeverityMedium},
		{"low", scanner.SeverityLow},
		{"LOW", scanner.SeverityLow},
		{"info", scanner.SeverityInfo},
		{"INFO", scanner.SeverityInfo},
		{"", scanner.SeverityInfo},
		{"invalid", scanner.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseSeverity(tt.input)
			if got != tt.want {
				t.Errorf("parseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
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

// captureStdout captures stdout during function execution
func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
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

// resetPipelineFlags puts the flag variables the scan pipeline reads back to
// their defaults, so a test does not inherit another test's settings.
func resetPipelineFlags(t *testing.T) {
	t.Helper()
	outputFormat = "text"
	outputFile = ""
	includeGlobs = ""
	excludeGlobs = ""
	minSeverity = "info"
	noColor = true
	showProgress = false
	ignorePatterns = ""
	ignoreCategories = ""
	failOn = ""
	baselineFile = ""
	configFile = ""
	gateFailOn = "high"
	t.Cleanup(func() {
		outputFormat = "text"
		outputFile = ""
	})
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
