// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/csnp/qramm-cryptoscan/pkg/scanner"
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
	if version != "1.0.0" {
		t.Errorf("version = %q, want %q", version, "1.0.0")
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
		printScanningFooter(10, 5, 100*time.Millisecond, true)
	})
	if !bytes.Contains([]byte(output), []byte("10")) {
		t.Error("printScanningFooter should contain finding count")
	}

	// Test without color
	output = captureStdout(func() {
		printScanningFooter(25, 10, 500*time.Millisecond, false)
	})
	if !bytes.Contains([]byte(output), []byte("25")) {
		t.Error("printScanningFooter should contain finding count")
	}
	if !bytes.Contains([]byte(output), []byte("Scan complete")) {
		t.Error("printScanningFooter should contain 'Scan complete'")
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
