// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/spf13/cobra"
)

func TestScanExitCode(t *testing.T) {
	unanalyzed := []scanner.UnanalyzedFile{{File: "bad.go", Line: 1, Reason: "internal error"}}
	high := []scanner.Finding{{Severity: scanner.SeverityHigh}}
	critical := []scanner.Finding{{Severity: scanner.SeverityCritical}}

	tests := []struct {
		name    string
		results *scanner.Results
		failOn  string
		want    int
	}{
		{"fail-on with no findings and full coverage", &scanner.Results{}, "high", 0},
		{"fail-on with a finding at the threshold", &scanner.Results{Findings: high}, "high", 1},
		{"fail-on with a finding below the threshold", &scanner.Results{Findings: high}, "critical", 0},
		{"fail-on with an unanalyzed file is a coverage gap", &scanner.Results{UnanalyzedFiles: unanalyzed}, "critical", 1},
		{"no fail-on and an unanalyzed file", &scanner.Results{UnanalyzedFiles: unanalyzed}, "", 0},
		{"no fail-on and a high finding", &scanner.Results{Findings: high}, "", 0},
		{
			"no fail-on and a critical finding",
			&scanner.Results{
				Findings: critical,
				Summary:  scanner.Summary{BySeverity: map[string]int{"CRITICAL": 1}},
			},
			"",
			1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.results, tt.failOn, true); got != tt.want {
				t.Errorf("exitCode(failOn=%q) = %d, want %d", tt.failOn, got, tt.want)
			}
		})
	}
}

func TestWriteUnanalyzedNotice(t *testing.T) {
	files := []scanner.UnanalyzedFile{
		{File: "/src/bad.go", Line: 3, Reason: "internal error: boom"},
		{File: "/src/early.go", Reason: "internal error: early"},
	}

	for _, format := range []string{"json", "sarif", "csv", "cbom"} {
		var buf bytes.Buffer
		writeUnanalyzedNotice(&buf, format, files)
		got := buf.String()
		for _, want := range []string{
			"cryptoscan: 2 file(s) could not be analyzed",
			"  /src/bad.go:3  internal error: boom\n",
			"  /src/early.go  internal error: early\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: notice %q is missing %q", format, got, want)
			}
		}
	}

	// The text report lists the files itself, and a scan with none says nothing.
	var buf bytes.Buffer
	writeUnanalyzedNotice(&buf, "text", files)
	writeUnanalyzedNotice(&buf, "json", nil)
	if buf.Len() != 0 {
		t.Errorf("expected no notice, got %q", buf.String())
	}
}

// The reproduction from the report: a line with four U+023A letters before a
// match at the end of the line stopped the scan with a panic and wrote no
// report.
func TestRunScanWritesReportForLettersThatGrowWhenLowercased(t *testing.T) {
	saved := []string{outputFormat, outputFile, minSeverity, failOn}
	savedNoColor, savedPretty, savedProgress := noColor, jsonPretty, showProgress
	t.Cleanup(func() {
		outputFormat, outputFile, minSeverity, failOn = saved[0], saved[1], saved[2], saved[3]
		noColor, jsonPretty, showProgress = savedNoColor, savedPretty, savedProgress
	})

	dir := t.TempDir()
	src := filepath.Join(dir, "a.go")
	// Four copies of U+023A, built from the code point to keep the source ASCII.
	line := `var s = "` + strings.Repeat(string(rune(0x023A)), 4) + `"; _ = rsa` + "\n"
	if err := os.WriteFile(src, []byte(line), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.json")

	outputFormat = "json"
	outputFile = out
	minSeverity = ""
	failOn = ""
	noColor = true
	jsonPretty = false
	showProgress = false

	if err := runScan(&cobra.Command{}, []string{dir}); err != nil {
		t.Fatalf("runScan failed: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report written: %v", err)
	}
	var report scanner.Results
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}
	found := false
	for _, f := range report.Findings {
		if f.File == src && f.Line == 1 && f.Match == "rsa" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the rsa match on line 1 to be reported, got %+v", report.Findings)
	}
	if len(report.UnanalyzedFiles) != 0 {
		t.Errorf("expected every file to be analyzed, got %+v", report.UnanalyzedFiles)
	}
}
