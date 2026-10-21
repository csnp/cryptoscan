// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// The reproduction from the report: the README and docs/ci.md write reports
// into the tree they scan, and the next scan read them as source. A directory
// holding only the pretty JSON report of crypto-samples gave 1313 findings,
// the SARIF report 793 and the CBOM 184, and each scan failed --fail-on high.
// Every report the reporters write is now named as not scanned, and none of
// them gives a finding. The text reports are saved under a .log name here,
// since a .txt file is documentation and is not scanned by default anyway.
func TestScanLeavesOutTheReportsCryptoScanWrites(t *testing.T) {
	samples, err := scanner.New(scanner.Config{Target: "../../crypto-samples", MinSeverity: scanner.SeverityInfo}).Scan()
	if err != nil {
		t.Fatalf("scan crypto-samples: %v", err)
	}
	if len(samples.Findings) == 0 {
		t.Fatal("crypto-samples gave no findings, so its reports would prove nothing")
	}

	type report struct {
		name   string
		rep    Reporter
		reason string
	}
	reports := []report{
		{"baseline.json", NewJSONReporter(false), "CryptoScan report: JSON"},
		{"crypto-bom.json", NewCBOMReporter(), "CryptoScan report: CycloneDX CBOM"},
		{"findings.csv", NewCSVReporter(), "CryptoScan report: CSV"},
		{"findings.json", NewJSONReporter(true), "CryptoScan report: JSON"},
		{"pqc-report.log", NewPQCReporter(false), "CryptoScan report: text"},
		{"results.sarif", NewSARIFReporter(), "CryptoScan report: SARIF"},
		{"scan-report-color.log", NewTextReporter(true), "CryptoScan report: text"},
		{"scan-report.log", NewTextReporter(false), "CryptoScan report: text"},
	}
	dir := t.TempDir()
	var want []scanner.SkippedFile
	for _, r := range reports {
		out, err := r.rep.Generate(samples)
		if err != nil {
			t.Fatalf("generate %s: %v", r.name, err)
		}
		path := filepath.Join(dir, r.name)
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		want = append(want, scanner.SkippedFile{File: path, Reason: r.reason})
	}

	results, err := scanner.New(scanner.Config{Target: dir, MinSeverity: scanner.SeverityInfo}).Scan()
	if err != nil {
		t.Fatalf("scan the reports: %v", err)
	}
	if len(results.Findings) != 0 || results.FilesScanned != 0 {
		t.Errorf("findings = %d, filesScanned = %d; want 0 and 0", len(results.Findings), results.FilesScanned)
	}
	if !reflect.DeepEqual(results.SkippedFiles, want) {
		t.Errorf("skippedFiles = %+v\nwant %+v", results.SkippedFiles, want)
	}
	if results.HasFindingsAtOrAbove(scanner.SeverityHigh) {
		t.Error("a directory of reports fails --fail-on high")
	}
}

// A report CryptoScan wrote is listed with the files that were not scanned.
// The advice for minified files does not fit it, so it has its own, and a list
// holding both kinds gets both.
func TestTextReportAdvisesOnCryptoScanReports(t *testing.T) {
	const (
		reportAdvice   = "\n  To leave CryptoScan reports off this list, write them outside the scanned folder or pass their names to --exclude.\n"
		minifiedAdvice = "\n  Scan the source these files were built from, or search them for algorithm names.\n"
	)
	report := scanner.SkippedFile{File: "/test/path/results.sarif", Reason: "CryptoScan report: SARIF"}
	output := scanner.SkippedFile{File: "/test/path/scan-report", Reason: "CryptoScan report: the --output file of this scan"}
	minified := scanner.SkippedFile{File: "/test/path/app.min.js", Reason: "minified: the file name ends in .min.js"}

	tests := []struct {
		name         string
		files        []scanner.SkippedFile
		wantReport   bool
		wantMinified bool
	}{
		{"reports only", []scanner.SkippedFile{report, output}, true, false},
		{"minified file only", []scanner.SkippedFile{minified}, false, true},
		{"minified file and report", []scanner.SkippedFile{minified, report}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := createTestResults()
			results.SkippedFiles = tt.files
			text, err := NewTextReporter(false).Generate(results)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}
			for _, sk := range tt.files {
				if want := "\n    " + sk.File + "  " + sk.Reason + "\n"; !strings.Contains(text, want) {
					t.Errorf("text report is missing %q", want)
				}
			}
			if got := strings.Contains(text, reportAdvice); got != tt.wantReport {
				t.Errorf("text report has %q: %v, want %v", reportAdvice, got, tt.wantReport)
			}
			if got := strings.Contains(text, minifiedAdvice); got != tt.wantMinified {
				t.Errorf("text report has %q: %v, want %v", minifiedAdvice, got, tt.wantMinified)
			}
		})
	}
}
