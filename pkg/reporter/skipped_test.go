// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

func TestTextReportListsSkippedFiles(t *testing.T) {
	results := createTestResults()
	results.SkippedFiles = []scanner.SkippedFile{
		{File: "/test/path/app.js", Reason: "minified or generated: its lines average 674 bytes"},
		{File: "/test/path/app.min.js", Reason: "minified: the file name ends in .min.js"},
	}
	output, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	for _, want := range []string{
		"\n  2 file(s) were not scanned, so cryptography in them is not in this report:\n",
		"\n    /test/path/app.js  minified or generated: its lines average 674 bytes\n",
		"\n    /test/path/app.min.js  minified: the file name ends in .min.js\n",
		"\n  Scan the source these files were built from, or search them for algorithm names.\n",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("text report is missing %q", want)
		}
	}

	clean, err := NewTextReporter(false).Generate(createTestResults())
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if strings.Contains(clean, "were not scanned") {
		t.Error("text report mentions skipped files when there are none")
	}
}

// A dependency manifest the scanner has no reader for is listed with the
// files that were not scanned. The advice for minified files does not fit it,
// so it has its own, and a list holding both kinds gets both.
func TestTextReportAdvisesOnDependencyManifestsTheScannerDoesNotRead(t *testing.T) {
	const (
		manifestAdvice = "\n  Check the dependency manifests for cryptography libraries by hand.\n"
		minifiedAdvice = "\n  Scan the source these files were built from, or search them for algorithm names.\n"
	)
	manifest := scanner.SkippedFile{File: "/test/path/build.gradle", Reason: "dependency manifest: the scanner does not read this format"}
	minified := scanner.SkippedFile{File: "/test/path/app.min.js", Reason: "minified: the file name ends in .min.js"}

	tests := []struct {
		name         string
		files        []scanner.SkippedFile
		wantManifest bool
		wantMinified bool
	}{
		{"manifest only", []scanner.SkippedFile{manifest}, true, false},
		{"minified file only", []scanner.SkippedFile{minified}, false, true},
		{"minified file and manifest", []scanner.SkippedFile{minified, manifest}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := createTestResults()
			results.SkippedFiles = tt.files
			output, err := NewTextReporter(false).Generate(results)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}
			for _, sk := range tt.files {
				if want := "\n    " + sk.File + "  " + sk.Reason + "\n"; !strings.Contains(output, want) {
					t.Errorf("text report is missing %q", want)
				}
			}
			if got := strings.Contains(output, manifestAdvice); got != tt.wantManifest {
				t.Errorf("text report has %q: %v, want %v", manifestAdvice, got, tt.wantManifest)
			}
			if got := strings.Contains(output, minifiedAdvice); got != tt.wantMinified {
				t.Errorf("text report has %q: %v, want %v", minifiedAdvice, got, tt.wantMinified)
			}
		})
	}
}

// A tree can hold many minified bundles, so the text report names ten and
// counts the rest.
func TestTextReportCapsTheSkippedFileList(t *testing.T) {
	results := createTestResults()
	for i := 0; i < 12; i++ {
		results.SkippedFiles = append(results.SkippedFiles, scanner.SkippedFile{
			File:   fmt.Sprintf("/test/path/f%02d.min.js", i),
			Reason: "minified: the file name ends in .min.js",
		})
	}
	output, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if !strings.Contains(output, "\n  12 file(s) were not scanned,") {
		t.Errorf("text report does not count all 12 skipped files:\n%s", output)
	}
	if n := strings.Count(output, "/test/path/f"); n != 10 {
		t.Errorf("text report names %d skipped files, want 10", n)
	}
	if !strings.Contains(output, "/test/path/f09.min.js") || strings.Contains(output, "/test/path/f10.min.js") {
		t.Error("text report should name the first ten skipped files in order")
	}
	if want := "\n    and 2 more, listed under skippedFiles in --format json\n"; !strings.Contains(output, want) {
		t.Errorf("text report is missing %q", want)
	}
}

func TestJSONReportListsSkippedFiles(t *testing.T) {
	results := createTestResults()
	want := []scanner.SkippedFile{
		{File: "/test/path/app.js", Reason: "minified or generated: its lines average 674 bytes"},
	}
	results.SkippedFiles = want
	output, err := NewJSONReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var report struct {
		SkippedFiles []scanner.SkippedFile `json:"skippedFiles"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !reflect.DeepEqual(report.SkippedFiles, want) {
		t.Errorf("skippedFiles = %+v, want %+v", report.SkippedFiles, want)
	}
}
