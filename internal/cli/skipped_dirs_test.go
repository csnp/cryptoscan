// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/spf13/cobra"
)

func TestWriteSkippedDirectoriesNotice(t *testing.T) {
	skipped := scanner.SkippedDirectories{
		Files:       3,
		Directories: 2,
		Rules:       []string{"examples", "node_modules"},
		Paths:       []string{"examples", "node_modules"},
	}
	want := "cryptoscan: 3 files in 2 directories were not scanned (default rules: examples, node_modules). Scan them with --include-skipped.\n"
	for _, format := range []string{"json", "sarif", "csv", "cbom"} {
		var buf bytes.Buffer
		writeSkippedDirectoriesNotice(&buf, format, skipped)
		if got := buf.String(); got != want {
			t.Errorf("%s: notice = %q, want %q", format, got, want)
		}
	}

	// The text report says it itself, and directories without files hide
	// nothing.
	var buf bytes.Buffer
	writeSkippedDirectoriesNotice(&buf, "text", skipped)
	writeSkippedDirectoriesNotice(&buf, "json", scanner.SkippedDirectories{Directories: 1, Rules: []string{"dist"}, Paths: []string{"dist"}})
	if buf.Len() != 0 {
		t.Errorf("expected no notice, got %q", buf.String())
	}
}

// skippedDirsFixture is the tree from the report: the same RSA file in src/
// and in directories the scan leaves out by default, here examples/,
// fixtures/ and testdata/ from the built-in list and vendor/ from the default
// exclude patterns.
func skippedDirsFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source := "from cryptography.hazmat.primitives.asymmetric import rsa\n" +
		"key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
	for _, sub := range []string{"src", "examples", "fixtures", "testdata", "vendor"} {
		writeFixtureFile(t, filepath.Join(dir, sub, "keys.py"), source)
	}
	return dir
}

// jsonScan is the part of a JSON report these tests read.
type jsonScan struct {
	FilesScanned int                        `json:"filesScanned"`
	Skipped      scanner.SkippedDirectories `json:"skipped"`
	Findings     []struct {
		File string `json:"file"`
	} `json:"findings"`
}

// findingDirs returns the top-level directories, under dir, of the files the
// report has findings in, in name order.
func findingDirs(t *testing.T, dir string, report jsonScan) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, f := range report.Findings {
		rel, err := filepath.Rel(dir, f.File)
		if err != nil {
			t.Fatal(err)
		}
		seen[strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]] = true
	}
	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs
}

// The reproduction from the report: the scan read src/ only, said
// "Scanned: 1 files" and nothing else, and had no flag to read the rest.
func TestScanCountsSkippedDirectoriesAndIncludeSkippedScansThem(t *testing.T) {
	dir := skippedDirsFixture(t)

	var report jsonScan
	out := runScanWith(t, dir, "--stream=false", "--format", "json", "--include", "*.py")
	if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
		t.Fatalf("scan output is not JSON: %v\n%s", err, out.stdout)
	}
	want := scanner.SkippedDirectories{
		Files:       4,
		Directories: 4,
		Rules:       []string{"examples", "fixtures", "testdata", "vendor"},
		Paths:       []string{"examples", "fixtures", "testdata", "vendor"},
	}
	if !reflect.DeepEqual(report.Skipped, want) {
		t.Errorf("skipped = %+v, want %+v", report.Skipped, want)
	}
	if report.FilesScanned != 1 {
		t.Errorf("filesScanned = %d, want 1", report.FilesScanned)
	}
	if got := findingDirs(t, dir, report); !reflect.DeepEqual(got, []string{"src"}) {
		t.Errorf("findings in %q, want src only", got)
	}

	text := runScanWith(t, dir, "--stream=false", "--no-color", "--include", "*.py")
	line := "\n  4 files in 4 directories were not scanned (default rules: examples, fixtures, testdata, vendor).\n" +
		"  Scan them with --include-skipped.\n"
	if !strings.Contains(text.stdout, line) {
		t.Errorf("text report is missing %q:\n%s", line, text.stdout)
	}

	report = jsonScan{}
	out = runScanWith(t, dir, "--stream=false", "--format", "json", "--include", "*.py", "--include-skipped")
	if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
		t.Fatalf("scan output is not JSON: %v\n%s", err, out.stdout)
	}
	none := scanner.SkippedDirectories{Rules: []string{}, Paths: []string{}}
	if !reflect.DeepEqual(report.Skipped, none) {
		t.Errorf("with --include-skipped, skipped = %+v, want %+v", report.Skipped, none)
	}
	if report.FilesScanned != 5 {
		t.Errorf("with --include-skipped, filesScanned = %d, want 5", report.FilesScanned)
	}
	if got, want := findingDirs(t, dir, report), []string{"examples", "fixtures", "src", "testdata", "vendor"}; !reflect.DeepEqual(got, want) {
		t.Errorf("with --include-skipped, findings in %q, want %q", got, want)
	}

	text = runScanWith(t, dir, "--stream=false", "--no-color", "--include", "*.py", "--include-skipped")
	if strings.Contains(text.stdout, "default rules") {
		t.Errorf("with --include-skipped, the text report still counts skipped directories:\n%s", text.stdout)
	}
}

// Every command that runs a scan takes the flag the report suggests, with
// the same help, since gate prints the scan's text report and cbom and pqc
// print the notice for their formats.
func TestIncludeSkippedOnEveryCommandThatScans(t *testing.T) {
	for _, cmd := range []*cobra.Command{scanCmd, gateCmd, cbomCmd, pqcCmd} {
		f := cmd.Flags().Lookup("include-skipped")
		if f == nil {
			t.Errorf("%s has no --include-skipped flag", cmd.Name())
			continue
		}
		if f.Usage != includeSkippedUsage || f.DefValue != "false" {
			t.Errorf("%s --include-skipped: usage %q, default %s; want %q, false", cmd.Name(), f.Usage, f.DefValue, includeSkippedUsage)
		}
	}
}
