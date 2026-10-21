// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/spf13/cobra"
)

// chdirForTest changes the working directory to dir until the test ends.
func chdirForTest(t *testing.T, dir string) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatal(err)
		}
	})
}

// scanHere runs "cryptoscan scan . --format <format> --output <output>
// --exclude <exclude>" from the working directory, the way the README and
// docs/ci.md run it from a project root, and returns the exit code and what
// the scan wrote to stderr.
func scanHere(t *testing.T, format, output, exclude string) (int, string) {
	t.Helper()
	resetPipelineFlags(t)
	outputFormat, outputFile, excludeGlobs = format, output, exclude
	var code int
	stderr := captureStderr(func() {
		var err error
		code, err = scanTarget(scanCmd, ".")
		if err != nil {
			t.Errorf("scan . --format %s --output %s: %v", format, output, err)
		}
	})
	return code, stderr
}

// reportSummary is what a JSON report says about which files were read: the
// base name of each file a finding is in, and the base name and reason of
// each file listed under skippedFiles.
type reportSummary struct {
	findingFiles map[string]int
	skipped      map[string]string
}

func readReportSummary(t *testing.T, path string) reportSummary {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no report written: %v", err)
	}
	var report scanner.Results
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}
	s := reportSummary{findingFiles: map[string]int{}, skipped: map[string]string{}}
	for _, f := range report.Findings {
		s.findingFiles[filepath.Base(f.File)]++
	}
	for _, sk := range report.SkippedFiles {
		s.skipped[filepath.Base(sk.File)] = sk.Reason
	}
	return s
}

// sarifResultFiles returns the base name of the file each result in the SARIF
// report at path points at.
func sarifResultFiles(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no SARIF report written: %v", err)
	}
	var report struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid SARIF report: %v", err)
	}
	var files []string
	for _, run := range report.Runs {
		for _, result := range run.Results {
			for _, loc := range result.Locations {
				files = append(files, filepath.Base(loc.PhysicalLocation.ArtifactLocation.URI))
			}
		}
	}
	return files
}

// The reproduction from the report, through the scan command: run from the
// project root, "scan . --format sarif --output results.sarif" writes its
// report into the tree it scans, and the next run read that report as
// source. The reports earlier runs wrote, in any format and from scan or
// pqc, are now named as not scanned, and the findings come from the source
// file alone. Naming the reports in --exclude leaves them off the list.
func TestScanDoesNotReadTheReportsEarlierRunsWrote(t *testing.T) {
	savedPretty, savedStream := jsonPretty, streamFindings
	t.Cleanup(func() { jsonPretty, streamFindings = savedPretty, savedStream })
	jsonPretty, streamFindings = true, false

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte("import hashlib\nh = hashlib.md5(b\"a\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	chdirForTest(t, dir)

	first, _ := scanHere(t, "sarif", "results.sarif", "")
	firstFiles := sarifResultFiles(t, "results.sarif")
	second, stderr := scanHere(t, "sarif", "results.sarif", "")
	if second != first {
		t.Errorf("exit code = %d on the second run and %d on the first; the first run's report changed the result", second, first)
	}
	if want := "results.sarif  CryptoScan report: the --output file of this scan\n"; !strings.Contains(stderr, want) {
		t.Errorf("stderr of the second run has no line ending %q:\n%s", want, stderr)
	}
	secondFiles := sarifResultFiles(t, "results.sarif")
	if len(firstFiles) == 0 || !reflect.DeepEqual(secondFiles, firstFiles) {
		t.Errorf("SARIF results are in %q on the second run and %q on the first; want the same non-empty list", secondFiles, firstFiles)
	}

	// The pqc JSON view and a scan's streamed text output, saved in the tree.
	resetPipelineFlags(t)
	outputFormat = "json"
	pqcJSON := captureStdout(func() {
		if _, err := pqcTarget(pqcCmd, "."); err != nil {
			t.Errorf("pqc . --format json: %v", err)
		}
	})
	if err := os.WriteFile("pqc.json", []byte(pqcJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	resetPipelineFlags(t)
	streamFindings = true
	streamed := captureStdout(func() {
		if _, err := scanTarget(scanCmd, "a.py"); err != nil {
			t.Errorf("scan a.py: %v", err)
		}
	})
	streamFindings = false
	if !strings.Contains(streamed, "MD5") {
		t.Fatalf("streamed output names no MD5 finding:\n%s", streamed)
	}
	if err := os.WriteFile("scan-output.log", []byte(streamed), 0o644); err != nil {
		t.Fatal(err)
	}

	scanHere(t, "json", "report.json", "")
	scanHere(t, "json", "report.json", "")
	got := readReportSummary(t, "report.json")
	wantSkipped := map[string]string{
		"pqc.json":        "CryptoScan report: JSON",
		"report.json":     "CryptoScan report: the --output file of this scan",
		"results.sarif":   "CryptoScan report: SARIF",
		"scan-output.log": "CryptoScan report: text",
	}
	if !reflect.DeepEqual(got.skipped, wantSkipped) {
		t.Errorf("skippedFiles = %v, want %v", got.skipped, wantSkipped)
	}
	if len(got.findingFiles) != 1 || got.findingFiles["a.py"] == 0 {
		t.Errorf("findings are in %v, want a.py alone", got.findingFiles)
	}

	scanHere(t, "json", "report.json", "report.json,results.sarif,pqc.json,scan-output.log")
	excluded := readReportSummary(t, "report.json")
	if len(excluded.skipped) != 0 || len(excluded.findingFiles) != 1 || excluded.findingFiles["a.py"] == 0 {
		t.Errorf("with the reports in --exclude: skippedFiles = %v, findings in %v; want none, and a.py alone",
			excluded.skipped, excluded.findingFiles)
	}
}

// The reproduction from the report on output saved with colour on: "scan
// crypto-samples --no-color=false > out/scan.log" saved text output that
// starts with the banner, and the next scan of out read it as source. What
// scan, scan --stream=false and gate print with colour on, saved in the tree,
// is now named as not scanned, and the findings come from the source file
// alone.
func TestScanDoesNotReadItsTextOutputSavedWithColourOn(t *testing.T) {
	savedStream := streamFindings
	t.Cleanup(func() { streamFindings = savedStream })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte("import hashlib\nh = hashlib.md5(b\"a\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	chdirForTest(t, dir)

	for _, run := range []struct {
		file   string
		cmd    *cobra.Command
		target func(*cobra.Command, string) (int, error)
		stream bool
	}{
		{"scan-output.log", scanCmd, scanTarget, true},
		{"scan-report.log", scanCmd, scanTarget, false},
		{"gate-output.log", gateCmd, gateTarget, true},
	} {
		resetPipelineFlags(t)
		streamFindings = run.stream
		// As --no-color=false sets it: given on the command line, the flag
		// keeps colour on although the test's stdout is a pipe.
		noColorFlag := run.cmd.Flags().Lookup("no-color")
		if err := noColorFlag.Value.Set("false"); err != nil {
			t.Fatal(err)
		}
		noColorFlag.Changed = true
		out := captureStdout(func() {
			if _, err := run.target(run.cmd, "a.py"); err != nil {
				t.Errorf("%s a.py --no-color=false: %v", run.cmd.Name(), err)
			}
		})
		noColorFlag.Changed = false
		if !strings.Contains(out, "\x1b[") || !strings.Contains(out, "MD5") {
			t.Fatalf("%s: the output has no colour sequence or names no MD5 finding:\n%s", run.file, out)
		}
		if err := os.WriteFile(run.file, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	scanHere(t, "json", "report.json", "")
	got := readReportSummary(t, "report.json")
	wantSkipped := map[string]string{
		"gate-output.log": "CryptoScan report: text",
		"scan-output.log": "CryptoScan report: text",
		"scan-report.log": "CryptoScan report: text",
	}
	if !reflect.DeepEqual(got.skipped, wantSkipped) {
		t.Errorf("skippedFiles = %v, want %v", got.skipped, wantSkipped)
	}
	if len(got.findingFiles) != 1 || got.findingFiles["a.py"] == 0 {
		t.Errorf("findings are in %v, want a.py alone", got.findingFiles)
	}
}
