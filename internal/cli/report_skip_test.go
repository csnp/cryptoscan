// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/reporter"
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

// desSource creates a DES cipher, which is reported at CRITICAL, so gate fails
// on it at its default threshold.
const desSource = "from Crypto.Cipher import DES\n\n\n" +
	"def encrypt(key, data):\n" +
	"    cipher = DES.new(key, DES.MODE_ECB)\n" +
	"    return cipher.encrypt(data)\n"

// streamHeaderDES is desSource below the line a scan prints ahead of the
// findings it streams, so that it starts like a scan's text output.
const streamHeaderDES = "Scanning... (findings appear as discovered)\n" + desSource

// setIncludeReports gives cmd --include-reports as the command line would,
// and takes it back when the test ends.
func setIncludeReports(t *testing.T, cmd *cobra.Command) {
	t.Helper()
	if err := cmd.ParseFlags([]string{"--include-reports"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f := cmd.Flags().Lookup("include-reports")
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
}

// The reproduction from the report: gate fails on a Python file that creates
// a DES cipher, and passed the same file with the stream header as its first
// line, which it listed as a CryptoScan report and did not read; no option
// read it. Without the flag that is unchanged, and the list now names
// --include-reports. With the flag, gate reads the file and fails on it.
func TestGateIncludeReportsReadsSourceThatStartsWithTheStreamHeader(t *testing.T) {
	plain := writeFixture(t, "legacy.py", desSource)
	headed := writeFixture(t, "legacy.py", streamHeaderDES)
	listed := "    " + filepath.Join(headed, "legacy.py") + "  CryptoScan report: text\n"
	gate := func(dir string) (int, string) {
		t.Helper()
		var code int
		out := captureStdout(func() {
			var err error
			if code, err = gateTarget(gateCmd, dir); err != nil {
				t.Errorf("gate %s: %v", dir, err)
			}
		})
		return code, out
	}

	resetPipelineFlags(t)
	if code, out := gate(plain); code != 1 {
		t.Fatalf("gate on the DES file: exit code %d, want 1\n%s", code, out)
	}
	code, out := gate(headed)
	if code != 0 {
		t.Errorf("gate on the DES file under the stream header: exit code %d, want 0 without --include-reports\n%s", code, out)
	}
	for _, want := range []string{listed, "\n  " + reporter.IncludeReportsHint + "\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("gate text report lacks %q:\n%s", want, out)
		}
	}

	setIncludeReports(t, gateCmd)
	code, out = gate(headed)
	if code != 1 || strings.Contains(out, listed) || strings.Contains(out, "--include-reports") {
		t.Errorf("gate --include-reports: exit code %d, want 1, with the file read rather than listed:\n%s", code, out)
	}
	outputFormat = "json"
	code, out = gate(headed)
	var report scanner.Results
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("gate --include-reports --format json stdout is not JSON: %v\n%s", err, out)
	}
	des := 0
	for _, f := range report.Findings {
		if f.Algorithm == "DES" {
			des++
		}
	}
	if code != 1 || report.FilesScanned != 1 || len(report.SkippedFiles) != 0 || des == 0 {
		t.Errorf("gate --include-reports --format json: exit code %d, filesScanned %d, skippedFiles %+v, DES findings %d; want 1, 1, none and at least 1",
			code, report.FilesScanned, report.SkippedFiles, des)
	}
}

// cbom and pqc leave the same file out and name it on stderr, and read it
// with --include-reports, when their output describes the DES cipher.
func TestCbomAndPqcIncludeReports(t *testing.T) {
	dir := writeFixture(t, "legacy.py", streamHeaderDES)
	listed := "  " + filepath.Join(dir, "legacy.py") + "  CryptoScan report: text\n"
	for _, run := range []struct {
		cmd    *cobra.Command
		target func(*cobra.Command, string) (int, error)
	}{
		{cbomCmd, cbomTarget},
		{pqcCmd, pqcTarget},
	} {
		for _, include := range []bool{false, true} {
			resetPipelineFlags(t)
			outputFormat = "json"
			if include {
				setIncludeReports(t, run.cmd)
			}
			var stdout string
			stderr := captureStderr(func() {
				stdout = captureStdout(func() {
					if _, err := run.target(run.cmd, dir); err != nil {
						t.Errorf("%s: %v", run.cmd.Name(), err)
					}
				})
			})
			gotListed, gotDES := strings.Contains(stderr, listed), strings.Contains(stdout, `"DES"`)
			if gotListed == include || gotDES != include {
				t.Errorf("%s, --include-reports %v: file named on stderr %v, \"DES\" in the output %v; want %v and %v\nstdout:\n%s\nstderr:\n%s",
					run.cmd.Name(), include, gotListed, gotDES, !include, include, stdout, stderr)
			}
		}
	}
}

// For the formats other than text, the notice on stderr ends with the flag
// when a file on it was left out for how it starts, wherever that file is on
// the list. The file --output names is left out for being that file, and
// --include-reports does not read it, so it alone gets no such line.
func TestSkippedNoticeNamesIncludeReports(t *testing.T) {
	hint := "cryptoscan: " + reporter.IncludeReportsHint + "\n"
	recognized := scanner.SkippedFile{File: "/src/legacy.py", Reason: "CryptoScan report: text"}
	output := scanner.SkippedFile{File: "/src/report.json", Reason: "CryptoScan report: the --output file of this scan"}
	minified := scanner.SkippedFile{File: "/src/app.min.js", Reason: "minified: the file name ends in .min.js"}
	var eleventh []scanner.SkippedFile
	for i := 0; i < maxSkippedNamed; i++ {
		eleventh = append(eleventh, minified)
	}
	eleventh = append(eleventh, recognized)

	for _, tt := range []struct {
		name  string
		files []scanner.SkippedFile
		want  bool
	}{
		{"file that starts like a report", []scanner.SkippedFile{recognized}, true},
		{"that file and the --output file", []scanner.SkippedFile{recognized, output}, true},
		{"that file eleventh on the list", eleventh, true},
		{"the --output file alone", []scanner.SkippedFile{output}, false},
		{"minified file alone", []scanner.SkippedFile{minified}, false},
	} {
		for _, format := range []string{"json", "sarif", "csv", "cbom"} {
			var buf bytes.Buffer
			writeSkippedNotice(&buf, format, tt.files)
			notice := buf.String()
			if got := strings.HasSuffix(notice, hint); got != tt.want || strings.Count(notice, hint) > 1 {
				t.Errorf("%s, %s: notice ends with %q: %v, want %v (once)\n%s", tt.name, format, hint, got, tt.want, notice)
			}
		}
	}
}

// Every command that runs a scan takes --include-reports with the same help,
// since each of them leaves out the files that start like a CryptoScan report.
func TestIncludeReportsOnEveryCommandThatScans(t *testing.T) {
	for _, cmd := range []*cobra.Command{scanCmd, gateCmd, cbomCmd, pqcCmd} {
		f := cmd.Flags().Lookup("include-reports")
		if f == nil {
			t.Errorf("%s has no --include-reports flag", cmd.Name())
			continue
		}
		if f.Usage != includeReportsUsage || f.DefValue != "false" {
			t.Errorf("%s --include-reports: usage %q, default %s; want %q, false", cmd.Name(), f.Usage, f.DefValue, includeReportsUsage)
		}
	}
}
