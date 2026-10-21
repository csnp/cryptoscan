// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/spf13/cobra"
)

// The reviewed tree. SHA-1 is reported at high severity, which is what a
// "--fail-on high" check trips on, and stays below critical so that runScan
// does not exit the test binary when a finding is reported as new.
const reviewedApp = `import hashlib


def fingerprint(data):
    return hashlib.sha1(data).hexdigest()


def legacy_id(data):
    return hashlib.sha1(data + b"id").hexdigest()
`

const reviewedTool = `import hashlib

DIGEST = hashlib.sha1(b"tool").hexdigest()
`

func writeReviewedTree(t *testing.T, dir string, app string) {
	t.Helper()
	files := map[string]string{
		filepath.Join("src", "app.py"):    app,
		filepath.Join("tools", "tool.py"): reviewedTool,
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// scanTree runs "cryptoscan scan . --format json --output out [--baseline b]"
// from inside dir, the form the README's CI recipe uses, and returns the
// findings written to out.
func scanTree(t *testing.T, dir, baseline, out string) []scanner.Finding {
	t.Helper()

	prevFormat, prevOutput, prevBaseline := outputFormat, outputFile, baselineFile
	prevFailOn, prevSeverity, prevConfig := failOn, minSeverity, configFile
	prevNoColor, prevProgress, prevStream := noColor, showProgress, streamFindings
	defer func() {
		outputFormat, outputFile, baselineFile = prevFormat, prevOutput, prevBaseline
		failOn, minSeverity, configFile = prevFailOn, prevSeverity, prevConfig
		noColor, showProgress, streamFindings = prevNoColor, prevProgress, prevStream
	}()

	outputFormat, outputFile, baselineFile = "json", out, baseline
	failOn, minSeverity, configFile = "", "", ""
	noColor, showProgress, streamFindings = true, false, false

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatal(err)
		}
	}()

	if err := runScan(&cobra.Command{}, []string{"."}); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	return loadReportFindings(t, out)
}

func loadReportFindings(t *testing.T, path string) []scanner.Finding {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Findings []scanner.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	return report.Findings
}

// writeBaseline scans dir and writes the report to a file outside the tree.
func writeBaseline(t *testing.T, dir string) string {
	t.Helper()
	baseline := filepath.Join(t.TempDir(), "baseline.json")
	if reviewed := scanTree(t, dir, "", baseline); len(reviewed) < 3 {
		t.Fatalf("the reviewed tree should report 3 findings, got %d", len(reviewed))
	}
	return baseline
}

func describe(findings []scanner.Finding) string {
	var lines []string
	for _, f := range findings {
		lines = append(lines, f.ID+" "+f.File+": "+f.Match)
	}
	return strings.Join(lines, "\n  ")
}

func TestBaselineAcceptsAnotherCheckout(t *testing.T) {
	a := t.TempDir()
	writeReviewedTree(t, a, reviewedApp)
	baseline := writeBaseline(t, a)

	// A byte-identical checkout at another path, which is what every CI
	// runner sees.
	b := t.TempDir()
	writeReviewedTree(t, b, reviewedApp)

	out := filepath.Join(t.TempDir(), "out.json")
	got := scanTree(t, b, baseline, out)
	if len(got) != 0 {
		t.Errorf("an identical checkout at another path should report 0 new findings, got %d:\n  %s",
			len(got), describe(got))
	}

	// Nothing new is an empty list, as for a scan that found nothing.
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]json.RawMessage
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if got := string(report["findings"]); got != "[]" {
		t.Errorf("a report with nothing new should list findings as [], got %s", got)
	}
}

func TestBaselineAcceptsLineShift(t *testing.T) {
	a := t.TempDir()
	writeReviewedTree(t, a, reviewedApp)
	baseline := writeBaseline(t, a)

	// One blank line above every reviewed finding in the file.
	writeReviewedTree(t, a, "\n"+reviewedApp)

	got := scanTree(t, a, baseline, filepath.Join(t.TempDir(), "out.json"))
	if len(got) != 0 {
		t.Errorf("a blank line above reviewed findings should report 0 new findings, got %d:\n  %s",
			len(got), describe(got))
	}
}

func TestBaselineReportsNewCall(t *testing.T) {
	a := t.TempDir()
	writeReviewedTree(t, a, reviewedApp)
	baseline := writeBaseline(t, a)

	// A genuinely new call, placed above the reviewed ones so that they move.
	newCall := `    return hashlib.sha1(data + b"sum").hexdigest()`
	app := strings.Replace(reviewedApp, "def fingerprint",
		"def checksum(data):\n"+newCall+"\n\n\ndef fingerprint", 1)
	writeReviewedTree(t, a, app)

	got := scanTree(t, a, baseline, filepath.Join(t.TempDir(), "out.json"))
	if len(got) != 1 {
		t.Fatalf("one new call should report exactly 1 new finding, got %d:\n  %s",
			len(got), describe(got))
	}
	if got[0].Line != 5 || !strings.HasSuffix(filepath.ToSlash(got[0].File), "src/app.py") {
		t.Errorf("the new finding should be src/app.py line 5, got %s line %d", got[0].File, got[0].Line)
	}
}

func TestBaselineReportsCopiedLine(t *testing.T) {
	a := t.TempDir()
	writeReviewedTree(t, a, reviewedApp)
	baseline := writeBaseline(t, a)

	// A second copy of a reviewed line is new use of SHA-1 even though its
	// text matches a reviewed entry: the baseline covers one such line.
	copied := `    return hashlib.sha1(data).hexdigest()`
	app := strings.Replace(reviewedApp, "def fingerprint",
		"def fingerprint_copy(data):\n"+copied+"\n\n\ndef fingerprint", 1)
	writeReviewedTree(t, a, app)

	got := scanTree(t, a, baseline, filepath.Join(t.TempDir(), "out.json"))
	if len(got) != 1 {
		t.Errorf("a copied reviewed line should report exactly 1 new finding, got %d:\n  %s",
			len(got), describe(got))
	}
}

func TestPatternID(t *testing.T) {
	for _, tc := range []struct {
		id   string
		line int
		want string
	}{
		{"SHA1-001-5-11", 5, "SHA1-001"},
		{"RSA-1024-1024-3", 1024, "RSA-1024"},
		{"3DES-001-12-0", 12, "3DES-001"},
		{"RSA-001-a1b2c3d4", 7, "RSA-001"},
		{"CERT-SELFSIGNED-001", 1, "CERT-SELFSIGNED-001"},
		{"DEP-pycryptodome-requirements.txt", 1, "DEP-pycryptodome-requirements.txt"},
	} {
		if got := patternID(scanner.Finding{ID: tc.id, Line: tc.line}); got != tc.want {
			t.Errorf("patternID(%q, line %d) = %q, want %q", tc.id, tc.line, got, tc.want)
		}
	}
}

func TestRelativeToKeepsOutsidePathsAbsolute(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "repo")
	inside := filepath.Join(root, "src", "app.py")
	outside := filepath.Join(work, "other", "app.py")

	if got := relativeTo(root, inside); got != "src/app.py" {
		t.Errorf("relativeTo(inside) = %q, want src/app.py", got)
	}
	if got := relativeTo(root, outside); got != filepath.ToSlash(outside) {
		t.Errorf("relativeTo(outside) = %q, want the absolute path", got)
	}
	if got := relativeTo(inside, inside); got != "app.py" {
		t.Errorf("relativeTo(file, file) = %q, want app.py", got)
	}
}

func TestInferBaselineRootPrefersWhatMostFilesAgreeOn(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	entries := []scanner.Finding{
		{File: filepath.Join(root, "src", "app.py")},
		{File: filepath.Join(root, "src", "app.py")},
		{File: filepath.Join(root, "tools", "tool.py")},
	}
	// The current tree also has a top-level app.py, which proposes root/src
	// for the first entry. Two files agree on root, one on root/src.
	current := map[string]bool{"src/app.py": true, "app.py": true, "tools/tool.py": true}
	if got := inferBaselineRoot(entries, current); got != root {
		t.Errorf("inferBaselineRoot = %q, want %q", got, root)
	}

	// With a single file, both directories get one vote; the shorter one
	// matches the longer relative path and wins.
	if got := inferBaselineRoot(entries[:1], current); got != root {
		t.Errorf("inferBaselineRoot with one file = %q, want %q", got, root)
	}

	if got := inferBaselineRoot(entries, map[string]bool{"other.py": true}); got != "" {
		t.Errorf("inferBaselineRoot with no match = %q, want empty", got)
	}
}

// A baseline written by 1.4.0 has no recorded scan root, and its scanTarget is
// whatever the user typed: "." for the README recipe, or an absolute path.
func TestBaselineFromEarlierRelease(t *testing.T) {
	a := t.TempDir()
	writeReviewedTree(t, a, reviewedApp)
	written := writeBaseline(t, a)

	// The absolute root exactly as the scan recorded it in each entry.
	var root string
	for _, f := range loadReportFindings(t, written) {
		if dir, ok := strings.CutSuffix(f.File, filepath.Join("src", "app.py")); ok {
			root = filepath.Clean(dir)
		}
	}
	if !filepath.IsAbs(root) {
		t.Fatalf("baseline entries should carry absolute paths, got root %q", root)
	}

	for _, tc := range []struct {
		name       string
		scanTarget string
	}{
		{"target written as dot", "."},
		{"target written as absolute path", root},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(written)
			if err != nil {
				t.Fatal(err)
			}
			var report map[string]json.RawMessage
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			delete(report, "metadata")
			report["scanTarget"], _ = json.Marshal(tc.scanTarget)
			legacy, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			baseline := filepath.Join(t.TempDir(), "baseline.json")
			if err := os.WriteFile(baseline, legacy, 0o644); err != nil {
				t.Fatal(err)
			}

			b := t.TempDir()
			writeReviewedTree(t, b, "\n"+reviewedApp)
			got := scanTree(t, b, baseline, filepath.Join(t.TempDir(), "out.json"))
			if len(got) != 0 {
				t.Errorf("an earlier baseline should still cover the reviewed findings, got %d new:\n  %s",
					len(got), describe(got))
			}
		})
	}
}

// A URL scan reports paths relative to the repository root and records no
// scan root. A baseline written by an earlier URL scan holds the paths of a
// clone that has since been removed, with or without that clone as its
// recorded root, and must still cover the same findings.
func TestBaselineCoversURLScanWithRelativePaths(t *testing.T) {
	const url = "https://example.invalid/org/repo.git"
	clone := filepath.Join(t.TempDir(), "cryptoscan-1234")
	finding := func(file string, line int) scanner.Finding {
		return scanner.Finding{
			ID:    "SHA1-001-" + strconv.Itoa(line) + "-11",
			File:  file,
			Line:  line,
			Match: "hashlib.sha1(data)",
		}
	}
	// The current scan: one line added at the top shifts the finding.
	current := []scanner.Finding{finding("src/app.py", 6)}

	for _, tc := range []struct {
		name string
		b    baseline
	}{
		{"this release", baseline{ScanTarget: url,
			Findings: []scanner.Finding{finding("src/app.py", 5)}}},
		{"earlier release with scanRoot", baseline{ScanTarget: url,
			Metadata: map[string]string{scanner.MetadataScanRoot: clone},
			Findings: []scanner.Finding{finding(filepath.Join(clone, "src", "app.py"), 5)}}},
		{"1.4.0 without scanRoot", baseline{ScanTarget: url,
			Findings: []scanner.Finding{finding(filepath.Join(clone, "src", "app.py"), 5)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := filterNewFindings(current, "", &tc.b); len(got) != 0 {
				t.Errorf("the baseline should cover the finding, got %d new:\n  %s", len(got), describe(got))
			}
			moved := []scanner.Finding{finding("lib/app.py", 6)}
			if got := filterNewFindings(moved, "", &tc.b); len(got) != 1 {
				t.Errorf("a finding in another file should be new, got %d new", len(got))
			}
		})
	}
}
