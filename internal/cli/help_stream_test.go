// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// cryptoscan --help opens by saying what the tool does, in plain words.
func TestRootHelpOpensWithAPlainDescription(t *testing.T) {
	paragraphs := strings.Split(rootCmd.Long, "\n\n")
	if len(paragraphs) < 2 {
		t.Fatalf("root help has %d paragraphs, want a title and a description", len(paragraphs))
	}
	opening := paragraphs[1]
	if !strings.HasPrefix(opening, "CryptoScan finds the cryptographic algorithms") {
		t.Errorf("root help opens with %q", firstLine(opening))
	}
	for _, word := range []string{"powerful", "enterprise-grade", "empower", "cutting-edge", "world-class"} {
		if strings.Contains(strings.ToLower(rootCmd.Long), word) {
			t.Errorf("root help contains %q", word)
		}
	}
}

// The scan help uses the report's words for SHA-2 and AES: the report classes
// them PARTIAL, not quantum-safe. A default scan leaves a SHA-256 call and an
// AES cipher out, and --include-quantum-safe reports both as PARTIAL.
func TestScanHelpUsesTheReportWordsForSHA2AndAES(t *testing.T) {
	if !strings.Contains(scanCmd.Long, "The report classes SHA-2 and AES as PARTIAL") {
		t.Error("scan --help does not say that the report classes SHA-2 and AES as PARTIAL")
	}
	if strings.Contains(scanCmd.Long, "Quantum-safe algorithms, including AES") {
		t.Error("scan --help still calls AES and SHA-2 quantum-safe")
	}
	usage := scanCmd.Flags().Lookup("include-quantum-safe").Usage
	if !strings.Contains(usage, "SHA-2 and AES") || !strings.Contains(usage, "PARTIAL") {
		t.Errorf("--include-quantum-safe help reads %q", usage)
	}

	dir := t.TempDir()
	writeFixtureFile(t, filepath.Join(dir, "digest.py"), "def digest(data):\n    return hashlib.sha256(data).hexdigest()\n\n"+
		"def seal(key):\n    return AES.new(key, AES.MODE_CBC)\n")
	partial := func(args ...string) map[string][]scanner.Finding {
		out := runScanWith(t, dir, append([]string{"--stream=false", "--format", "json"}, args...)...)
		var report scanner.Results
		if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
			t.Fatalf("scan output is not JSON: %v\n%s", err, out.stdout)
		}
		found := map[string][]scanner.Finding{}
		for _, f := range report.Findings {
			if f.Algorithm == "SHA-2" || f.Algorithm == "AES" {
				found[f.Algorithm] = append(found[f.Algorithm], f)
			}
		}
		return found
	}
	if got := partial(); len(got) != 0 {
		t.Errorf("a default scan reported %v, which the help says are left out", got)
	}
	got := partial("--include-quantum-safe")
	for _, algo := range []string{"SHA-2", "AES"} {
		if len(got[algo]) == 0 {
			t.Errorf("--include-quantum-safe did not report the %s line", algo)
		}
		for _, f := range got[algo] {
			if f.Quantum != scanner.QuantumPartial {
				t.Errorf("%s finding at line %d is classed %s, and the help says PARTIAL", algo, f.Line, f.Quantum)
			}
		}
	}
}

// The --fail-on help names what a scan does without it: a CRITICAL finding
// exits 1.
func TestFailOnHelpNamesTheCriticalDefault(t *testing.T) {
	usage := scanCmd.Flags().Lookup("fail-on").Usage
	if !strings.Contains(usage, "exits 1 when any finding is CRITICAL") {
		t.Errorf("--fail-on help reads %q, which does not name the default", usage)
	}
	if !strings.Contains(scanCmd.Long, "the scan exits 1 when any finding is CRITICAL") {
		t.Error("the CI/CD section of scan --help does not name the --fail-on default")
	}
	critical := &scanner.Results{Findings: []scanner.Finding{{Severity: scanner.SeverityCritical}}}
	critical.Summary = calculateSummary(critical.Findings)
	if code := exitCode(critical, "", true); code != 1 {
		t.Errorf("without --fail-on a CRITICAL finding exits %d, and the help says 1", code)
	}
}

// streamedMatch is one numbered line of the list printed while the scan runs.
var streamedMatch = regexp.MustCompile(`(?m)^  \[\w+\] #\d+`)

// The list printed while the scan runs stops after maxStreamedMatches lines
// and says that the report lists the rest. The report still counts every
// finding.
func TestStreamListsAtMostTheFirstMatches(t *testing.T) {
	const lines = maxStreamedMatches + 30
	var body strings.Builder
	for i := 0; i < lines; i++ {
		fmt.Fprintf(&body, "h%d = hashlib.md5(data)\n", i)
	}
	dir := t.TempDir()
	writeFixtureFile(t, filepath.Join(dir, "digests.py"), body.String())

	out := runScanWith(t, dir, "--stream").stdout

	if got := len(streamedMatch.FindAllString(out, -1)); got != maxStreamedMatches {
		t.Errorf("the stream listed %d matches, want %d", got, maxStreamedMatches)
	}
	notice := fmt.Sprintf("  Matches after the first %d are not listed while the scan runs; the report lists every finding.\n", maxStreamedMatches)
	if n := strings.Count(out, notice); n != 1 {
		t.Errorf("the stream printed the notice %d times, want once:\n%s", n, firstLines(out, maxStreamedMatches+8))
	}
	footer := fmt.Sprintf("The scan found %d matches; the list above shows the first %d.", lines, maxStreamedMatches)
	if !strings.Contains(out, footer) {
		t.Errorf("the stream footer does not say %q", footer)
	}
	if want := fmt.Sprintf("Scan complete: %d findings", lines); !strings.Contains(out, want) {
		t.Errorf("the stream footer does not say %q", want)
	}
	if want := fmt.Sprintf("Total Findings: %d ", lines); !strings.Contains(out, want) {
		t.Errorf("the report does not say %q", want)
	}
}

// The footer of a capped stream says how many matches were found and how many
// were listed, and still accounts for the repeats.
func TestPrintScanningFooterNamesTheCap(t *testing.T) {
	out := captureStdout(func() {
		printScanningFooter(streamTally{listed: 250, hidden: 50, unique: 240, reported: 240, files: 3}, time.Millisecond, false)
	})
	for _, want := range []string{
		"Scan complete: 240 findings in 3 files",
		"The scan found 250 matches; the list above shows the first 200.",
		"10 repeat a match of the same kind on the same line and are counted with it.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("footer should contain %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "The list above has") {
		t.Errorf("footer of a capped stream says how many matches the list has:\n%s", out)
	}
}

// JSON, CSV, SARIF and CBOM output names the node_modules directories the scan
// did not enter on stderr; the text report lists them itself.
func TestSkippedDependencyNoticeOnStderr(t *testing.T) {
	var buf bytes.Buffer
	writeSkippedDependencyNotice(&buf, "json", []string{"node_modules", "web/node_modules"})
	want := "cryptoscan: 2 dependency directories were not scanned, so the packages installed there are not in this report:\n" +
		"  node_modules\n  web/node_modules\n"
	if buf.String() != want {
		t.Errorf("notice reads\n%s\nwant\n%s", buf.String(), want)
	}
	for _, tc := range []struct {
		format string
		dirs   []string
	}{
		{"text", []string{"node_modules"}},
		{"sarif", nil},
	} {
		buf.Reset()
		writeSkippedDependencyNotice(&buf, tc.format, tc.dirs)
		if buf.Len() != 0 {
			t.Errorf("format %s with %d directories printed %q", tc.format, len(tc.dirs), buf.String())
		}
	}
}

// firstLines returns the first n lines of s.
func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
