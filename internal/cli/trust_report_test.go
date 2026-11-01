// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// trustBundle is a committed CA bundle laid out as the OpenBSD cert.pem is:
// fifty-eight generated Ed25519 test CA certificates, each after a text
// header computed from it (subject, signature algorithm, validity, SHA-1 and
// SHA-256 fingerprints), with the removed root, after a header of its own,
// following the first fifty-five. The keys of the generated certificates were
// not kept. The root's block starts after more than 200 other matches, past
// the end of the list the scan prints while it runs, and the report's
// priority order puts the SHA-1 findings of the headers before the root's
// trust finding.
const (
	trustBundle     = "../../pkg/patterns/testdata/trust-bundle"
	trustBundleFile = "ca-bundle.crt"
	trustRootFile   = "../../pkg/patterns/testdata/trust/root/86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b.crt"
)

// The two commands the removed-root page gives under its Fix, after the
// trust-store paragraph, and the sentence beside the first. FILE is the name
// of the file whose match is recorded as reviewed.
const (
	pageCategoryCommand = `cryptoscan gate . --ignore-category "Certificate,Deprecated Hash,Asymmetric Encryption"`
	pageExcludeSentence = "Excluding the file's path hides this finding too."
	pageRecordCommand   = "cryptoscan scan FILE --format json --output reviewed.json"
	pageReviewedCommand = "cryptoscan gate . --baseline reviewed.json"
)

// rootLineIn returns the line of the removed root's header in the bundle at
// path, read from the committed root certificate, which the bundle holds once.
func rootLineIn(t *testing.T, path string) int {
	t.Helper()
	bundle, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile(trustRootFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(bundle), string(root)) != 1 {
		t.Fatalf("%s does not hold the committed root exactly once", path)
	}
	if strings.Contains(string(bundle), "PRIVATE KEY") {
		t.Fatalf("%s holds a private key block", path)
	}
	return strings.Count(string(bundle[:strings.Index(string(bundle), string(root))]), "\n") + 1
}

// afterScanComplete returns the line that follows the scan-complete line of
// a text report, and the lines before it.
func afterScanComplete(t *testing.T, stdout string) (string, []string) {
	t.Helper()
	lines := strings.Split(stdout, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "  Scan complete: ") && i+1 < len(lines) {
			return lines[i+1], lines[:i]
		}
	}
	t.Fatalf("no scan-complete line in:\n%s", stdout)
	return "", nil
}

// On a CA bundle whose other findings come first in the report's order, the
// text report prints the trust block as Finding #1, and the line after the
// scan-complete line names the trust finding count and the first trust
// finding's file and line. The root comes after the end of the list the scan
// prints while it runs, so that line is the first place the output names it.
// gate prints the same report: the page-command test below runs it on a tree
// that holds this bundle.
func TestTrustBundleReportListsTheTrustFindingFirst(t *testing.T) {
	bundle, err := filepath.Abs(filepath.Join(trustBundle, trustBundleFile))
	if err != nil {
		t.Fatal(err)
	}
	rootLine := rootLineIn(t, bundle)
	rootAt := bundle + ":" + strconv.Itoa(rootLine)
	out := runTrust(t, scanCmd, trustBundle, "--no-color")
	if out.err != "" || out.code != 0 {
		t.Errorf("scan: exit %d, error %q, want exit 0", out.code, out.err)
	}
	next, streamed := afterScanComplete(t, out.stdout)
	if want := "  1 Trust finding, at " + rootAt; next != want {
		t.Errorf("the line after the scan-complete line is %q, want %q", next, want)
	}
	if !strings.Contains(strings.Join(streamed, "\n"), "Matches after the first 200 are not listed") {
		t.Error("the streamed list does not stop before the root")
	}
	for _, line := range streamed {
		if strings.Contains(line, trustBundleFile+":"+strconv.Itoa(rootLine)) {
			t.Errorf("the streamed list reaches the root: %q", line)
		}
	}
	blocks := reportBlocks(out.stdout)
	if len(blocks) < 2 {
		t.Fatalf("%d finding blocks", len(blocks))
	}
	if want := "  ┌── Finding #1 [HIGH]\n  │ Type: " + rootFileType + "\n  │ File: " + rootAt + "\n"; !strings.HasPrefix(blocks[0], want) {
		t.Errorf("Finding #1 is not the trust block:\n%s", blocks[0][:min(len(blocks[0]), 400)])
	}
	for i, b := range blocks[1:] {
		if strings.Contains(b, "│ Reference: "+trustPages[distrustedRootID]) {
			t.Errorf("Finding #%d is a trust block after another finding", i+2)
		}
	}
}

// With more than one trust finding, the line after the scan-complete line
// gives their count and names the file and line of Finding #1.
func TestTrustCountLineNamesFindingOne(t *testing.T) {
	out := runTrust(t, scanCmd, trustFixture, "--no-color")
	next, _ := afterScanComplete(t, out.stdout)
	blocks := reportBlocks(out.stdout)
	if len(blocks) == 0 {
		t.Fatal("no finding blocks")
	}
	_, rest, _ := strings.Cut(blocks[0], "\n  │ File: ")
	file, _, _ := strings.Cut(rest, "\n")
	if want := "  " + strconv.Itoa(trustFixtureFindings) + " Trust findings, the first at " + file; file == "" || next != want {
		t.Errorf("the line after the scan-complete line is %q, want %q", next, want)
	}
}

// With no trust finding in the report, the line after the scan-complete line
// says nothing about trust findings: on the control bundle, and on the trust
// fixture when both trust patterns are ignored.
func TestTrustCountLineAbsentWithoutATrustFinding(t *testing.T) {
	for _, c := range []struct {
		target string
		args   []string
	}{
		{filepath.Join(trustFixture, "control"), nil},
		{trustFixture, []string{"--ignore", compromisedKeyID + "," + distrustedRootID}},
	} {
		out := runTrust(t, scanCmd, c.target, append([]string{"--no-color"}, c.args...)...)
		if next, _ := afterScanComplete(t, out.stdout); strings.Contains(next, "Trust finding") {
			t.Errorf("scan %s %v: the line after the scan-complete line is %q", c.target, c.args, next)
		}
	}
}

// pageCommand runs a cryptoscan command as the removed-root page prints it,
// with target in place of the page's target and the flags as a shell would
// split them.
func pageCommand(t *testing.T, command, target string) scanOutcome {
	t.Helper()
	words := shellWord.FindAllString(command, -1)
	if len(words) < 3 || words[0] != "cryptoscan" {
		t.Fatalf("%q is not a cryptoscan command with a target", command)
	}
	cmd, ok := map[string]*cobra.Command{"scan": scanCmd, "gate": gateCmd}[words[1]]
	if !ok {
		t.Fatalf("%q is not a scan or gate command", command)
	}
	args := make([]string, 0, len(words)-3)
	for _, w := range words[3:] {
		args = append(args, strings.Trim(w, `"`))
	}
	return runTrust(t, cmd, target, args...)
}

// The removed-root page gives, under its Fix and after the trust-store
// paragraph, a command that leaves out a bundle's other findings by category
// and keeps its trust finding, with the sentence that excluding the file's
// path hides this finding too; and a command that records the match of a
// file held on purpose as reviewed, with the gate command that uses the
// record. Both run here as the page prints them, with the exit codes it
// states: the category command exits 1 with the trust finding alone; with
// the record, gate exits 0 on a folder that holds only the reviewed file,
// exits 1 and reports the other file once a second file holds the root, and
// still exits 0 after the reviewed file's lines move.
func TestTrustPageCommandsForTheRemovedRoot(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../../docs/findings", "trust-distrusted-root.md"))
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	_, fix, ok := strings.Cut(page, "\n## Fix\n")
	if !ok {
		t.Fatal("the page has no Fix section")
	}
	fix, _, _ = strings.Cut(fix, "\n## ")
	_, afterStore, ok := strings.Cut(fix, "\n- Trust store or CA bundle (rule 3): ")
	if !ok {
		t.Fatal("the Fix section has no trust-store paragraph")
	}
	for _, want := range []string{"`" + pageCategoryCommand + "`", pageExcludeSentence, "`" + pageRecordCommand + "`", "`" + pageReviewedCommand + "`"} {
		if !strings.Contains(afterStore, want) {
			t.Errorf("the Fix section does not carry %q after the trust-store paragraph", want)
		}
	}

	// The category command, on the committed bundle.
	out := pageCommand(t, pageCategoryCommand, trustBundle)
	blocks := reportBlocks(out.stdout)
	if out.err != "" || out.code != 1 || !strings.Contains(out.stdout, "Total Findings: 1 ") || len(blocks) != 1 ||
		!strings.Contains(blocks[0], "│ Reference: "+trustPages[distrustedRootID]+"\n") {
		t.Errorf("%s: exit %d, error %q, %d blocks; want exit 1 and the trust finding alone", pageCategoryCommand, out.code, out.err, len(blocks))
	}
	// Excluding the bundle's path hides the trust finding.
	out = runTrust(t, scanCmd, trustBundle, "--no-color", "--fail-on", "high", "--exclude", trustBundleFile)
	if out.err != "" || out.code != 0 || strings.Contains(out.stdout, "Trust finding") || len(reportBlocks(out.stdout)) != 0 {
		t.Errorf("scan --exclude %s: exit %d, error %q; want exit 0 and no trust finding", trustBundleFile, out.code, out.err)
	}

	// The record, made in a folder that holds only the reviewed file.
	root, err := os.ReadFile(trustRootFile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(trustBundle, trustBundleFile))
	if err != nil {
		t.Fatal(err)
	}
	secondRootLine := rootLineIn(t, filepath.Join(trustBundle, trustBundleFile))
	dir := t.TempDir()
	const reviewed = "distrusted.pem"
	if err := os.WriteFile(filepath.Join(dir, reviewed), root, 0o644); err != nil {
		t.Fatal(err)
	}
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
	out = pageCommand(t, pageRecordCommand, reviewed)
	if out.err != "" {
		t.Fatalf("%s: %s", pageRecordCommand, out.err)
	}
	record, err := os.ReadFile("reviewed.json")
	if err != nil {
		t.Fatalf("%s wrote no record: %v", pageRecordCommand, err)
	}
	if !strings.Contains(string(record), distrustedRootID+"-") {
		t.Fatalf("the record does not hold the root's finding")
	}

	// (i) A folder that holds only the reviewed file passes.
	out = pageCommand(t, pageReviewedCommand, ".")
	if out.err != "" || out.code != 0 || len(reportBlocks(out.stdout)) != 0 {
		t.Errorf("(i) %s on the reviewed file alone: exit %d, error %q, %d blocks; want exit 0 and none", pageReviewedCommand, out.code, out.err, len(reportBlocks(out.stdout)))
	}
	if next, _ := afterScanComplete(t, out.stdout); strings.Contains(next, "Trust finding") {
		t.Errorf("(i) the line after the scan-complete line is %q", next)
	}

	// (ii) A second file that holds the root fails the gate, which reports
	// that file and not the reviewed one.
	if err := os.WriteFile(trustBundleFile, second, 0o644); err != nil {
		t.Fatal(err)
	}
	out = pageCommand(t, pageReviewedCommand, ".")
	blocks = reportBlocks(out.stdout)
	if out.err != "" || out.code != 1 || len(blocks) == 0 || !strings.Contains(blocks[0], "│ Type: "+rootFileType+"\n") {
		t.Errorf("(ii) %s with a second file holding the root: exit %d, error %q; want exit 1 and the second file's trust block first", pageReviewedCommand, out.code, out.err)
	}
	for _, b := range blocks {
		if !strings.Contains(b, "/"+trustBundleFile+":") {
			t.Errorf("(ii) a block does not name %s:\n%s", trustBundleFile, b[:min(len(b), 300)])
		}
	}
	if next, _ := afterScanComplete(t, out.stdout); !strings.HasPrefix(next, "  1 Trust finding, at ") || !strings.HasSuffix(next, "/"+trustBundleFile+":"+strconv.Itoa(secondRootLine)) {
		t.Errorf("(ii) the line after the scan-complete line is %q, want the second file's root", next)
	}

	// (iii) With the second file gone, a line added above the root in the
	// reviewed file does not bring its finding back: the record keys a
	// finding on its file, its pattern and the text of its line, not on its
	// line number.
	if err := os.Remove(trustBundleFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reviewed, append([]byte("# held on purpose, reviewed\n"), root...), 0o644); err != nil {
		t.Fatal(err)
	}
	out = pageCommand(t, pageReviewedCommand, ".")
	if out.err != "" || out.code != 0 || len(reportBlocks(out.stdout)) != 0 {
		t.Errorf("(iii) %s after the reviewed file's lines moved: exit %d, error %q; want exit 0", pageReviewedCommand, out.code, out.err)
	}
}
