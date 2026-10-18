// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/csnp/cryptoscan/pkg/version"
)

// The README shows what "cryptoscan scan crypto-samples" prints, trimmed from
// a capture under docs/captures. These tests keep the three in step: the
// README block must be the capture trimmed as the capture's metadata says, the
// metadata must describe the capture file, and the lines the README shows must
// still be what the scanner prints today.
//
// For a release, regenerate all three from one scan:
//
//	go test -ldflags "-X github.com/csnp/cryptoscan/pkg/version.value=<version>" \
//	  ./internal/cli -run TestReadmeExcerptIsCurrent -update-capture=/tmp/cryptoscan
//
// The directory must be empty or absent; its path appears in the capture.
const (
	readmePath      = "../../README.md"
	captureMetaPath = "../../docs/captures/scan-crypto-samples.json"
	captureDir      = "../../docs/captures"

	// readmeExcerptLead begins the README line that introduces the block.
	readmeExcerptLead = "What `cryptoscan scan crypto-samples` prints"
)

var updateCapture = flag.String("update-capture", "",
	"directory in which to scan a copy of crypto-samples; rewrites docs/captures/scan-crypto-samples.{txt,json} and the README block from that scan")

// captureMeta is scan-crypto-samples.json, in the order the file keeps.
type captureMeta struct {
	Capture          string         `json:"capture"`
	Command          string         `json:"command"`
	Version          string         `json:"version"`
	Build            string         `json:"build"`
	Commit           string         `json:"commit"`
	Fixture          string         `json:"fixture"`
	WorkingDirectory string         `json:"workingDirectory"`
	Invocation       string         `json:"invocation"`
	CapturedAt       string         `json:"capturedAt"`
	ExitCode         int            `json:"exitCode"`
	LineCount        int            `json:"lineCount"`
	OutputSha256     string         `json:"outputSha256"`
	Excerpt          captureExcerpt `json:"excerpt"`
}

// captureExcerpt says which capture lines the README block shows.
type captureExcerpt struct {
	Doc           string   `json:"doc"`
	StartLine     int      `json:"startLine"`
	EndLine       int      `json:"endLine"`
	ElidedLines   [][2]int `json:"elidedLines"`
	ElisionMarker string   `json:"elisionMarker"`
	Sha256        string   `json:"sha256"`
}

func loadCaptureMeta(t *testing.T) captureMeta {
	t.Helper()
	data, err := os.ReadFile(captureMetaPath)
	if err != nil {
		t.Fatalf("read %s: %v", captureMetaPath, err)
	}
	var meta captureMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("parse %s: %v", captureMetaPath, err)
	}
	return meta
}

// readmeBlockBounds returns the index of the first line inside the fenced
// block that follows the README line beginning with readmeExcerptLead, and
// the index of the closing fence.
func readmeBlockBounds(t *testing.T, lines []string) (start, end int) {
	t.Helper()
	for i, line := range lines {
		if !strings.HasPrefix(line, readmeExcerptLead) {
			continue
		}
		if i+2 >= len(lines) || lines[i+2] != "```text" {
			t.Fatalf("%s:%d: expected a ```text fence two lines after %q", readmePath, i+3, readmeExcerptLead)
		}
		for j := i + 3; j < len(lines); j++ {
			if lines[j] == "```" {
				return i + 3, j
			}
		}
		t.Fatalf("%s:%d: the ```text block is not closed", readmePath, i+3)
	}
	t.Fatalf("%s has no line beginning with %q", readmePath, readmeExcerptLead)
	return 0, 0
}

// readmeExcerpt returns the lines of the README block.
func readmeExcerpt(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read %s: %v", readmePath, err)
	}
	lines := strings.Split(string(data), "\n")
	start, end := readmeBlockBounds(t, lines)
	return lines[start:end]
}

// trimCapture returns the capture lines the excerpt keeps, with each elided
// range replaced by one marker line.
func trimCapture(t *testing.T, captured []string, ex captureExcerpt) []string {
	t.Helper()
	if ex.StartLine < 1 || ex.EndLine > len(captured) || ex.StartLine > ex.EndLine {
		t.Fatalf("excerpt lines %d-%d are outside the %d-line capture", ex.StartLine, ex.EndLine, len(captured))
	}
	elided := func(n int) (first bool, inside bool) {
		for _, r := range ex.ElidedLines {
			if n >= r[0] && n <= r[1] {
				return n == r[0], true
			}
		}
		return false, false
	}
	var out []string
	for n := ex.StartLine; n <= ex.EndLine; n++ {
		first, inside := elided(n)
		switch {
		case first:
			out = append(out, ex.ElisionMarker)
		case inside:
		default:
			out = append(out, captured[n-1])
		}
	}
	return out
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// captureLines splits a capture into lines, requiring the final newline.
func captureLines(t *testing.T, raw string) []string {
	t.Helper()
	if !strings.HasSuffix(raw, "\n") {
		t.Fatal("the capture does not end with a newline")
	}
	return strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
}

// TestReadmeExcerptMatchesCapture checks that the capture metadata describes
// the capture file, and that the README block is the capture's lines from
// startLine to endLine with each elided range replaced by the marker.
func TestReadmeExcerptMatchesCapture(t *testing.T) {
	meta := loadCaptureMeta(t)
	if meta.Excerpt.Doc != "README.md" {
		t.Fatalf("excerpt.doc = %q, want README.md", meta.Excerpt.Doc)
	}

	capturePath := filepath.Join(captureDir, meta.Capture)
	raw, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("read %s: %v", capturePath, err)
	}
	if got := sha256Hex(raw); got != meta.OutputSha256 {
		t.Errorf("outputSha256 is %s but %s hashes to %s", meta.OutputSha256, meta.Capture, got)
	}
	captured := captureLines(t, string(raw))
	if len(captured) != meta.LineCount {
		t.Errorf("lineCount is %d but %s has %d lines", meta.LineCount, meta.Capture, len(captured))
	}

	want := trimCapture(t, captured, meta.Excerpt)
	got := readmeExcerpt(t)
	for i := 0; i < len(want) || i < len(got); i++ {
		var w, g string
		if i < len(want) {
			w = want[i]
		}
		if i < len(got) {
			g = got[i]
		}
		if w != g {
			t.Fatalf("README excerpt line %d differs from the capture trimmed as %s describes:\n README:  %q\n capture: %q",
				i+1, filepath.Base(captureMetaPath), g, w)
		}
	}
	if gotSum := sha256Hex([]byte(strings.Join(got, "\n") + "\n")); gotSum != meta.Excerpt.Sha256 {
		t.Errorf("excerpt.sha256 is %s but the README block hashes to %s", meta.Excerpt.Sha256, gotSum)
	}
}

var (
	// streamedLine is a finding printed while the scan runs. The number is
	// the order of discovery, which differs between runs.
	streamedLine = regexp.MustCompile(`^(  \[[A-Z]+\] )#\d+\s+`)
	// elapsedTime is the duration the stream footer prints in parentheses: a
	// time.Duration rounded to a millisecond, so "15ms" on a fast machine,
	// "1.023s" on a slow one, "0s" under half a millisecond, "1m2.5s" past
	// a minute.
	elapsedTime = regexp.MustCompile(`\((?:\d+(?:\.\d+)?(?:h|ms|m|s))+\)`)
	// volatileRow is a row of the Scan Information box that changes with the
	// clock or the machine.
	volatileRow = regexp.MustCompile(`^│ (Time|Duration|Speed):`)
)

// normalizeScanLine removes what legitimately differs between two scans of
// the same tree, so the README lines can be compared with a fresh scan.
func normalizeScanLine(line string) string {
	line = streamedLine.ReplaceAllString(line, "${1}#N ")
	return elapsedTime.ReplaceAllString(line, "(ms)")
}

// TestNormalizeScanLineIgnoresElapsedTime checks that the stream footer
// compares equal whatever duration it prints. The footer prints the scan's
// duration rounded to a millisecond, which is "15ms" on a fast machine,
// "1.023s" on a slow one, "0s" under half a millisecond and "1m2.5s" past a
// minute; the README's line must match a fresh scan in every case.
func TestNormalizeScanLineIgnoresElapsedTime(t *testing.T) {
	const readme = "  Scan complete: 110 findings in 6 files (15ms)"
	want := normalizeScanLine(readme)
	if want == readme {
		t.Fatalf("normalizeScanLine(%q) left the duration in place", readme)
	}
	for _, elapsed := range []string{"0s", "999ms", "1s", "1.023s", "12.5s", "1m2.5s", "1h2m3.004s"} {
		line := "  Scan complete: 110 findings in 6 files (" + elapsed + ")"
		if got := normalizeScanLine(line); got != want {
			t.Errorf("normalizeScanLine(%q) = %q, want %q", line, got, want)
		}
	}
	// Parentheses holding something other than a duration are kept, so a
	// README line that differs there is still reported.
	for _, line := range []string{
		"  Scanning... (findings appear as discovered)",
		"  Scan complete: 110 findings in 6 files (15)",
	} {
		if got := normalizeScanLine(line); got != line {
			t.Errorf("normalizeScanLine(%q) = %q, want the line unchanged", line, got)
		}
	}
}

// captureOutput runs f with stdout and stderr joined into one pipe, as a
// shell's "2>&1" would, and returns what was written. The pipe is drained
// while f runs, since a scan report is larger than a pipe buffer.
func captureOutput(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	f()
	_ = w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return <-done
}

// scanCryptoSamplesIn copies crypto-samples into root, scans it from root
// the way the README shows ("cryptoscan scan crypto-samples", no terminal,
// an empty HOME) and returns what the scan printed and its exit code.
func scanCryptoSamplesIn(t *testing.T, root string) (out string, code int) {
	t.Helper()
	fixture := filepath.Join(root, "crypto-samples")
	if err := os.MkdirAll(fixture, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(cryptoSamples)
	if err != nil {
		t.Fatalf("read %s: %v", cryptoSamples, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			t.Fatalf("%s holds a directory %q; this test copies files only", cryptoSamples, e.Name())
		}
		body, err := os.ReadFile(filepath.Join(cryptoSamples, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture, e.Name()), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	// os.Getwd prefers $PWD when it names the working directory, so the
	// report prints root as given rather than with symlinks resolved.
	t.Setenv("PWD", root)
	t.Setenv("HOME", t.TempDir())

	resetPipelineFlags(t)
	savedStream := streamFindings
	streamFindings = true // the capture shows the streamed list
	t.Cleanup(func() { streamFindings = savedStream })
	out = captureOutput(t, func() {
		var err error
		code, err = scanTarget(scanCmd, "crypto-samples")
		if err != nil {
			t.Errorf("scan crypto-samples: %v", err)
		}
	})

	// Back to the package directory, so the relative paths this file uses
	// resolve again.
	if err := os.Chdir(wd); err != nil {
		t.Fatal(err)
	}
	os.Setenv("PWD", wd)
	return out, code
}

// indexWithPrefix returns the index of the first line at or after from that
// begins with prefix, or -1.
func indexWithPrefix(lines []string, from int, prefix string) int {
	for i := from; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], prefix) {
			return i
		}
	}
	return -1
}

// writeCapture records out as the capture, derives the metadata and the
// README block from it, and writes all three. The block keeps the first
// three streamed findings, the stream footer and the report through the
// Scan Information box, without the Time row.
func writeCapture(t *testing.T, out string, code int, root string, at time.Time) {
	t.Helper()
	if version.Get() == "dev" {
		t.Fatalf(`-update-capture records the release version; build the test with -ldflags "-X github.com/csnp/cryptoscan/pkg/version.value=<version>"`)
	}
	lines := captureLines(t, out)

	complete := indexWithPrefix(lines, 0, "  Scan complete:")
	if complete < 7 {
		t.Fatalf("no stream footer after at least three streamed findings in the scan output")
	}
	info := indexWithPrefix(lines, complete, "┌─ Scan Information")
	if info < 0 {
		t.Fatal("no Scan Information box in the scan output")
	}
	end := indexWithPrefix(lines, info, "└")
	timeRow := indexWithPrefix(lines, info, "│ Time:")
	if end < 0 || timeRow < 0 || timeRow > end {
		t.Fatal("the Scan Information box has no Time row or no closing line")
	}

	head, err := exec.Command("git", "-C", "../..", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("git rev-parse HEAD: %v", err)
	}

	meta := captureMeta{
		Capture: "scan-crypto-samples.txt",
		Command: "cryptoscan scan crypto-samples",
		Version: version.Get(),
		Build: fmt.Sprintf("go test -ldflags \"-X github.com/csnp/cryptoscan/pkg/version.value=%s\" ./internal/cli -run TestReadmeExcerptIsCurrent -update-capture=%s",
			version.Get(), root),
		Commit:           strings.TrimSpace(string(head)),
		Fixture:          "crypto-samples",
		WorkingDirectory: root,
		Invocation: "run in-process by TestReadmeExcerptIsCurrent from a directory holding only crypto-samples copied from the commit, " +
			"stdout and stderr joined into one pipe (so no color), with HOME set to a new empty directory",
		CapturedAt:   at.UTC().Format(time.RFC3339),
		ExitCode:     code,
		LineCount:    len(lines),
		OutputSha256: sha256Hex([]byte(out)),
		Excerpt: captureExcerpt{
			Doc:           "README.md",
			StartLine:     1,
			EndLine:       end + 1,
			ElidedLines:   [][2]int{{6, complete - 1}, {timeRow + 1, timeRow + 1}},
			ElisionMarker: "  ...",
		},
	}
	block := trimCapture(t, lines, meta.Excerpt)
	meta.Excerpt.Sha256 = sha256Hex([]byte(strings.Join(block, "\n") + "\n"))

	if err := os.WriteFile(filepath.Join(captureDir, meta.Capture), []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(captureMetaPath, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read %s: %v", readmePath, err)
	}
	readme := strings.Split(string(data), "\n")
	start, stop := readmeBlockBounds(t, readme)
	updated := append(append(append([]string{}, readme[:start]...), block...), readme[stop:]...)
	if err := os.WriteFile(readmePath, []byte(strings.Join(updated, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s, %s and the README block from a %d-line scan", meta.Capture, filepath.Base(captureMetaPath), len(lines))
}

// TestReadmeExcerptIsCurrent scans crypto-samples the way the capture was
// made, from a directory named cryptoscan that holds only the fixture, and
// checks that every line the README shows is still printed. Streamed findings
// are matched without their discovery number and in any order; the other
// lines must appear in the README's order. Durations and the clock are
// ignored. With -update-capture, the scan runs in that directory and the
// capture, its metadata and the README block are rewritten from it first.
func TestReadmeExcerptIsCurrent(t *testing.T) {
	meta := loadCaptureMeta(t)
	if meta.Command != "cryptoscan scan crypto-samples" {
		t.Fatalf("capture command is %q; this test runs cryptoscan scan crypto-samples", meta.Command)
	}

	var root string
	if *updateCapture != "" {
		abs, err := filepath.Abs(*updateCapture)
		if err != nil {
			t.Fatal(err)
		}
		if entries, err := os.ReadDir(abs); err == nil && len(entries) > 0 {
			t.Fatalf("%s is not empty; the capture must come from a directory holding only crypto-samples", abs)
		}
		root = abs
	} else {
		// os.MkdirTemp rather than t.TempDir, whose path carries the test
		// name. The directory name matters: the report abbreviates paths to
		// their last characters, and the README shows ...scan/crypto-samples/.
		dir, err := os.MkdirTemp("", "readme-")
		if err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		root = filepath.Join(dir, "cryptoscan")
	}

	at := time.Now()
	out, code := scanCryptoSamplesIn(t, root)
	if *updateCapture != "" {
		writeCapture(t, out, code, root, at)
		meta = loadCaptureMeta(t)
	}
	if code != meta.ExitCode {
		t.Errorf("scan crypto-samples exited %d, the capture records %d", code, meta.ExitCode)
	}

	live := strings.Split(out, "\n")
	streamed := make(map[string]bool)
	for i := range live {
		live[i] = normalizeScanLine(live[i])
		if streamedLine.MatchString(live[i]) || strings.HasPrefix(live[i], "  [") {
			streamed[live[i]] = true
		}
	}

	excerpt := readmeExcerpt(t)
	next := 0 // position in live after the last matched line
	var missing []string
	for i, line := range excerpt {
		if line == meta.Excerpt.ElisionMarker || volatileRow.MatchString(line) {
			continue
		}
		want := normalizeScanLine(line)
		if streamedLine.MatchString(line) {
			if !streamed[want] {
				missing = append(missing, fmt.Sprintf("README line %d (streamed finding): %q", i+1, line))
			}
			continue
		}
		found := -1
		for j := next; j < len(live); j++ {
			if live[j] == want {
				found = j
				break
			}
		}
		if found < 0 {
			missing = append(missing, fmt.Sprintf("README line %d: %q", i+1, line))
			continue
		}
		next = found + 1
	}
	if len(missing) > 0 {
		t.Errorf("%d of the %d lines the README shows for cryptoscan scan crypto-samples are not in a fresh scan; regenerate %s and the README block with -update-capture:\n%s",
			len(missing), len(excerpt), meta.Capture, strings.Join(missing, "\n"))
	}
}
