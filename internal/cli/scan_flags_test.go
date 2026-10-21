// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// flagFixture writes a tree whose scan every scan flag can visibly change: a
// Go file in the target with an RSA key generation (HIGH), an RSA import
// (LOW), a comment naming RSA (INFO), a log message naming RSA (withheld as
// narrative), a SHA-256 call (withheld as quantum safe) and library imports
// (withheld), and a Python file one directory down with a SHA-1 call (HIGH).
// Nothing in it is CRITICAL, so the exit code is 0 until --fail-on asks for
// more.
func flagFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	app := "package main\n\n" +
		"import (\n" +
		"\t\"crypto/rsa\"\n" +
		"\t\"crypto/sha256\"\n" +
		"\t\"log\"\n" +
		")\n\n" +
		"// Keys come from rsa.GenerateKey at startup.\n" +
		"func key() {\n" +
		"\tlog.Printf(\"generating an RSA key\")\n" +
		"\t_, _ = rsa.GenerateKey(nil, 2048)\n" +
		"}\n\n" +
		"func sum(data []byte) {\n" +
		"\t_ = sha256.Sum256(data)\n" +
		"}\n"
	legacy := "import hashlib\n\n" +
		"def digest(data):\n" +
		"    return hashlib.sha1(data).hexdigest()\n"
	writeFixtureFile(t, filepath.Join(dir, "app.go"), app)
	writeFixtureFile(t, filepath.Join(dir, "sub", "legacy.py"), legacy)
	return dir
}

func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// resetScanFlags puts every scan flag back to its default, value and
// "changed" state both, now and when the test ends. The flag variables are
// shared by every run in the process, so without this a run would inherit the
// previous run's settings.
func resetScanFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		scanCmd.Flags().VisitAll(func(f *pflag.Flag) {
			if err := f.Value.Set(f.DefValue); err != nil {
				t.Errorf("reset --%s to %q: %v", f.Name, f.DefValue, err)
			}
			f.Changed = false
		})
	}
	reset()
	t.Cleanup(reset)
}

// fakeTerminal makes the scan believe standard output is a terminal until
// the test ends, which is the one condition the progress line waits for.
func fakeTerminal(t *testing.T) {
	t.Helper()
	saved := isTerminal
	isTerminal = func(*os.File) bool { return true }
	t.Cleanup(func() { isTerminal = saved })
}

// scanOutcome is what one run of the scan command leaves for its user: what
// it printed, the code it would exit with, and the error it returned.
type scanOutcome struct {
	stdout string
	code   int
	err    string
}

// runScanWith runs scan on target with args through the command's own code
// path, without exiting the process, and returns what the run produced.
func runScanWith(t *testing.T, target string, args ...string) scanOutcome {
	t.Helper()
	resetScanFlags(t)
	if err := scanCmd.ParseFlags(args); err != nil {
		t.Fatalf("scan %s: %v", strings.Join(args, " "), err)
	}
	var out scanOutcome
	var err error
	out.stdout = captureStdout(func() {
		out.code, err = scanTarget(scanCmd, target)
	})
	if err != nil {
		out.err = err.Error()
	}
	return out
}

// volatileOutput matches what two runs of the same scan print differently:
// the time, duration and speed lines of the text report, the scanTime and
// scanDuration fields of the JSON report, and the timing in the stream
// footer. The replacement keeps the label and drops the value.
var volatileOutput = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(Time|Duration|Speed): +[^│\n]*`), "$1: <volatile>"},
	{regexp.MustCompile(`"scanTime": *"[^"]*"`), `"scanTime": "<volatile>"`},
	{regexp.MustCompile(`"scanDuration": *[0-9]+`), `"scanDuration": 0`},
	{regexp.MustCompile(`\([0-9.]+(ns|µs|ms|s)\)`), "(<volatile>)"},
}

// normalizeScanOutput makes two runs of one scan comparable: it blanks the
// volatile values and sorts the lines, since the order in which the parallel
// workers find things, and the order of the map-rendered "Categories Found"
// block, change from run to run.
func normalizeScanOutput(o scanOutcome) string {
	s := o.stdout
	for _, v := range volatileOutput {
		s = v.re.ReplaceAllString(s, v.repl)
	}
	lines := strings.Split(s, "\n")
	sort.Strings(lines)
	return fmt.Sprintf("exit %d, error %q\n%s", o.code, o.err, strings.Join(lines, "\n"))
}

// firstDifference names the first line on which a and b differ.
func firstDifference(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return fmt.Sprintf("line %d:\n\t%q\n\t%q", i+1, x, y)
		}
	}
	return "no differing line"
}

// expandArgs joins the common arguments with extra, with {scratch} in an
// argument replaced by the scratch directory.
func expandArgs(common, extra []string, scratch string) []string {
	args := append([]string{}, common...)
	for _, a := range extra {
		args = append(args, strings.ReplaceAll(a, "{scratch}", scratch))
	}
	return args
}

// flagEffect says how a scan flag's effect is observed: the fixture is
// scanned with and without the flag, and the two runs must differ in what
// they print, in the exit code or in the error. {scratch} in an argument is
// a directory outside the scanned tree.
type flagEffect struct {
	with    []string
	without []string
	setup   func(t *testing.T, dir, scratch string)
}

// TestScanFlagsEachChangeTheOutput runs every flag scan --help lists with and
// without the flag and fails when the two runs are the same, so that a flag
// that parses and does nothing cannot be advertised. A flag without a case
// here fails the test too.
func TestScanFlagsEachChangeTheOutput(t *testing.T) {
	ignoreRSA := "ignore:\n  patterns:\n    - RSA-001\n"
	cases := map[string]flagEffect{
		"format":               {with: []string{"--format", "json"}},
		"output":               {with: []string{"--output", "{scratch}/report.txt"}},
		"include":              {with: []string{"--include", "*.py"}},
		"exclude":              {with: []string{"--exclude", "sub/*"}},
		"max-depth":            {with: []string{"--max-depth", "1"}},
		"progress":             {with: []string{"--progress"}, setup: func(t *testing.T, _, _ string) { fakeTerminal(t) }},
		"min-severity":         {with: []string{"--min-severity", "high"}},
		"no-color":             {with: []string{"--no-color=false"}, without: []string{"--no-color"}},
		"pretty":               {with: []string{"--format", "json", "--pretty"}, without: []string{"--format", "json"}},
		"group-by":             {with: []string{"--group-by", "file"}},
		"context":              {with: []string{"--context", "1"}},
		"stream":               {with: []string{"--stream"}},
		"include-imports":      {with: []string{"--include-imports"}},
		"include-quantum-safe": {with: []string{"--include-quantum-safe"}},
		"include-narrative":    {with: []string{"--include-narrative"}},
		"verbose":              {with: []string{"--verbose"}},
		"ignore":               {with: []string{"--ignore", "RSA-001"}},
		"ignore-category":      {with: []string{"--ignore-category", "Deprecated Hash"}},
		"fail-on":              {with: []string{"--fail-on", "high"}},
		"include-skipped": {with: []string{"--include-skipped"}, setup: func(t *testing.T, dir, _ string) {
			writeFixtureFile(t, filepath.Join(dir, "examples", "keys.py"), "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
		}},
		"baseline": {with: []string{"--baseline", "{scratch}/baseline.json"}, setup: func(t *testing.T, dir, scratch string) {
			runScanWith(t, dir, "--stream=false", "--format", "json", "--output", filepath.Join(scratch, "baseline.json"))
		}},
		"config": {with: []string{"--config", "{scratch}/cryptoscan.yaml"}, setup: func(t *testing.T, _, scratch string) {
			writeFixtureFile(t, filepath.Join(scratch, "cryptoscan.yaml"), ignoreRSA)
		}},
		"no-config": {with: []string{"--no-config"}, setup: func(t *testing.T, dir, _ string) {
			writeFixtureFile(t, filepath.Join(dir, ".cryptoscan.yaml"), ignoreRSA)
		}},
	}

	// --help is cobra's own flag; TestScanHelpFlagPrintsUsage covers it.
	scanCmd.InitDefaultHelpFlag()
	scanCmd.Flags().VisitAll(func(f *pflag.Flag) {
		if _, ok := cases[f.Name]; !ok && f.Name != "help" {
			t.Errorf("scan --help lists --%s, but this test has no case showing what it changes", f.Name)
		}
	})
	names := make([]string, 0, len(cases))
	for name := range cases {
		if scanCmd.Flags().Lookup(name) == nil {
			t.Errorf("this test has a case for --%s, which scan does not have", name)
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	// The streamed list is left out of the baseline: it numbers the findings
	// in the order the parallel workers find them, which differs between runs.
	common := []string{"--stream=false"}
	for _, name := range names {
		c := cases[name]
		t.Run(name, func(t *testing.T) {
			dir := flagFixture(t)
			scratch := t.TempDir()
			if c.setup != nil {
				c.setup(t, dir, scratch)
			}
			with := expandArgs(common, c.with, scratch)
			without := expandArgs(common, c.without, scratch)

			base := normalizeScanOutput(runScanWith(t, dir, without...))
			again := normalizeScanOutput(runScanWith(t, dir, without...))
			if base != again {
				t.Fatalf("two runs of scan %s differ, so a difference with --%s would prove nothing:\n%s",
					strings.Join(without, " "), name, firstDifference(base, again))
			}
			flagged := normalizeScanOutput(runScanWith(t, dir, with...))
			if flagged == base {
				t.Errorf("scan %s prints the same report, with the same exit code, as scan %s: --%s has no observable effect",
					strings.Join(with, " "), strings.Join(without, " "), name)
			}
		})
	}
}

func TestScanHelpFlagPrintsUsage(t *testing.T) {
	resetScanFlags(t)
	stdout, cobraOutput, err := executeScan(t, "--help")
	if err != nil {
		t.Fatalf("scan --help: %v", err)
	}
	if stdout != "" {
		t.Errorf("scan --help ran a scan and printed:\n%s", stdout)
	}
	if !strings.Contains(cobraOutput, "Usage:\n  cryptoscan scan [path or URL] [flags]") {
		t.Errorf("scan --help did not print the usage:\n%s", cobraOutput)
	}
}

// TestScanRejectsGitHistory: the flag never scanned anything beyond the
// working tree and was removed, so passing it is an error rather than a
// scan that silently did not do what was asked.
func TestScanRejectsGitHistory(t *testing.T) {
	resetScanFlags(t)
	dir := t.TempDir()
	stdout, _, err := executeScan(t, dir, "--git-history")
	if err == nil || err.Error() != "unknown flag: --git-history" {
		t.Fatalf("scan --git-history: err = %v, want unknown flag: --git-history", err)
	}
	if stdout != "" {
		t.Errorf("scan --git-history printed before failing:\n%s", stdout)
	}
}

// TestScanRejectsUnknownGroupBy: severity, category and quantum were once
// listed as accepted and ignored. Only file is implemented, and the other
// values are rejected before anything is scanned.
func TestScanRejectsUnknownGroupBy(t *testing.T) {
	for _, value := range []string{"severity", "category", "quantum", "line"} {
		t.Run(value, func(t *testing.T) {
			resetScanFlags(t)
			dir := t.TempDir()
			stdout, _, err := executeScan(t, dir, "--group-by", value)
			want := `unknown --group-by "` + value + `" (valid: file)`
			if err == nil || err.Error() != want {
				t.Fatalf("scan --group-by %s: err = %v, want %q", value, err, want)
			}
			if stdout != "" {
				t.Errorf("scan --group-by %s printed before failing:\n%s", value, stdout)
			}
		})
	}
}

func TestScanRejectsNegativeMaxDepthAndContext(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"--max-depth", "-1"}, "--max-depth must be 0 (unlimited) or a positive number, not -1"},
		{[]string{"--context", "-2"}, "--context must be 0 or a positive number, not -2"},
	}
	for _, tt := range tests {
		t.Run(tt.args[0], func(t *testing.T) {
			resetScanFlags(t)
			dir := t.TempDir()
			stdout, _, err := executeScan(t, append([]string{dir}, tt.args...)...)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("scan %s: err = %v, want %q", strings.Join(tt.args, " "), err, tt.want)
			}
			if stdout != "" {
				t.Errorf("scan %s printed before failing:\n%s", strings.Join(tt.args, " "), stdout)
			}
		})
	}
}
