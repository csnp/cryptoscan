// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/spf13/cobra"
)

// TestFailOnStopsOnUnparsableAutoDetectedConfig covers an auto-detected
// config file that is not valid YAML. With --fail-on, and under gate, the run
// went on without the file's rules after a warning.
func TestFailOnStopsOnUnparsableAutoDetectedConfig(t *testing.T) {
	dir := configScanDir(t, "ignore: [unclosed\n")
	wantErr := "config file " + filepath.Join(dir, ".cryptoscan.yaml") + " could not be parsed: "

	tests := []struct {
		name string
		cmd  *cobra.Command
		args []string
		run  func() (int, error)
	}{
		{"scan --fail-on critical", scanCmd, []string{"--stream=false", "--fail-on", "critical"},
			func() (int, error) { return scanTarget(scanCmd, dir) }},
		{"gate", gateCmd, nil, func() (int, error) { return gateTarget(gateCmd, dir) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetScanFlags(t)
			resetPipelineFlags(t)
			if err := tt.cmd.ParseFlags(tt.args); err != nil {
				t.Fatal(err)
			}
			var err error
			stdout := captureStdout(func() {
				_, err = tt.run()
			})
			if err == nil || !strings.HasPrefix(err.Error(), wantErr) {
				t.Fatalf("err = %v, want one starting %q", err, wantErr)
			}
			if stdout != "" {
				t.Errorf("printed a report before stopping:\n%s", stdout)
			}
			var hinted *hintedError
			if !errors.As(err, &hinted) {
				t.Fatalf("error %q carries no hint", err)
			}
			// Each flag the hint names is one this command has.
			for _, flag := range regexp.MustCompile(`--[a-z-]+`).FindAllString(hinted.hint, -1) {
				if tt.cmd.Flags().Lookup(strings.TrimPrefix(flag, "--")) == nil {
					t.Errorf("hint %q names %s, which %s does not have", hinted.hint, flag, tt.cmd.Name())
				}
			}
		})
	}

	// Without --fail-on the scan still runs without the file, after the
	// warning TestRunScanWarnsAboutUnparsableConfigFile checks.
	t.Run("scan without --fail-on", func(t *testing.T) {
		var out scanOutcome
		captureStderr(func() {
			out = runScanWith(t, dir, "--stream=false")
		})
		if out.err != "" {
			t.Errorf("scan failed: %s", out.err)
		}
		if out.stdout == "" {
			t.Error("scan printed no report")
		}
	})
}

// TestUnparsableAutoDetectedConfigHintOffersNoConfig checks the next step a
// stopped run prints on both commands, now that gate has --no-config, and
// that the step runs: with --no-config the file is not read and the run goes
// on with the command line's options alone.
func TestUnparsableAutoDetectedConfigHintOffersNoConfig(t *testing.T) {
	dir := configScanDir(t, "ignore: [unclosed\n")
	const hint = "With --fail-on, and with gate, a config file that does not parse stops the scan. " +
		"Fix the file, or add --no-config to use only command-line options."

	stops := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"scan --fail-on low", scanCmd, []string{"--stream=false", "--fail-on", "low"}},
		{"gate", gateCmd, nil},
	}
	for _, tt := range stops {
		t.Run(tt.name, func(t *testing.T) {
			resetScanFlags(t)
			resetGateFlags(t)
			if err := tt.cmd.ParseFlags(tt.args); err != nil {
				t.Fatal(err)
			}
			run := scanTarget
			if tt.cmd == gateCmd {
				run = gateTarget
			}
			var err error
			captureStdout(func() {
				_, err = run(tt.cmd, dir)
			})
			var hinted *hintedError
			if !errors.As(err, &hinted) {
				t.Fatalf("err = %v, want a stop that names the next step", err)
			}
			if hinted.hint != hint {
				t.Errorf("hint = %q, want %q", hinted.hint, hint)
			}
		})
	}

	// The RSA findings of the tree are HIGH, so with the file left out both
	// runs fail on them, as the same tree without a config file does.
	runs := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"scan --fail-on high --no-config", scanCmd, []string{"--stream=false", "--fail-on", "high", "--no-config"}},
		{"gate --no-config", gateCmd, []string{"--no-config"}},
	}
	for _, tt := range runs {
		t.Run(tt.name, func(t *testing.T) {
			out := runCommandWith(t, tt.cmd, dir, tt.args...)
			if out.err != "" {
				t.Fatalf("%s stopped: %s", tt.name, out.err)
			}
			if out.code != 1 {
				t.Errorf("exit code = %d, want 1 for the HIGH findings", out.code)
			}
			if strings.Contains(out.stderr, "could not be parsed") {
				t.Errorf("stderr = %q; --no-config reads no config file", out.stderr)
			}
		})
	}
}

func TestGateExitCode(t *testing.T) {
	// found is a config file from source whose ignore.patterns removed
	// findings of the given severities, none of which a baseline accepts.
	found := func(source string, removed scanner.ConfigSeverityCounts) *scanner.ConfigReport {
		n := removed.AtOrAbove(scanner.SeverityInfo)
		return &scanner.ConfigReport{
			Path:   "/repo/.cryptoscan.yaml",
			Source: source,
			FindingsRemoved: scanner.ConfigFindingsRemoved{
				IgnorePatterns:           n,
				Total:                    n,
				BySeverity:               removed,
				IgnorePatternsBySeverity: removed,
			},
			Unbaselined: removed,
		}
	}
	twoHighOneLow := scanner.ConfigSeverityCounts{High: 2, Low: 1}
	baselineOnly := &scanner.ConfigReport{
		Source: scanner.ConfigSourceScanTarget,
		FindingsRemoved: scanner.ConfigFindingsRemoved{
			Baseline: 3, Total: 3, BySeverity: twoHighOneLow, BaselineBySeverity: twoHighOneLow,
		},
	}
	acceptedByBaseline := &scanner.ConfigReport{
		Source: scanner.ConfigSourceScanTarget,
		FindingsRemoved: scanner.ConfigFindingsRemoved{
			IgnorePatterns: 2, Total: 2,
			BySeverity:               scanner.ConfigSeverityCounts{High: 2},
			IgnorePatternsBySeverity: scanner.ConfigSeverityCounts{High: 2},
		},
	}
	skippedOnly := &scanner.ConfigReport{
		Source:       scanner.ConfigSourceScanTarget,
		PathsSkipped: scanner.ConfigPathsSkipped{Files: 2},
	}
	low := []scanner.Finding{{Severity: scanner.SeverityLow}}
	high := []scanner.Finding{{Severity: scanner.SeverityHigh}}

	tests := []struct {
		name      string
		results   *scanner.Results
		failOn    string
		threshold string
		want      int
	}{
		{"no config file and no findings", &scanner.Results{}, "high", "high", 0},
		{"file in the scan target removed findings at the threshold", &scanner.Results{Config: found(scanner.ConfigSourceScanTarget, twoHighOneLow)}, "high", "high", 1},
		{"file above the scan target removed a finding at the threshold", &scanner.Results{Config: found(scanner.ConfigSourceParentDirectory, scanner.ConfigSeverityCounts{Critical: 1})}, "critical", "critical", 1},
		{"file from the working directory removed a finding at the threshold", &scanner.Results{Config: found(scanner.ConfigSourceWorkingDirectory, scanner.ConfigSeverityCounts{Critical: 1})}, "critical", "critical", 1},
		{"file removed only findings below the threshold", &scanner.Results{Config: found(scanner.ConfigSourceScanTarget, scanner.ConfigSeverityCounts{Info: 2})}, "high", "high", 0},
		{"file removed findings at a threshold of info", &scanner.Results{Config: found(scanner.ConfigSourceScanTarget, scanner.ConfigSeverityCounts{Info: 2})}, "info", "info", 1},
		{"only a baseline named in the file removed findings", &scanner.Results{Config: baselineOnly}, "high", "high", 0},
		{"file removed findings a baseline accepts", &scanner.Results{Config: acceptedByBaseline}, "high", "high", 0},
		{"file passed with --config removed findings at the threshold", &scanner.Results{Config: found(scanner.ConfigSourceFlag, twoHighOneLow)}, "high", "high", 0},
		{"file left a finding below the threshold", &scanner.Results{Findings: low, Config: found(scanner.ConfigSourceScanTarget, twoHighOneLow)}, "high", "high", 1},
		{"file left a finding at the threshold", &scanner.Results{Findings: high, Config: found(scanner.ConfigSourceScanTarget, twoHighOneLow)}, "high", "high", 1},
		{"file only kept files out of the scan", &scanner.Results{Config: skippedOnly}, "high", "high", 0},
		{"the command line's threshold, not a lower one from the file, counts the removals", &scanner.Results{Config: found(scanner.ConfigSourceScanTarget, scanner.ConfigSeverityCounts{Low: 1})}, "low", "high", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gateExitCode(tt.results, tt.failOn, tt.threshold); got != tt.want {
				t.Errorf("gateExitCode(failOn=%q, threshold=%q) = %d, want %d", tt.failOn, tt.threshold, got, tt.want)
			}
		})
	}
}

// TestConfigRemovedAtThresholdCounts checks the count the stderr line gives:
// the removed findings at or above the threshold, and none when a finding at
// or above it is left, since the run then fails for that finding.
func TestConfigRemovedAtThresholdCounts(t *testing.T) {
	report := func(source string) *scanner.ConfigReport {
		return &scanner.ConfigReport{Source: source, Unbaselined: scanner.ConfigSeverityCounts{High: 2, Low: 1}}
	}
	tests := []struct {
		name      string
		results   *scanner.Results
		threshold string
		want      int
	}{
		{"at or above low", &scanner.Results{Config: report(scanner.ConfigSourceScanTarget)}, "low", 3},
		{"at or above high", &scanner.Results{Config: report(scanner.ConfigSourceScanTarget)}, "high", 2},
		{"threshold given in capitals", &scanner.Results{Config: report(scanner.ConfigSourceScanTarget)}, "HIGH", 2},
		{"at or above critical", &scanner.Results{Config: report(scanner.ConfigSourceScanTarget)}, "critical", 0},
		{"a finding at the threshold is left", &scanner.Results{Findings: []scanner.Finding{{Severity: scanner.SeverityHigh}}, Config: report(scanner.ConfigSourceScanTarget)}, "high", 0},
		{"file passed with --config", &scanner.Results{Config: report(scanner.ConfigSourceFlag)}, "low", 0},
		{"no config file", &scanner.Results{}, "low", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := configRemovedAtThreshold(tt.results, tt.threshold); got != tt.want {
				t.Errorf("configRemovedAtThreshold(%q) = %d, want %d", tt.threshold, got, tt.want)
			}
		})
	}
}

// TestFailOnFailsWhenAFoundConfigRemovedAFindingAtTheThreshold is the check
// from the issue: with --fail-on low, the tree configScanDir writes, whose
// .cryptoscan.yaml ignores every pattern, exited 0 and said nothing about the
// exit code, while the same tree scanned with --no-config exits 1. The file
// removes two HIGH findings and one LOW, so the line counts the removals at
// or above the run's own threshold, and a threshold above all of them keeps
// exit code 0.
func TestFailOnFailsWhenAFoundConfigRemovedAFindingAtTheThreshold(t *testing.T) {
	dir := configScanDir(t, "ignore:\n  patterns: [\"*\"]\n")
	cfgPath := filepath.Join(dir, ".cryptoscan.yaml")
	const linePrefix = "cryptoscan: exit code 1: a config file found without --config"
	headline := "No findings reported: the config file removed"

	runs := []struct {
		name string
		cmd  *cobra.Command
		args []string
		want int
		line string
	}{
		{"scan --fail-on low", scanCmd, []string{"--fail-on", "low"}, 1, configExitLine(3, "low", cfgPath)},
		{"scan --fail-on high", scanCmd, []string{"--fail-on", "high"}, 1, configExitLine(2, "high", cfgPath)},
		{"scan --fail-on low --format json", scanCmd, []string{"--fail-on", "low", "--format", "json"}, 1, configExitLine(3, "low", cfgPath)},
		{"scan --fail-on low --format sarif", scanCmd, []string{"--fail-on", "low", "--format", "sarif"}, 1, configExitLine(3, "low", cfgPath)},
		{"scan --fail-on critical", scanCmd, []string{"--fail-on", "critical"}, 0, ""},
		{"scan --fail-on low --config", scanCmd, []string{"--fail-on", "low", "--config", cfgPath}, 0, ""},
		{"scan without --fail-on", scanCmd, nil, 0, ""},
		{"gate", gateCmd, nil, 1, configExitLine(2, "high", cfgPath)},
		{"gate --config", gateCmd, []string{"--config", cfgPath}, 0, ""},
		{"gate --fail-on critical", gateCmd, []string{"--fail-on", "critical"}, 0, ""},
	}
	for _, tt := range runs {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			if tt.cmd == scanCmd {
				args = append([]string{"--stream=false"}, args...)
			}
			out := runCommandWith(t, tt.cmd, dir, args...)
			if out.err != "" {
				t.Fatalf("%s failed: %s", tt.name, out.err)
			}
			if out.code != tt.want {
				t.Errorf("exit code = %d, want %d", out.code, tt.want)
			}
			if tt.line != "" {
				if !strings.Contains(out.stderr, tt.line+"\n") {
					t.Errorf("stderr = %q, want the line %q", out.stderr, tt.line)
				}
			} else if strings.Contains(out.stderr, linePrefix) {
				t.Errorf("stderr = %q, which gives the config file as a reason for exit code 1", out.stderr)
			}
		})
	}

	// An explicit --config keeps the normal exit code, and the text report
	// still says that the file left no findings in the report.
	t.Run("headline with --config", func(t *testing.T) {
		out := runCommandWith(t, scanCmd, dir, "--stream=false", "--fail-on", "low", "--config", cfgPath)
		if !strings.Contains(out.stdout, headline) {
			t.Errorf("text report with --config lacks %q", headline)
		}
	})

	// The config block counts what the file removed by severity.
	t.Run("severities in the config block", func(t *testing.T) {
		out := runCommandWith(t, gateCmd, dir)
		if want := "ignore.patterns removed 3 findings (2 high, 1 low)"; !strings.Contains(out.stdout, want) {
			t.Errorf("text report lacks %q:\n%s", want, out.stdout)
		}
	})

	// A failOn in the file is not a threshold from the command line, so the
	// file that set it does not fail a plain scan by removing findings.
	t.Run("failOn set by the file", func(t *testing.T) {
		fileDir := configScanDir(t, "failOn: low\nignore:\n  patterns: [\"*\"]\n")
		out := runCommandWith(t, scanCmd, fileDir, "--stream=false")
		if out.err != "" || out.code != 0 {
			t.Errorf("scan = exit code %d, error %q; want exit code 0", out.code, out.err)
		}
		if strings.Contains(out.stderr, linePrefix) {
			t.Errorf("stderr = %q, which gives a reason for an exit code of 1", out.stderr)
		}
	})
}

// TestConfigFileOwnTextIsNotCountedForTheExitCode covers a match in the
// config file itself. The file is scanned like any file in the tree, and
// RSA-001 in its own ignore list is a HIGH match that the list then removes.
// The config block counts it, but it is the file's own text, not a finding
// the file kept out of the scanned code, so it does not fail a gated run.
func TestConfigFileOwnTextIsNotCountedForTheExitCode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("print(\"hello\")\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cryptoscan.yaml"), []byte("ignore:\n  patterns: [\"RSA-001\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	without := runCommandWith(t, gateCmd, dir, "--no-config", "--format", "json")
	var report struct {
		Findings []scanner.Finding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(without.stdout), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(report.Findings) != 1 || filepath.Base(report.Findings[0].File) != ".cryptoscan.yaml" || report.Findings[0].Severity != scanner.SeverityHigh {
		t.Fatalf("the fixture no longer gives one HIGH match in the config file itself: %+v", report.Findings)
	}

	out := runCommandWith(t, gateCmd, dir)
	if out.err != "" || out.code != 0 {
		t.Errorf("gate = exit code %d, error %q; want 0: the only removal is the file's own text", out.code, out.err)
	}
	if strings.Contains(out.stderr, "cryptoscan: exit code 1:") {
		t.Errorf("stderr = %q, which gives the config file as a reason for exit code 1", out.stderr)
	}
	if want := "ignore.patterns removed 1 finding (1 high)"; !strings.Contains(out.stdout, want) {
		t.Errorf("text report lacks %q:\n%s", want, out.stdout)
	}
}

// TestConfigReportJSONRecordsSeveritiesAndFailOn reads the config object of
// the JSON report: what the file removed, by severity, and whether its
// failOn set the run's threshold.
func TestConfigReportJSONRecordsSeveritiesAndFailOn(t *testing.T) {
	type config struct {
		FindingsRemoved struct {
			Total      int            `json:"total"`
			BySeverity map[string]int `json:"bySeverity"`
		} `json:"findingsRemoved"`
		FailOn *struct {
			Value   string `json:"value"`
			Applied bool   `json:"applied"`
		} `json:"failOn"`
	}
	read := func(t *testing.T, out commandOutcome) config {
		t.Helper()
		var report struct {
			Config *config `json:"config"`
		}
		if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
			t.Fatalf("invalid JSON (error %q): %v", out.err, err)
		}
		if report.Config == nil {
			t.Fatal("JSON report has no config object")
		}
		return *report.Config
	}

	// A dependency finding the file removes is counted under its severity.
	dep := t.TempDir()
	if err := os.WriteFile(filepath.Join(dep, "package.json"), []byte(cryptoJSManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dep, ".cryptoscan.yaml"), []byte("ignore: {patterns: [\"DEP-*\"]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := read(t, runCommandWith(t, scanCmd, dep, "--stream=false", "--format", "json"))
	want := map[string]int{"info": 0, "low": 0, "medium": 1, "high": 0, "critical": 0}
	if got.FindingsRemoved.Total != 1 || !reflect.DeepEqual(got.FindingsRemoved.BySeverity, want) {
		t.Errorf("findingsRemoved = total %d, bySeverity %v; want total 1, bySeverity %v", got.FindingsRemoved.Total, got.FindingsRemoved.BySeverity, want)
	}
	if got.FailOn != nil {
		t.Errorf("failOn = %+v for a file that sets none", *got.FailOn)
	}

	// failOn: critical sets plain scan's threshold and a --config gate's,
	// not one given with --fail-on, and not gate's when the file was found.
	dir := configScanDir(t, "failOn: critical\n")
	cfgPath := filepath.Join(dir, ".cryptoscan.yaml")
	cases := []struct {
		name    string
		cmd     *cobra.Command
		args    []string
		applied bool
	}{
		{"scan", scanCmd, []string{"--stream=false"}, true},
		{"scan --fail-on high", scanCmd, []string{"--stream=false", "--fail-on", "high"}, false},
		{"gate", gateCmd, nil, false},
		{"gate --config", gateCmd, []string{"--config", cfgPath}, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := read(t, runCommandWith(t, tt.cmd, dir, append(tt.args, "--format", "json")...))
			if got.FailOn == nil || got.FailOn.Value != "critical" || got.FailOn.Applied != tt.applied {
				t.Errorf("failOn = %+v, want value critical, applied %v", got.FailOn, tt.applied)
			}
		})
	}
}

// TestApplyBaselineAcceptsRemovedFindingsWithEntriesLeftOver checks how the
// findings a config file removed are set against a baseline: each entry
// covers one finding, and the findings in the report take theirs first.
func TestApplyBaselineAcceptsRemovedFindingsWithEntriesLeftOver(t *testing.T) {
	finding := func(file, pattern, line string) scanner.Finding {
		return scanner.Finding{File: "/repo/" + file, PatternID: pattern, Match: line}
	}
	keyGen := finding("app.py", "RSA-001", "key = rsa.generate_private_key()")
	b := &baseline{
		Metadata: map[string]string{scanner.MetadataScanRoot: "/old/checkout"},
		Findings: []scanner.Finding{
			{File: "/old/checkout/app.py", PatternID: "RSA-001", Match: "key = rsa.generate_private_key()"},
			{File: "/old/checkout/app.py", PatternID: "RSA-001", Match: "key = rsa.generate_private_key()"},
		},
	}
	tests := []struct {
		name     string
		reported []scanner.Finding
		removed  []scanner.Finding
		wantNew  int
		want     []bool
	}{
		{"two entries, nothing reported, two removed", nil, []scanner.Finding{keyGen, keyGen}, 0, []bool{true, true}},
		{"two entries, one reported, two removed", []scanner.Finding{keyGen}, []scanner.Finding{keyGen, keyGen}, 0, []bool{true, false}},
		{"a removed finding the baseline does not hold", nil, []scanner.Finding{finding("app.py", "RSA-001", "other = rsa.generate_private_key()")}, 0, []bool{false}},
		{"no removed findings", []scanner.Finding{keyGen}, nil, 0, []bool{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newFindings, accepted := applyBaseline(tt.reported, tt.removed, "/repo", b)
			if len(newFindings) != tt.wantNew {
				t.Errorf("%d new findings, want %d", len(newFindings), tt.wantNew)
			}
			if !reflect.DeepEqual(accepted, tt.want) {
				t.Errorf("accepted = %v, want %v", accepted, tt.want)
			}
		})
	}
}

// TestApplyBaselineWithoutRecordedRootAcceptsRemovedFindings sets the
// findings a config file removed against a baseline in the form 1.4.0
// writes, which records no root and holds the target as typed, and against
// the same baseline with its root recorded. Each case expects the same
// result from both. The root of the first was found from the reported
// findings alone, so when the file removed every finding in the baseline's
// files, none of the removed findings was matched to its entry.
// TestApplyBaselineWithoutRecordedRootFindsItFromTheReportedFindings covers
// trees in which the two give different results.
func TestApplyBaselineWithoutRecordedRootAcceptsRemovedFindings(t *testing.T) {
	oldRoot := filepath.Join(t.TempDir(), "old", "checkout")
	repo := filepath.Join(t.TempDir(), "repo")
	const (
		importLine = "from cryptography.hazmat.primitives.asymmetric import rsa"
		keyLine    = "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)"
		toolLine   = `DIGEST = hashlib.sha1(b"tool").hexdigest()`
	)
	finding := func(dir, file, pattern, line string) scanner.Finding {
		return scanner.Finding{File: filepath.Join(dir, filepath.FromSlash(file)), PatternID: pattern, Match: line}
	}
	entries := []scanner.Finding{
		finding(oldRoot, "keys.py", "RSA-001", importLine),
		finding(oldRoot, "keys.py", "RSA-001", keyLine),
		finding(oldRoot, "auth.py", "RSA-001", keyLine),
		finding(oldRoot, "tools/tool.py", "SHA1-001", toolLine),
	}
	baselines := []struct {
		name string
		b    *baseline
	}{
		{"root recorded", &baseline{ScanTarget: ".", Metadata: map[string]string{scanner.MetadataScanRoot: oldRoot}, Findings: entries}},
		{"no root recorded", &baseline{ScanTarget: ".", Findings: entries}},
	}
	removed := []scanner.Finding{
		finding(repo, "keys.py", "RSA-001", importLine),
		finding(repo, "keys.py", "RSA-001", keyLine),
		finding(repo, "auth.py", "RSA-001", keyLine),
	}
	tests := []struct {
		name     string
		reported []scanner.Finding
		removed  []scanner.Finding
		wantNew  int
		want     []bool
	}{
		{"nothing reported", nil, removed, 0, []bool{true, true, true}},
		{"a finding reported in a file the baseline does not list",
			[]scanner.Finding{finding(repo, "new.py", "MD5-001", "h = hashlib.md5(data)")}, removed, 1, []bool{true, true, true}},
		{"one finding of a baseline file reported and the others removed",
			removed[:1], removed[1:], 0, []bool{true, true}},
		{"a removed finding the baseline does not hold",
			nil, []scanner.Finding{finding(repo, "keys.py", "RSA-001", "weak = rsa.generate_private_key(public_exponent=3, key_size=512)")}, 0, []bool{false}},
	}
	for _, bl := range baselines {
		for _, tt := range tests {
			t.Run(bl.name+"/"+tt.name, func(t *testing.T) {
				newFindings, accepted := applyBaseline(tt.reported, tt.removed, repo, bl.b)
				if len(newFindings) != tt.wantNew {
					t.Errorf("%d new findings, want %d", len(newFindings), tt.wantNew)
				}
				if !reflect.DeepEqual(accepted, tt.want) {
					t.Errorf("accepted = %v, want %v", accepted, tt.want)
				}
			})
		}
	}
}

// TestApplyBaselineWithoutRecordedRootFindsItFromTheReportedFindings sets a
// baseline in the form 1.4.0 writes, which records no root, against trees in
// which files moved or were added after it was written, with findings
// reported and findings a config file removed. The root of such a baseline is
// found from the reported findings whenever their paths give one, so in each
// case the removed findings leave the reported ones as they are without them.
// In the first two cases that is also the result with the root recorded. In
// the third and fourth, the reported path tool.py alone places the baseline's
// tools/tool.py at tool.py, as it did before, and so gives a root that
// keys.py, which the baseline lists, is not under. The removed findings are
// then set against the root found from the reported and the removed paths
// together among the directories that hold every file the baseline lists,
// and are accepted, as with the root recorded. With the root recorded,
// tool.py's finding is new in both. In the fifth, the reported path util.py
// gives such a root too, and that root also places the baseline's
// tools/tool.py at the moved tool.py: the removed finding in tool.py is
// accepted under it, as it was before, and the removed finding in keys.py
// under the root that holds every listed file. With the root recorded,
// util.py's finding is new and the removed finding in tool.py is not
// accepted. In the sixth and seventh, two removed findings hold the same line
// in files with the same name, one at the top of the tree and one in tools/,
// and the root of the reported findings places the baseline's file in tools/
// at the one at the top. The finding at the top takes that entry under it,
// which left the finding in tools/ not accepted; it now moves to the entry
// for its own file under the root that holds every listed file, and the
// finding in tools/ takes the entry it left. Each removed finding is
// accepted, as with the root recorded.
func TestApplyBaselineWithoutRecordedRootFindsItFromTheReportedFindings(t *testing.T) {
	oldRoot := filepath.Join(t.TempDir(), "old", "checkout")
	repo := filepath.Join(t.TempDir(), "repo")
	const (
		md5Line      = `H = hashlib.md5(b"t").hexdigest()`
		toolLine     = `DIGEST = hashlib.sha1(b"tool").hexdigest()`
		checkLine    = `CHECK = hashlib.sha1(b"check").hexdigest()`
		importLine   = "from cryptography.hazmat.primitives.asymmetric import rsa"
		keyLine      = "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)"
		blowfishLine = "c = Blowfish.new(key)"
	)
	finding := func(dir, file, pattern, line string) scanner.Finding {
		return scanner.Finding{File: filepath.Join(dir, filepath.FromSlash(file)), PatternID: pattern, Match: line}
	}
	// files lists the paths, relative to repo, of the findings given.
	files := func(findings []scanner.Finding) []string {
		var paths []string
		for _, f := range findings {
			paths = append(paths, filepath.ToSlash(strings.TrimPrefix(f.File, repo+string(filepath.Separator))))
		}
		return paths
	}
	type outcome struct {
		newFiles []string // the files of the reported findings that are new
		accepted []bool   // whether the baseline accepts each removed finding
	}
	tests := []struct {
		name              string
		entries           []scanner.Finding // from the checkout the baseline was written in
		reported, removed []scanner.Finding
		noRoot, rooted    outcome
	}{
		{
			// t.py held an MD5 line and a/t.py a SHA1 line. t.py now holds
			// the SHA1 line, a/u.py moved to u.py, and the file removed the
			// findings in u.py.
			name: "a reported finding the baseline does not list at its path",
			entries: []scanner.Finding{
				finding(oldRoot, "t.py", "MD5-001", md5Line),
				finding(oldRoot, "a/t.py", "SHA1-001", toolLine),
				finding(oldRoot, "a/u.py", "RSA-001", importLine),
				finding(oldRoot, "a/u.py", "RSA-001", keyLine),
			},
			reported: []scanner.Finding{finding(repo, "t.py", "SHA1-001", toolLine)},
			removed: []scanner.Finding{
				finding(repo, "u.py", "RSA-001", importLine),
				finding(repo, "u.py", "RSA-001", keyLine),
			},
			noRoot: outcome{[]string{"t.py"}, []bool{false, false}},
			rooted: outcome{[]string{"t.py"}, []bool{false, false}},
		},
		{
			// a/x.py and a/y.py moved to x.py and y.py, and the file removed
			// the findings in them. z.py did not move.
			name: "the reported findings of a file that did not move",
			entries: []scanner.Finding{
				finding(oldRoot, "a/x.py", "SHA1-001", toolLine),
				finding(oldRoot, "a/y.py", "SHA1-001", checkLine),
				finding(oldRoot, "z.py", "RSA-001", importLine),
				finding(oldRoot, "z.py", "RSA-001", keyLine),
			},
			reported: []scanner.Finding{
				finding(repo, "z.py", "RSA-001", importLine),
				finding(repo, "z.py", "RSA-001", keyLine),
			},
			removed: []scanner.Finding{
				finding(repo, "x.py", "SHA1-001", toolLine),
				finding(repo, "y.py", "SHA1-001", checkLine),
			},
			noRoot: outcome{nil, []bool{false, false}},
			rooted: outcome{nil, []bool{false, false}},
		},
		{
			// A tool.py at the top of the tree is a file the baseline does
			// not list, although its name and line are those of
			// tools/tool.py. The file removed every finding in keys.py and
			// auth.py.
			name: "a reported finding in a file with the name of a baseline file in another directory",
			entries: []scanner.Finding{
				finding(oldRoot, "keys.py", "RSA-001", importLine),
				finding(oldRoot, "keys.py", "RSA-001", keyLine),
				finding(oldRoot, "auth.py", "RSA-001", keyLine),
				finding(oldRoot, "tools/tool.py", "SHA1-001", toolLine),
			},
			reported: []scanner.Finding{finding(repo, "tool.py", "SHA1-001", toolLine)},
			removed: []scanner.Finding{
				finding(repo, "keys.py", "RSA-001", importLine),
				finding(repo, "keys.py", "RSA-001", keyLine),
				finding(repo, "auth.py", "RSA-001", keyLine),
			},
			noRoot: outcome{nil, []bool{true, true, true}},
			rooted: outcome{[]string{"tool.py"}, []bool{true, true, true}},
		},
		{
			// tools/tool.py did not move, and a tool.py added at the top of
			// the tree holds a line the baseline does not list. The file
			// removed every finding in keys.py and tools/tool.py.
			name: "a new finding in a file with the name of a baseline file in another directory",
			entries: []scanner.Finding{
				finding(oldRoot, "keys.py", "RSA-001", importLine),
				finding(oldRoot, "keys.py", "RSA-001", keyLine),
				finding(oldRoot, "keys.py", "KEYSIZE-001", keyLine),
				finding(oldRoot, "tools/tool.py", "SHA1-001", toolLine),
			},
			reported: []scanner.Finding{finding(repo, "tool.py", "BLOWFISH-001", blowfishLine)},
			removed: []scanner.Finding{
				finding(repo, "keys.py", "RSA-001", importLine),
				finding(repo, "keys.py", "RSA-001", keyLine),
				finding(repo, "keys.py", "KEYSIZE-001", keyLine),
				finding(repo, "tools/tool.py", "SHA1-001", toolLine),
			},
			noRoot: outcome{[]string{"tool.py"}, []bool{true, true, true, true}},
			rooted: outcome{[]string{"tool.py"}, []bool{true, true, true, true}},
		},
		{
			// tools/tool.py and tools/util.py moved to tool.py and util.py,
			// and keys.py did not move. The file removed the findings in
			// keys.py and tool.py, and util.py's finding is reported.
			name: "a removed finding in a file that moved with the reported one",
			entries: []scanner.Finding{
				finding(oldRoot, "keys.py", "BLOWFISH-001", blowfishLine),
				finding(oldRoot, "tools/tool.py", "SHA1-001", toolLine),
				finding(oldRoot, "tools/util.py", "MD5-001", md5Line),
			},
			reported: []scanner.Finding{finding(repo, "util.py", "MD5-001", md5Line)},
			removed: []scanner.Finding{
				finding(repo, "keys.py", "BLOWFISH-001", blowfishLine),
				finding(repo, "tool.py", "SHA1-001", toolLine),
			},
			noRoot: outcome{nil, []bool{true, true}},
			rooted: outcome{[]string{"util.py"}, []bool{true, false}},
		},
		{
			// helper.py and tools/helper.py hold the same line, and a
			// tool.py added at the top of the tree holds a line the baseline
			// does not list. The file removed every finding in helper.py,
			// tools/helper.py, keys.py and tools/tool.py.
			name: "removed findings with the same line in files with the same name",
			entries: []scanner.Finding{
				finding(oldRoot, "keys.py", "RSA-001", importLine),
				finding(oldRoot, "keys.py", "RSA-001", keyLine),
				finding(oldRoot, "keys.py", "KEYSIZE-001", keyLine),
				finding(oldRoot, "tools/tool.py", "SHA1-001", toolLine),
				finding(oldRoot, "helper.py", "MD5-001", md5Line),
				finding(oldRoot, "tools/helper.py", "MD5-001", md5Line),
			},
			reported: []scanner.Finding{finding(repo, "tool.py", "BLOWFISH-001", blowfishLine)},
			removed: []scanner.Finding{
				finding(repo, "helper.py", "MD5-001", md5Line),
				finding(repo, "tools/helper.py", "MD5-001", md5Line),
				finding(repo, "keys.py", "RSA-001", importLine),
				finding(repo, "keys.py", "RSA-001", keyLine),
				finding(repo, "keys.py", "KEYSIZE-001", keyLine),
				finding(repo, "tools/tool.py", "SHA1-001", toolLine),
			},
			noRoot: outcome{[]string{"tool.py"}, []bool{true, true, true, true, true, true}},
			rooted: outcome{[]string{"tool.py"}, []bool{true, true, true, true, true, true}},
		},
		{
			// tool.py and tools/tool.py hold the same line, and
			// tools/util.py moved to util.py. The file removed the findings
			// in tool.py and tools/tool.py, and util.py's finding is
			// reported.
			name: "removed findings with the same line in files with the same name, and a file that moved",
			entries: []scanner.Finding{
				finding(oldRoot, "tool.py", "SHA1-001", toolLine),
				finding(oldRoot, "tools/tool.py", "SHA1-001", toolLine),
				finding(oldRoot, "tools/util.py", "BLOWFISH-001", blowfishLine),
			},
			reported: []scanner.Finding{finding(repo, "util.py", "BLOWFISH-001", blowfishLine)},
			removed: []scanner.Finding{
				finding(repo, "tool.py", "SHA1-001", toolLine),
				finding(repo, "tools/tool.py", "SHA1-001", toolLine),
			},
			noRoot: outcome{nil, []bool{true, true}},
			rooted: outcome{[]string{"util.py"}, []bool{true, true}},
		},
	}
	for _, tt := range tests {
		baselines := []struct {
			name string
			b    *baseline
			want outcome
		}{
			{"root recorded", &baseline{ScanTarget: ".", Metadata: map[string]string{scanner.MetadataScanRoot: oldRoot}, Findings: tt.entries}, tt.rooted},
			{"no root recorded", &baseline{ScanTarget: ".", Findings: tt.entries}, tt.noRoot},
		}
		for _, bl := range baselines {
			t.Run(bl.name+"/"+tt.name, func(t *testing.T) {
				newFindings, accepted := applyBaseline(tt.reported, tt.removed, repo, bl.b)
				if got := files(newFindings); !reflect.DeepEqual(got, bl.want.newFiles) {
					t.Errorf("new findings in %v, want %v", got, bl.want.newFiles)
				}
				alone, _ := applyBaseline(tt.reported, nil, repo, bl.b)
				if got, without := files(newFindings), files(alone); !reflect.DeepEqual(got, without) {
					t.Errorf("new findings in %v with the removed findings set against the baseline, in %v without them", got, without)
				}
				if !reflect.DeepEqual(accepted, bl.want.accepted) {
					t.Errorf("accepted = %v, want %v", accepted, bl.want.accepted)
				}
			})
		}
	}
}

// TestApplyBaselineWithoutRecordedRootAndNoRootFromTheReportedFindings sets a
// baseline in the form 1.4.0 writes, which records no root, against trees in
// which tools/a.py and tools/b.py moved to a.py and b.py after it was written
// and no reported finding's path is the end of a path the baseline lists, so
// that the root is found from the paths of the reported and the removed
// findings together. In the first two cases keys.py did not move, and a.py
// and b.py propose tools/, the directory they moved out of, over the
// directory keys.py proposes. The removed findings in a.py and b.py are
// accepted under tools/, as they were before, and the removed findings in
// keys.py, which is not under tools/, under the root found among the
// directories that hold every file the baseline lists, as with the root
// recorded. With the root recorded, the removed findings in a.py and b.py are
// not accepted. In the third, keys.py is gone, no directory proposed holds
// the keys.py the baseline lists, and the removed findings are set against
// tools/ alone, as before.
func TestApplyBaselineWithoutRecordedRootAndNoRootFromTheReportedFindings(t *testing.T) {
	oldRoot := filepath.Join(t.TempDir(), "old", "checkout")
	repo := filepath.Join(t.TempDir(), "repo")
	const (
		importLine = "from cryptography.hazmat.primitives.asymmetric import rsa"
		keyLine    = "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)"
		aLine      = "c = Blowfish.new(key)"
		bLine      = "d = Blowfish.new(other)"
		md5Line    = `H = hashlib.md5(b"t").hexdigest()`
	)
	finding := func(dir, file, pattern, line string) scanner.Finding {
		return scanner.Finding{File: filepath.Join(dir, filepath.FromSlash(file)), PatternID: pattern, Match: line}
	}
	// files lists the paths, relative to repo, of the findings given.
	files := func(findings []scanner.Finding) []string {
		var paths []string
		for _, f := range findings {
			paths = append(paths, filepath.ToSlash(strings.TrimPrefix(f.File, repo+string(filepath.Separator))))
		}
		return paths
	}
	entries := []scanner.Finding{
		finding(oldRoot, "keys.py", "RSA-001", importLine),
		finding(oldRoot, "keys.py", "RSA-001", keyLine),
		finding(oldRoot, "keys.py", "KEYSIZE-001", keyLine),
		finding(oldRoot, "tools/a.py", "BLOWFISH-001", aLine),
		finding(oldRoot, "tools/b.py", "BLOWFISH-001", bLine),
	}
	removed := []scanner.Finding{
		finding(repo, "keys.py", "RSA-001", importLine),
		finding(repo, "keys.py", "RSA-001", keyLine),
		finding(repo, "keys.py", "KEYSIZE-001", keyLine),
		finding(repo, "a.py", "BLOWFISH-001", aLine),
		finding(repo, "b.py", "BLOWFISH-001", bLine),
	}
	type outcome struct {
		newFiles []string // the files of the reported findings that are new
		accepted []bool   // whether the baseline accepts each removed finding
	}
	tests := []struct {
		name              string
		reported, removed []scanner.Finding
		noRoot, rooted    outcome
	}{
		{
			name:    "nothing reported",
			removed: removed,
			noRoot:  outcome{nil, []bool{true, true, true, true, true}},
			rooted:  outcome{nil, []bool{true, true, true, false, false}},
		},
		{
			name:     "a finding reported in a file the baseline does not list",
			reported: []scanner.Finding{finding(repo, "new.py", "MD5-001", md5Line)},
			removed:  removed,
			noRoot:   outcome{[]string{"new.py"}, []bool{true, true, true, true, true}},
			rooted:   outcome{[]string{"new.py"}, []bool{true, true, true, false, false}},
		},
		{
			name:    "the file that did not move is gone",
			removed: removed[3:],
			noRoot:  outcome{nil, []bool{true, true}},
			rooted:  outcome{nil, []bool{false, false}},
		},
	}
	for _, tt := range tests {
		baselines := []struct {
			name string
			b    *baseline
			want outcome
		}{
			{"root recorded", &baseline{ScanTarget: ".", Metadata: map[string]string{scanner.MetadataScanRoot: oldRoot}, Findings: entries}, tt.rooted},
			{"no root recorded", &baseline{ScanTarget: ".", Findings: entries}, tt.noRoot},
		}
		for _, bl := range baselines {
			t.Run(bl.name+"/"+tt.name, func(t *testing.T) {
				newFindings, accepted := applyBaseline(tt.reported, tt.removed, repo, bl.b)
				if got := files(newFindings); !reflect.DeepEqual(got, bl.want.newFiles) {
					t.Errorf("new findings in %v, want %v", got, bl.want.newFiles)
				}
				alone, _ := applyBaseline(tt.reported, nil, repo, bl.b)
				if got, without := files(newFindings), files(alone); !reflect.DeepEqual(got, without) {
					t.Errorf("new findings in %v with the removed findings set against the baseline, in %v without them", got, without)
				}
				if !reflect.DeepEqual(accepted, bl.want.accepted) {
					t.Errorf("accepted = %v, want %v", accepted, bl.want.accepted)
				}
			})
		}
	}
}

// TestApplyBaselineWithoutRecordedRootAcceptsReportedFindingsInFilesThatDidNotMove
// sets a baseline in the form 1.4.0 writes, which records no root, against
// trees in which files the baseline lists in tools/ moved to the top of the
// tree after it was written and outnumber the listed files that did not
// move, with the findings in keys.py, which did not move, reported. The
// reported paths propose tools/, which keys.py is not under, over the
// directory keys.py proposes, and under tools/ alone the findings in keys.py
// were new. They are accepted under the root that holds every file the
// baseline lists, as with the root recorded, and the findings in the files
// that moved are still accepted under tools/. With the root recorded, the
// findings in the files that moved are new. In the third case tools/a.py did
// not move and a copy of it was added at the top of the tree: tools/a.py
// takes its entry, as with the root recorded, and the copy is new.
func TestApplyBaselineWithoutRecordedRootAcceptsReportedFindingsInFilesThatDidNotMove(t *testing.T) {
	oldRoot := filepath.Join(t.TempDir(), "old", "checkout")
	repo := filepath.Join(t.TempDir(), "repo")
	const (
		importLine = "from cryptography.hazmat.primitives.asymmetric import rsa"
		keyLine    = "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)"
		aLine      = "c = Blowfish.new(key)"
		bLine      = "d = Blowfish.new(other)"
		cLine      = "e = Blowfish.new(third)"
	)
	finding := func(dir, file, pattern, line string) scanner.Finding {
		return scanner.Finding{File: filepath.Join(dir, filepath.FromSlash(file)), PatternID: pattern, Match: line}
	}
	// files lists the paths, relative to repo, of the findings given.
	files := func(findings []scanner.Finding) []string {
		var paths []string
		for _, f := range findings {
			paths = append(paths, filepath.ToSlash(strings.TrimPrefix(f.File, repo+string(filepath.Separator))))
		}
		return paths
	}
	// keys returns the findings in keys.py under dir: RSA-001 twice and
	// KEYSIZE-001.
	keys := func(dir string) []scanner.Finding {
		return []scanner.Finding{
			finding(dir, "keys.py", "RSA-001", importLine),
			finding(dir, "keys.py", "RSA-001", keyLine),
			finding(dir, "keys.py", "KEYSIZE-001", keyLine),
		}
	}
	entries := append(keys(oldRoot),
		finding(oldRoot, "tools/a.py", "BLOWFISH-001", aLine),
		finding(oldRoot, "tools/b.py", "BLOWFISH-001", bLine),
	)
	moved := []scanner.Finding{
		finding(repo, "a.py", "BLOWFISH-001", aLine),
		finding(repo, "b.py", "BLOWFISH-001", bLine),
	}
	type outcome struct {
		newFiles []string // the files of the reported findings that are new
		accepted []bool   // whether the baseline accepts each removed finding
	}
	tests := []struct {
		name              string
		entries           []scanner.Finding // from the checkout the baseline was written in
		reported, removed []scanner.Finding
		noRoot, rooted    outcome
	}{
		{
			// tools/a.py and tools/b.py moved to a.py and b.py.
			name:     "every finding reported",
			entries:  entries,
			reported: append(keys(repo), moved...),
			noRoot:   outcome{nil, []bool{}},
			rooted:   outcome{[]string{"a.py", "b.py"}, []bool{}},
		},
		{
			// The same tree, with the RSA-001 findings removed.
			name:     "the RSA-001 findings removed",
			entries:  entries,
			reported: append(keys(repo)[2:], moved...),
			removed:  keys(repo)[:2],
			noRoot:   outcome{nil, []bool{true, true}},
			rooted:   outcome{[]string{"a.py", "b.py"}, []bool{true, true}},
		},
		{
			// tools/b.py and tools/c.py moved to b.py and c.py, tools/a.py
			// did not move, and a.py is a copy of it.
			name:    "a copy of a listed file that did not move",
			entries: append(entries[:len(entries):len(entries)], finding(oldRoot, "tools/c.py", "BLOWFISH-001", cLine)),
			reported: append(keys(repo),
				finding(repo, "tools/a.py", "BLOWFISH-001", aLine),
				finding(repo, "a.py", "BLOWFISH-001", aLine),
				finding(repo, "b.py", "BLOWFISH-001", bLine),
				finding(repo, "c.py", "BLOWFISH-001", cLine),
			),
			noRoot: outcome{[]string{"a.py"}, []bool{}},
			rooted: outcome{[]string{"a.py", "b.py", "c.py"}, []bool{}},
		},
	}
	for _, tt := range tests {
		baselines := []struct {
			name string
			b    *baseline
			want outcome
		}{
			{"root recorded", &baseline{ScanTarget: ".", Metadata: map[string]string{scanner.MetadataScanRoot: oldRoot}, Findings: tt.entries}, tt.rooted},
			{"no root recorded", &baseline{ScanTarget: ".", Findings: tt.entries}, tt.noRoot},
		}
		for _, bl := range baselines {
			t.Run(bl.name+"/"+tt.name, func(t *testing.T) {
				newFindings, accepted := applyBaseline(tt.reported, tt.removed, repo, bl.b)
				if got := files(newFindings); !reflect.DeepEqual(got, bl.want.newFiles) {
					t.Errorf("new findings in %v, want %v", got, bl.want.newFiles)
				}
				alone, _ := applyBaseline(tt.reported, nil, repo, bl.b)
				if got, without := files(newFindings), files(alone); !reflect.DeepEqual(got, without) {
					t.Errorf("new findings in %v with the removed findings set against the baseline, in %v without them", got, without)
				}
				if !reflect.DeepEqual(accepted, bl.want.accepted) {
					t.Errorf("accepted = %v, want %v", accepted, bl.want.accepted)
				}
			})
		}
	}
}

// TestApplyBaselineWithoutRecordedRootAcceptsAFileThatMovedIntoTheOldPathOfAListedFile
// sets a baseline in the form 1.4.0 writes, which records no root, against
// trees in which a file the baseline lists in tools/ moved to the top of the
// tree and a file the baseline lists in tools/tools/, holding the same lines,
// moved into the path it left. The reported paths propose tools/, which a
// listed file is not under, and the root that holds every listed file is the
// top of the tree. Under that root, the findings in tools/ took the entries of
// the file that moved, so the findings in the file that moved were new,
// although under tools/ alone every reported finding is accepted. They are
// all accepted: the findings in tools/ move to the entries of the file that
// moved into tools/, and the findings in the file that moved take its
// entries. In the first two cases, old.py, which the baseline lists, was
// deleted; in the third, keys.py did not move. With the root recorded, the
// findings in the files that moved to the top of the tree are new.
func TestApplyBaselineWithoutRecordedRootAcceptsAFileThatMovedIntoTheOldPathOfAListedFile(t *testing.T) {
	oldRoot := filepath.Join(t.TempDir(), "old", "checkout")
	repo := filepath.Join(t.TempDir(), "repo")
	const (
		importLine = "from cryptography.hazmat.primitives.asymmetric import rsa"
		keyLine    = "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)"
		aLine      = "c = Blowfish.new(key)"
		bLine      = "d = Blowfish.new(other)"
	)
	finding := func(dir, file, pattern, line string) scanner.Finding {
		return scanner.Finding{File: filepath.Join(dir, filepath.FromSlash(file)), PatternID: pattern, Match: line}
	}
	// files lists the paths, relative to repo, of the findings given.
	files := func(findings []scanner.Finding) []string {
		var paths []string
		for _, f := range findings {
			paths = append(paths, filepath.ToSlash(strings.TrimPrefix(f.File, repo+string(filepath.Separator))))
		}
		return paths
	}
	// rsaIn returns the findings in file under dir: RSA-001 twice and
	// KEYSIZE-001.
	rsaIn := func(dir, file string) []scanner.Finding {
		return []scanner.Finding{
			finding(dir, file, "RSA-001", importLine),
			finding(dir, file, "RSA-001", keyLine),
			finding(dir, file, "KEYSIZE-001", keyLine),
		}
	}
	join := func(lists ...[]scanner.Finding) []scanner.Finding {
		var all []scanner.Finding
		for _, list := range lists {
			all = append(all, list...)
		}
		return all
	}
	// The baseline lists old.py, tools/keys.py and tools/tools/keys.py.
	// old.py was then deleted, tools/keys.py moved to keys.py and
	// tools/tools/keys.py to tools/keys.py.
	entries := join(
		[]scanner.Finding{finding(oldRoot, "old.py", "BLOWFISH-001", aLine)},
		rsaIn(oldRoot, "tools/keys.py"),
		rsaIn(oldRoot, "tools/tools/keys.py"),
	)
	type outcome struct {
		newFiles []string // the files of the reported findings that are new
		accepted []bool   // whether the baseline accepts each removed finding
	}
	tests := []struct {
		name              string
		entries           []scanner.Finding // from the checkout the baseline was written in
		reported, removed []scanner.Finding
		noRoot, rooted    outcome
	}{
		{
			name:     "every finding reported",
			entries:  entries,
			reported: join(rsaIn(repo, "keys.py"), rsaIn(repo, "tools/keys.py")),
			noRoot:   outcome{nil, []bool{}},
			rooted:   outcome{[]string{"keys.py", "keys.py", "keys.py"}, []bool{}},
		},
		{
			// The same tree, with the RSA-001 findings removed.
			name:     "the RSA-001 findings removed",
			entries:  entries,
			reported: join(rsaIn(repo, "keys.py")[2:], rsaIn(repo, "tools/keys.py")[2:]),
			removed:  join(rsaIn(repo, "keys.py")[:2], rsaIn(repo, "tools/keys.py")[:2]),
			noRoot:   outcome{nil, []bool{true, true, true, true}},
			rooted:   outcome{[]string{"keys.py"}, []bool{false, false, true, true}},
		},
		{
			// keys.py did not move, tools/a.py and tools/b.py moved to a.py
			// and b.py, and tools/tools/a.py, which holds the line of
			// tools/a.py, moved to tools/a.py.
			name: "keys.py did not move",
			entries: join(rsaIn(oldRoot, "keys.py"), []scanner.Finding{
				finding(oldRoot, "tools/a.py", "BLOWFISH-001", aLine),
				finding(oldRoot, "tools/b.py", "BLOWFISH-001", bLine),
				finding(oldRoot, "tools/tools/a.py", "BLOWFISH-001", aLine),
			}),
			reported: join(rsaIn(repo, "keys.py"), []scanner.Finding{
				finding(repo, "a.py", "BLOWFISH-001", aLine),
				finding(repo, "b.py", "BLOWFISH-001", bLine),
				finding(repo, "tools/a.py", "BLOWFISH-001", aLine),
			}),
			noRoot: outcome{nil, []bool{}},
			rooted: outcome{[]string{"a.py", "b.py"}, []bool{}},
		},
	}
	for _, tt := range tests {
		baselines := []struct {
			name string
			b    *baseline
			want outcome
		}{
			{"root recorded", &baseline{ScanTarget: ".", Metadata: map[string]string{scanner.MetadataScanRoot: oldRoot}, Findings: tt.entries}, tt.rooted},
			{"no root recorded", &baseline{ScanTarget: ".", Findings: tt.entries}, tt.noRoot},
		}
		for _, bl := range baselines {
			t.Run(bl.name+"/"+tt.name, func(t *testing.T) {
				newFindings, accepted := applyBaseline(tt.reported, tt.removed, repo, bl.b)
				if got := files(newFindings); !reflect.DeepEqual(got, bl.want.newFiles) {
					t.Errorf("new findings in %v, want %v", got, bl.want.newFiles)
				}
				alone, _ := applyBaseline(tt.reported, nil, repo, bl.b)
				if got, without := files(newFindings), files(alone); !reflect.DeepEqual(got, without) {
					t.Errorf("new findings in %v with the removed findings set against the baseline, in %v without them", got, without)
				}
				if !reflect.DeepEqual(accepted, bl.want.accepted) {
					t.Errorf("accepted = %v, want %v", accepted, bl.want.accepted)
				}
			})
		}
	}
}

// TestGateWithBaselineWithoutRecordedRootAcceptsWhatAFoundConfigRemoved is
// the reproduction from the issue. keys.py gives RSA-001 twice at HIGH and
// KEYSIZE-001 at LOW, a baseline lists all three, and a .cryptoscan.yaml
// found in the scan target ignores both patterns. With the baseline in the
// form 1.4.0 writes, with no metadata.scanRoot, scanTarget "." and no
// patternId, gate exited 1 and named the config file, although the baseline
// lists every finding the file removed from keys.py. Each run is made from
// inside the tree with target ".", as in the issue.
func TestGateWithBaselineWithoutRecordedRootAcceptsWhatAFoundConfigRemoved(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys.py"), []byte(rsaSource), 0o600); err != nil {
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
			t.Errorf("restore working directory: %v", err)
		}
	})

	rooted := filepath.Join(t.TempDir(), "baseline.json")
	if out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--output", rooted); out.err != "" {
		t.Fatalf("baseline scan failed: %s", out.err)
	}
	legacy := legacyBaseline(t, rooted, 3)

	cfgPath := filepath.Join(dir, ".cryptoscan.yaml")
	if err := os.WriteFile(cfgPath, []byte("ignore:\n  patterns: [RSA-001, KEYSIZE-001]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Without a baseline, the file's removals fail the run.
	line := configExitLine(2, "high", cfgPath)
	if out := runCommandWith(t, gateCmd, "."); out.code != 1 || !strings.Contains(out.stderr, line+"\n") {
		t.Fatalf("gate without a baseline = exit code %d, stderr %q; want 1 and the line %q", out.code, out.stderr, line)
	}

	runs := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"gate, baseline in the 1.4.0 form", gateCmd, []string{"--baseline", legacy}},
		{"scan --fail-on high, baseline in the 1.4.0 form", scanCmd, []string{"--stream=false", "--fail-on", "high", "--baseline", legacy}},
		{"gate, baseline that records its root", gateCmd, []string{"--baseline", rooted}},
	}
	for _, tt := range runs {
		t.Run(tt.name, func(t *testing.T) {
			out := runCommandWith(t, tt.cmd, ".", tt.args...)
			if out.err != "" || out.code != 0 {
				t.Errorf("exit code %d, error %q; want exit code 0", out.code, out.err)
			}
			if strings.Contains(out.stderr, "cryptoscan: exit code 1:") {
				t.Errorf("stderr = %q, which gives the config file as a reason for exit code 1", out.stderr)
			}
		})
	}
}

// TestGateWithBaselineWithoutRecordedRootAndANewFileNamedAsAListedFile is the
// reproduction from the issue. keys.py gives RSA-001 twice at HIGH and
// KEYSIZE-001 at LOW, tools/tool.py gives SHA1-001 at HIGH, and a baseline
// lists all four. A tool.py added at the top of the tree then gives
// BLOWFISH-001 at MEDIUM, and a .cryptoscan.yaml found in the scan target
// ignores RSA-001, KEYSIZE-001 and SHA1-001. With the baseline in the form
// 1.4.0 writes, the reported path tool.py gave the baseline the root of
// tools/tool.py, which keys.py is not under, and gate exited 1 and named the
// config file, although the baseline lists every finding the file removed.
// Each run is made from inside the tree with target ".", as in the issue.
func TestGateWithBaselineWithoutRecordedRootAndANewFileNamedAsAListedFile(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("keys.py", rsaSource)
	write("tools/tool.py", "DIGEST = hashlib.sha1(b\"tool\").hexdigest()\n")
	chdirForTest(t, dir)

	rooted := filepath.Join(t.TempDir(), "baseline.json")
	if out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--output", rooted); out.err != "" {
		t.Fatalf("baseline scan failed: %s", out.err)
	}
	legacy := legacyBaseline(t, rooted, 4)

	write("tool.py", "c = Blowfish.new(key)\n")
	write(".cryptoscan.yaml", "ignore:\n  patterns: [RSA-001, KEYSIZE-001, SHA1-001]\n")
	cfgPath := filepath.Join(dir, ".cryptoscan.yaml")
	// Without a baseline, the file's removals fail the run.
	line := configExitLine(3, "high", cfgPath)
	if out := runCommandWith(t, gateCmd, "."); out.code != 1 || !strings.Contains(out.stderr, line+"\n") {
		t.Fatalf("gate without a baseline = exit code %d, stderr %q; want 1 and the line %q", out.code, out.stderr, line)
	}

	runs := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"gate, baseline in the 1.4.0 form", gateCmd, []string{"--baseline", legacy}},
		{"scan --fail-on high, baseline in the 1.4.0 form", scanCmd, []string{"--stream=false", "--fail-on", "high", "--baseline", legacy}},
		{"gate, baseline that records its root", gateCmd, []string{"--baseline", rooted}},
	}
	for _, tt := range runs {
		t.Run(tt.name, func(t *testing.T) {
			out := runCommandWith(t, tt.cmd, ".", tt.args...)
			if out.err != "" || out.code != 0 {
				t.Errorf("exit code %d, error %q; want exit code 0", out.code, out.err)
			}
			if strings.Contains(out.stderr, "cryptoscan: exit code 1:") {
				t.Errorf("stderr = %q, which gives the config file as a reason for exit code 1", out.stderr)
			}
		})
	}

	// The finding in the new tool.py is the one finding the report lists.
	out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--baseline", legacy)
	if out.err != "" {
		t.Fatalf("scan with the baseline in the 1.4.0 form failed: %s", out.err)
	}
	var report struct {
		Findings []struct {
			File      string `json:"file"`
			PatternID string `json:"patternId"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
		t.Fatalf("scan output is not JSON: %v", err)
	}
	want := filepath.Join(dir, "tool.py")
	if len(report.Findings) != 1 || report.Findings[0].PatternID != "BLOWFISH-001" || report.Findings[0].File != want {
		t.Errorf("findings = %+v, want BLOWFISH-001 in %s alone", report.Findings, want)
	}
}

// TestGateWithBaselineWithoutRecordedRootAcceptsARemovedFindingInAMovedFile
// sets a baseline in the form 1.4.0 writes against a tree in which
// tools/tool.py and tools/util.py moved to the top after it was written.
// keys.py gives BLOWFISH-001 at MEDIUM, tools/tool.py SHA1-001 at HIGH and
// tools/util.py MD5-001, and the baseline lists all three. The reported path
// util.py gives the baseline the root of tools/util.py, which places the
// baseline's tools/tool.py at the moved tool.py, so without a config file the
// baseline accepts every finding at or above HIGH and gate exits 0. A
// .cryptoscan.yaml found in the scan target that ignores SHA1-001 and
// BLOWFISH-001 then made gate exit 1 and name the file for the SHA1 finding
// in tool.py, which the baseline accepts without it. Each run is made from
// inside the tree with target ".".
func TestGateWithBaselineWithoutRecordedRootAcceptsARemovedFindingInAMovedFile(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("keys.py", "c = Blowfish.new(key)\n")
	write("tools/tool.py", "DIGEST = hashlib.sha1(b\"tool\").hexdigest()\n")
	write("tools/util.py", "h = hashlib.md5(b\"util\").hexdigest()\n")
	chdirForTest(t, dir)

	rooted := filepath.Join(t.TempDir(), "baseline.json")
	if out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--output", rooted); out.err != "" {
		t.Fatalf("baseline scan failed: %s", out.err)
	}
	legacy := legacyBaseline(t, rooted, 3)

	for _, name := range []string{"tool.py", "util.py"} {
		if err := os.Rename(filepath.Join(dir, "tools", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	// Without a config file, the baseline accepts the SHA1 finding in the
	// moved tool.py, and the findings in util.py and in keys.py, which did
	// not move, as well.
	if out := runCommandWith(t, gateCmd, ".", "--baseline", legacy); out.err != "" || out.code != 0 {
		t.Fatalf("gate without a config file = exit code %d, error %q; want exit code 0", out.code, out.err)
	}

	write(".cryptoscan.yaml", "ignore:\n  patterns: [SHA1-001, BLOWFISH-001]\n")
	runs := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"gate, baseline in the 1.4.0 form", gateCmd, []string{"--baseline", legacy}},
		{"scan --fail-on high, baseline in the 1.4.0 form", scanCmd, []string{"--stream=false", "--fail-on", "high", "--baseline", legacy}},
	}
	for _, tt := range runs {
		t.Run(tt.name, func(t *testing.T) {
			out := runCommandWith(t, tt.cmd, ".", tt.args...)
			if out.err != "" || out.code != 0 {
				t.Errorf("exit code %d, error %q; want exit code 0", out.code, out.err)
			}
			if strings.Contains(out.stderr, "cryptoscan: exit code 1:") {
				t.Errorf("stderr = %q, which gives the config file as a reason for exit code 1", out.stderr)
			}
		})
	}

	// The baseline accepts the reported finding in util.py, so the report
	// lists none.
	out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--baseline", legacy)
	if out.err != "" {
		t.Fatalf("scan with the baseline in the 1.4.0 form failed: %s", out.err)
	}
	var report struct {
		Findings []struct {
			File      string `json:"file"`
			PatternID string `json:"patternId"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
		t.Fatalf("scan output is not JSON: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("findings = %+v, want none", report.Findings)
	}
}

// TestGateWithBaselineWithoutRecordedRootAcceptsRemovedFindingsAfterFilesMovedUp
// is the reproduction from the issue. keys.py gives RSA-001 twice at HIGH and
// KEYSIZE-001 at LOW, tools/a.py and tools/b.py each give BLOWFISH-001 at
// MEDIUM, and a baseline lists all five. a.py and b.py then moved to the top
// of the tree, and a .cryptoscan.yaml found in the scan target ignores
// RSA-001, KEYSIZE-001 and BLOWFISH-001, so no finding is reported. With the
// baseline in the form 1.4.0 writes, the paths a.py and b.py gave the
// baseline the root of tools/a.py and tools/b.py, which keys.py is not under,
// and gate exited 1 and named the config file, although the baseline lists
// both HIGH findings the file removed. Each run is made from inside the tree
// with target ".", as in the issue.
func TestGateWithBaselineWithoutRecordedRootAcceptsRemovedFindingsAfterFilesMovedUp(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("keys.py", rsaSource)
	write("tools/a.py", "c = Blowfish.new(key)\n")
	write("tools/b.py", "d = Blowfish.new(other)\n")
	chdirForTest(t, dir)

	rooted := filepath.Join(t.TempDir(), "baseline.json")
	if out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--output", rooted); out.err != "" {
		t.Fatalf("baseline scan failed: %s", out.err)
	}
	legacy := legacyBaseline(t, rooted, 5)

	for _, name := range []string{"a.py", "b.py"} {
		if err := os.Rename(filepath.Join(dir, "tools", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	write(".cryptoscan.yaml", "ignore:\n  patterns: [RSA-001, KEYSIZE-001, BLOWFISH-001]\n")
	cfgPath := filepath.Join(dir, ".cryptoscan.yaml")
	// Without a baseline, the file's removals fail the run.
	line := configExitLine(2, "high", cfgPath)
	if out := runCommandWith(t, gateCmd, "."); out.code != 1 || !strings.Contains(out.stderr, line+"\n") {
		t.Fatalf("gate without a baseline = exit code %d, stderr %q; want 1 and the line %q", out.code, out.stderr, line)
	}

	runs := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"gate, baseline in the 1.4.0 form", gateCmd, []string{"--baseline", legacy}},
		{"scan --fail-on high, baseline in the 1.4.0 form", scanCmd, []string{"--stream=false", "--fail-on", "high", "--baseline", legacy}},
		{"gate, baseline that records its root", gateCmd, []string{"--baseline", rooted}},
	}
	for _, tt := range runs {
		t.Run(tt.name, func(t *testing.T) {
			out := runCommandWith(t, tt.cmd, ".", tt.args...)
			if out.err != "" || out.code != 0 {
				t.Errorf("exit code %d, error %q; want exit code 0", out.code, out.err)
			}
			if strings.Contains(out.stderr, "cryptoscan: exit code 1:") {
				t.Errorf("stderr = %q, which gives the config file as a reason for exit code 1", out.stderr)
			}
		})
	}

	// The config file removed every finding, so the report lists none.
	out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--baseline", legacy)
	if out.err != "" {
		t.Fatalf("scan with the baseline in the 1.4.0 form failed: %s", out.err)
	}
	var report struct {
		Findings []struct {
			File      string `json:"file"`
			PatternID string `json:"patternId"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
		t.Fatalf("scan output is not JSON: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("findings = %+v, want none", report.Findings)
	}
}

// TestGateWithBaselineWithoutRecordedRootAcceptsRemovedFindingsWithTheSameLine
// is the reproduction from the issue. Two files with the same name, one at
// the top of the tree and one in tools/, hold the same line, and a baseline
// in the form 1.4.0 writes lists both. After it was written, a file is added
// or moved to the top of the tree, and the path of its reported finding gives
// the baseline the root tools/, which places the baseline's file in tools/ at
// the one at the top; a .cryptoscan.yaml found in the scan target removes the
// findings in both files. The removed
// finding at the top took the entry for the file in tools/, and gate exited 1
// and named the config file for the removed finding in tools/, although the
// baseline lists each removed finding at its own path. Each run is made from
// inside the tree with target ".".
func TestGateWithBaselineWithoutRecordedRootAcceptsRemovedFindingsWithTheSameLine(t *testing.T) {
	const (
		toolSource   = "DIGEST = hashlib.sha1(b\"tool\").hexdigest()\n"
		helperSource = "h = hashlib.md5(data).hexdigest()\n"
	)
	trees := []struct {
		name    string
		files   map[string]string // the tree the baseline is written from
		entries int               // the findings the baseline lists
		moves   map[string]string // files moved after it was written
		added   map[string]string // files added after it was written
		ignore  string            // the patterns .cryptoscan.yaml ignores
		removed int               // the removed findings at or above HIGH
	}{
		{
			// keys.py gives RSA-001 twice at HIGH and KEYSIZE-001 at LOW,
			// tools/tool.py SHA1-001 at HIGH, and helper.py and
			// tools/helper.py MD5-001 at CRITICAL each. The added tool.py
			// gives BLOWFISH-001 at MEDIUM.
			name: "a new file with the name of a listed file",
			files: map[string]string{
				"keys.py":         rsaSource,
				"tools/tool.py":   toolSource,
				"helper.py":       helperSource,
				"tools/helper.py": helperSource,
			},
			entries: 6,
			added:   map[string]string{"tool.py": "c = Blowfish.new(key)\n"},
			ignore:  "RSA-001, KEYSIZE-001, SHA1-001, MD5-001",
			removed: 5,
		},
		{
			// tool.py and tools/tool.py give SHA1-001 at HIGH each, and
			// tools/util.py, which moves to util.py, BLOWFISH-001 at MEDIUM.
			name: "a listed file moved to the top of the tree",
			files: map[string]string{
				"tool.py":       toolSource,
				"tools/tool.py": toolSource,
				"tools/util.py": "c = Blowfish.new(key)\n",
			},
			entries: 3,
			moves:   map[string]string{"tools/util.py": "util.py"},
			ignore:  "SHA1-001",
			removed: 2,
		},
	}
	for _, tree := range trees {
		t.Run(tree.name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			write := func(files map[string]string) {
				t.Helper()
				for name, content := range files {
					path := filepath.Join(dir, filepath.FromSlash(name))
					if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			write(tree.files)
			chdirForTest(t, dir)

			rooted := filepath.Join(t.TempDir(), "baseline.json")
			if out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--output", rooted); out.err != "" {
				t.Fatalf("baseline scan failed: %s", out.err)
			}
			legacy := legacyBaseline(t, rooted, tree.entries)

			for from, to := range tree.moves {
				if err := os.Rename(filepath.Join(dir, filepath.FromSlash(from)), filepath.Join(dir, filepath.FromSlash(to))); err != nil {
					t.Fatal(err)
				}
			}
			write(tree.added)
			// Without a config file, the baseline accepts every finding at or
			// above HIGH.
			if out := runCommandWith(t, gateCmd, ".", "--baseline", legacy); out.err != "" || out.code != 0 {
				t.Fatalf("gate without a config file = exit code %d, error %q; want exit code 0", out.code, out.err)
			}

			write(map[string]string{".cryptoscan.yaml": "ignore:\n  patterns: [" + tree.ignore + "]\n"})
			cfgPath := filepath.Join(dir, ".cryptoscan.yaml")
			// Without a baseline, the file's removals fail the run.
			line := configExitLine(tree.removed, "high", cfgPath)
			if out := runCommandWith(t, gateCmd, "."); out.code != 1 || !strings.Contains(out.stderr, line+"\n") {
				t.Fatalf("gate without a baseline = exit code %d, stderr %q; want 1 and the line %q", out.code, out.stderr, line)
			}

			runs := []struct {
				name string
				cmd  *cobra.Command
				args []string
			}{
				{"gate, baseline in the 1.4.0 form", gateCmd, []string{"--baseline", legacy}},
				{"scan --fail-on high, baseline in the 1.4.0 form", scanCmd, []string{"--stream=false", "--fail-on", "high", "--baseline", legacy}},
				{"gate, baseline that records its root", gateCmd, []string{"--baseline", rooted}},
			}
			for _, tt := range runs {
				t.Run(tt.name, func(t *testing.T) {
					out := runCommandWith(t, tt.cmd, ".", tt.args...)
					if out.err != "" || out.code != 0 {
						t.Errorf("exit code %d, error %q; want exit code 0", out.code, out.err)
					}
					if strings.Contains(out.stderr, "cryptoscan: exit code 1:") {
						t.Errorf("stderr = %q, which gives the config file as a reason for exit code 1", out.stderr)
					}
				})
			}
		})
	}
}

// TestGateWithBaselineWithoutRecordedRootAcceptsTheFindingsInFilesThatDidNotMove
// is the reproduction from the issue. keys.py gives RSA-001 twice at HIGH and
// KEYSIZE-001 at LOW, tools/a.py and tools/b.py each give BLOWFISH-001 at
// MEDIUM, and a baseline lists all five. a.py and b.py then moved to the top
// of the tree. With the baseline in the form 1.4.0 writes, the paths a.py
// and b.py gave the baseline the root of tools/a.py and tools/b.py, which
// keys.py is not under: the report listed the findings in keys.py, which did
// not move, as new, and gate exited 1 with no config file and with
// --no-config, while a .cryptoscan.yaml found in the scan target that
// ignores RSA-001 and KEYSIZE-001, with or without BLOWFISH-001, made gate
// exit 0. Each run is made from inside the tree with target ".", as in the
// issue.
func TestGateWithBaselineWithoutRecordedRootAcceptsTheFindingsInFilesThatDidNotMove(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("keys.py", rsaSource)
	write("tools/a.py", "c = Blowfish.new(key)\n")
	write("tools/b.py", "d = Blowfish.new(other)\n")
	chdirForTest(t, dir)

	rooted := filepath.Join(t.TempDir(), "baseline.json")
	if out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--output", rooted); out.err != "" {
		t.Fatalf("baseline scan failed: %s", out.err)
	}
	legacy := legacyBaseline(t, rooted, 5)

	for _, name := range []string{"a.py", "b.py"} {
		if err := os.Rename(filepath.Join(dir, "tools", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	// The report lists no finding in keys.py, as with the root recorded.
	keys := filepath.Join(dir, "keys.py")
	baselines := []struct{ name, path string }{
		{"baseline in the 1.4.0 form", legacy},
		{"baseline that records its root", rooted},
	}
	for _, bl := range baselines {
		out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--baseline", bl.path)
		if out.err != "" {
			t.Fatalf("scan with the %s failed: %s", bl.name, out.err)
		}
		var report struct {
			Findings []struct {
				File      string `json:"file"`
				PatternID string `json:"patternId"`
			} `json:"findings"`
		}
		if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
			t.Fatalf("scan output is not JSON: %v", err)
		}
		for _, f := range report.Findings {
			if f.File == keys {
				t.Errorf("with the %s, the report lists %s in keys.py, which did not move, as new", bl.name, f.PatternID)
			}
		}
	}

	// gate and scan --fail-on high exit 0 with no config file and with each
	// config file found in the scan target. With --no-config, a config file
	// left in the tree is scanned as a source file, and its RSA-001 line is a
	// finding the baseline does not list, so gate --no-config runs with no
	// file in the tree.
	type run struct {
		name string
		cmd  *cobra.Command
		args []string
	}
	gate := run{"gate", gateCmd, []string{"--baseline", legacy}}
	noConfig := run{"gate --no-config", gateCmd, []string{"--no-config", "--baseline", legacy}}
	scan := run{"scan --fail-on high", scanCmd, []string{"--stream=false", "--fail-on", "high", "--baseline", legacy}}
	configs := []struct {
		name, content string
		runs          []run
	}{
		{"no config file", "", []run{gate, noConfig, scan}},
		{"a config file that ignores RSA-001, KEYSIZE-001 and BLOWFISH-001", "ignore:\n  patterns: [RSA-001, KEYSIZE-001, BLOWFISH-001]\n", []run{gate, scan}},
		{"a config file that ignores RSA-001 and KEYSIZE-001", "ignore:\n  patterns: [RSA-001, KEYSIZE-001]\n", []run{gate, scan}},
	}
	for _, cfg := range configs {
		if cfg.content != "" {
			write(".cryptoscan.yaml", cfg.content)
		}
		for _, tt := range cfg.runs {
			t.Run(cfg.name+"/"+tt.name, func(t *testing.T) {
				out := runCommandWith(t, tt.cmd, ".", tt.args...)
				if out.err != "" || out.code != 0 {
					t.Errorf("exit code %d, error %q; want exit code 0", out.code, out.err)
				}
				if strings.Contains(out.stderr, "cryptoscan: exit code 1:") {
					t.Errorf("stderr = %q, which gives the config file as a reason for exit code 1", out.stderr)
				}
			})
		}
	}
}

// TestGateWithBaselineWithoutRecordedRootAcceptsAFileThatMovedIntoTheOldPathOfAListedFile
// sets a baseline in the 1.4.0 form against a tree in which the directory
// tools/a.py, tools/b.py and tools/tool.py propose, tools/, holds a
// subdirectory of the same name, tools/tools/, which tools/tools/tool.py,
// holding the same line as tools/tool.py, is under. keys.py gives RSA-001
// twice at HIGH and KEYSIZE-001 at LOW, tools/a.py and tools/b.py each give
// BLOWFISH-001 at MEDIUM, tools/tool.py gives SHA1-001 at HIGH, and
// tools/tools/tool.py gives SHA1-001 at HIGH on the same line. A baseline
// lists all seven.
// tools/a.py and tools/b.py then move to the top of the tree as before,
// tools/tool.py moves out to the top of the tree as tool.py, and
// tools/tools/tool.py moves into the path tools/tool.py left. Matching the
// reported findings first under the directory that holds every listed file
// and then under the directory tools/a.py, tools/b.py and tools/tool.py
// propose, with no finding able to move between the two passes, gives
// tools/tool.py's entry to tools/tool.py's new finding (which holds the
// same line under either directory) under the first pass, leaving
// tool.py's finding, which matches that entry only under the second pass,
// with nothing: the report lists SHA1-001 in tool.py, which moved, as new,
// and gate exits 1 with no config file and with --no-config. Each run is
// made from inside the tree with target ".", as in the issue.
func TestGateWithBaselineWithoutRecordedRootAcceptsAFileThatMovedIntoTheOldPathOfAListedFile(t *testing.T) {
	const toolSource = "DIGEST = hashlib.sha1(b\"tool\").hexdigest()\n"
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("keys.py", rsaSource)
	write("tools/a.py", "c = Blowfish.new(key)\n")
	write("tools/b.py", "d = Blowfish.new(other)\n")
	write("tools/tool.py", toolSource)
	write("tools/tools/tool.py", toolSource)
	chdirForTest(t, dir)

	rooted := filepath.Join(t.TempDir(), "baseline.json")
	if out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--output", rooted); out.err != "" {
		t.Fatalf("baseline scan failed: %s", out.err)
	}
	legacy := legacyBaseline(t, rooted, 7)

	for _, name := range []string{"a.py", "b.py"} {
		if err := os.Rename(filepath.Join(dir, "tools", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	// tools/tool.py moves out to the top of the tree first, so
	// tools/tools/tool.py can then move into the path it left.
	if err := os.Rename(filepath.Join(dir, "tools", "tool.py"), filepath.Join(dir, "tool.py")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "tools", "tools", "tool.py"), filepath.Join(dir, "tools", "tool.py")); err != nil {
		t.Fatal(err)
	}

	// With the baseline in the 1.4.0 form, the report lists no finding in
	// tool.py, which moved out, or in tools/tool.py, which moved in: the
	// root every listed file is under rescues tool.py's own entry, and
	// tools/tool.py matches the entry tools/tools/tool.py gives it, holding
	// the same line. With the root recorded, tool.py, which moved, is new,
	// as a.py and b.py are; tools/tool.py still matches: it holds the same
	// line as the entry recorded at that same path.
	moved := filepath.Join(dir, "tool.py")
	movedIn := filepath.Join(dir, "tools", "tool.py")
	baselines := []struct {
		name    string
		path    string
		wantNew map[string]bool
	}{
		{"baseline in the 1.4.0 form", legacy, map[string]bool{}},
		{"baseline that records its root", rooted, map[string]bool{moved: true}},
	}
	for _, bl := range baselines {
		out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--baseline", bl.path)
		if out.err != "" {
			t.Fatalf("scan with the %s failed: %s", bl.name, out.err)
		}
		var report struct {
			Findings []struct {
				File      string `json:"file"`
				PatternID string `json:"patternId"`
			} `json:"findings"`
		}
		if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
			t.Fatalf("scan output is not JSON: %v", err)
		}
		gotNew := map[string]bool{}
		for _, f := range report.Findings {
			if f.File == moved || f.File == movedIn {
				gotNew[f.File] = true
			}
		}
		for _, file := range []string{moved, movedIn} {
			if gotNew[file] != bl.wantNew[file] {
				t.Errorf("with the %s, %s reported as new = %v, want %v", bl.name, file, gotNew[file], bl.wantNew[file])
			}
		}
	}

	// gate and scan --fail-on high exit 0 with no config file and with each
	// config file found in the scan target.
	type run struct {
		name string
		cmd  *cobra.Command
		args []string
	}
	gate := run{"gate", gateCmd, []string{"--baseline", legacy}}
	noConfig := run{"gate --no-config", gateCmd, []string{"--no-config", "--baseline", legacy}}
	scan := run{"scan --fail-on high", scanCmd, []string{"--stream=false", "--fail-on", "high", "--baseline", legacy}}
	configs := []struct {
		name, content string
		runs          []run
	}{
		{"no config file", "", []run{gate, noConfig, scan}},
		{"a config file that ignores RSA-001, KEYSIZE-001, BLOWFISH-001 and SHA1-001", "ignore:\n  patterns: [RSA-001, KEYSIZE-001, BLOWFISH-001, SHA1-001]\n", []run{gate, scan}},
		{"a config file that ignores RSA-001 and KEYSIZE-001", "ignore:\n  patterns: [RSA-001, KEYSIZE-001]\n", []run{gate, scan}},
	}
	for _, cfg := range configs {
		if cfg.content != "" {
			write(".cryptoscan.yaml", cfg.content)
		}
		for _, tt := range cfg.runs {
			t.Run(cfg.name+"/"+tt.name, func(t *testing.T) {
				out := runCommandWith(t, tt.cmd, ".", tt.args...)
				if out.err != "" || out.code != 0 {
					t.Errorf("exit code %d, error %q; want exit code 0", out.code, out.err)
				}
				if strings.Contains(out.stderr, "cryptoscan: exit code 1:") {
					t.Errorf("stderr = %q, which gives the config file as a reason for exit code 1", out.stderr)
				}
			})
		}
	}
}

// TestApplyBaselineWithoutRecordedRootAcceptsAnUnmovedFileWhenListedFilesShareAFolder
// sets a baseline in the form 1.4.0 writes, which records no root, whose
// files are all in tools/, against a tree in which tools/a.py and tools/b.py
// moved to a.py and b.py and tools/keys.py did not move. The reported paths
// propose tools/, which holds every listed file, over the directory
// tools/keys.py proposes, and under tools/ alone the findings in
// tools/keys.py were new. They are accepted under the other directory that
// holds every listed file, as with the root recorded, and the findings in
// the files that moved are still accepted under tools/. With the root
// recorded, the findings in the files that moved are new.
func TestApplyBaselineWithoutRecordedRootAcceptsAnUnmovedFileWhenListedFilesShareAFolder(t *testing.T) {
	oldRoot := filepath.Join(t.TempDir(), "old", "checkout")
	repo := filepath.Join(t.TempDir(), "repo")
	const (
		importLine = "from cryptography.hazmat.primitives.asymmetric import rsa"
		keyLine    = "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)"
		aLine      = "c = Blowfish.new(key)"
		bLine      = "d = Blowfish.new(other)"
	)
	finding := func(dir, file, pattern, line string) scanner.Finding {
		return scanner.Finding{File: filepath.Join(dir, filepath.FromSlash(file)), PatternID: pattern, Match: line}
	}
	files := func(findings []scanner.Finding) []string {
		var paths []string
		for _, f := range findings {
			paths = append(paths, filepath.ToSlash(strings.TrimPrefix(f.File, repo+string(filepath.Separator))))
		}
		return paths
	}
	// keys returns the findings in tools/keys.py under dir: RSA-001 twice
	// and KEYSIZE-001.
	keys := func(dir string) []scanner.Finding {
		return []scanner.Finding{
			finding(dir, "tools/keys.py", "RSA-001", importLine),
			finding(dir, "tools/keys.py", "RSA-001", keyLine),
			finding(dir, "tools/keys.py", "KEYSIZE-001", keyLine),
		}
	}
	entries := append(keys(oldRoot),
		finding(oldRoot, "tools/a.py", "BLOWFISH-001", aLine),
		finding(oldRoot, "tools/b.py", "BLOWFISH-001", bLine),
	)
	moved := []scanner.Finding{
		finding(repo, "a.py", "BLOWFISH-001", aLine),
		finding(repo, "b.py", "BLOWFISH-001", bLine),
	}
	join := func(parts ...[]scanner.Finding) []scanner.Finding {
		var all []scanner.Finding
		for _, p := range parts {
			all = append(all, p...)
		}
		return all
	}
	type outcome struct {
		newFiles []string // the files of the reported findings that are new
		accepted []bool   // whether the baseline accepts each removed finding
	}
	tests := []struct {
		name              string
		reported, removed []scanner.Finding
		noRoot, rooted    outcome
	}{
		{
			name:     "every finding reported",
			reported: join(keys(repo), moved),
			noRoot:   outcome{nil, []bool{}},
			rooted:   outcome{[]string{"a.py", "b.py"}, []bool{}},
		},
		{
			name:     "the RSA-001 findings removed",
			reported: join(keys(repo)[2:], moved),
			removed:  keys(repo)[:2],
			noRoot:   outcome{nil, []bool{true, true}},
			rooted:   outcome{[]string{"a.py", "b.py"}, []bool{true, true}},
		},
		{
			name:     "every finding in tools/keys.py removed",
			reported: moved,
			removed:  keys(repo),
			noRoot:   outcome{nil, []bool{true, true, true}},
			rooted:   outcome{[]string{"a.py", "b.py"}, []bool{true, true, true}},
		},
	}
	for _, tt := range tests {
		baselines := []struct {
			name string
			b    *baseline
			want outcome
		}{
			{"root recorded", &baseline{ScanTarget: ".", Metadata: map[string]string{scanner.MetadataScanRoot: oldRoot}, Findings: entries}, tt.rooted},
			{"no root recorded", &baseline{ScanTarget: ".", Findings: entries}, tt.noRoot},
		}
		for _, bl := range baselines {
			t.Run(bl.name+"/"+tt.name, func(t *testing.T) {
				newFindings, accepted := applyBaseline(tt.reported, tt.removed, repo, bl.b)
				if got := files(newFindings); !reflect.DeepEqual(got, bl.want.newFiles) {
					t.Errorf("new findings in %v, want %v", got, bl.want.newFiles)
				}
				if !reflect.DeepEqual(accepted, bl.want.accepted) {
					t.Errorf("accepted = %v, want %v", accepted, bl.want.accepted)
				}
			})
		}
	}
}

// TestGateWithBaselineWithoutRecordedRootAcceptsAnUnmovedFileWhenListedFilesShareAFolder
// runs the reproduction of the issue: tools/keys.py holds an RSA key
// generation, and tools/a.py and tools/b.py each hold a Blowfish line; after
// a baseline is written, tools/a.py and tools/b.py move to a.py and b.py.
// With the baseline in the 1.4.0 form, the report lists no finding in
// tools/keys.py, and gate and scan --fail-on high exit 0, with no config file
// and with a config file that ignores RSA-001 and KEYSIZE-001.
func TestGateWithBaselineWithoutRecordedRootAcceptsAnUnmovedFileWhenListedFilesShareAFolder(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("tools/keys.py", rsaSource)
	write("tools/a.py", "c = Blowfish.new(key)\n")
	write("tools/b.py", "d = Blowfish.new(other)\n")
	chdirForTest(t, dir)

	rooted := filepath.Join(t.TempDir(), "baseline.json")
	if out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--output", rooted); out.err != "" {
		t.Fatalf("baseline scan failed: %s", out.err)
	}
	legacy := legacyBaseline(t, rooted, 5)

	for _, name := range []string{"a.py", "b.py"} {
		if err := os.Rename(filepath.Join(dir, "tools", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	unmoved := filepath.Join(dir, "tools", "keys.py")
	baselines := []struct {
		name string
		path string
	}{
		{"baseline in the 1.4.0 form", legacy},
		{"baseline that records its root", rooted},
	}
	for _, bl := range baselines {
		out := runCommandWith(t, scanCmd, ".", "--stream=false", "--format", "json", "--baseline", bl.path)
		if out.err != "" {
			t.Fatalf("scan with the %s failed: %s", bl.name, out.err)
		}
		var report struct {
			Findings []struct {
				File      string `json:"file"`
				PatternID string `json:"patternId"`
			} `json:"findings"`
		}
		if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
			t.Fatalf("scan output is not JSON: %v", err)
		}
		for _, f := range report.Findings {
			if f.File == unmoved {
				t.Errorf("with the %s, %s %s reported as new", bl.name, f.File, f.PatternID)
			}
		}
	}

	type run struct {
		name string
		cmd  *cobra.Command
		args []string
	}
	gate := run{"gate", gateCmd, []string{"--baseline", legacy}}
	noConfig := run{"gate --no-config", gateCmd, []string{"--no-config", "--baseline", legacy}}
	scan := run{"scan --fail-on high", scanCmd, []string{"--stream=false", "--fail-on", "high", "--baseline", legacy}}
	configs := []struct {
		name, content string
		runs          []run
	}{
		{"no config file", "", []run{gate, noConfig, scan}},
		{"a config file that ignores RSA-001 and KEYSIZE-001", "ignore:\n  patterns: [RSA-001, KEYSIZE-001]\n", []run{gate, scan}},
	}
	for _, cfg := range configs {
		if cfg.content != "" {
			write(".cryptoscan.yaml", cfg.content)
		}
		for _, tt := range cfg.runs {
			t.Run(cfg.name+"/"+tt.name, func(t *testing.T) {
				out := runCommandWith(t, tt.cmd, ".", tt.args...)
				if out.err != "" || out.code != 0 {
					t.Errorf("exit code %d, error %q; want exit code 0", out.code, out.err)
				}
				if strings.Contains(out.stderr, "cryptoscan: exit code 1:") {
					t.Errorf("stderr = %q, which gives the config file as a reason for exit code 1", out.stderr)
				}
			})
		}
	}
}

// legacyBaseline writes the report a scan saved at rooted again in the form
// 1.4.0 writes, with no metadata, so no metadata.scanRoot, scanTarget "."
// and no patternId, and returns the path of the copy. It stops the test
// unless the report lists want findings.
func legacyBaseline(t *testing.T, rooted string, want int) string {
	t.Helper()
	data, err := os.ReadFile(rooted)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]json.RawMessage
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	var findings []map[string]json.RawMessage
	if err := json.Unmarshal(report["findings"], &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != want {
		t.Fatalf("the baseline lists %d findings; the fixture should give %d", len(findings), want)
	}
	for _, f := range findings {
		delete(f, "patternId")
	}
	delete(report, "metadata")
	report["scanTarget"], _ = json.Marshal(".")
	report["findings"], _ = json.Marshal(findings)
	if data, err = json.Marshal(report); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(legacy, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return legacy
}
