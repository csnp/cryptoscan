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
