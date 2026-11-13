// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// TestScanWithoutItLineRepeatsTheRunsCommand checks the command the config
// block gives for running without the file. A gate run, and a scan with
// --fail-on, are read by their exit code, which follows the threshold, so a
// command that ran scan with its default threshold would not repeat them.
func TestScanWithoutItLineRepeatsTheRunsCommand(t *testing.T) {
	tests := []struct {
		name  string
		rerun scanner.ConfigRerun
		want  string
	}{
		{"zero value", scanner.ConfigRerun{}, "Scan without it: cryptoscan scan /repo/service --no-config"},
		{"plain scan", scanner.ConfigRerun{Command: "scan"}, "Scan without it: cryptoscan scan /repo/service --no-config"},
		{"scan with --fail-on", scanner.ConfigRerun{Command: "scan", FailOn: "high"}, "Scan without it: cryptoscan scan /repo/service --fail-on high --no-config"},
		{"gate", scanner.ConfigRerun{Command: "gate"}, "Scan without it: cryptoscan gate /repo/service --no-config"},
		{"gate with --fail-on", scanner.ConfigRerun{Command: "gate", FailOn: "low"}, "Scan without it: cryptoscan gate /repo/service --fail-on low --no-config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := emptyResultsWithConfig(&scanner.ConfigReport{
				Path:            "/repo/.cryptoscan.yaml",
				Source:          scanner.ConfigSourceScanTarget,
				FindingsRemoved: scanner.ConfigFindingsRemoved{IgnorePatterns: 3, Total: 3},
				Rerun:           tt.rerun,
			})
			out, err := NewTextReporter(false).Generate(results)
			if err != nil {
				t.Fatal(err)
			}
			var lines []string
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "Scan without it:") {
					lines = append(lines, strings.TrimSpace(line))
				}
			}
			if len(lines) != 1 || lines[0] != tt.want {
				t.Errorf("Scan without it lines = %q, want [%q]", lines, tt.want)
			}
		})
	}
}

// TestScanWithoutItLineIsLeftOutForAFilePassedWithConfig keeps the existing
// rule: a file the command line named is not one the reader overlooked.
func TestScanWithoutItLineIsLeftOutForAFilePassedWithConfig(t *testing.T) {
	results := emptyResultsWithConfig(&scanner.ConfigReport{
		Path:            "/repo/.cryptoscan.yaml",
		Source:          scanner.ConfigSourceFlag,
		FindingsRemoved: scanner.ConfigFindingsRemoved{IgnorePatterns: 3, Total: 3},
		Rerun:           scanner.ConfigRerun{Command: "gate"},
	})
	out, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Scan without it:") {
		t.Errorf("text report gives a command without --config for a file passed with --config:\n%s", out)
	}
}

// TestConfigBlockCountsRemovalsBySeverity checks the severity breakdown each
// setting's line gains, highest first and in the names --fail-on takes, in
// the text report and in the SARIF invocation's notification.
func TestConfigBlockCountsRemovalsBySeverity(t *testing.T) {
	report := &scanner.ConfigReport{
		Path:   "/repo/.cryptoscan.yaml",
		Source: scanner.ConfigSourceScanTarget,
		FindingsRemoved: scanner.ConfigFindingsRemoved{
			IgnorePatterns: 3, Baseline: 2, Total: 5,
			BySeverity:               scanner.ConfigSeverityCounts{Critical: 1, High: 2, Low: 1, Info: 1},
			IgnorePatternsBySeverity: scanner.ConfigSeverityCounts{High: 2, Low: 1},
			BaselineBySeverity:       scanner.ConfigSeverityCounts{Critical: 1, Info: 1},
		},
	}
	want := []string{
		"ignore.patterns removed 3 findings (2 high, 1 low)",
		"baseline removed 2 findings (1 critical, 1 info)",
	}

	text, err := NewTextReporter(false).Generate(emptyResultsWithConfig(report))
	if err != nil {
		t.Fatal(err)
	}
	sarif, err := NewSARIFReporter().Generate(emptyResultsWithConfig(report))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range want {
		if !strings.Contains(text, line) {
			t.Errorf("text report lacks %q:\n%s", line, text)
		}
		if !strings.Contains(sarif, line) {
			t.Errorf("SARIF notification lacks %q", line)
		}
	}
}

// TestConfigBlockLineWithoutSeverities keeps a count whose severities were
// not recorded free of an empty breakdown.
func TestConfigBlockLineWithoutSeverities(t *testing.T) {
	text, err := NewTextReporter(false).Generate(emptyResultsWithConfig(&scanner.ConfigReport{
		Path:            "/repo/.cryptoscan.yaml",
		Source:          scanner.ConfigSourceScanTarget,
		FindingsRemoved: scanner.ConfigFindingsRemoved{MinSeverity: 1, Total: 1},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "minSeverity removed 1 finding\n") {
		t.Errorf("text report lacks the plain count line:\n%s", text)
	}
	if strings.Contains(text, "()") {
		t.Errorf("text report has an empty breakdown:\n%s", text)
	}
}

// TestConfigBlockSaysWhenFailOnWasNotApplied checks the line a gate run
// prints when a config file it found sets a failOn above gate's threshold,
// and that no other failOn record prints it.
func TestConfigBlockSaysWhenFailOnWasNotApplied(t *testing.T) {
	line := "failOn: critical in the file was not applied: a config file found without --config cannot raise the threshold above high. " +
		"Pass --config /repo/.cryptoscan.yaml to apply it."
	tests := []struct {
		name   string
		failOn *scanner.ConfigFailOn
		want   bool
	}{
		{"held back by gate", &scanner.ConfigFailOn{Value: "critical", Cap: "high"}, true},
		{"overridden by --fail-on", &scanner.ConfigFailOn{Value: "critical"}, false},
		{"applied", &scanner.ConfigFailOn{Value: "low", Applied: true}, false},
		{"not set", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, err := NewTextReporter(false).Generate(emptyResultsWithConfig(&scanner.ConfigReport{
				Path:   "/repo/.cryptoscan.yaml",
				Source: scanner.ConfigSourceScanTarget,
				FailOn: tt.failOn,
			}))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(text, line); got != tt.want {
				t.Errorf("text report has the not-applied line: %v, want %v\n%s", got, tt.want, text)
			}
		})
	}
}
