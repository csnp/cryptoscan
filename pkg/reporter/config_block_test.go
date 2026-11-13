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
