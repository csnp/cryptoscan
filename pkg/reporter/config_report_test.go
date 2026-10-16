// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

func emptyResultsWithConfig(c *scanner.ConfigReport) *scanner.Results {
	return &scanner.Results{
		ScanTarget:   "/repo/service",
		ScanTime:     time.Now(),
		ScanDuration: time.Millisecond,
		FilesScanned: 1,
		Findings:     []scanner.Finding{},
		Summary: scanner.Summary{
			BySeverity:    map[string]int{},
			ByCategory:    map[string]int{},
			ByQuantumRisk: map[string]int{},
		},
		Config: c,
	}
}

// TestTextReportNamesTheConfigFileThatRemovedEverything is the case from the
// issue: a config file above the scan target removed every finding, and the
// report printed a check mark and "No cryptographic findings detected".
func TestTextReportNamesTheConfigFileThatRemovedEverything(t *testing.T) {
	results := emptyResultsWithConfig(&scanner.ConfigReport{
		Path:            "/repo/.cryptoscan.yaml",
		Source:          scanner.ConfigSourceParentDirectory,
		FindingsRemoved: scanner.ConfigFindingsRemoved{IgnorePatterns: 3, Total: 3},
		PathsSkipped:    scanner.ConfigPathsSkipped{Files: 2},
	})

	out, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Config file applied: /repo/.cryptoscan.yaml",
		"(found in a directory above the scan target, not in the target itself)",
		"ignore.patterns removed 3 findings",
		"ignore.files kept 2 files out of the scan",
		"Scan without it: cryptoscan scan /repo/service --no-config",
		"! No findings reported: the config file removed 3 findings and kept 2 files out of the scan",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report lacks %q", want)
		}
	}
	if strings.Contains(out, "No cryptographic findings detected") {
		t.Error("text report claims nothing was detected although the config file removed findings")
	}
}

func TestTextReportConfigFileThatRemovedNothing(t *testing.T) {
	results := emptyResultsWithConfig(&scanner.ConfigReport{
		Path:   "/repo/service/.cryptoscan.yaml",
		Source: scanner.ConfigSourceFlag,
	})

	out, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Config file applied: /repo/service/.cryptoscan.yaml",
		"(passed with --config)",
		"It removed no findings and kept no files out of the scan.",
		"✓ No cryptographic findings detected",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report lacks %q", want)
		}
	}
	if strings.Contains(out, "--no-config") {
		t.Error("text report suggests --no-config for a file passed with --config")
	}
}

func TestTextReportWithoutConfigFile(t *testing.T) {
	out, err := NewTextReporter(false).Generate(emptyResultsWithConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Config file applied") {
		t.Error("text report names a config file although none was applied")
	}
	if !strings.Contains(out, "✓ No cryptographic findings detected") {
		t.Error("text report without a config file lost its no-findings line")
	}
}

// TestSARIFRecordsTheConfigFileInInvocations checks that a SARIF consumer can
// see the config file and its counts without reading the text report.
func TestSARIFRecordsTheConfigFileInInvocations(t *testing.T) {
	results := emptyResultsWithConfig(&scanner.ConfigReport{
		Path:            "/repo/.cryptoscan.yaml",
		Source:          scanner.ConfigSourceParentDirectory,
		FindingsRemoved: scanner.ConfigFindingsRemoved{MinSeverity: 1, Baseline: 2, Total: 3},
	})

	out, err := NewSARIFReporter().Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful            bool `json:"executionSuccessful"`
				ToolConfigurationNotifications []struct {
					Level   string `json:"level"`
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
				} `json:"toolConfigurationNotifications"`
				Properties struct {
					ConfigFile scanner.ConfigReport `json:"configFile"`
				} `json:"properties"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Invocations) != 1 {
		t.Fatalf("want one run with one invocation, got %+v", doc.Runs)
	}
	inv := doc.Runs[0].Invocations[0]
	if !inv.ExecutionSuccessful {
		t.Error("executionSuccessful is false")
	}
	if inv.Properties.ConfigFile != *results.Config {
		t.Errorf("configFile property = %+v, want %+v", inv.Properties.ConfigFile, *results.Config)
	}
	if len(inv.ToolConfigurationNotifications) != 1 {
		t.Fatalf("want one notification, got %d", len(inv.ToolConfigurationNotifications))
	}
	n := inv.ToolConfigurationNotifications[0]
	if n.Level != "warning" {
		t.Errorf("notification level %q, want warning", n.Level)
	}
	for _, want := range []string{"/repo/.cryptoscan.yaml", "minSeverity removed 1 finding", "baseline removed 2 findings"} {
		if !strings.Contains(n.Message.Text, want) {
			t.Errorf("notification %q lacks %q", n.Message.Text, want)
		}
	}

	plain, err := NewSARIFReporter().Generate(emptyResultsWithConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, `"invocations"`) {
		t.Error("SARIF without a config file has an invocations array")
	}
}
