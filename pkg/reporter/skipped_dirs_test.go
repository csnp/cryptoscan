// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/scanner"
)

// threeSkipped is what a scan of a tree with one file in each of examples/,
// fixtures/ and testdata/ reports.
var threeSkipped = scanner.SkippedDirectories{
	Files:       3,
	Directories: 3,
	Rules:       []string{"examples", "fixtures", "testdata"},
	Paths:       []string{"examples", "fixtures", "testdata"},
}

func TestSkippedDirectoriesSummary(t *testing.T) {
	cases := []struct {
		skipped scanner.SkippedDirectories
		want    string
	}{
		{threeSkipped, "3 files in 3 directories were not scanned (default rules: examples, fixtures, testdata)."},
		{
			scanner.SkippedDirectories{Files: 1, Directories: 1, Rules: []string{"testdata"}, Paths: []string{"testdata"}},
			"1 file in 1 directory was not scanned (default rules: testdata).",
		},
		{
			scanner.SkippedDirectories{Files: 52, Directories: 2, Rules: []string{"node_modules"}, Paths: []string{"node_modules", "web/node_modules"}},
			"52 files in 2 directories were not scanned (default rules: node_modules).",
		},
	}
	for _, c := range cases {
		if got := SkippedDirectoriesSummary(c.skipped); got != c.want {
			t.Errorf("SkippedDirectoriesSummary(%+v) = %q, want %q", c.skipped, got, c.want)
		}
	}
}

// The text report used to print "Scanned: N files" and nothing about the
// directories the default rules left out. It now says how many files they
// hold and how to scan them, and says nothing when they hold none.
func TestTextReportCountsTheFilesInSkippedDirectories(t *testing.T) {
	results := createTestResults()
	results.Skipped = threeSkipped
	output, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	want := "\n  3 files in 3 directories were not scanned (default rules: examples, fixtures, testdata).\n" +
		"  Scan them with --include-skipped.\n"
	if !strings.Contains(output, want) {
		t.Errorf("text report is missing %q:\n%s", want, output)
	}

	results.Skipped = scanner.SkippedDirectories{Directories: 1, Rules: []string{"dist"}, Paths: []string{"dist"}}
	output, err = NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if strings.Contains(output, "include-skipped") || strings.Contains(output, "default rules") {
		t.Errorf("text report mentions skipped directories that hold no files:\n%s", output)
	}
}

// The pqc view printed neither line, and the command prints no notice for a
// text view, so a view of a tree whose one file was under examples/ said only
// that nothing was checked. The view now prints the text report's two lines,
// once, the count in yellow, for a scan with findings and for one that read no
// files, and neither line when the skipped directories hold no files.
func TestPQCViewCountsTheFilesInSkippedDirectories(t *testing.T) {
	const (
		summary = "  3 files in 3 directories were not scanned (default rules: examples, fixtures, testdata)."
		hint    = "  Scan them with --include-skipped."
	)
	cases := []struct {
		name    string
		results *scanner.Results
	}{
		{"with findings", pqcTestResults()},
		{"no files scanned", &scanner.Results{ScanTarget: "/repo/empty", MigrationScore: analyzer.CalculateMigrationScore(nil)}},
	}
	for _, c := range cases {
		c.results.Skipped = threeSkipped
		report, err := NewTextReporter(false).Generate(c.results)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		view, err := NewPQCReporter(false).Generate(c.results)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		for _, line := range []string{summary, hint} {
			if got := lineContaining(report, strings.TrimSpace(line)); got != line {
				t.Fatalf("%s: the text report prints %q, want %q", c.name, got, line)
			}
			if n := strings.Count(view, line+"\n"); n != 1 {
				t.Errorf("%s: the view has %q %d times, want 1:\n%s", c.name, line, n, view)
			}
		}
		if !strings.Contains(view, summary+"\n"+hint+"\n") {
			t.Errorf("%s: the view does not print the hint under the count:\n%s", c.name, view)
		}

		colored, err := NewPQCReporter(true).Generate(c.results)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		if want := colorYellow + summary + "\n" + colorReset + hint + "\n"; !strings.Contains(colored, want) {
			t.Errorf("%s: the colored view lacks %q:\n%q", c.name, want, colored)
		}

		c.results.Skipped = scanner.SkippedDirectories{Directories: 1, Rules: []string{"dist"}, Paths: []string{"dist"}}
		view, err = NewPQCReporter(false).Generate(c.results)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		if strings.Contains(view, "include-skipped") || strings.Contains(view, "default rules") {
			t.Errorf("%s: the view mentions skipped directories that hold no files:\n%s", c.name, view)
		}
	}
}

func TestJSONReportCountsTheFilesInSkippedDirectories(t *testing.T) {
	results := createTestResults()
	results.Skipped = threeSkipped
	output, err := NewJSONReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var report struct {
		Skipped scanner.SkippedDirectories `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !reflect.DeepEqual(report.Skipped, threeSkipped) {
		t.Errorf("skipped = %+v, want %+v", report.Skipped, threeSkipped)
	}
}

// sarifInvocations is the part of a SARIF report these tests read.
type sarifInvocations struct {
	Runs []struct {
		Invocations []struct {
			ExecutionSuccessful            bool `json:"executionSuccessful"`
			ToolConfigurationNotifications []struct {
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"toolConfigurationNotifications"`
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"invocations"`
	} `json:"runs"`
}

func TestSARIFReportCountsTheFilesInSkippedDirectories(t *testing.T) {
	results := createTestResults()
	results.Skipped = threeSkipped
	out, err := NewSARIFReporter().Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	var doc sarifInvocations
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
	if len(inv.ToolConfigurationNotifications) != 1 {
		t.Fatalf("want one notification, got %+v", inv.ToolConfigurationNotifications)
	}
	n := inv.ToolConfigurationNotifications[0]
	want := "3 files in 3 directories were not scanned (default rules: examples, fixtures, testdata). Scan them with --include-skipped."
	if n.Level != "note" || n.Message.Text != want {
		t.Errorf("notification = %s %q, want note %q", n.Level, n.Message.Text, want)
	}
	if _, ok := inv.Properties["configFile"]; ok {
		t.Error("properties has a configFile although no config file was applied")
	}
	var skipped scanner.SkippedDirectories
	if err := json.Unmarshal(inv.Properties["skipped"], &skipped); err != nil {
		t.Fatalf("properties.skipped: %v", err)
	}
	if !reflect.DeepEqual(skipped, threeSkipped) {
		t.Errorf("properties.skipped = %+v, want %+v", skipped, threeSkipped)
	}

	// With a config file applied, both notes are in the one invocation.
	results.Config = &scanner.ConfigReport{Path: "/repo/.cryptoscan.yaml", Source: scanner.ConfigSourceScanTarget}
	out, err = NewSARIFReporter().Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	doc = sarifInvocations{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	inv = doc.Runs[0].Invocations[0]
	if len(inv.ToolConfigurationNotifications) != 2 || inv.ToolConfigurationNotifications[1].Message.Text != want {
		t.Errorf("with a config file, notifications = %+v, want the config file's, then %q", inv.ToolConfigurationNotifications, want)
	}
	for _, key := range []string{"configFile", "skipped"} {
		if _, ok := inv.Properties[key]; !ok {
			t.Errorf("with a config file, properties has no %s", key)
		}
	}
}

func TestSARIFReportOmitsSkippedDirectoriesThatHoldNoFiles(t *testing.T) {
	results := createTestResults()
	results.Skipped = scanner.SkippedDirectories{Directories: 1, Rules: []string{"dist"}, Paths: []string{"dist"}}
	out, err := NewSARIFReporter().Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `"invocations"`) {
		t.Errorf("SARIF has an invocations array although the skipped directories hold no files:\n%s", out)
	}
}
