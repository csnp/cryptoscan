// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

func resultsWithUnanalyzedFiles() *scanner.Results {
	results := createTestResults()
	results.UnanalyzedFiles = []scanner.UnanalyzedFile{
		{File: "/test/path/bad.go", Line: 7, Reason: "internal error: slice bounds out of range"},
		{File: "/test/path/early.go", Reason: "internal error: before line analysis"},
	}
	return results
}

func TestTextReportListsUnanalyzedFiles(t *testing.T) {
	output, err := NewTextReporter(false).Generate(resultsWithUnanalyzedFiles())
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	for _, want := range []string{
		"2 file(s) could not be analyzed, so findings for them may be incomplete:",
		"/test/path/bad.go:7  internal error: slice bounds out of range",
		"/test/path/early.go  internal error: before line analysis",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("text report is missing %q", want)
		}
	}

	clean, err := NewTextReporter(false).Generate(createTestResults())
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if strings.Contains(clean, "could not be analyzed") {
		t.Error("text report mentions unanalyzed files when there are none")
	}
}

func TestJSONReportListsUnanalyzedFiles(t *testing.T) {
	output, err := NewJSONReporter(false).Generate(resultsWithUnanalyzedFiles())
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var report struct {
		UnanalyzedFiles []struct {
			File   string `json:"file"`
			Line   int    `json:"line"`
			Reason string `json:"reason"`
		} `json:"unanalyzedFiles"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(report.UnanalyzedFiles) != 2 {
		t.Fatalf("expected 2 unanalyzed files, got %+v", report.UnanalyzedFiles)
	}
	first := report.UnanalyzedFiles[0]
	if first.File != "/test/path/bad.go" || first.Line != 7 || !strings.Contains(first.Reason, "slice bounds") {
		t.Errorf("unexpected first entry: %+v", first)
	}
}

type sarifNotificationsReport struct {
	Runs []struct {
		Invocations []struct {
			ExecutionSuccessful        bool `json:"executionSuccessful"`
			ToolExecutionNotifications []struct {
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
	} `json:"runs"`
}

func TestSARIFReportListsUnanalyzedFiles(t *testing.T) {
	output, err := NewSARIFReporter().Generate(resultsWithUnanalyzedFiles())
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var report sarifNotificationsReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if len(report.Runs) != 1 || len(report.Runs[0].Invocations) != 1 {
		t.Fatalf("expected one run with one invocation, got %s", output)
	}
	invocation := report.Runs[0].Invocations[0]
	if !invocation.ExecutionSuccessful {
		t.Error("executionSuccessful = false, want true: the run completed")
	}
	notes := invocation.ToolExecutionNotifications
	if len(notes) != 2 {
		t.Fatalf("expected 2 notifications, got %d", len(notes))
	}

	withLine := notes[0]
	if withLine.Level != "error" {
		t.Errorf("level = %q, want error", withLine.Level)
	}
	if !strings.Contains(withLine.Message.Text, "could not be analyzed") ||
		!strings.Contains(withLine.Message.Text, "slice bounds out of range") {
		t.Errorf("message %q does not explain the gap", withLine.Message.Text)
	}
	loc := withLine.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "bad.go" {
		t.Errorf("uri = %q, want bad.go", loc.ArtifactLocation.URI)
	}
	if loc.Region == nil || loc.Region.StartLine != 7 {
		t.Errorf("region = %+v, want startLine 7", loc.Region)
	}

	// SARIF requires startLine >= 1, so a file with no known line carries no
	// region at all.
	if region := notes[1].Locations[0].PhysicalLocation.Region; region != nil {
		t.Errorf("expected no region for a file with no known line, got %+v", region)
	}
}

func TestSARIFReportOmitsInvocationsWhenEveryFileWasAnalyzed(t *testing.T) {
	output, err := NewSARIFReporter().Generate(createTestResults())
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if strings.Contains(output, `"invocations"`) {
		t.Errorf("expected no invocations when every file was analyzed, got %s", output)
	}
	if !strings.Contains(output, `"startLine": 42`) {
		t.Error("finding results lost their region")
	}
}
