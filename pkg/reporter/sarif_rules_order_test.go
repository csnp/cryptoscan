// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// TestSARIFRulesFollowFirstResultOrder checks that the rules array lists each
// rule once, in the order of its first result, and that repeated runs on the
// same findings produce byte-identical output.
func TestSARIFRulesFollowFirstResultOrder(t *testing.T) {
	var findings []scanner.Finding
	var wantIDs []string
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("RULE-%03d", 40-i)
		wantIDs = append(wantIDs, id)
		findings = append(findings, scanner.Finding{
			ID: id, Type: "Type " + id, Severity: scanner.SeverityHigh, File: "/a.go", Line: i + 1,
		})
	}
	// A later result for an earlier rule must not add or move a rule.
	findings = append(findings, scanner.Finding{
		ID: wantIDs[5], Type: "Type " + wantIDs[5], Severity: scanner.SeverityHigh, File: "/b.go", Line: 1,
	})
	results := &scanner.Results{ScanTarget: "/", Findings: findings}

	reporter := NewSARIFReporter()
	first, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal([]byte(first), &report); err != nil {
		t.Fatalf("Invalid SARIF: %v", err)
	}
	rules := report.Runs[0].Tool.Driver.Rules
	if len(rules) != len(wantIDs) {
		t.Fatalf("Expected %d rules, got %d", len(wantIDs), len(rules))
	}
	for i, rule := range rules {
		if rule.ID != wantIDs[i] {
			t.Fatalf("rules[%d].id = %q, want %q (order of first result)", i, rule.ID, wantIDs[i])
		}
	}

	for run := 0; run < 20; run++ {
		again, err := reporter.Generate(results)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		if again != first {
			t.Fatalf("run %d produced different SARIF output for the same findings", run+2)
		}
	}
}
