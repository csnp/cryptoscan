// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/types"
)

// trustPages is the one reference of each Trust pattern, its finding page.
var trustPages = map[string]string{
	"TRUST-COMPROMISED-KEY-001": "https://github.com/csnp/cryptoscan/blob/main/docs/findings/trust-compromised-key.md",
	"TRUST-DISTRUSTED-ROOT-001": "https://github.com/csnp/cryptoscan/blob/main/docs/findings/trust-distrusted-root.md",
}

// trustPatternOf is the pattern ID of a finding or SARIF rule ID, which is the
// pattern ID followed by "-<line>-<column>", or "" for any other pattern.
func trustPatternOf(id string) string {
	for pattern := range trustPages {
		if strings.HasPrefix(id, pattern+"-") {
			return pattern
		}
	}
	return ""
}

// scanTrustFixture scans the committed fixture of the Trust patterns, which
// holds certificate inventory findings as well as trust findings.
func scanTrustFixture(t *testing.T) *scanner.Results {
	t.Helper()
	results, err := scanner.New(scanner.Config{Target: "../patterns/testdata/trust", MinSeverity: types.SeverityInfo}).Scan()
	if err != nil {
		t.Fatalf("scan the trust fixture: %v", err)
	}
	trust := 0
	for _, f := range results.Findings {
		if f.IsTrust() {
			trust++
		}
	}
	if trust == 0 || trust == len(results.Findings) || results.MigrationScore == nil {
		t.Fatalf("the fixture scan gave %d trust findings of %d and score %v; the tests below need both kinds of finding and a score",
			trust, len(results.Findings), results.MigrationScore)
	}
	return results
}

// withoutTrust returns a copy of results holding only the findings that are
// not trust findings.
func withoutTrust(results *scanner.Results) *scanner.Results {
	out := *results
	out.Findings = nil
	for _, f := range results.Findings {
		if !f.IsTrust() {
			out.Findings = append(out.Findings, f)
		}
	}
	return &out
}

// The CBOM's components are the same with and without the trust findings: a
// trust finding is not a cryptographic asset, and the certificate it was
// raised on is already a component through the inventory pattern.
func TestTrustFindingsAreNotCBOMComponents(t *testing.T) {
	results := scanTrustFixture(t)
	with := cbomOf(t, results).Components
	without := cbomOf(t, withoutTrust(results)).Components
	if len(with) == 0 {
		t.Fatal("the fixture's CBOM has no components, so this test checks nothing")
	}
	if !reflect.DeepEqual(with, without) {
		t.Errorf("CBOM components differ with the trust findings: %d components with, %d without", len(with), len(without))
	}
}

// In SARIF, each trust rule's helpUri is its finding page and each trust
// result carries the trust fields under the JSON report's names, the rule
// number (trustRule) as an integer from 1 to 4. No other rule gets a helpUri,
// no other result gets the trust fields, and no result carries a property
// named rule.
func TestTrustSARIFRulesAndResults(t *testing.T) {
	out, err := NewSARIFReporter().Generate(scanTrustFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []map[string]any `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID     string         `json:"ruleId"`
				Properties map[string]any `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("%d runs, want 1", len(log.Runs))
	}
	trustRules := 0
	for _, rule := range log.Runs[0].Tool.Driver.Rules {
		id, _ := rule["id"].(string)
		helpURI, has := rule["helpUri"]
		if pattern := trustPatternOf(id); pattern != "" {
			trustRules++
			if helpURI != trustPages[pattern] {
				t.Errorf("rule %s: helpUri %v, want %s", id, helpURI, trustPages[pattern])
			}
		} else if has {
			t.Errorf("rule %s is not a trust rule but has helpUri %v", id, helpURI)
		}
	}
	if trustRules == 0 {
		t.Error("no trust rule in the SARIF report")
	}
	fields := []string{"kind", "matchedValue", "valueType", "keyUse", "trustRule"}
	for _, r := range log.Runs[0].Results {
		pattern := trustPatternOf(r.RuleID)
		want := fields
		if pattern == "TRUST-DISTRUSTED-ROOT-001" {
			want = append(append([]string{}, fields...), "distrustDate")
		}
		for _, field := range append(fields, "issuerSpkiSha256", "distrustDate") {
			_, has := r.Properties[field]
			switch {
			case pattern == "" && has:
				t.Errorf("result %s is not a trust result but has property %s", r.RuleID, field)
			case pattern != "" && !has && slices.Contains(want, field):
				t.Errorf("result %s has no property %s: %v", r.RuleID, field, r.Properties)
			}
		}
		if rule, isNumber := r.Properties["trustRule"].(float64); pattern != "" && (!isNumber || !slices.Contains([]float64{1, 2, 3, 4}, rule)) {
			t.Errorf("result %s: trustRule %v (%T), want an integer from 1 to 4", r.RuleID, r.Properties["trustRule"], r.Properties["trustRule"])
		}
		if _, has := r.Properties["rule"]; has {
			t.Errorf("result %s carries a property named rule; the rule number's key is trustRule", r.RuleID)
		}
	}
}

// words joins the words of the lines of a text report, so that a sentence
// wrapped across indented lines can be found whole.
func words(report string) string {
	return strings.Join(strings.Fields(report), " ")
}

// The text report's note under the quantum risk counts names the trust
// findings the readiness box leaves out, and a report without trust findings
// keeps the note it had and mentions no trust finding.
func TestTrustTextNoteNamesTheFindingsTheBoxLeavesOut(t *testing.T) {
	results := scanTrustFixture(t)
	out, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	n := results.MigrationScore.TrustFindings
	if n < 2 {
		t.Fatalf("fixture has %d trust findings in the score, want several", n)
	}
	want := "The migration readiness box above counts the same findings, except the " +
		strconv.Itoa(n) + " Trust findings, by migration status, which also weighs hybrid use and algorithms that are already broken, so its rows differ from these."
	if !strings.Contains(words(out), want) {
		t.Errorf("text report has no note %q", want)
	}

	// The control bundle's three roots raise inventory findings and no trust
	// finding.
	plain, err := scanner.New(scanner.Config{Target: "../patterns/testdata/trust/control", MinSeverity: types.SeverityInfo}).Scan()
	if err != nil {
		t.Fatal(err)
	}
	out, err = NewTextReporter(false).Generate(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(words(out), "The migration readiness box above counts the same findings by migration status,") {
		t.Error("text report without trust findings lost its note")
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Trust") {
			t.Errorf("text report without trust findings mentions them: %q", line)
		}
	}
}

// In the report grouped by file, a trust finding shows its matched value and
// the listed key in place of the quantum risk, then its Fix, its Verify and
// its page; an inventory finding on the same certificate keeps its quantum
// risk.
func TestTrustTextGroupedByFile(t *testing.T) {
	results := scanTrustFixture(t)
	rep := NewTextReporter(false)
	rep.SetGroupBy("file")
	out, err := rep.Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	for pattern, page := range trustPages {
		if !strings.Contains(out, "    Reference: "+page+"\n") {
			t.Errorf("grouped report has no Reference row for %s", pattern)
		}
	}
	if !strings.Contains(out, "    SPKI SHA-256: ") || !strings.Contains(out, "    Certificate SHA-256: ") || !strings.Contains(out, "    Signed by: ") {
		t.Error("grouped report does not show both value forms")
	}
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "    Match: ") {
			continue
		}
		valueRow := i+1 < len(lines) && (strings.HasPrefix(lines[i+1], "    SPKI SHA-256: ") || strings.HasPrefix(lines[i+1], "    Certificate SHA-256: "))
		quantum := strings.Contains(line, "  •  ")
		if valueRow == quantum {
			t.Errorf("line %d: a match line shows %s:\n%s\n%s",
				i+1, map[bool]string{true: "both a quantum risk and a value row", false: "neither a quantum risk nor a value row"}[quantum], line, lines[i+1])
		}
	}
}
