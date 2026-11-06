// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/patterns"
	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/types"
)

// decodedSARIF is the part of a SARIF log the tests in this file read,
// decoded with the names SARIF defines rather than with the reporter's own
// types.
type decodedSARIF struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []decodedRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []decodedResult `json:"results"`
	} `json:"runs"`
}

type decodedText struct {
	Text string `json:"text"`
}

type decodedRule struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	ShortDescription     decodedText `json:"shortDescription"`
	FullDescription      decodedText `json:"fullDescription"`
	Help                 decodedText `json:"help"`
	HelpURI              string      `json:"helpUri"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
}

type decodedResult struct {
	RuleID     string         `json:"ruleId"`
	Level      string         `json:"level"`
	Message    decodedText    `json:"message"`
	Properties map[string]any `json:"properties"`
}

// decodedFinding is the part of a JSON report's finding the tests in this
// file read.
type decodedFinding struct {
	ID          string `json:"id"`
	PatternID   string `json:"patternId"`
	Type        string `json:"type"`
	FindingType string `json:"findingType"`
	Match       string `json:"match"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// sarifAndJSON writes results as SARIF and as JSON and returns the decoded
// SARIF log, the SARIF text, and the JSON report's findings, which are listed
// in the order SARIF lists their results.
func sarifAndJSON(t *testing.T, results *scanner.Results) (decodedSARIF, string, []decodedFinding) {
	t.Helper()
	out, err := NewSARIFReporter().Generate(results)
	if err != nil {
		t.Fatalf("generate SARIF: %v", err)
	}
	var log decodedSARIF
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("SARIF has %d runs, want 1", len(log.Runs))
	}

	report, err := NewJSONReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("generate JSON: %v", err)
	}
	var decoded struct {
		Findings []decodedFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(report), &decoded); err != nil {
		t.Fatalf("JSON report is not valid JSON: %v", err)
	}
	if n := len(decoded.Findings); n == 0 || n != len(log.Runs[0].Results) {
		t.Fatalf("%d JSON findings and %d SARIF results; want the same number, and more than 0", n, len(log.Runs[0].Results))
	}
	return log, out, decoded.Findings
}

// scanDir scans dir with the real scanner, at every severity.
func scanDir(t *testing.T, dir string) *scanner.Results {
	t.Helper()
	results, err := scanner.New(scanner.Config{Target: dir, MinSeverity: types.SeverityInfo}).Scan()
	if err != nil {
		t.Fatalf("scan %s: %v", dir, err)
	}
	results.ScanTarget = dir
	return results
}

// writeSARIFFixture writes files, by name relative to a new directory, and
// returns the directory.
func writeSARIFFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// ruleIDsOf returns the ruleId of each result of log, in order.
func ruleIDsOf(log decodedSARIF) []string {
	var ids []string
	for _, r := range log.Runs[0].Results {
		ids = append(ids, r.RuleID)
	}
	return ids
}

// SARIF results use the pattern ID as ruleId, so that code scanning groups
// them by pattern. On crypto-samples, each result's ruleId is its finding's
// patternId and never ends in a line and offset, the rules array holds one
// rule per pattern in the order of each pattern's first result, and each
// result carries its finding's own ID, which adds the line and offset, as
// properties.findingId. No result carries partialFingerprints.
func TestSARIFRuleIDIsThePatternID(t *testing.T) {
	log, out, findings := sarifAndJSON(t, scanDir(t, filepath.Join("..", "..", "crypto-samples")))
	run := log.Runs[0]

	location := regexp.MustCompile(`-[0-9]+-[0-9]+$`)
	var noPatternID, notPatternID, withLocation, wrongFindingID []string
	var firstSeen []string
	for i, r := range run.Results {
		f := findings[i]
		if f.PatternID == "" {
			noPatternID = append(noPatternID, f.ID)
		} else if r.RuleID != f.PatternID {
			notPatternID = append(notPatternID, r.RuleID+" (patternId "+f.PatternID+")")
		}
		if location.MatchString(r.RuleID) {
			withLocation = append(withLocation, r.RuleID)
		}
		if id, _ := r.Properties["findingId"].(string); id == "" || id != f.ID {
			wrongFindingID = append(wrongFindingID, f.ID)
		}
		if !slices.Contains(firstSeen, r.RuleID) {
			firstSeen = append(firstSeen, r.RuleID)
		}
	}
	report := func(what string, ids []string) {
		if len(ids) > 0 {
			t.Errorf("%d of %d results %s, first %q", len(ids), len(run.Results), what, ids[0])
		}
	}
	report("have a finding without patternId", noPatternID)
	report("have a ruleId that is not their finding's patternId", notPatternID)
	report("have a ruleId that ends in a line and offset", withLocation)
	report("do not carry their finding's id as properties.findingId", wrongFindingID)

	var ruleIDs []string
	for _, rule := range run.Tool.Driver.Rules {
		ruleIDs = append(ruleIDs, rule.ID)
	}
	if !slices.Equal(ruleIDs, firstSeen) {
		t.Errorf("rules %v, want one per ruleId in the order of its first result: %v", ruleIDs, firstSeen)
	}
	if len(ruleIDs) >= len(run.Results) {
		t.Errorf("%d rules for %d results; crypto-samples raises several findings of one pattern, so results share rules", len(ruleIDs), len(run.Results))
	}
	if strings.Contains(out, "partialFingerprints") {
		t.Error("the SARIF log carries partialFingerprints")
	}
}

// A line inserted above the findings moves each finding's ID, which carries
// the line, and leaves every ruleId as it was, so code scanning keeps each
// result under its rule.
func TestSARIFRuleIDsSurviveAnInsertedLine(t *testing.T) {
	const source = `import hashlib


def digest(data):
    return hashlib.md5(data).hexdigest()


def legacy(data):
    return hashlib.sha1(data).hexdigest()
`
	before, _, beforeFindings := sarifAndJSON(t, scanDir(t, writeSARIFFixture(t, map[string]string{"app.py": source})))
	after, _, afterFindings := sarifAndJSON(t, scanDir(t, writeSARIFFixture(t, map[string]string{"app.py": "import os\n" + source})))

	if len(beforeFindings) != len(afterFindings) {
		t.Fatalf("%d findings before the inserted line and %d after; want the same findings", len(beforeFindings), len(afterFindings))
	}
	for i := range beforeFindings {
		if beforeFindings[i].ID == afterFindings[i].ID {
			t.Errorf("finding %d kept the id %q with a line inserted above it, so the pair does not move it", i, beforeFindings[i].ID)
		}
	}
	if b, a := ruleIDsOf(before), ruleIDsOf(after); !slices.Equal(b, a) {
		t.Errorf("ruleIds changed with a line inserted above the findings:\n  before %v\n  after  %v", b, a)
	}
}

// A rule's name, descriptions, help and default level are its pattern's, as
// patterns list gives them, and not those of its first result's finding. The
// import below is a match inside a path, which lowers its finding's severity
// below the pattern's, and its rule keeps the pattern's level. A dependency
// rule is the library's class, DEP- followed by the library name, with the
// library's replacement text as its help.
func TestSARIFRuleTextComesFromThePattern(t *testing.T) {
	dir := writeSARIFFixture(t, map[string]string{
		"app.go":       "package app\n\nimport \"crypto/md5\"\n",
		"package.json": `{"name": "fixture", "dependencies": {"crypto-js": "^4.2.0"}}`,
	})
	log, _, findings := sarifAndJSON(t, scanDir(t, dir))
	run := log.Runs[0]

	registry := map[string]patterns.Pattern{}
	for _, p := range patterns.NewMatcher().Patterns() {
		registry[p.ID] = p
	}
	var cryptoJS analyzer.CryptoLibrary
	for _, lib := range analyzer.KnownCryptoLibraries {
		if lib.Name == "crypto-js" {
			cryptoJS = lib
		}
	}
	if cryptoJS.Migration == "" {
		t.Fatal("the crypto-js library entry has no replacement text to compare with")
	}

	levels := map[string]string{}
	dependencyRules := 0
	for _, rule := range run.Tool.Driver.Rules {
		levels[rule.ID] = rule.DefaultConfiguration.Level
		if strings.HasPrefix(rule.ID, "DEP-") {
			dependencyRules++
			if rule.ID != "DEP-crypto-js" {
				t.Errorf("dependency rule %q, want DEP-crypto-js", rule.ID)
			}
			if rule.Help.Text != cryptoJS.Migration {
				t.Errorf("rule %s: help %q, want the library's replacement text %q", rule.ID, rule.Help.Text, cryptoJS.Migration)
			}
			continue
		}
		p, ok := registry[rule.ID]
		if !ok {
			t.Errorf("rule %q names no pattern", rule.ID)
			continue
		}
		for _, field := range []struct{ name, got, want string }{
			{"name", rule.Name, p.Name},
			{"shortDescription", rule.ShortDescription.Text, p.Description},
			{"fullDescription", rule.FullDescription.Text, p.Description},
			{"help", rule.Help.Text, p.Remediation},
			{"defaultConfiguration.level", rule.DefaultConfiguration.Level, severityToSARIFLevel(p.Severity)},
		} {
			if field.got != field.want {
				t.Errorf("rule %s: %s %q, want the pattern's %q", rule.ID, field.name, field.got, field.want)
			}
		}
	}
	if dependencyRules != 1 {
		t.Errorf("%d dependency rules, want 1", dependencyRules)
	}

	lowered := 0
	for i, r := range run.Results {
		if level, ok := levels[r.RuleID]; ok && r.Level != level {
			lowered++
		}
		if f := findings[i]; f.FindingType == "dependency" && f.PatternID != r.RuleID {
			t.Errorf("dependency result %s: ruleId %q, want the finding's patternId %q", f.ID, r.RuleID, f.PatternID)
		}
	}
	if lowered == 0 {
		t.Error("no result's level differs from its rule's default level, so the fixture does not show where the rule's level comes from")
	}
}

// A trust finding's description depends on the key rule it met, so it can
// differ from its rule's, which is the pattern's. Such a result's message
// carries the finding's own description after its type and match: in the
// committed fixture, the certificate signed by a listed key is reported under
// TRUST-COMPROMISED-KEY-001, whose description is that of a certificate whose
// own key is listed. A result whose finding's description is its rule's keeps
// the message "<type>: <match>", followed by the finding's remediation when
// that is not its rule's help (the test below).
func TestSARIFMessageCarriesADescriptionItsRuleDoesNot(t *testing.T) {
	log, _, findings := sarifAndJSON(t, scanTrustFixture(t))
	run := log.Runs[0]

	descriptions, help := map[string]string{}, map[string]string{}
	for _, rule := range run.Tool.Driver.Rules {
		descriptions[rule.ID] = rule.FullDescription.Text
		help[rule.ID] = rule.Help.Text
	}
	differing := 0
	for i, r := range run.Results {
		f := findings[i]
		plain := f.Type + ": " + f.Match
		if f.Description == descriptions[r.RuleID] {
			want := plain
			if f.Remediation != "" && f.Remediation != help[r.RuleID] {
				want += ". Remediation: " + f.Remediation
			}
			if r.Message.Text != want {
				t.Errorf("result %s: message %q, want %q", f.ID, r.Message.Text, want)
			}
			continue
		}
		differing++
		if !strings.HasPrefix(r.Message.Text, plain) || !strings.Contains(r.Message.Text, f.Description) {
			t.Errorf("result %s under rule %s: message %q, want %q followed by the finding's description %q", f.ID, r.RuleID, r.Message.Text, plain, f.Description)
		}
	}
	if differing == 0 {
		t.Error("no finding in the fixture has a description its rule does not, so the message check reads nothing")
	}
}

// A trust finding's remediation depends on the use of the listed key it
// matched and, for the removed root's own certificate, on the key rule it met,
// so it can differ from its rule's help text, which is the pattern's. Such a
// result's message ends with a full stop, "Remediation:" and the finding's own
// remediation: in the committed fixture, the rule-3 match of
// TRUST-DISTRUSTED-ROOT-001 on emSign ECC Root CA - G3 itself has the action
// for each kind of file that holds the root, where its rule's help is the
// action for a certificate the root signed. A result whose finding's
// remediation is its rule's help carries no "Remediation:".
func TestSARIFMessageCarriesARemediationItsRuleDoesNot(t *testing.T) {
	log, _, findings := sarifAndJSON(t, scanTrustFixture(t))
	run := log.Runs[0]

	help := map[string]string{}
	for _, rule := range run.Tool.Driver.Rules {
		help[rule.ID] = rule.Help.Text
	}
	rootFile := 0
	for i, r := range run.Results {
		f := findings[i]
		if f.Remediation == "" || f.Remediation == help[r.RuleID] {
			if strings.Contains(r.Message.Text, "Remediation:") {
				t.Errorf("result %s under rule %s: message %q carries a remediation, but the finding's remediation is its rule's help", f.ID, r.RuleID, r.Message.Text)
			}
			continue
		}
		if trustRule, _ := r.Properties["trustRule"].(float64); r.RuleID == "TRUST-DISTRUSTED-ROOT-001" && trustRule == 3 {
			rootFile++
		}
		plain := f.Type + ": " + f.Match
		before, found := strings.CutSuffix(r.Message.Text, " Remediation: "+f.Remediation)
		if !found || !strings.HasPrefix(before, plain) || !strings.HasSuffix(before, ".") || strings.HasSuffix(before, "..") {
			t.Errorf("result %s under rule %s: message %q, want %q and a full stop, then \"Remediation:\" and the finding's remediation %q",
				f.ID, r.RuleID, r.Message.Text, plain, f.Remediation)
		}
	}
	if rootFile != 1 {
		t.Errorf("%d rule-3 results of TRUST-DISTRUSTED-ROOT-001 have a remediation their rule's help does not, want 1: the fixture's root/ file holds emSign ECC Root CA - G3", rootFile)
	}
}
