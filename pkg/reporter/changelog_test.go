// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// changelogFile is the release history. Its entries quote text that the
// reporters write, and the test in this file holds such a quote to the SARIF
// and CSV output of a real scan.
const changelogFile = "../../CHANGELOG.md"

// changelogEntry is one top-level list item of the CHANGELOG, with its lines
// joined by single spaces, and the "## " heading of the release it is under.
type changelogEntry struct {
	release string
	text    string
}

// changelogEntries returns the top-level list items of markdown. An item
// starts at a line beginning with "- " and takes in the indented and blank
// lines after it, up to the next item, heading or unindented line.
func changelogEntries(markdown string) []changelogEntry {
	var entries []changelogEntry
	var release string
	var lines []string
	flush := func() {
		if lines != nil {
			entries = append(entries, changelogEntry{
				release: release,
				text:    strings.Join(strings.Fields(strings.Join(lines, " ")), " "),
			})
			lines = nil
		}
	}
	for _, line := range strings.Split(markdown, "\n") {
		switch {
		case strings.HasPrefix(line, "- "):
			flush()
			lines = []string{strings.TrimPrefix(line, "- ")}
		case lines != nil && (line == "" || strings.HasPrefix(line, "  ")):
			lines = append(lines, line)
		default:
			flush()
			if strings.HasPrefix(line, "## ") {
				release = strings.TrimPrefix(line, "## ")
			}
		}
	}
	flush()
	return entries
}

func TestChangelogEntries(t *testing.T) {
	markdown := "# Changelog\n\n## [2.0.0] - 2026-01-02\n\n### Fixed\n\n" +
		"- **First.** Wrapped\n  across `two\n  lines`.\n\n  A second paragraph.\n" +
		"- **Second.**\n\n## [1.0.0]\n\n- **Third.**\n"
	got := changelogEntries(markdown)
	want := []changelogEntry{
		{"[2.0.0] - 2026-01-02", "**First.** Wrapped across `two lines`. A second paragraph."},
		{"[2.0.0] - 2026-01-02", "**Second.**"},
		{"[1.0.0]", "**Third.**"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// scanCryptoJSDependency runs the real scanner over a directory whose
// package.json lists crypto-js, and returns the ID and help text of the
// crypto-js dependency rule in the SARIF output, and the Remediation column
// of that finding's CSV row. The SARIF output is decoded with the field names
// SARIF defines, from runs down to help.text, rather than with the reporter's
// own types.
func scanCryptoJSDependency(t *testing.T) (ruleID, sarifHelp, csvRemediation string) {
	t.Helper()

	// os.MkdirTemp rather than t.TempDir, whose path carries the test name.
	root, err := os.MkdirTemp("", "changelog-crypto-js-")
	if err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	manifest := `{"name": "fixture", "dependencies": {"crypto-js": "^4.2.0"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	results, err := scanner.New(scanner.Config{
		Target:      root,
		MinSeverity: scanner.SeverityInfo,
	}).Scan()
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	results.ScanTarget = root

	out, err := NewSARIFReporter().Generate(results)
	if err != nil {
		t.Fatalf("generate SARIF: %v", err)
	}
	var report struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID   string `json:"id"`
						Help struct {
							Text string `json:"text"`
						} `json:"help"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("SARIF has %d runs, want 1", len(report.Runs))
	}
	for _, rule := range report.Runs[0].Tool.Driver.Rules {
		if strings.HasPrefix(rule.ID, "DEP-crypto-js-") {
			ruleID, sarifHelp = rule.ID, rule.Help.Text
		}
	}
	if ruleID == "" {
		t.Fatalf("the SARIF output has no crypto-js dependency rule:\n%s", out)
	}

	table, err := NewCSVReporter().Generate(results)
	if err != nil {
		t.Fatalf("generate CSV: %v", err)
	}
	rows, err := csv.NewReader(strings.NewReader(table)).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}
	idColumn, remediationColumn := -1, -1
	for i, name := range rows[0] {
		switch name {
		case "ID":
			idColumn = i
		case "Remediation":
			remediationColumn = i
		}
	}
	if idColumn < 0 || remediationColumn < 0 {
		t.Fatalf("the CSV header has no ID or Remediation column: %q", rows[0])
	}
	found := false
	for _, row := range rows[1:] {
		if row[idColumn] == ruleID {
			csvRemediation, found = row[remediationColumn], true
		}
	}
	if !found {
		t.Fatalf("the CSV output has no row for %s:\n%s", ruleID, table)
	}
	return ruleID, sarifHelp, csvRemediation
}

// The 1.5.0 entry that gave the crypto-js dependency finding its replacement
// text said "SARIF output is unchanged", but SARIF writes a finding's
// remediation as its rule's help text, and CSV writes it in the Remediation
// column. An entry that quotes the text must name both places.
func TestChangelogSaysWhereSARIFAndCSVCarryTheCryptoJSText(t *testing.T) {
	ruleID, help, remediation := scanCryptoJSDependency(t)
	if help == "" || help != remediation {
		t.Fatalf("SARIF rule %s has help text %q and its CSV row has Remediation %q; want the same crypto-js text in both", ruleID, help, remediation)
	}

	raw, err := os.ReadFile(changelogFile)
	if err != nil {
		t.Fatal(err)
	}
	quote := "`" + help + "`"
	checked := 0
	for _, entry := range changelogEntries(string(raw)) {
		if !strings.Contains(entry.text, quote) {
			continue
		}
		checked++
		for _, want := range []string{"`" + ruleID + "`", "`help.text`", "Remediation column"} {
			if !strings.Contains(entry.text, want) {
				t.Errorf("%s, under %q: the entry that quotes %s does not contain %q; SARIF writes that text as the help.text of rule %s, and CSV writes it in the Remediation column", changelogFile, entry.release, quote, want, ruleID)
			}
		}
		if strings.Contains(entry.text, "SARIF output is unchanged") {
			t.Errorf("%s, under %q: the entry that quotes %s says SARIF output is unchanged, but SARIF writes that text as the help of rule %s", changelogFile, entry.release, quote, ruleID)
		}
	}
	if checked == 0 {
		t.Fatalf("%s has no entry that quotes %s, the text SARIF writes as the help of rule %s and CSV writes in the Remediation column", changelogFile, quote, ruleID)
	}
}
