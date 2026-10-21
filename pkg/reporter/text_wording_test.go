// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/types"
)

// A file with one finding reads "1 finding", in the TOP PRIORITY FILES rows
// of the readiness box and in the file headers of --group-by file. The row
// keeps the width it had, so the box border does not move.
func TestTextReportSaysOneFinding(t *testing.T) {
	results := createTestResults()
	results.MigrationScore = &scanner.MigrationScore{
		Score: 10, Level: "HIGH", TotalCount: 3,
		TopRiskFiles: []types.FileRiskScore{
			{File: "/test/crypto.go", TotalFindings: 2, VulnerableCount: 2, RiskScore: 20},
			{File: "/test/encrypt.go", TotalFindings: 1, VulnerableCount: 1, RiskScore: 10},
		},
	}

	text, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("generate text: %v", err)
	}
	two := lineWith(text, "1. /test/crypto.go")
	one := lineWith(text, "2. /test/encrypt.go")
	if !strings.Contains(two, "(2 findings)") {
		t.Errorf("row for 2 findings reads %q", two)
	}
	if !strings.Contains(one, "(1 finding) ") || strings.Contains(one, "1 findings") {
		t.Errorf("row for 1 finding reads %q, want (1 finding) followed by the padding", one)
	}
	if utf8.RuneCountInString(one) != utf8.RuneCountInString(two) {
		t.Errorf("the row for 1 finding is %d columns wide and the row for 2 is %d:\n%s\n%s",
			utf8.RuneCountInString(one), utf8.RuneCountInString(two), one, two)
	}

	grouped := NewTextReporter(false)
	grouped.SetGroupBy("file")
	text, err = grouped.Generate(createTestResults())
	if err != nil {
		t.Fatalf("generate grouped text: %v", err)
	}
	for _, file := range []string{"/test/crypto.go", "/test/encrypt.go"} {
		header := lineWith(text, "━━━ "+file)
		if !strings.Contains(header, "(1 finding)") {
			t.Errorf("header for %s reads %q, want (1 finding)", file, header)
		}
	}
	if strings.Contains(text, "1 findings") {
		t.Error("the grouped report says 1 findings")
	}
}

// The footer names the tool and its links. It carries no mission statement.
func TestFooterCarriesNoMissionStatement(t *testing.T) {
	text, err := NewTextReporter(false).Generate(createTestResults())
	if err != nil {
		t.Fatalf("generate text: %v", err)
	}
	footer := text[strings.LastIndex(text, "  QRAMM CryptoScan - "):]
	for _, phrase := range []string{"Mission", "empower", "Advancing cybersecurity"} {
		if strings.Contains(footer, phrase) {
			t.Errorf("the footer contains %q:\n%s", phrase, footer)
		}
	}
	for _, line := range []string{
		"  Part of the QRAMM Toolkit: https://qramm.org\n",
		"  Developed by CSNP: https://csnp.org\n",
	} {
		if !strings.Contains(footer, line) {
			t.Errorf("the footer lost %q:\n%s", strings.TrimSpace(line), footer)
		}
	}
}

// The text report names the node_modules directories the scan did not enter,
// and says nothing about them when there were none.
func TestTextReportListsSkippedDependencyDirs(t *testing.T) {
	results := createTestResults()
	results.SkippedDependencyDirs = []string{"node_modules", "web/node_modules"}
	text, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("generate text: %v", err)
	}
	for _, want := range []string{
		"  2 dependency directories were not scanned, so the packages installed there are not in this report:\n" +
			"    node_modules\n" +
			"    web/node_modules\n",
		"  To scan one installed package, pass its directory to cryptoscan scan.\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text report does not contain %q", want)
		}
	}

	results.SkippedDependencyDirs = []string{"node_modules"}
	text, err = NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("generate text: %v", err)
	}
	if !strings.Contains(text, "  1 dependency directory was not scanned,") {
		t.Error("text report does not use the singular for one directory")
	}

	results.SkippedDependencyDirs = []string{}
	text, err = NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("generate text: %v", err)
	}
	if strings.Contains(text, "dependency director") {
		t.Error("text report mentions dependency directories when none were skipped")
	}
}
