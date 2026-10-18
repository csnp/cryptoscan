// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/patterns"
	"github.com/csnp/cryptoscan/pkg/scanner"
)

// An ML-KEM use needs no change, and its block printed the pattern's
// reassurance as "Fix: ML-KEM is NIST-approved and quantum-safe." It now
// prints that sentence as Guidance, in both layouts and in JSON, while a
// finding with a change to make keeps its Fix line.
func TestReportsPrintGuidanceForFindingsThatNeedNoChange(t *testing.T) {
	m := patterns.NewMatcher()
	engine := analyzer.NewRemediationEngine()
	pick := func(line, file string, lang analyzer.Language, lineNum int, id string) scanner.Finding {
		t.Helper()
		ctx := &analyzer.FileContext{Language: lang, FileType: analyzer.FileTypeCode}
		for _, f := range m.MatchWithContext(line, file, lineNum, ctx, nil) {
			if strings.HasPrefix(f.ID, id+"-") {
				engine.Apply(&f)
				return f
			}
		}
		t.Fatalf("no %s match in %q", id, line)
		return scanner.Finding{}
	}
	md5 := pick(`        MessageDigest md = MessageDigest.getInstance("MD5");`, "src/A.java", analyzer.LangJava, 96, "MD5-001")
	mlkem := pick(`from circl.kem.mlkem import mlkem768`, "src/kem.py", analyzer.LangPython, 45, "PQC-MLKEM-001")

	const guidance = "ML-KEM is NIST-approved and quantum-safe. Recommended for key exchange."
	const fix = `Replace MessageDigest.getInstance("MD5") with MessageDigest.getInstance("SHA-256")`
	results := &scanner.Results{Findings: []scanner.Finding{md5, mlkem}}

	text, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	blocks := findingBlocks(text)
	if len(blocks) != 2 {
		t.Fatalf("found %d finding blocks, want 2:\n%s", len(blocks), text)
	}
	md5Block, mlkemBlock := blocks[0], blocks[1]
	if !strings.Contains(mlkemBlock, "│ Guidance: "+guidance) {
		t.Errorf("ML-KEM block lacks the Guidance line:\n%s", mlkemBlock)
	}
	for _, unwanted := range []string{"│ Fix:", "│ Remediation:"} {
		if strings.Contains(mlkemBlock, unwanted) {
			t.Errorf("ML-KEM block prints %q for a finding that needs no change:\n%s", unwanted, mlkemBlock)
		}
	}
	if !strings.Contains(md5Block, "│ Fix: "+fix) || strings.Contains(md5Block, "│ Guidance:") {
		t.Errorf("MD5 block should print its Fix line and no Guidance line:\n%s", md5Block)
	}

	grouped := NewTextReporter(false)
	grouped.SetGroupBy("file")
	byFile, err := grouped.Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"    Guidance: " + guidance + "\n", "    Fix: " + fix + "\n"} {
		if !strings.Contains(byFile, want) {
			t.Errorf("--group-by file output lacks %q:\n%s", want, byFile)
		}
	}
	if strings.Contains(byFile, "Fix: "+guidance) {
		t.Errorf("--group-by file output prints the ML-KEM guidance as a fix:\n%s", byFile)
	}

	js, err := NewJSONReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			ID       string `json:"id"`
			Fix      string `json:"fix"`
			Guidance string `json:"guidance"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(js), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 2 {
		t.Fatalf("JSON has %d findings, want 2", len(doc.Findings))
	}
	if got := doc.Findings[0]; got.Fix != fix || got.Guidance != "" {
		t.Errorf("JSON MD5 finding: fix %q, guidance %q; want the fix and no guidance", got.Fix, got.Guidance)
	}
	if got := doc.Findings[1]; got.Fix != "" || got.Guidance != guidance {
		t.Errorf("JSON ML-KEM finding: fix %q, guidance %q; want no fix and the guidance", got.Fix, got.Guidance)
	}
}
