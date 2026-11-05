// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/types"
)

// Every finding the matcher builds carries the ID of the pattern that raised
// it, one the matcher lists, and the finding's own ID is that pattern ID
// followed by the line and the match's offset. Match, MatchWithContext and
// MatchInFile build findings, and MatchInFile alone builds those of the Trust
// patterns, here for the committed certificate signed by a listed key.
func TestFindingsCarryTheirPatternID(t *testing.T) {
	m := NewMatcher()
	listed := map[string]bool{}
	for _, p := range m.Patterns() {
		listed[p.ID] = true
	}
	location := regexp.MustCompile(`^-[0-9]+-[0-9]+$`)
	check := func(how string, findings []types.Finding) {
		t.Helper()
		if len(findings) == 0 {
			t.Fatalf("%s built no finding", how)
		}
		for _, f := range findings {
			if !listed[f.PatternID] {
				t.Errorf("%s: finding %s has PatternID %q, which names no pattern", how, f.ID, f.PatternID)
				continue
			}
			if rest, ok := strings.CutPrefix(f.ID, f.PatternID); !ok || !location.MatchString(rest) {
				t.Errorf("%s: finding ID %q is not its PatternID %q followed by a line and offset", how, f.ID, f.PatternID)
			}
		}
	}

	const line = "digest = hashlib.md5(data).hexdigest()"
	check("Match", m.Match(line, "app.py", 3))
	fileCtx := analyzer.Analyze("app.py")
	check("MatchWithContext", m.MatchWithContext(line, "app.py", 3, fileCtx, analyzer.AnalyzeLine(line, fileCtx.Language, nil)))

	leaf, err := filepath.Glob(filepath.Join("testdata", "trust", "leaf", "*.crt"))
	if err != nil || len(leaf) != 1 {
		t.Fatalf("the committed leaf certificate: %v, %v", leaf, err)
	}
	data, err := os.ReadFile(leaf[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	certCtx := analyzer.Analyze(leaf[0])
	inFile := m.MatchInFile(lines, 0, leaf[0], certCtx, analyzer.AnalyzeLine(lines[0], certCtx.Language, nil))
	check("MatchInFile", inFile)
	trust := 0
	for _, f := range inFile {
		if f.IsTrust() {
			trust++
			if f.PatternID != TrustCompromisedKeyID {
				t.Errorf("trust finding %s has PatternID %q, want %s", f.ID, f.PatternID, TrustCompromisedKeyID)
			}
		}
	}
	if trust == 0 {
		t.Error("MatchInFile built no trust finding for the leaf certificate, so no Trust pattern was checked")
	}
}
