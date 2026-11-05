// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/patterns"
	"github.com/csnp/cryptoscan/pkg/types"
)

// LookupPattern knows every pattern the matcher lists and the dependency
// class of every library the dependency reader knows, and gives each
// pattern's own name, category, severity, quantum risk, description,
// remediation, references and tags. A finding's ID, which adds where the
// finding is, is not a pattern ID.
func TestLookupPattern(t *testing.T) {
	for _, p := range patterns.NewMatcher().Patterns() {
		got, ok := LookupPattern(p.ID)
		if !ok {
			t.Errorf("LookupPattern(%q) found nothing", p.ID)
			continue
		}
		want := PatternInfo{
			ID: p.ID, Name: p.Name, Category: p.Category, Severity: p.Severity, Quantum: p.Quantum,
			Description: p.Description, Remediation: p.Remediation, References: p.References, Tags: p.Tags,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("LookupPattern(%q) = %+v, want %+v", p.ID, got, want)
		}
	}
	for _, lib := range analyzer.KnownCryptoLibraries {
		id := DependencyPatternPrefix + lib.Name
		if got, ok := LookupPattern(id); !ok || got.ID != id {
			t.Errorf("LookupPattern(%q) = %+v, %v; want the class of library %s", id, got, ok, lib.Name)
		}
	}
	for _, id := range []string{"MD5-001-8-9", "DEP-crypto-js-package.json", DependencyPatternPrefix, ""} {
		if got, ok := LookupPattern(id); ok {
			t.Errorf("LookupPattern(%q) = %+v; it names no pattern", id, got)
		}
	}
}

// A dependency finding's PatternID is DEP- and the library's name, its ID
// adds the manifest's file name, and LookupPattern gives for that pattern ID
// the type, category, severity, quantum risk, description, remediation and
// tags the finding carries, for a library without post-quantum algorithms
// (crypto-js) and for one whose findings are tagged pqc-ready (bcrypt).
func TestDependencyFindingPatternID(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"name": "fixture", "dependencies": {"crypto-js": "^4.2.0", "bcrypt": "^5.1.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	results, err := New(Config{Target: dir, MinSeverity: SeverityInfo}).Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	got := map[string]bool{}
	for _, f := range results.Findings {
		if f.FindingType != types.FindingTypeDependency {
			continue
		}
		got[f.PatternID] = true
		if want := f.PatternID + "-package.json"; f.ID != want {
			t.Errorf("dependency finding ID %q, want %q", f.ID, want)
		}
		info, ok := LookupPattern(f.PatternID)
		if !ok {
			t.Errorf("LookupPattern(%q) found nothing", f.PatternID)
			continue
		}
		fromFinding := PatternInfo{
			ID: f.PatternID, Name: f.Type, Category: f.Category, Severity: f.Severity, Quantum: f.Quantum,
			Description: f.Description, Remediation: f.Remediation, References: f.References, Tags: f.Tags,
		}
		if !reflect.DeepEqual(info, fromFinding) {
			t.Errorf("LookupPattern(%q) = %+v, want what the finding carries, %+v", f.PatternID, info, fromFinding)
		}
	}
	want := map[string]bool{"DEP-crypto-js": true, "DEP-bcrypt": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dependency findings with PatternID %v, want %v", got, want)
	}
}
