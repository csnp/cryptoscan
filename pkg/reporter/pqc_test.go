// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"fmt"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/scanner"
)

func pqcTestResults() *scanner.Results {
	var findings []scanner.Finding
	for i := 1; i <= 5; i++ {
		findings = append(findings, scanner.Finding{
			ID: fmt.Sprintf("PQC-MLKEM-001-%d-1", i), Type: "ML-KEM Key Encapsulation",
			Algorithm: "ML-KEM", Quantum: scanner.QuantumSafe, File: "/src/kem.py", Line: i,
		})
	}
	findings = append(findings,
		scanner.Finding{
			ID: "PQC-LIB-001-1-1", Type: "Post-Quantum Crypto Library",
			Category: "PQC Library Import", Quantum: scanner.QuantumSafe, File: "/src/deps.go", Line: 3,
		},
		scanner.Finding{
			ID: "HYBRID-001-9-1", Type: "Hybrid Key Exchange",
			Algorithm: "Hybrid-KEM", Quantum: scanner.QuantumSafe, File: "/src/tls.go", Line: 9,
		},
		scanner.Finding{
			ID: "RSA-001-4-1", Type: "RSA Key Generation",
			Algorithm: "RSA", Quantum: scanner.QuantumVulnerable, File: "/src/old.go", Line: 4,
		},
		scanner.Finding{
			ID: "RSA-001-8-1", Type: "RSA Key Generation",
			Algorithm: "RSA", Quantum: scanner.QuantumVulnerable, File: "/src/old.go", Line: 8,
		},
		scanner.Finding{
			ID: "MD5-001-2-1", Type: "MD5 Hash",
			Algorithm: "MD5", Quantum: scanner.QuantumVulnerable, File: "/src/old.go", Line: 2,
		},
		scanner.Finding{
			ID: "SHA2-001-6-1", Type: "SHA-256 Hash",
			Algorithm: "SHA-2", Quantum: scanner.QuantumPartial, File: "/src/old.go", Line: 6,
		},
	)
	return &scanner.Results{
		ScanTarget:     "/src",
		Findings:       findings,
		MigrationScore: analyzer.CalculateMigrationScore(findings),
	}
}

func TestPQCFindingsKeepsOnlyPQCAndHybridIDs(t *testing.T) {
	got := PQCFindings(pqcTestResults().Findings)
	if len(got) != 7 {
		t.Fatalf("PQCFindings returned %d findings, want 7 (5 ML-KEM, 1 library, 1 hybrid)", len(got))
	}
	for _, f := range got {
		if !strings.HasPrefix(f.ID, "PQC-") && !strings.HasPrefix(f.ID, "HYBRID-") {
			t.Errorf("PQCFindings kept %s", f.ID)
		}
	}
	if none := PQCFindings(nil); none == nil || len(none) != 0 {
		t.Errorf("PQCFindings(nil) = %#v, want an empty, non-nil slice so JSON shows []", none)
	}
}

func TestPQCReporterSections(t *testing.T) {
	out, err := NewPQCReporter(false).Generate(pqcTestResults())
	if err != nil {
		t.Fatal(err)
	}

	pqc := section(t, out, "Post-quantum algorithms found", "Hybrid constructions found")
	for _, want := range []string{"ML-KEM", "5", "/src/kem.py:1", "/src/kem.py:2", "/src/kem.py:3", "and 2 more", "PQC library imports", "/src/deps.go:3"} {
		if !strings.Contains(pqc, want) {
			t.Errorf("post-quantum section is missing %q:\n%s", want, pqc)
		}
	}
	if strings.Contains(pqc, "/src/kem.py:4") {
		t.Errorf("post-quantum section should list at most three locations per algorithm:\n%s", pqc)
	}
	if strings.Index(pqc, "ML-KEM") > strings.Index(pqc, "PQC library imports") {
		t.Errorf("library imports should follow the algorithms:\n%s", pqc)
	}

	hybrid := section(t, out, "Hybrid constructions found", "Quantum-vulnerable algorithms")
	for _, want := range []string{"Hybrid Key Exchange", "/src/tls.go:9"} {
		if !strings.Contains(hybrid, want) {
			t.Errorf("hybrid section is missing %q:\n%s", want, hybrid)
		}
	}

	vulnerable := section(t, out, "Quantum-vulnerable algorithms", "QUANTUM MIGRATION READINESS")
	if !strings.Contains(vulnerable, "RSA") || !strings.Contains(vulnerable, "MD5") {
		t.Errorf("vulnerable section should name RSA and MD5:\n%s", vulnerable)
	}
	if strings.Index(vulnerable, "RSA") > strings.Index(vulnerable, "MD5") {
		t.Errorf("vulnerable algorithms should be listed most found first:\n%s", vulnerable)
	}
	if strings.Contains(vulnerable, "SHA-2") || strings.Contains(vulnerable, "ML-KEM") {
		t.Errorf("vulnerable section should list only quantum-vulnerable algorithms:\n%s", vulnerable)
	}
}

// A scan that read a file and found nothing says None found. under each
// list. A scan that read no files is TestPQCReporterSaysNothingWasScanned.
func TestPQCReporterEmptySections(t *testing.T) {
	results := &scanner.Results{ScanTarget: "/empty", FilesScanned: 1, MigrationScore: analyzer.CalculateMigrationScore(nil)}
	out, err := NewPQCReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "None found."); n != 3 {
		t.Errorf("an empty scan should say None found. under each of the 3 sections, got %d:\n%s", n, out)
	}
}

// TestPQCReporterSaysNothingWasScanned checks the view of a scan that read no
// files, as for an empty directory. The line the scan report prints for it,
// colors included, takes the place of the three lists, so no list says
// "None found.", and the readiness block still follows. A scan that read a
// file keeps the lists and does not say that nothing was checked.
func TestPQCReporterSaysNothingWasScanned(t *testing.T) {
	results := &scanner.Results{ScanTarget: "/repo/empty", MigrationScore: analyzer.CalculateMigrationScore(nil)}
	const nothing = "Nothing was checked: no files were scanned under /repo/empty"
	lists := []string{"Post-quantum algorithms found", "Hybrid constructions found", "Quantum-vulnerable algorithms", "None found."}

	for _, useColor := range []bool{false, true} {
		view, err := NewPQCReporter(useColor).Generate(results)
		if err != nil {
			t.Fatal(err)
		}
		report, err := NewTextReporter(useColor).Generate(results)
		if err != nil {
			t.Fatal(err)
		}
		want := lineContaining(report, nothing)
		if want == "" {
			t.Fatalf("color %v: the scan report of a scan with 0 files scanned has no line containing %q", useColor, nothing)
		}
		if n := strings.Count(view, nothing); n != 1 {
			t.Errorf("color %v: the view of a scan with 0 files scanned has %q %d times, want 1:\n%s", useColor, nothing, n, view)
		}
		if got := lineContaining(view, nothing); got != want {
			t.Errorf("color %v: the view prints\n\t%q\nthe scan report prints\n\t%q", useColor, got, want)
		}
		for _, s := range lists {
			if strings.Contains(view, s) {
				t.Errorf("color %v: the view of a scan with 0 files scanned prints %q:\n%s", useColor, s, view)
			}
		}
		if !strings.Contains(view, "QUANTUM MIGRATION READINESS") {
			t.Errorf("color %v: the view of a scan with 0 files scanned has no readiness block:\n%s", useColor, view)
		}
	}

	results.FilesScanned = 1
	view, err := NewPQCReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(view, "Nothing was checked") {
		t.Errorf("the view of a scan with 1 file scanned says nothing was checked:\n%s", view)
	}
	for _, s := range lists {
		if !strings.Contains(view, s) {
			t.Errorf("the view of a scan with 1 file scanned and no findings lacks %q:\n%s", s, view)
		}
	}
}

// TestPQCReporterReusesReadinessBlock pins that the readiness lines are the
// ones the scan report prints, not a second implementation of them.
func TestPQCReporterReusesReadinessBlock(t *testing.T) {
	results := pqcTestResults()
	full, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	view, err := NewPQCReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"│  Score:", "│  QRAMM DIMENSION 1", "│    Practice 1.1", "│    Practice 1.2", "│    Practice 1.3"} {
		want := lineStartingWith(full, prefix)
		if want == "" {
			t.Fatalf("the scan report has no line starting %q", prefix)
		}
		if got := lineStartingWith(view, prefix); got != want {
			t.Errorf("pqc line %q\n  differs from the scan report's %q", got, want)
		}
	}
}

func section(t *testing.T, out, from, to string) string {
	t.Helper()
	start := strings.Index(out, from)
	end := strings.Index(out, to)
	if start < 0 || end < start {
		t.Fatalf("cannot find the section between %q and %q in:\n%s", from, to, out)
	}
	return out[start:end]
}

func lineStartingWith(out, prefix string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

func lineContaining(out, s string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, s) {
			return line
		}
	}
	return ""
}
