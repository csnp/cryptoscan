// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

func scoringFinding(file string, quantum types.QuantumRisk) types.Finding {
	return types.Finding{
		File:     file,
		Category: "Asymmetric Cryptography",
		Quantum:  quantum,
		Severity: types.SeverityHigh,
	}
}

func TestCalculateMigrationScoreStatesMethod(t *testing.T) {
	findings := []types.Finding{
		scoringFinding("src/pqc.go", types.QuantumSafe),
		scoringFinding("src/aes.go", types.QuantumPartial),
		scoringFinding("src/rsa.go", types.QuantumVulnerable),
		scoringFinding("src/ecdsa.go", types.QuantumVulnerable),
	}

	score := CalculateMigrationScore(findings)

	if score.SafeCount != 1 || score.PartialCount != 1 || score.VulnerableCount != 2 || score.TotalCount != 4 {
		t.Fatalf("unexpected counts: safe %d, partial %d, vulnerable %d, total %d",
			score.SafeCount, score.PartialCount, score.VulnerableCount, score.TotalCount)
	}

	want := "(safe 1 + 0.8 x hybrid 0 + 0.3 x partial 1) / 4 findings, as a percentage. " +
		"Every finding counts once; test and example files count the same as production code."
	if score.Method != want {
		t.Errorf("Method = %q, want %q", score.Method, want)
	}

	// The stated method must reproduce the score it describes.
	if got := (1 + 0.8*0 + 0.3*1) / 4.0 * 100; score.Score != got {
		t.Errorf("Score = %v, the stated method gives %v", score.Score, got)
	}
}

func TestCalculateMigrationScoreMethodWithNoFindings(t *testing.T) {
	score := CalculateMigrationScore(nil)

	if score.Method == "" {
		t.Fatal("Method is empty for a scan with no findings")
	}
	if strings.Contains(score.Method, "/ 0") {
		t.Errorf("Method divides by zero: %q", score.Method)
	}
}

func TestCalculateMigrationScoreCountsTestDirectoryFindings(t *testing.T) {
	findings := []types.Finding{
		scoringFinding("tests/x.py", types.QuantumVulnerable),
		scoringFinding("test/a.go", types.QuantumVulnerable),
		scoringFinding("src/tests/b.py", types.QuantumVulnerable),
		scoringFinding("__tests__/c.js", types.QuantumVulnerable),
		scoringFinding("spec/d.rb", types.QuantumVulnerable),
		scoringFinding("lib/specs/e.rb", types.QuantumVulnerable),
		// Not test directories: the names must match a whole directory exactly.
		scoringFinding("src/main.go", types.QuantumVulnerable),
		scoringFinding("testing/f.go", types.QuantumVulnerable),
		scoringFinding("contest/g.go", types.QuantumVulnerable),
		scoringFinding("Tests/h.cs", types.QuantumVulnerable),
		scoringFinding("src/test_util.py", types.QuantumVulnerable),
		// A file named like a test directory is not a directory.
		scoringFinding("bin/test", types.QuantumVulnerable),
	}

	score := CalculateMigrationScore(findings)

	if score.TestDirectoryFindings != 6 {
		t.Errorf("TestDirectoryFindings = %d, want 6 of %d", score.TestDirectoryFindings, score.TotalCount)
	}
}

func TestCalculateMigrationScoreForRootIgnoresDirectoriesAboveTheTarget(t *testing.T) {
	root := "/home/user/tests/project"
	findings := []types.Finding{
		scoringFinding(root+"/src/a.go", types.QuantumVulnerable),
		scoringFinding(root+"/src/b.go", types.QuantumVulnerable),
		scoringFinding(root+"/test/c.go", types.QuantumVulnerable),
	}

	score := CalculateMigrationScoreForRoot(findings, root)

	if score.TestDirectoryFindings != 1 {
		t.Errorf("TestDirectoryFindings = %d, want 1: the tests directory above the scan target must not count",
			score.TestDirectoryFindings)
	}
	if score.TotalCount != 3 {
		t.Errorf("TotalCount = %d, want 3", score.TotalCount)
	}
}

func TestTopRiskFilesOrdersTiedFilesByPath(t *testing.T) {
	// src/high.go has two findings and the seven other files one each, so
	// six files tie at the second place and only four of them fit in the
	// list of five.
	findings := []types.Finding{
		scoringFinding("src/g.go", types.QuantumVulnerable),
		scoringFinding("src/c.go", types.QuantumVulnerable),
		scoringFinding("src/high.go", types.QuantumVulnerable),
		scoringFinding("src/e.go", types.QuantumVulnerable),
		scoringFinding("src/a.go", types.QuantumVulnerable),
		scoringFinding("src/high.go", types.QuantumVulnerable),
		scoringFinding("src/f.go", types.QuantumVulnerable),
		scoringFinding("src/b.go", types.QuantumVulnerable),
		scoringFinding("src/d.go", types.QuantumVulnerable),
	}
	want := []string{"src/high.go", "src/a.go", "src/b.go", "src/c.go", "src/d.go"}

	// The files are collected in a map, so one run can match by chance.
	for run := 0; run < 20; run++ {
		input := make([]types.Finding, len(findings))
		copy(input, findings)
		score := CalculateMigrationScore(input)

		var got []string
		for _, fr := range score.TopRiskFiles {
			got = append(got, fr.File)
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Fatalf("run %d: TopRiskFiles = %v, want %v", run, got, want)
		}
		if score.TopRiskFiles[0].RiskScore != 2*score.TopRiskFiles[1].RiskScore {
			t.Fatalf("run %d: RiskScore of %s = %d, want twice the %d of %s", run,
				want[0], score.TopRiskFiles[0].RiskScore, score.TopRiskFiles[1].RiskScore, want[1])
		}
	}
}

func TestNoQuantumSafeRecommendationRespectsHybridFindings(t *testing.T) {
	const noSafe = "No quantum-safe algorithms detected"

	hybrid := scoringFinding("src/kex.go", types.QuantumVulnerable)
	hybrid.Category = "Hybrid Cryptography"
	withHybrid := CalculateMigrationScore([]types.Finding{
		hybrid,
		scoringFinding("src/rsa.go", types.QuantumVulnerable),
	})
	if withHybrid.HybridCount != 1 {
		t.Fatalf("HybridCount = %d, want 1", withHybrid.HybridCount)
	}
	for _, rec := range withHybrid.QRAMMReadiness.Recommendations {
		if strings.Contains(rec, noSafe) {
			t.Errorf("recommendation %q printed although the scan found a hybrid algorithm", rec)
		}
	}

	classicalOnly := CalculateMigrationScore([]types.Finding{
		scoringFinding("src/rsa.go", types.QuantumVulnerable),
	})
	found := false
	for _, rec := range classicalOnly.QRAMMReadiness.Recommendations {
		if strings.Contains(rec, noSafe) {
			found = true
		}
	}
	if !found {
		t.Errorf("recommendation %q missing for a scan with no safe or hybrid findings", noSafe)
	}
}
