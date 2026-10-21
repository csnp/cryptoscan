// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pqcFixture names ML-KEM and calls MD5 and SHA-256. A default scan reports
// the ML-KEM and MD5 findings and withholds the SHA-256 one, which only
// --include-quantum-safe shows.
const pqcFixture = `import hashlib
kem = ML_KEM_768
h = hashlib.md5(b"x")
d = hashlib.sha256(b"y")
`

// cryptoSamples is the sample tree at the repository root.
const cryptoSamples = "../../crypto-samples"

// pqcJSONView is the pqc command's JSON output.
type pqcJSONView struct {
	Tool struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tool"`
	MigrationScore *struct {
		Score       float64        `json:"score"`
		ByAlgorithm map[string]int `json:"byAlgorithm"`
	} `json:"migrationScore"`
	PQCFindings []struct {
		ID string `json:"id"`
	} `json:"pqcFindings"`
}

// runPqcCapture runs pqc on target and returns what it printed and its exit
// code.
func runPqcCapture(t *testing.T, target string) (string, int) {
	t.Helper()
	var code int
	out := captureStdout(func() {
		var err error
		code, err = pqcTarget(pqcCmd, target)
		if err != nil {
			t.Errorf("pqc failed: %v", err)
		}
	})
	return out, code
}

func TestPqcCmdExists(t *testing.T) {
	if pqcCmd == nil {
		t.Fatal("pqcCmd should not be nil")
	}
	if pqcCmd.Use != "pqc [path or URL]" {
		t.Errorf("pqcCmd.Use = %q, want %q", pqcCmd.Use, "pqc [path or URL]")
	}
	if !isRegistered("pqc") {
		t.Error("pqc is not registered on the root command")
	}
	want := "Show post-quantum readiness: PQC and hybrid usage found, quantum-vulnerable usage, and the QRAMM Dimension 1 levels"
	if pqcCmd.Short != want {
		t.Errorf("pqcCmd.Short = %q, want %q", pqcCmd.Short, want)
	}
}

func TestPqcCmdFlags(t *testing.T) {
	for _, name := range []string{"format", "include", "exclude", "ignore", "config", "no-color"} {
		if pqcCmd.Flags().Lookup(name) == nil {
			t.Errorf("pqcCmd missing expected flag: %s", name)
		}
	}
	// pqc exists to show post-quantum usage, so quantum-safe findings cannot
	// be turned off, and a readiness view is not a verdict.
	for _, name := range []string{"include-quantum-safe", "fail-on"} {
		if pqcCmd.Flags().Lookup(name) != nil {
			t.Errorf("pqc must not offer --%s", name)
		}
	}
	assertSubsetOfScan(t, pqcCmd.Flags())
}

func TestPqcIncludesQuantumSafeWithoutFlag(t *testing.T) {
	dir := writeFixture(t, "app.py", pqcFixture)

	resetPipelineFlags(t)
	outputFormat = "json"
	out, _ := runPqcCapture(t, dir)
	var view pqcJSONView
	if err := json.Unmarshal([]byte(out), &view); err != nil {
		t.Fatalf("pqc --format json is not a single JSON document: %v\n%s", err, out)
	}
	if len(view.PQCFindings) != 1 || !strings.HasPrefix(view.PQCFindings[0].ID, "PQC-MLKEM-001") {
		t.Errorf("pqcFindings = %+v, want exactly one PQC-MLKEM-001 finding", view.PQCFindings)
	}
	if view.Tool.Name != "CryptoScan" {
		t.Errorf("tool.name = %q, want CryptoScan", view.Tool.Name)
	}
	if view.MigrationScore == nil {
		t.Fatal("pqc --format json has no migrationScore")
	}
	if view.MigrationScore.ByAlgorithm["SHA-2"] != 1 {
		t.Errorf("pqc should count the SHA-256 call without --include-quantum-safe; byAlgorithm = %v",
			view.MigrationScore.ByAlgorithm)
	}
	if includeQuantumSafe {
		t.Error("pqc must force quantum-safe findings on without changing scan's --include-quantum-safe")
	}

	// scan withholds the SHA-256 call unless --include-quantum-safe is
	// passed. That is the difference pqc pins: scan already reports the
	// ML-KEM finding by default.
	resetPipelineFlags(t)
	outputFormat = "json"
	out = captureStdout(func() {
		if _, err := scanTarget(scanCmd, dir); err != nil {
			t.Errorf("scan failed: %v", err)
		}
	})
	var report struct {
		Findings []struct {
			ID        string `json:"id"`
			Algorithm string `json:"algorithm"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("scan stdout is not JSON: %v", err)
	}
	for _, f := range report.Findings {
		if f.Algorithm == "SHA-2" {
			t.Errorf("scan without --include-quantum-safe reported %s, so the fixture no longer shows what pqc forces on", f.ID)
		}
	}
}

func TestPqcExitsZeroWithVulnerableFindings(t *testing.T) {
	dir := writeFixture(t, "app.py", criticalFixture)

	// The same fixture fails the default scan, so pqc's 0 below is a
	// decision, not an empty scan.
	resetPipelineFlags(t)
	outputFormat = "json"
	var scanCode int
	captureStdout(func() {
		var err error
		scanCode, err = scanTarget(scanCmd, dir)
		if err != nil {
			t.Errorf("scan failed: %v", err)
		}
	})
	if scanCode != 1 {
		t.Fatalf("scan exit code = %d, want 1: the fixture should carry a CRITICAL finding", scanCode)
	}

	for _, format := range []string{"text", "json"} {
		resetPipelineFlags(t)
		outputFormat = format
		out, code := runPqcCapture(t, dir)
		if code != 0 {
			t.Errorf("pqc --format %s exit code = %d, want 0 whatever it finds", format, code)
		}
		if !strings.Contains(out, "DES") {
			t.Errorf("pqc --format %s should show the DES usage it found:\n%s", format, out)
		}
	}
}

func TestPqcRejectsOtherFormats(t *testing.T) {
	dir := writeFixture(t, "app.py", pqcFixture)
	resetPipelineFlags(t)
	outputFormat = "sarif"
	if _, err := pqcTarget(pqcCmd, dir); err == nil {
		t.Error("pqc --format sarif should be refused; pqc prints text or json")
	}
}

func TestPqcTextNamesEveryPQCAlgorithmFound(t *testing.T) {
	resetPipelineFlags(t)
	out, code := runPqcCapture(t, cryptoSamples)
	if code != 0 {
		t.Errorf("pqc exit code = %d, want 0", code)
	}

	// The sections come in this order, and the readiness block ends the view.
	sections := []string{
		"Post-quantum algorithms found",
		"Hybrid constructions found",
		"Quantum-vulnerable algorithms",
		"QUANTUM MIGRATION READINESS",
		"Score:",
		"QRAMM DIMENSION 1",
		"Practice 1.1 Discovery",
		"Practice 1.2 Assessment",
		"Practice 1.3 Mapping",
	}
	last := -1
	for _, s := range sections {
		i := strings.Index(out, s)
		if i < 0 {
			t.Errorf("pqc text output is missing %q", s)
			continue
		}
		if i < last {
			t.Errorf("%q appears before the section it should follow", s)
		}
		last = i
	}

	start := strings.Index(out, "Post-quantum algorithms found")
	end := strings.Index(out, "Hybrid constructions found")
	if start < 0 || end < start {
		t.Fatalf("cannot find the post-quantum section in:\n%s", out)
	}
	pqcSection := out[start:end]
	for _, alg := range []string{"ML-KEM", "ML-DSA", "SLH-DSA"} {
		if !strings.Contains(pqcSection, alg) {
			t.Errorf("the post-quantum section does not name %s:\n%s", alg, pqcSection)
		}
	}

	// The view is the report alone: no streamed findings, no full report.
	for _, s := range []string{"Scanning...", "Scan complete", "DETAILED FINDINGS"} {
		if strings.Contains(out, s) {
			t.Errorf("pqc text output should not contain %q", s)
		}
	}
}

func TestPqcOutputIsDeterministic(t *testing.T) {
	// A fixture of several files with several findings each, so that an
	// ordering that depends on map iteration or walk order shows up.
	dir := t.TempDir()
	for i := 0; i < 6; i++ {
		content := pqcFixture + "sig = ML_DSA_65\nk = X25519MLKEM768\n"
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d.py", i)), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	for _, target := range []string{cryptoSamples, dir} {
		var first string
		for n := 0; n < 3; n++ {
			resetPipelineFlags(t)
			out, _ := runPqcCapture(t, target)
			if n == 0 {
				if strings.TrimSpace(out) == "" {
					t.Fatalf("pqc on %s printed nothing", target)
				}
				first = out
				continue
			}
			if out != first {
				t.Fatalf("pqc on %s: run %d differs from run 0", target, n)
			}
		}
	}

	// The JSON check covers pqcFindings, the part pqc adds, and the embedded
	// migrationScore, whose topRiskFiles lists files the six fixture files
	// tie on.
	var firstFindings, firstScore string
	for n := 0; n < 3; n++ {
		resetPipelineFlags(t)
		outputFormat = "json"
		out, _ := runPqcCapture(t, dir)
		var view struct {
			PQCFindings    json.RawMessage `json:"pqcFindings"`
			MigrationScore json.RawMessage `json:"migrationScore"`
		}
		if err := json.Unmarshal([]byte(out), &view); err != nil {
			t.Fatalf("pqc --format json is not JSON: %v", err)
		}
		if n == 0 {
			firstFindings = string(view.PQCFindings)
			firstScore = string(view.MigrationScore)
			if firstScore == "" {
				t.Fatalf("pqc --format json has no migrationScore:\n%s", out)
			}
			continue
		}
		if string(view.PQCFindings) != firstFindings {
			t.Fatalf("pqc --format json: pqcFindings in run %d differs from run 0", n)
		}
		if string(view.MigrationScore) != firstScore {
			t.Fatalf("pqc --format json: migrationScore in run %d differs from run 0", n)
		}
	}
}
