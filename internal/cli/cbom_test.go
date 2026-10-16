// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// criticalFixture is a Python file whose DES and MD5 calls are both reported
// at CRITICAL, so the default scan exit code for it is 1.
const criticalFixture = `from Crypto.Cipher import DES
import hashlib
c = DES.new(key, DES.MODE_ECB)
h = hashlib.md5(b"a").hexdigest()
`

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// isRegistered reports whether the root command has a subcommand named name.
func isRegistered(name string) bool {
	for _, c := range rootCmd.Commands() {
		if c.Name() == name {
			return true
		}
	}
	return false
}

// assertSubsetOfScan fails when a command offers a flag that scan does not,
// or offers a scan flag under a different shorthand.
func assertSubsetOfScan(t *testing.T, flags *pflag.FlagSet) {
	t.Helper()
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Name == "help" {
			return
		}
		sf := scanCmd.Flags().Lookup(f.Name)
		if sf == nil {
			t.Errorf("--%s is not a scan flag; new commands offer a subset of scan's flags", f.Name)
			return
		}
		if f.Shorthand != sf.Shorthand {
			t.Errorf("--%s shorthand = %q, scan uses %q", f.Name, f.Shorthand, sf.Shorthand)
		}
	})
}

func TestCbomCmdExists(t *testing.T) {
	if cbomCmd == nil {
		t.Fatal("cbomCmd should not be nil")
	}
	if cbomCmd.Use != "cbom [path or URL]" {
		t.Errorf("cbomCmd.Use = %q, want %q", cbomCmd.Use, "cbom [path or URL]")
	}
	if !isRegistered("cbom") {
		t.Error("cbom is not registered on the root command")
	}
	want := "Write a CycloneDX 1.6 Cryptographic Bill of Materials (equivalent to scan --format cbom)"
	if cbomCmd.Short != want {
		t.Errorf("cbomCmd.Short = %q, want %q", cbomCmd.Short, want)
	}
}

func TestCbomCmdFlags(t *testing.T) {
	for _, name := range []string{"output", "include", "exclude", "ignore", "ignore-category", "config"} {
		if cbomCmd.Flags().Lookup(name) == nil {
			t.Errorf("cbomCmd missing expected flag: %s", name)
		}
	}
	if f := cbomCmd.Flags().ShorthandLookup("o"); f == nil || f.Name != "output" {
		t.Error("cbom -o should map to --output")
	}
	assertSubsetOfScan(t, cbomCmd.Flags())
}

func TestCbomRejectsFailOn(t *testing.T) {
	if cbomCmd.Flags().Lookup("fail-on") != nil {
		t.Fatal("cbom must not offer --fail-on; an inventory is not a verdict")
	}
	err := cbomCmd.ParseFlags([]string{"--fail-on", "high"})
	if err == nil || !strings.Contains(err.Error(), "unknown flag: --fail-on") {
		t.Errorf("cbom --fail-on: got error %v, want unknown flag", err)
	}
	if !strings.Contains(cbomCmd.Long, "To fail a build on findings, use cryptoscan gate.") {
		t.Error("cbom help should point to cryptoscan gate for failing a build")
	}
}

func TestCbomExitsZeroWithCriticalFindings(t *testing.T) {
	dir := writeFixture(t, "app.py", criticalFixture)

	// The same fixture fails the default scan, so cbom's 0 below is a
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

	resetPipelineFlags(t)
	var code int
	out := captureStdout(func() {
		var err error
		code, err = cbomTarget(cbomCmd, dir)
		if err != nil {
			t.Errorf("cbom failed: %v", err)
		}
	})
	if code != 0 {
		t.Errorf("cbom exit code = %d, want 0 whatever the findings are", code)
	}

	// The whole of stdout must be the CBOM: nothing else is printed.
	var bom struct {
		BomFormat   string            `json:"bomFormat"`
		SpecVersion string            `json:"specVersion"`
		Components  []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &bom); err != nil {
		t.Fatalf("cbom stdout is not a single JSON document: %v\n%s", err, out)
	}
	if bom.BomFormat != "CycloneDX" || bom.SpecVersion != "1.6" {
		t.Errorf("bomFormat %q specVersion %q, want CycloneDX 1.6", bom.BomFormat, bom.SpecVersion)
	}
	if len(bom.Components) == 0 {
		t.Error("cbom should list at least one component for the fixture")
	}
}

func TestCbomWritesOutputFileAndNothingToStdout(t *testing.T) {
	dir := writeFixture(t, "app.py", criticalFixture)
	resetPipelineFlags(t)
	outputFile = filepath.Join(t.TempDir(), "crypto-bom.json")

	out := captureStdout(func() {
		if _, err := cbomTarget(cbomCmd, dir); err != nil {
			t.Errorf("cbom failed: %v", err)
		}
	})
	if out != "" {
		t.Errorf("cbom -o printed to stdout: %q", out)
	}
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("cbom -o did not write the file: %v", err)
	}
	var bom map[string]any
	if err := json.Unmarshal(data, &bom); err != nil || bom["specVersion"] != "1.6" {
		t.Errorf("cbom -o file is not a CycloneDX 1.6 document (err %v)", err)
	}
}

func TestCbomWriteErrorIsReported(t *testing.T) {
	dir := writeFixture(t, "app.py", criticalFixture)
	resetPipelineFlags(t)
	outputFile = filepath.Join(t.TempDir(), "missing-dir", "crypto-bom.json")

	if _, err := cbomTarget(cbomCmd, dir); err == nil {
		t.Error("cbom should return an error when the output file cannot be written")
	}
}

func TestCbomIgnoresConfigBaseline(t *testing.T) {
	dir := writeFixture(t, "app.py", criticalFixture)

	// A baseline holding every current finding, named by the config file.
	baseline := filepath.Join(t.TempDir(), "baseline.json")
	resetPipelineFlags(t)
	outputFormat = "json"
	outputFile = baseline
	captureStdout(func() {
		if _, err := scanTarget(scanCmd, dir); err != nil {
			t.Errorf("writing the baseline failed: %v", err)
		}
	})
	config := "baseline: " + baseline + "\nminSeverity: critical\n"
	if err := os.WriteFile(filepath.Join(dir, ".cryptoscan.yaml"), []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	// scan honours that baseline, so nothing is left to report.
	resetPipelineFlags(t)
	outputFormat = "json"
	out := captureStdout(func() {
		if _, err := scanTarget(scanCmd, dir); err != nil {
			t.Errorf("scan failed: %v", err)
		}
	})
	var report struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("scan stdout is not JSON: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("scan with the config baseline reported %d findings, want 0", len(report.Findings))
	}

	// cbom lists everything regardless.
	resetPipelineFlags(t)
	out = captureStdout(func() {
		if _, err := cbomTarget(cbomCmd, dir); err != nil {
			t.Errorf("cbom failed: %v", err)
		}
	})
	var bom struct {
		Components []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &bom); err != nil {
		t.Fatalf("cbom stdout is not JSON: %v", err)
	}
	if len(bom.Components) == 0 {
		t.Error("a config file baseline must not filter the CBOM")
	}
}

func TestCbomIgnoresConfigFormat(t *testing.T) {
	dir := writeFixture(t, "app.py", criticalFixture)
	if err := os.WriteFile(filepath.Join(dir, ".cryptoscan.yaml"), []byte("format: json\n"), 0644); err != nil {
		t.Fatal(err)
	}
	resetPipelineFlags(t)

	out := captureStdout(func() {
		if _, err := cbomTarget(cbomCmd, dir); err != nil {
			t.Errorf("cbom failed: %v", err)
		}
	})
	if !strings.Contains(out, `"bomFormat"`) {
		t.Error("a config file format must not change what cbom writes")
	}
}
