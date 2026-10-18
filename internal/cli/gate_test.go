// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// highFixture generates an RSA-2048 key. RSA key generation is reported at
// HIGH and nothing in the file is CRITICAL, so scan's default lets it pass.
const highFixture = `from cryptography.hazmat.primitives.asymmetric import rsa
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
`

// setGateFailOn sets --fail-on on the gate command as if it had been given on
// the command line, and puts it back afterwards.
func setGateFailOn(t *testing.T, value string) {
	t.Helper()
	f := gateCmd.Flags().Lookup("fail-on")
	if err := f.Value.Set(value); err != nil {
		t.Fatal(err)
	}
	f.Changed = true
	t.Cleanup(func() {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
}

func TestGateCmdExists(t *testing.T) {
	if gateCmd == nil {
		t.Fatal("gateCmd should not be nil")
	}
	if gateCmd.Use != "gate [path or URL]" {
		t.Errorf("gateCmd.Use = %q, want %q", gateCmd.Use, "gate [path or URL]")
	}
	if !isRegistered("gate") {
		t.Error("gate is not registered on the root command")
	}
	want := "Fail a build when findings reach a severity (equivalent to scan --fail-on high)"
	if gateCmd.Short != want {
		t.Errorf("gateCmd.Short = %q, want %q", gateCmd.Short, want)
	}
}

func TestGateCmdFlags(t *testing.T) {
	for _, name := range []string{"fail-on", "baseline", "format", "ignore", "ignore-category", "config", "no-color"} {
		if gateCmd.Flags().Lookup(name) == nil {
			t.Errorf("gateCmd missing expected flag: %s", name)
		}
	}
	if got := gateCmd.Flags().Lookup("fail-on").DefValue; got != "high" {
		t.Errorf("gate --fail-on default = %q, want high", got)
	}
	if got := gateCmd.Flags().Lookup("format").DefValue; got != "text" {
		t.Errorf("gate --format default = %q, want text", got)
	}
	assertSubsetOfScan(t, gateCmd.Flags())
}

// TestGateAndPqcNoColorFlag runs gate and pqc through the root command with
// --no-color, as a user types it. Both print a text report, so both take the
// flag scan takes. --no-color=false turns colour on although the test's
// stdout is a pipe, which shows that the flag, not the pipe, decides.
func TestGateAndPqcNoColorFlag(t *testing.T) {
	// ML-KEM is reported at INFO, below gate's default threshold, so gate
	// exits 0 and the run returns to the test.
	dir := writeFixture(t, "kem.py", "kem = ML_KEM_768\n")
	scanUsage := scanCmd.Flags().Lookup("no-color").Usage
	// Cleanup functions run in reverse order, so this one runs after the
	// flags below are reset.
	savedNoColor := noColor
	t.Cleanup(func() { noColor = savedNoColor })

	for _, cmd := range []*cobra.Command{gateCmd, pqcCmd} {
		flag := cmd.Flags().Lookup("no-color")
		if flag == nil {
			t.Errorf("%s has no --no-color flag", cmd.Name())
			continue
		}
		if flag.Usage != scanUsage {
			t.Errorf("%s --no-color help = %q, scan prints %q", cmd.Name(), flag.Usage, scanUsage)
		}
		reset := func() {
			_ = flag.Value.Set(flag.DefValue)
			flag.Changed = false
		}
		t.Cleanup(reset)

		for _, tc := range []struct {
			arg       string
			wantColor bool
		}{
			{"--no-color", false},
			{"--no-color=false", true},
		} {
			resetPipelineFlags(t)
			out, err := executeRoot(t, cmd.Name(), tc.arg, dir)
			reset()
			if err != nil {
				t.Errorf("cryptoscan %s %s: %v\n%s", cmd.Name(), tc.arg, err, out)
				continue
			}
			if !strings.Contains(out, "ML-KEM") {
				t.Errorf("cryptoscan %s %s did not print the report:\n%s", cmd.Name(), tc.arg, out)
			}
			if got := strings.Contains(out, "\x1b["); got != tc.wantColor {
				t.Errorf("cryptoscan %s %s: colour escape sequences printed = %v, want %v", cmd.Name(), tc.arg, got, tc.wantColor)
			}
		}
	}
}

func TestGateDefaultThresholdIsHigh(t *testing.T) {
	dir := writeFixture(t, "keys.py", highFixture)

	resetPipelineFlags(t)
	var gateCode int
	out := captureStdout(func() {
		var err error
		gateCode, err = gateTarget(gateCmd, dir)
		if err != nil {
			t.Errorf("gate failed: %v", err)
		}
	})
	if gateCode != 1 {
		t.Errorf("gate exit code = %d, want 1 for a HIGH finding", gateCode)
	}
	if !strings.Contains(out, "RSA") {
		t.Errorf("gate should print the text report naming the RSA finding:\n%s", out)
	}

	resetPipelineFlags(t)
	var scanCode int
	captureStdout(func() {
		var err error
		scanCode, err = scanTarget(scanCmd, dir)
		if err != nil {
			t.Errorf("scan failed: %v", err)
		}
	})
	if scanCode != 0 {
		t.Errorf("scan exit code = %d, want 0: with no flags scan fails only on CRITICAL", scanCode)
	}
}

func TestGateFailOnCriticalPassesHigh(t *testing.T) {
	dir := writeFixture(t, "keys.py", highFixture)
	resetPipelineFlags(t)
	setGateFailOn(t, "critical")

	var code int
	captureStdout(func() {
		var err error
		code, err = gateTarget(gateCmd, dir)
		if err != nil {
			t.Errorf("gate failed: %v", err)
		}
	})
	if code != 0 {
		t.Errorf("gate --fail-on critical exit code = %d, want 0 for a HIGH finding", code)
	}
}

func TestGateConfigFailOnAppliesWhenFlagNotGiven(t *testing.T) {
	dir := writeFixture(t, "keys.py", highFixture)
	if err := os.WriteFile(filepath.Join(dir, ".cryptoscan.yaml"), []byte("failOn: critical\n"), 0644); err != nil {
		t.Fatal(err)
	}
	resetPipelineFlags(t)

	var code int
	captureStdout(func() {
		var err error
		code, err = gateTarget(gateCmd, dir)
		if err != nil {
			t.Errorf("gate failed: %v", err)
		}
	})
	if code != 0 {
		t.Errorf("gate with config failOn critical exit code = %d, want 0", code)
	}
}

func TestGateEmptyDirExitsZero(t *testing.T) {
	dir := t.TempDir()
	resetPipelineFlags(t)

	var code int
	captureStdout(func() {
		var err error
		code, err = gateTarget(gateCmd, dir)
		if err != nil {
			t.Errorf("gate on an empty directory failed: %v", err)
		}
	})
	if code != 0 {
		t.Errorf("gate exit code on an empty directory = %d, want 0", code)
	}
}

func TestGateJSONReport(t *testing.T) {
	dir := writeFixture(t, "keys.py", highFixture)
	resetPipelineFlags(t)
	outputFormat = "json"

	out := captureStdout(func() {
		if _, err := gateTarget(gateCmd, dir); err != nil {
			t.Errorf("gate failed: %v", err)
		}
	})
	var report struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("gate --format json stdout is not JSON: %v\n%s", err, out)
	}
	if len(report.Findings) == 0 {
		t.Error("gate --format json should list the findings")
	}
}

func TestGateRejectsUnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	for _, format := range []string{"cbom", "csv"} {
		resetPipelineFlags(t)
		outputFormat = format
		if _, err := gateTarget(gateCmd, dir); err == nil {
			t.Errorf("gate --format %s should be rejected", format)
		}
	}
}
