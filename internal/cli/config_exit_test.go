// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestFailOnStopsOnUnparsableAutoDetectedConfig covers an auto-detected
// config file that is not valid YAML. With --fail-on, and under gate, the run
// went on without the file's rules after a warning.
func TestFailOnStopsOnUnparsableAutoDetectedConfig(t *testing.T) {
	dir := configScanDir(t, "ignore: [unclosed\n")
	wantErr := "config file " + filepath.Join(dir, ".cryptoscan.yaml") + " could not be parsed: "

	tests := []struct {
		name string
		cmd  *cobra.Command
		args []string
		run  func() (int, error)
	}{
		{"scan --fail-on critical", scanCmd, []string{"--stream=false", "--fail-on", "critical"},
			func() (int, error) { return scanTarget(scanCmd, dir) }},
		{"gate", gateCmd, nil, func() (int, error) { return gateTarget(gateCmd, dir) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetScanFlags(t)
			resetPipelineFlags(t)
			if err := tt.cmd.ParseFlags(tt.args); err != nil {
				t.Fatal(err)
			}
			var err error
			stdout := captureStdout(func() {
				_, err = tt.run()
			})
			if err == nil || !strings.HasPrefix(err.Error(), wantErr) {
				t.Fatalf("err = %v, want one starting %q", err, wantErr)
			}
			if stdout != "" {
				t.Errorf("printed a report before stopping:\n%s", stdout)
			}
			var hinted *hintedError
			if !errors.As(err, &hinted) {
				t.Fatalf("error %q carries no hint", err)
			}
			// Each flag the hint names is one this command has.
			for _, flag := range regexp.MustCompile(`--[a-z-]+`).FindAllString(hinted.hint, -1) {
				if tt.cmd.Flags().Lookup(strings.TrimPrefix(flag, "--")) == nil {
					t.Errorf("hint %q names %s, which %s does not have", hinted.hint, flag, tt.cmd.Name())
				}
			}
		})
	}

	// Without --fail-on the scan still runs without the file, after the
	// warning TestRunScanWarnsAboutUnparsableConfigFile checks.
	t.Run("scan without --fail-on", func(t *testing.T) {
		var out scanOutcome
		captureStderr(func() {
			out = runScanWith(t, dir, "--stream=false")
		})
		if out.err != "" {
			t.Errorf("scan failed: %s", out.err)
		}
		if out.stdout == "" {
			t.Error("scan printed no report")
		}
	})
}

// TestUnparsableAutoDetectedConfigHintOffersNoConfig checks the next step a
// stopped run prints on both commands, now that gate has --no-config, and
// that the step runs: with --no-config the file is not read and the run goes
// on with the command line's options alone.
func TestUnparsableAutoDetectedConfigHintOffersNoConfig(t *testing.T) {
	dir := configScanDir(t, "ignore: [unclosed\n")
	const hint = "With --fail-on, and with gate, a config file that does not parse stops the scan. " +
		"Fix the file, or add --no-config to use only command-line options."

	stops := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"scan --fail-on low", scanCmd, []string{"--stream=false", "--fail-on", "low"}},
		{"gate", gateCmd, nil},
	}
	for _, tt := range stops {
		t.Run(tt.name, func(t *testing.T) {
			resetScanFlags(t)
			resetGateFlags(t)
			if err := tt.cmd.ParseFlags(tt.args); err != nil {
				t.Fatal(err)
			}
			run := scanTarget
			if tt.cmd == gateCmd {
				run = gateTarget
			}
			var err error
			captureStdout(func() {
				_, err = run(tt.cmd, dir)
			})
			var hinted *hintedError
			if !errors.As(err, &hinted) {
				t.Fatalf("err = %v, want a stop that names the next step", err)
			}
			if hinted.hint != hint {
				t.Errorf("hint = %q, want %q", hinted.hint, hint)
			}
		})
	}

	// The RSA findings of the tree are HIGH, so with the file left out both
	// runs fail on them, as the same tree without a config file does.
	runs := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"scan --fail-on high --no-config", scanCmd, []string{"--stream=false", "--fail-on", "high", "--no-config"}},
		{"gate --no-config", gateCmd, []string{"--no-config"}},
	}
	for _, tt := range runs {
		t.Run(tt.name, func(t *testing.T) {
			out := runCommandWith(t, tt.cmd, dir, tt.args...)
			if out.err != "" {
				t.Fatalf("%s stopped: %s", tt.name, out.err)
			}
			if out.code != 1 {
				t.Errorf("exit code = %d, want 1 for the HIGH findings", out.code)
			}
			if strings.Contains(out.stderr, "could not be parsed") {
				t.Errorf("stderr = %q; --no-config reads no config file", out.stderr)
			}
		})
	}
}
