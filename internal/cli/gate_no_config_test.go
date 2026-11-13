// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// commandOutcome is what one run of scan or gate left: what it printed on
// standard output and standard error, the code it would exit with, and the
// error it returned.
type commandOutcome struct {
	stdout string
	stderr string
	code   int
	err    string
}

// runCommandWith runs scan or gate on target with args through the command's
// own code path, without exiting the process. Every flag of both commands is
// at its default before the run and again when the test ends.
func runCommandWith(t *testing.T, cmd *cobra.Command, target string, args ...string) commandOutcome {
	t.Helper()
	resetScanFlags(t)
	resetGateFlags(t)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("%s %s: %v", cmd.Name(), strings.Join(args, " "), err)
	}
	run := scanTarget
	if cmd == gateCmd {
		run = gateTarget
	}
	var out commandOutcome
	var err error
	out.stderr = captureStderr(func() {
		out.stdout = captureStdout(func() {
			out.code, err = run(cmd, target)
		})
	})
	if err != nil {
		out.err = err.Error()
	}
	return out
}

// TestGateHasNoConfig checks that gate offers --no-config with scan's words,
// so the documented way to keep a found config file out of a gate exists on
// the command named gate.
func TestGateHasNoConfig(t *testing.T) {
	flag := gateCmd.Flags().Lookup("no-config")
	if flag == nil {
		t.Fatal("gate has no --no-config flag")
	}
	if want := scanCmd.Flags().Lookup("no-config").Usage; flag.Usage != want {
		t.Errorf("gate --no-config usage = %q, want scan's %q", flag.Usage, want)
	}
	if flag.DefValue != "false" {
		t.Errorf("gate --no-config default = %q, want false", flag.DefValue)
	}
}

// TestGateNoConfigReadsNoConfigFile runs gate with --no-config on the tree
// from the issue, whose .cryptoscan.yaml ignores every pattern. The file is
// not read, so the HIGH findings stay in the report and the gate fails.
func TestGateNoConfigReadsNoConfigFile(t *testing.T) {
	dir := configScanDir(t, "ignore:\n  patterns: [\"*\"]\n")
	out := runCommandWith(t, gateCmd, dir, "--no-config")
	if out.err != "" {
		t.Fatalf("gate --no-config failed: %s", out.err)
	}
	if out.code != 1 {
		t.Errorf("exit code = %d, want 1: the file is not read and the RSA findings are HIGH", out.code)
	}
	if strings.Contains(out.stdout, "Config file applied") {
		t.Errorf("gate --no-config applied a config file:\n%s", out.stdout)
	}
}

// TestGateRejectsConfigWithNoConfig checks that gate, like scan, refuses
// --config together with --no-config.
func TestGateRejectsConfigWithNoConfig(t *testing.T) {
	dir := configScanDir(t, "ignore:\n  patterns: [\"*\"]\n")
	out := runCommandWith(t, gateCmd, dir, "--no-config", "--config", filepath.Join(dir, ".cryptoscan.yaml"))
	if want := "--config and --no-config cannot be used together"; out.err != want {
		t.Errorf("err = %q, want %q", out.err, want)
	}
}

// TestScanWithoutItLineNamesTheCommandThatRan runs scan and gate on the tree
// from the issue and reads the config block's "Scan without it:" line. It
// names the command that ran and the --fail-on value given, and each flag it
// names is one that command has.
func TestScanWithoutItLineNamesTheCommandThatRan(t *testing.T) {
	dir := configScanDir(t, "ignore:\n  patterns: [\"*\"]\n")
	tests := []struct {
		name string
		cmd  *cobra.Command
		args []string
		want string
	}{
		{"scan", scanCmd, []string{"--stream=false"}, "Scan without it: cryptoscan scan " + dir + " --no-config"},
		{"scan --fail-on high", scanCmd, []string{"--stream=false", "--fail-on", "high"}, "Scan without it: cryptoscan scan " + dir + " --fail-on high --no-config"},
		{"gate", gateCmd, nil, "Scan without it: cryptoscan gate " + dir + " --no-config"},
		{"gate --fail-on low", gateCmd, []string{"--fail-on", "low"}, "Scan without it: cryptoscan gate " + dir + " --fail-on low --no-config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runCommandWith(t, tt.cmd, dir, tt.args...)
			if out.err != "" {
				t.Fatalf("%s failed: %s", tt.name, out.err)
			}
			if !strings.Contains(out.stdout, tt.want) {
				t.Fatalf("report lacks %q:\n%s", tt.want, out.stdout)
			}
			for _, flag := range regexp.MustCompile(`--[a-z-]+`).FindAllString(tt.want, -1) {
				if tt.cmd.Flags().Lookup(strings.TrimPrefix(flag, "--")) == nil {
					t.Errorf("the line names %s, which %s does not have", flag, tt.cmd.Name())
				}
			}
		})
	}
}
