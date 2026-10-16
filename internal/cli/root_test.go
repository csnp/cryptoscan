// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// executeRoot runs the root command with args the way main does and returns
// everything it printed. Cobra writes the usage block to the command's output
// writer and the error line to its error writer; both go to one buffer here,
// alongside what the scan prints directly to stdout.
func executeRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(args)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		// runScan sets this for the rest of the process, which in a test
		// binary would also silence the usage block for later usage errors.
		scanCmd.SilenceUsage = false
		outputFormat = "text"
		outputFile = ""
		configFile = ""
		baselineFile = ""
	})
	var err error
	printed := captureStdout(func() {
		err = Execute()
	})
	return printed + buf.String(), err
}

func TestVersionFlagMatchesVersionCommand(t *testing.T) {
	SetVersionInfo("1.2.3", "abc1234", "2026-01-02")

	fromFlag, err := executeRoot(t, "--version")
	if err != nil {
		t.Fatalf("cryptoscan --version failed: %v (output %q)", err, fromFlag)
	}
	fromCommand, err := executeRoot(t, "version")
	if err != nil {
		t.Fatalf("cryptoscan version failed: %v", err)
	}

	if !strings.HasPrefix(fromFlag, "cryptoscan 1.2.3\n") {
		t.Errorf("--version output = %q, want it to start with %q", fromFlag, "cryptoscan 1.2.3\n")
	}
	if fromFlag != fromCommand {
		t.Errorf("--version and version print different text:\n--version: %q\nversion:   %q", fromFlag, fromCommand)
	}
}

func TestRuntimeErrorsOmitUsageAndNameANextStep(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	tests := []struct {
		name     string
		args     []string
		wantErr  string
		wantHint string
	}{
		{
			name:     "missing scan target",
			args:     []string{"scan", "--no-color", missing},
			wantErr:  "cannot access target",
			wantHint: "Check the path",
		},
		{
			name:     "missing config file",
			args:     []string{"scan", "--no-color", "--config", missing + ".yaml", t.TempDir()},
			wantErr:  "failed to load config file",
			wantHint: "Check the --config path",
		},
		{
			name:     "missing baseline file",
			args:     []string{"scan", "--no-color", "--baseline", missing + ".json", t.TempDir()},
			wantErr:  "failed to load baseline",
			wantHint: "Check the --baseline path",
		},
		{
			name:     "output folder missing",
			args:     []string{"scan", "--no-color", "--output", filepath.Join(missing, "report.txt"), t.TempDir()},
			wantErr:  "failed to write output",
			wantHint: "Check that the folder for --output exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeRoot(t, tt.args...)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(output, "Error: ") || !strings.Contains(output, tt.wantErr) {
				t.Errorf("output = %q, want an Error line containing %q", output, tt.wantErr)
			}
			if strings.Contains(output, "Usage:") {
				t.Errorf("output prints the usage block for a runtime error:\n%s", output)
			}
			if !strings.Contains(output, tt.wantHint) {
				t.Errorf("output = %q, want a next step containing %q", output, tt.wantHint)
			}
		})
	}
}

func TestCloneFailureSaysRepositoryNotAccessible(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("GIT_TERMINAL_PROMPT", "0")

	// Port 1 on the loopback address refuses the connection, so git fails
	// without reaching the network.
	output, err := executeRoot(t, "scan", "--no-color", "https://127.0.0.1:1/missing/repo.git")
	if err == nil {
		t.Fatal("expected the clone to fail")
	}
	if !strings.Contains(output, "repository not found or not accessible") {
		t.Errorf("output = %q, want it to say the repository is not found or not accessible", output)
	}
	if strings.Contains(output, "Usage:") {
		t.Errorf("output prints the usage block for a clone failure:\n%s", output)
	}
	if !strings.Contains(output, "Check the URL") {
		t.Errorf("output = %q, want a next step containing %q", output, "Check the URL")
	}
}

func TestMissingGitSaysToInstallIt(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	output, err := executeRoot(t, "scan", "--no-color", "https://127.0.0.1:1/missing/repo.git")
	if err == nil {
		t.Fatal("expected the scan to fail without git")
	}
	if !strings.Contains(output, "git is required to scan a repository URL") {
		t.Errorf("output = %q, want it to say git is required", output)
	}
	if !strings.Contains(output, "Install git") {
		t.Errorf("output = %q, want a next step containing %q", output, "Install git")
	}
}

func TestScanErrorHint(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"clone failed", fmt.Errorf("failed to clone repository: %w", scanner.ErrCloneFailed), "Check the URL"},
		{"git missing", fmt.Errorf("git is required: %w", &exec.Error{Name: "git", Err: exec.ErrNotFound}), "Install git"},
		{"path missing", fmt.Errorf("cannot access target: %w", fs.ErrNotExist), "Check the path"},
		{"path unreadable", fmt.Errorf("cannot access target: %w", fs.ErrPermission), "permission to read"},
		{"other", errors.New("something else"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanErrorHint(tt.err)
			if tt.want == "" {
				if got != "" {
					t.Errorf("scanErrorHint() = %q, want no hint", got)
				}
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("scanErrorHint() = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

func TestWithHintLeavesErrorTextUnchanged(t *testing.T) {
	base := errors.New("scan failed: boom")
	if got := withHint(base, ""); got != base {
		t.Errorf("withHint with an empty hint = %v, want the original error", got)
	}
	hinted := withHint(base, "Try again.")
	if hinted.Error() != base.Error() {
		t.Errorf("withHint changed the error text to %q", hinted.Error())
	}
	if !errors.Is(hinted, base) {
		t.Error("withHint error does not unwrap to the original error")
	}
}

func TestUsageErrorsStillPrintUsage(t *testing.T) {
	output, err := executeRoot(t, "scan")
	if err == nil {
		t.Fatal("expected an error for a missing argument")
	}
	if !strings.Contains(output, "Usage:") {
		t.Errorf("output = %q, want the usage block for a missing argument", output)
	}
}
