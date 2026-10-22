// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// stubGit puts a program named git first on PATH for the rest of the test.
// It writes each argument it is run with on a line of its own, then a line
// saying whether CRYPTOSCAN_GIT_PASSWORD is set in its environment, and
// fails as a clone of an unreachable host does. The function it returns
// reads what the last run wrote and removes it.
func stubGit(t *testing.T) func() (args []string, passwordSet bool) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the git stub is a shell script")
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "record")
	script := "#!/bin/sh\n" +
		"{\n" +
		"  for arg in \"$@\"; do printf 'arg %s\\n' \"$arg\"; done\n" +
		"  printf 'password %s\\n' \"${" + scanner.EnvGitPassword + ":+set}\"\n" +
		"} > '" + record + "'\n" +
		"exit 128\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return func() ([]string, bool) {
		t.Helper()
		data, err := os.ReadFile(record)
		if err != nil {
			t.Fatalf("git was not run: %v", err)
		}
		if err := os.Remove(record); err != nil {
			t.Fatal(err)
		}
		var args []string
		passwordSet := false
		for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
			if arg, ok := strings.CutPrefix(line, "arg "); ok {
				args = append(args, arg)
			} else if value, ok := strings.CutPrefix(line, "password "); ok {
				passwordSet = value == "set"
			}
		}
		return args, passwordSet
	}
}

// The reproduction in the issue, with the credential given in
// CRYPTOSCAN_GIT_USERNAME and CRYPTOSCAN_GIT_PASSWORD instead of the URL. git
// is given the URL as typed, with no user information in it, and neither
// value is on its command line: the options before clone set a credential
// helper for the URL's host alone, which reads the values from the
// environment git is run with. Every command that takes a URL clones it the
// same way.
func TestURLScanGivesGitTheEnvironmentCredentialOffItsCommandLine(t *testing.T) {
	readGit := stubGit(t)
	const (
		user     = "FAKE-USER"
		password = "FAKE-PASSWORD-1234"
		target   = "https://127.0.0.1:1/repo.git"
		helper   = "credential.https://127.0.0.1:1.helper="
	)
	t.Setenv(scanner.EnvGitUsername, user)
	t.Setenv(scanner.EnvGitPassword, password)

	for _, command := range []string{"scan", "cbom", "gate", "pqc"} {
		t.Run(command, func(t *testing.T) {
			resetPipelineFlags(t)
			if _, err := runCLI(t, command, target); err == nil {
				t.Fatal("expected the clone to fail")
			}
			args, passwordSet := readGit()
			assertHoldsNone(t, "git's command line", strings.Join(args, "\n"), user, password)
			if len(args) < 7 || args[0] != "-c" || args[1] != helper || args[2] != "-c" ||
				!strings.HasPrefix(args[3], helper+"!") || args[4] != "clone" {
				t.Fatalf("git was not run as git -c %s -c %s!... clone ...:\n%s", helper, helper, strings.Join(args, "\n"))
			}
			for _, name := range []string{scanner.EnvGitUsername, scanner.EnvGitPassword} {
				if !strings.Contains(args[3], "$"+name) {
					t.Errorf("the credential helper does not read %s:\n%s", name, args[3])
				}
			}
			if got := args[len(args)-2]; got != target {
				t.Errorf("git was given the URL %q, want %q", got, target)
			}
			if !passwordSet {
				t.Errorf("%s is not set in the environment git is run with", scanner.EnvGitPassword)
			}
		})
	}

	// No helper is set where the password would not be used.
	for _, tt := range []struct {
		name, target, password string
	}{
		{"http URL", "http://127.0.0.1:1/repo.git", password},
		{"no password in the environment", target, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resetPipelineFlags(t)
			t.Setenv(scanner.EnvGitPassword, tt.password)
			if _, err := runCLI(t, "scan", tt.target); err == nil {
				t.Fatal("expected the clone to fail")
			}
			args, _ := readGit()
			if len(args) == 0 || args[0] != "clone" {
				t.Errorf("git was run with options before clone:\n%s", strings.Join(args, "\n"))
			}
		})
	}
}
