// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The committed fixtures, records and key table, from this package's
// directory, where go test runs its tests.
const (
	committedFixtures = "../../testdata/trust"
	committedRecords  = "../../testdata/trust-captured/source-records.txt"
	committedTable    = "../../trust_keys.json"
)

// runMainEnv, set to 1 in a child process's environment, makes the test
// binary run the command instead of the tests.
const runMainEnv = "TRUSTGEN_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runTrustgen runs the command with args in a child process and returns its
// exit status and what it wrote to standard error.
func runTrustgen(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), runMainEnv+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), stderr.String()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, stderr.String()
}

// mkdir makes dir and any parent it lacks.
func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

// copyUseDirs copies the committed certificates of each named use directory
// into a directory of the same name under fixtures.
func copyUseDirs(t *testing.T, fixtures string, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(committedFixtures, dir, "*.crt"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no committed certificate in %s (%v)", dir, err)
		}
		mkdir(t, filepath.Join(fixtures, dir))
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(fixtures, dir, filepath.Base(file)), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// A fixtures directory that does not exist, and a use directory that does
// not exist or holds no .crt file, make the command exit 1 with an error
// naming that directory, and it writes no key table.
func TestTrustgenRefusesADirectoryWithNoCertificate(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, fixtures string)
		named string // the directory the error names, relative to fixtures
	}{
		{"fixtures directory does not exist", func(*testing.T, string) {}, "."},
		{"fixtures directory is empty", func(t *testing.T, fixtures string) { mkdir(t, fixtures) }, "tls"},
		{"codesigning directory does not exist", func(t *testing.T, fixtures string) { copyUseDirs(t, fixtures, "tls", "root") }, "codesigning"},
		{"root directory holds no .crt file", func(t *testing.T, fixtures string) {
			copyUseDirs(t, fixtures, "tls", "codesigning")
			mkdir(t, filepath.Join(fixtures, "root"))
		}, "root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			fixtures := filepath.Join(dir, "fixtures")
			c.setup(t, fixtures)
			keys := filepath.Join(dir, "keys.json")
			status, stderr := runTrustgen(t, "-fixtures", fixtures, "-records", committedRecords, "-keys", keys)
			if status != 1 {
				t.Errorf("exit status %d, want 1", status)
			}
			if named := filepath.Join(fixtures, c.named); !strings.Contains(stderr, named+":") {
				t.Errorf("the error does not name %s: %q", named, stderr)
			}
			if _, err := os.Stat(keys); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a key table was written to %s (stat error %v)", keys, err)
			}
		})
	}
}

// From the committed fixtures and records the command exits 0 and writes the
// committed key table, byte for byte.
func TestTrustgenWritesTheCommittedTable(t *testing.T) {
	keys := filepath.Join(t.TempDir(), "keys.json")
	if status, stderr := runTrustgen(t, "-fixtures", committedFixtures, "-records", committedRecords, "-keys", keys); status != 0 {
		t.Fatalf("exit status %d, want 0: %q", status, stderr)
	}
	got, err := os.ReadFile(keys)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(committedTable)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("the committed fixtures and records do not give trust_keys.json; regenerate it with go generate ./pkg/patterns")
	}
}
