// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// U+023A is two bytes long and lowercases to a three-byte letter, so an index
// found in strings.ToLower(line) can run past the end of line.
const capitalAWithStroke = string(rune(0x023A))

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func scanWithConfig(t *testing.T, cfg Config) *Results {
	t.Helper()
	if cfg.MinSeverity == 0 {
		cfg.MinSeverity = SeverityInfo
	}
	results, err := New(cfg).Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	return results
}

// Four U+023A letters before a match at the end of the line used to stop the
// whole scan with "slice bounds out of range" and write no report.
func TestScanReportsMatchAfterLettersThatGrowWhenLowercased(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "a.go",
		`var s = "`+strings.Repeat(capitalAWithStroke, 4)+`"; _ = rsa`+"\n")

	results := scanWithConfig(t, Config{Target: dir})

	found := false
	for _, f := range results.Findings {
		if f.File == path && f.Line == 1 && f.Match == "rsa" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the rsa match on line 1 of %s to be reported, got %+v", path, results.Findings)
	}
	if len(results.UnanalyzedFiles) != 0 {
		t.Errorf("expected every file to be analyzed, got %+v", results.UnanalyzedFiles)
	}

	// The field is always written, so a JSON consumer can tell "none" from
	// "not reported".
	data, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"unanalyzedFiles":[]`) {
		t.Errorf("expected an empty unanalyzedFiles array in JSON, got %s", data)
	}
}

// The ignore directive parser had the same defect: it found the directive in
// a lowercased copy of the line and sliced the original with that position.
func TestIgnoreDirectiveAfterLettersThatGrowWhenLowercased(t *testing.T) {
	tests := []struct {
		name         string
		line         string
		wantFindings bool
	}{
		{
			// Used to panic.
			name: "blanket ignore",
			line: `_ = rsa // ` + capitalAWithStroke + ` cryptoscan:ignore`,
		},
		{
			// Used to read the pattern as "SA-*" and report the finding.
			name: "pattern-specific ignore",
			line: `_ = rsa // ` + strings.Repeat(capitalAWithStroke, 2) + ` cryptoscan:ignore RSA-*`,
		},
		{
			// Control: the line does produce a finding when the directive
			// names a different pattern.
			name:         "ignore for another pattern",
			line:         `_ = rsa // ` + strings.Repeat(capitalAWithStroke, 2) + ` cryptoscan:ignore AES-*`,
			wantFindings: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "a.go", tt.line+"\n")

			results := scanWithConfig(t, Config{Target: dir})

			if got := len(results.Findings) > 0; got != tt.wantFindings {
				t.Errorf("findings reported = %v, want %v: %+v", got, tt.wantFindings, results.Findings)
			}
			if len(results.UnanalyzedFiles) != 0 {
				t.Errorf("expected every file to be analyzed, got %+v", results.UnanalyzedFiles)
			}
		})
	}
}

// An internal error in one file must not end the run for the others. The
// OnFinding callback runs inside per-file analysis, so a callback that panics
// stands in for any internal error there.
func TestScanRecoversFromAnErrorInOneFile(t *testing.T) {
	const content = "package main\nkey, _ := rsa.GenerateKey(rand.Reader, 2048)\n"

	panicOn := func(name string) func(Finding) {
		return func(f Finding) {
			if filepath.Base(f.File) == name {
				panic("simulated analyzer failure")
			}
		}
	}

	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		okPath := writeTestFile(t, dir, "ok.go", content)
		badPath := writeTestFile(t, dir, "bad.go", content)

		results := scanWithConfig(t, Config{Target: dir, OnFinding: panicOn("bad.go")})

		reportedOK, keptBad := false, false
		for _, f := range results.Findings {
			if f.File == okPath && f.Algorithm == "RSA" {
				reportedOK = true
			}
			if f.File == badPath && f.Algorithm == "RSA" {
				keptBad = true
			}
		}
		if !reportedOK {
			t.Errorf("expected the RSA finding in %s to be reported, got %+v", okPath, results.Findings)
		}
		// The finding is recorded before the callback that fails, so it is
		// kept even though the file is reported as not analyzed.
		if !keptBad {
			t.Errorf("expected the finding recorded before the error in %s to be kept", badPath)
		}

		if len(results.UnanalyzedFiles) != 1 {
			t.Fatalf("expected one unanalyzed file, got %+v", results.UnanalyzedFiles)
		}
		u := results.UnanalyzedFiles[0]
		if u.File != badPath {
			t.Errorf("unanalyzed file = %q, want %q", u.File, badPath)
		}
		if u.Line != 2 {
			t.Errorf("unanalyzed line = %d, want 2", u.Line)
		}
		if !strings.Contains(u.Reason, "simulated analyzer failure") {
			t.Errorf("reason %q does not carry the error", u.Reason)
		}
	})

	t.Run("single file target", func(t *testing.T) {
		dir := t.TempDir()
		badPath := writeTestFile(t, dir, "bad.go", content)

		results := scanWithConfig(t, Config{Target: badPath, OnFinding: panicOn("bad.go")})

		if len(results.UnanalyzedFiles) != 1 || results.UnanalyzedFiles[0].File != badPath {
			t.Errorf("expected %s to be reported as unanalyzed, got %+v", badPath, results.UnanalyzedFiles)
		}
	})
}
