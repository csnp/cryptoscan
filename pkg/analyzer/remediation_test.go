// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

// runVerify runs a printed Verify command from dir and returns its output.
func runVerify(t *testing.T, dir, command string) string {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no POSIX shell on this system")
	}
	cmd := exec.Command("sh", "-c", command)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%q failed: %v\n%s", command, err, out)
	}
	return strings.TrimRight(string(out), "\n")
}

// Each Verify command runs as printed and prints the matched line, including
// for paths a shell would otherwise split, expand or read as an option.
func TestVerifyCommandPrintsTheMatchedLine(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"plain.go", "with space.go", "it's.go", "-dash.go", "$HOME.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("first\nmatched line\nlast\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		f := &types.Finding{File: name, Line: 2}
		command := VerifyCommand(f)
		if !strings.HasPrefix(command, "sed -n '2p' ") {
			t.Errorf("%s: Verify = %q, want a sed command for line 2", name, command)
		}
		if got := runVerify(t, dir, command); got != "matched line" {
			t.Errorf("%s: %q printed %q, want %q", name, command, got, "matched line")
		}
	}

	if got := VerifyCommand(&types.Finding{File: "src/a.java", Line: 96}); got != "sed -n '96p' src/a.java" {
		t.Errorf("Verify = %q, want the path unquoted when it needs no quoting", got)
	}
}

// Dependency findings carry line 1 whatever the manifest says, so their
// Verify command searches for the package instead of printing line 1.
func TestVerifyCommandForDependencyFindsThePackage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==3.0\ncryptography==41.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &types.Finding{FindingType: types.FindingTypeDependency, File: "requirements.txt", Line: 1, Match: "cryptography"}
	command := VerifyCommand(f)
	if got := runVerify(t, dir, command); got != "2:cryptography==41.0" {
		t.Errorf("%q printed %q, want the manifest line that names the package", command, got)
	}
}

func TestApplySetsFixFromLanguageTextOrRemediation(t *testing.T) {
	engine := NewRemediationEngine()
	tests := []struct {
		name string
		f    types.Finding
		want string
	}{
		{"MD5 in Python", types.Finding{Algorithm: "MD5", File: "app.py", Line: 3, Quantum: types.QuantumVulnerable, Remediation: "Replace with SHA-256."},
			"Replace hashlib.md5() with hashlib.sha256()"},
		{"SHA-1 in JavaScript", types.Finding{Algorithm: "SHA-1", File: "app.js", Line: 3, Quantum: types.QuantumVulnerable, Remediation: "Replace with SHA-256."},
			"Replace crypto.createHash('sha1') with crypto.createHash('sha256')"},
		{"DES in Go", types.Finding{Algorithm: "DES", File: "main.go", Line: 3, Quantum: types.QuantumVulnerable, Remediation: "Replace with AES-256-GCM."},
			"Replace des.NewCipher(key) with aes.NewCipher(key) on a 32-byte key, wrapped in cipher.NewGCM"},
		{"3DES in Java", types.Finding{Algorithm: "3DES", File: "A.java", Line: 3, Quantum: types.QuantumVulnerable, Remediation: "Replace with AES-256-GCM."},
			`Replace the "DESede" transformation in Cipher.getInstance with "AES/GCM/NoPadding" and a 32-byte key`},
		{"DH in Go", types.Finding{Algorithm: "DH", File: "main.go", Line: 3, Quantum: types.QuantumVulnerable, Remediation: "Migrate to ML-KEM."},
			"Migrate DH key exchange to ML-KEM-768 using cloudflare/circl"},
		{"ECC in Python", types.Finding{Algorithm: "ECC", File: "app.py", Line: 3, Quantum: types.QuantumVulnerable, Remediation: "Migrate to ML-DSA or ML-KEM."},
			"Migrate ECC to ML-KEM-768 for encryption and key exchange, or to ML-DSA-65 for signatures, using liboqs-python"},
		{"MD5 in Ruby has no language text", types.Finding{Algorithm: "MD5", File: "app.rb", Line: 3, Quantum: types.QuantumVulnerable, Remediation: "Replace with SHA-256."},
			"Replace with SHA-256."},
		{"dependency keeps the library remediation", types.Finding{FindingType: types.FindingTypeDependency, Algorithm: "RSA, ECDSA", File: "requirements.txt", Line: 1, Match: "cryptography", Quantum: types.QuantumVulnerable, Remediation: "Upgrade to a release with ML-KEM support."},
			"Upgrade to a release with ML-KEM support."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.f
			engine.Apply(&f)
			if f.Fix != tt.want {
				t.Errorf("Fix = %q, want %q", f.Fix, tt.want)
			}
			if f.Verify == "" {
				t.Error("Verify is empty")
			}
		})
	}
}

func TestEstimateEffort(t *testing.T) {
	engine := NewRemediationEngine()
	tests := []struct {
		f    types.Finding
		want string
	}{
		{types.Finding{Algorithm: "MD5", Quantum: types.QuantumVulnerable}, "Low"},
		{types.Finding{Algorithm: "DES", Quantum: types.QuantumVulnerable}, "Medium"},
		{types.Finding{Algorithm: "Blowfish", Quantum: types.QuantumPartial}, "Medium"},
		{types.Finding{Algorithm: "RSA", Quantum: types.QuantumVulnerable}, "Medium to High"},
		{types.Finding{Algorithm: "ECC", Quantum: types.QuantumVulnerable}, "Medium to High"},
		{types.Finding{Algorithm: "AES-GCM", Quantum: types.QuantumPartial}, ""},
		{types.Finding{Algorithm: "ML-DSA", Quantum: types.QuantumSafe}, ""},
	}
	for _, tt := range tests {
		if got := engine.EstimateEffort(&tt.f); got != tt.want {
			t.Errorf("EstimateEffort(%s) = %q, want %q", tt.f.Algorithm, got, tt.want)
		}
	}
}
