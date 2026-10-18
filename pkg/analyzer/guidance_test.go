// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

// A finding that needs no change carries its remediation sentence as
// Guidance, and every other finding carries it, or the language-specific
// replacement, as Fix. Exactly one of the two is set.
func TestApplySetsGuidanceWhenNoChangeIsNeeded(t *testing.T) {
	engine := NewRemediationEngine()
	tests := []struct {
		name         string
		f            types.Finding
		wantFix      string
		wantGuidance string
	}{
		{"ML-KEM is advice",
			types.Finding{Algorithm: "ML-KEM", File: "kem.py", Line: 3, Severity: types.SeverityInfo, Quantum: types.QuantumSafe,
				Remediation: "ML-KEM is NIST-approved and quantum-safe. Recommended for key exchange."},
			"", "ML-KEM is NIST-approved and quantum-safe. Recommended for key exchange."},
		{"AES-256-GCM is advice",
			types.Finding{Algorithm: "AES-256-GCM", File: "box.go", Line: 3, Severity: types.SeverityInfo, Quantum: types.QuantumPartial,
				Remediation: "AES-256-GCM is recommended. Provides confidentiality and integrity."},
			"", "AES-256-GCM is recommended. Provides confidentiality and integrity."},
		{"a PQC library dependency is advice",
			types.Finding{FindingType: types.FindingTypeDependency, Algorithm: "ML-KEM, ML-DSA, SLH-DSA", File: "requirements.txt", Line: 1, Match: "liboqs-python",
				Severity: types.SeverityInfo, Quantum: types.QuantumSafe,
				Remediation: "This library supports post-quantum algorithms. Ensure you're using the PQC options."},
			"", "This library supports post-quantum algorithms. Ensure you're using the PQC options."},
		{"an informational quantum-vulnerable finding keeps a fix",
			types.Finding{File: "certs.go", Line: 3, Severity: types.SeverityInfo, Quantum: types.QuantumVulnerable,
				Remediation: "Current Let's Encrypt certificates use RSA/ECDSA. Monitor for PQC certificate support."},
			"Current Let's Encrypt certificates use RSA/ECDSA. Monitor for PQC certificate support.", ""},
		{"a finding above INFO keeps a fix",
			types.Finding{Algorithm: "PBKDF2", File: "kdf.py", Line: 3, Severity: types.SeverityHigh, Quantum: types.QuantumPartial,
				Remediation: "Use Argon2id, scrypt, or PBKDF2-SHA256 with >= 600,000 iterations."},
			"Use Argon2id, scrypt, or PBKDF2-SHA256 with >= 600,000 iterations.", ""},
		{"a language-specific replacement is always a fix",
			types.Finding{Algorithm: "MD5", File: "app.py", Line: 3, Severity: types.SeverityInfo, Quantum: types.QuantumPartial,
				Remediation: "Replace with SHA-256."},
			"Replace hashlib.md5() with hashlib.sha256()", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.f
			// A finding passed through Apply a second time must not keep the
			// field it no longer uses.
			f.Fix, f.Guidance = "stale", "stale"
			engine.Apply(&f)
			if f.Fix != tt.wantFix || f.Guidance != tt.wantGuidance {
				t.Errorf("Fix = %q, Guidance = %q; want Fix %q, Guidance %q", f.Fix, f.Guidance, tt.wantFix, tt.wantGuidance)
			}
		})
	}
}

// The crypto-js entry said "Consider using Web Crypto API or node:crypto for
// better security", which names no change to make. It now names the
// replacement and the manifest it comes out of.
func TestCryptoJSDependencyNamesItsReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(`{"dependencies": {"crypto-js": "^4.2.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := ScanDependencies(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Library.Package != "crypto-js" {
		t.Fatalf("expected one crypto-js dependency finding, got %+v", deps)
	}

	const want = "Replace crypto-js with node:crypto in Node.js or the Web Crypto API (crypto.subtle) in the browser, then remove crypto-js from package.json"
	f := types.Finding{
		FindingType: types.FindingTypeDependency, File: path, Line: 1, Match: "crypto-js",
		Severity: deps[0].Severity, Quantum: deps[0].Quantum, Remediation: deps[0].Remediation,
	}
	NewRemediationEngine().Apply(&f)
	if f.Fix != want || f.Guidance != "" {
		t.Errorf("crypto-js Fix = %q, Guidance = %q; want Fix %q", f.Fix, f.Guidance, want)
	}
}
