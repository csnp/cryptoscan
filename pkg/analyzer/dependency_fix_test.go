// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

// applyToDependency runs the remediation engine over the finding the scanner
// builds from dep, and returns its Fix and Guidance.
func applyToDependency(dep DependencyFinding) (fix, guidance string) {
	f := types.Finding{
		FindingType: types.FindingTypeDependency, File: dep.File, Line: 1, Match: dep.Library.Package,
		Severity: dep.Severity, Quantum: dep.Quantum, Remediation: dep.Remediation,
	}
	NewRemediationEngine().Apply(&f)
	return f.Fix, f.Guidance
}

// Eleven libraries without post-quantum algorithms printed "Fix: Plan
// migration to a PQC-capable library or enable hybrid mode when available.",
// which names no change to make. Every such library now has a fix that names
// it and the replacement for what it provides.
func TestDependencyFixNamesAReplacementForEveryLibraryWithoutPQC(t *testing.T) {
	for _, lib := range KnownCryptoLibraries {
		if lib.QuantumSafe {
			continue
		}
		t.Run(lib.Name, func(t *testing.T) {
			fix, guidance := applyToDependency(createDependencyFinding(lib, "1.0.0", "manifest"))
			if fix == "" || guidance != "" {
				t.Fatalf("Fix = %q, Guidance = %q; want a fix and no guidance", fix, guidance)
			}
			for _, vague := range []string{"Plan migration", "when available", "Consider"} {
				if strings.Contains(fix, vague) {
					t.Errorf("Fix %q says %q, which names no change", fix, vague)
				}
			}
			if !strings.Contains(fix, lib.Package) && !strings.Contains(fix, lib.Name) {
				t.Errorf("Fix %q names neither the package %q nor the library %q", fix, lib.Package, lib.Name)
			}
			named := strings.HasPrefix(fix, "Replace ")
			for _, replacement := range []string{"ML-KEM-768", "ML-DSA-65", "256-bit"} {
				named = named || strings.Contains(fix, replacement)
			}
			if !named {
				t.Errorf("Fix %q names no replacement", fix)
			}
		})
	}
}

// The libraries from the report's ecosystems, read from real manifests: each
// fix names the algorithms to move, their replacements and the library to add.
func TestDependencyFindingsNameTheirReplacement(t *testing.T) {
	dir := t.TempDir()
	manifests := map[string]string{
		"package.json":     `{"dependencies": {"node-forge": "^1.3.1", "tweetnacl": "^1.0.3", "jose": "^5.9.0"}}`,
		"requirements.txt": "pycryptodome==3.20.0\npynacl==1.5.0\ncryptography==43.0.0\n",
	}
	want := map[string]string{
		"node-forge":   "Add liboqs-node and move RSA from node-forge to ML-KEM-768 for encryption and key exchange and ML-DSA-65 for signatures",
		"tweetnacl":    "Add liboqs-node and move X25519 key exchange from tweetnacl to ML-KEM-768 and Ed25519 signatures to ML-DSA-65",
		"jose":         "Add liboqs-node and move RSA, ECDSA and EdDSA signatures made with jose to ML-DSA-65, and RSA key encryption to ML-KEM-768",
		"pycryptodome": "Add liboqs-python and move RSA and ECC from pycryptodome to ML-KEM-768 for key exchange and ML-DSA-65 for signatures",
		"pynacl":       "Add liboqs-python and move X25519 key exchange from pynacl to ML-KEM-768 and Ed25519 signatures to ML-DSA-65",
		"cryptography": "Add liboqs-python alongside cryptography and move RSA and ECC to ML-KEM-768 for key exchange and ML-DSA-65 for signatures",
	}
	got := map[string]string{}
	for name, content := range manifests {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		deps, err := ScanDependencies(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, dep := range deps {
			fix, guidance := applyToDependency(dep)
			if guidance != "" {
				t.Errorf("%s: Guidance = %q, want none", dep.Library.Package, guidance)
			}
			got[dep.Library.Package] = fix
		}
	}
	for pkg, wantFix := range want {
		if got[pkg] != wantFix {
			t.Errorf("%s: Fix = %q\nwant %q", pkg, got[pkg], wantFix)
		}
	}
	if len(got) != len(want) {
		t.Errorf("findings for %d packages, want %d: %v", len(got), len(want), got)
	}
}
