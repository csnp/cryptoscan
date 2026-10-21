// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// cbomOf generates the CBOM for results and reads it back into the
// reporter's own types.
func cbomOf(t *testing.T, results *scanner.Results) cbomReport {
	t.Helper()
	out, err := NewCBOMReporter().Generate(results)
	if err != nil {
		t.Fatalf("generate CBOM: %v", err)
	}
	var bom cbomReport
	if err := json.Unmarshal([]byte(out), &bom); err != nil {
		t.Fatalf("CBOM is not valid JSON: %v", err)
	}
	return bom
}

// componentsNamed returns the components called name.
func componentsNamed(bom cbomReport, name string) []cbomComponent {
	var out []cbomComponent
	for _, c := range bom.Components {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

// AES-GCM and ChaCha20-Poly1305 are authenticated encryption, which CycloneDX
// calls "ae". ChaCha20-Poly1305 was written as a MAC, after the Poly1305 in its
// name, and AES-GCM as "other". Poly1305 on its own is still a MAC.
func TestCBOMWritesAuthenticatedEncryptionAsAE(t *testing.T) {
	for algo, want := range map[string]string{
		"AES-GCM":           "ae",
		"AES-256-GCM":       "ae",
		"AES-CCM":           "ae",
		"ChaCha20-Poly1305": "ae",
		"Poly1305":          "mac",
		"ChaCha20":          "stream-cipher",
		"AES":               "block-cipher",
	} {
		if got := algorithmToPrimitive(algo); got != want {
			t.Errorf("algorithmToPrimitive(%q) = %q, want %q", algo, got, want)
		}
	}

	bom := cbomOf(t, scanCryptoSamples(t))
	for _, name := range []string{"AES-GCM", "ChaCha20-Poly1305"} {
		comps := componentsNamed(bom, name)
		if len(comps) == 0 {
			t.Fatalf("the CBOM of crypto-samples has no %s component", name)
		}
		for _, c := range comps {
			p := c.CryptoProperties.AlgorithmProperties
			if p == nil || p.Primitive != "ae" {
				t.Errorf("%s is written with algorithm properties %+v, want primitive ae", name, p)
			}
		}
	}
}

// A TLS finding is a protocol asset with protocol properties, not an
// algorithm with primitive "other".
func TestCBOMWritesTLSAsAProtocol(t *testing.T) {
	for _, category := range []string{"TLS/SSL", "Deprecated Protocol"} {
		if got := categoryToAssetType(category); got != "protocol" {
			t.Errorf("categoryToAssetType(%q) = %q, want protocol", category, got)
		}
	}

	bom := cbomOf(t, scanCryptoSamples(t))
	comps := componentsNamed(bom, "TLS")
	if len(comps) == 0 {
		t.Fatal("the CBOM of crypto-samples has no TLS component")
	}
	for _, c := range comps {
		cp := c.CryptoProperties
		if cp.AssetType != "protocol" {
			t.Errorf("TLS is written with assetType %q, want protocol", cp.AssetType)
		}
		if cp.AlgorithmProperties != nil {
			t.Errorf("TLS carries algorithm properties %+v", cp.AlgorithmProperties)
		}
		if cp.ProtocolProperties == nil || cp.ProtocolProperties.Type != "tls" || cp.ProtocolProperties.Version != "1.3" {
			t.Errorf("TLS is written with protocol properties %+v, want type tls and version 1.3 (the samples name TLSv1.3)", cp.ProtocolProperties)
		}
	}
}

// TLS 1.2 and TLS 1.3 are separate components, each with its own version, and
// a version written with "_" is read.
func TestCBOMKeepsOneProtocolComponentPerVersion(t *testing.T) {
	for match, want := range map[string]string{
		"TLSv1.3": "1.3",
		"TLSv1_2": "1.2",
		"TLS_1_3": "1.3",
		"TLS-1.2": "1.2",
		"TLS13":   "1.3",
		"TLS":     "",
	} {
		if got := extractTLSVersion(match); got != want {
			t.Errorf("extractTLSVersion(%q) = %q, want %q", match, got, want)
		}
	}

	bom := cbomOf(t, resultsWith("/tmp/project",
		scanner.Finding{ID: "TLS-002", Algorithm: "TLS", Category: "TLS/SSL", File: "/tmp/project/a.py", Line: 1, Match: "TLSv1_2"},
		scanner.Finding{ID: "TLS-002", Algorithm: "TLS", Category: "TLS/SSL", File: "/tmp/project/b.py", Line: 2, Match: "TLSv1.3"},
		scanner.Finding{ID: "TLS-002", Algorithm: "TLS", Category: "TLS/SSL", File: "/tmp/project/c.py", Line: 3, Match: "TLS_1_3"},
	))
	versions := map[string]int{}
	for _, c := range componentsNamed(bom, "TLS") {
		versions[c.CryptoProperties.ProtocolProperties.Version] = len(c.Evidence.Occurrences)
	}
	if len(versions) != 2 || versions["1.2"] != 1 || versions["1.3"] != 2 {
		t.Errorf("TLS components by version and occurrence count: %v, want map[1.2:1 1.3:2]", versions)
	}
}

// A hard-coded key size and a post-quantum library import are not
// cryptographic assets, so they are not written as algorithm components with
// no properties. A finding that names an algorithm is always written.
func TestCBOMLeavesOutFindingsThatAreNotAssets(t *testing.T) {
	results := scanCryptoSamples(t)
	present := map[string]bool{}
	for _, f := range results.Findings {
		present[f.Type] = true
	}
	notAssets := []string{"Hardcoded Key Size", "Post-Quantum Crypto Library"}
	for _, name := range notAssets {
		if !present[name] {
			t.Fatalf("the scan of crypto-samples no longer finds %q, so this test checks nothing for it", name)
		}
	}

	bom := cbomOf(t, results)
	for _, name := range notAssets {
		if comps := componentsNamed(bom, name); len(comps) > 0 {
			t.Errorf("the CBOM writes %d component(s) named %q", len(comps), name)
		}
	}

	if !isCryptoAsset(scanner.Finding{Category: "Configuration", Algorithm: "RSA"}) {
		t.Error("a Configuration finding that names an algorithm is left out of the CBOM")
	}
	for _, category := range []string{"Configuration", "Library Import", "PQC Library Import"} {
		if isCryptoAsset(scanner.Finding{Category: category}) {
			t.Errorf("a %s finding that names no algorithm is written to the CBOM", category)
		}
	}
	for _, category := range []string{"Weak Cipher", "Secret Detection", "Certificate", "dependency"} {
		if !isCryptoAsset(scanner.Finding{Category: category}) {
			t.Errorf("a %s finding is left out of the CBOM", category)
		}
	}
}

// Each RSA key size is a component of its own with the security level of that
// size. One RSA component took the level of whichever finding came first, so
// a 1024-bit key gave every RSA occurrence a classical level of 80.
func TestCBOMKeepsOneComponentPerKeySize(t *testing.T) {
	rsa := func(line, size int) scanner.Finding {
		return scanner.Finding{
			ID: "RSA-001", Algorithm: "RSA", KeySize: size, Category: "Asymmetric Encryption",
			File: "/tmp/project/keys.go", Line: line, Match: "rsa.GenerateKey",
		}
	}
	bom := cbomOf(t, resultsWith("/tmp/project", rsa(1, 1024), rsa(2, 0), rsa(3, 2048), rsa(4, 1024), rsa(5, 0)))

	want := map[string]struct{ level, occurrences int }{
		"RSA-1024": {80, 2},
		"RSA-2048": {112, 1},
		"RSA":      {0, 2},
	}
	if len(bom.Components) != len(want) {
		t.Errorf("%d components, want %d", len(bom.Components), len(want))
	}
	for name, w := range want {
		comps := componentsNamed(bom, name)
		if len(comps) != 1 {
			t.Errorf("%d components named %s, want 1", len(comps), name)
			continue
		}
		c := comps[0]
		if got := c.CryptoProperties.AlgorithmProperties.ClassicalSecurityLevel; got != w.level {
			t.Errorf("%s classicalSecurityLevel = %d, want %d", name, got, w.level)
		}
		if got := len(c.Evidence.Occurrences); got != w.occurrences {
			t.Errorf("%s has %d occurrences, want %d", name, got, w.occurrences)
		}
		if got := c.CryptoProperties.OID; got != "1.2.840.113549.1.1.1" {
			t.Errorf("%s oid = %q, want the RSA OID", name, got)
		}
	}
}
