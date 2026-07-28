// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/types"
)

// cycloneDXPrimitiveEnum is the closed enum CycloneDX 1.6 allows for
// cryptoProperties.algorithmProperties.primitive.
var cycloneDXPrimitiveEnum = map[string]bool{
	"drbg": true, "mac": true, "block-cipher": true, "stream-cipher": true,
	"signature": true, "hash": true, "pke": true, "xof": true, "kdf": true,
	"key-agree": true, "kem": true, "ae": true, "combiner": true,
	"other": true, "unknown": true,
}

// cycloneDXAssetTypeEnum is the closed enum for cryptoProperties.assetType.
var cycloneDXAssetTypeEnum = map[string]bool{
	"algorithm": true, "certificate": true, "protocol": true,
	"related-crypto-material": true,
}

// cycloneDXRelatedCryptoMaterialTypes is the closed enum for
// relatedCryptoMaterialProperties.type.
var cycloneDXRelatedCryptoMaterialTypes = map[string]bool{
	"private-key": true, "public-key": true, "secret-key": true, "key": true,
	"ciphertext": true, "signature": true, "digest": true, "initialization-vector": true,
	"nonce": true, "seed": true, "salt": true, "shared-secret": true,
	"tag": true, "additional-data": true, "password": true, "credential": true,
	"token": true, "other": true, "unknown": true,
}

var cbomSerialPattern = regexp.MustCompile(
	`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type parsedCBOM struct {
	SerialNumber string `json:"serialNumber"`
	SpecVersion  string `json:"specVersion"`
	Components   []struct {
		Name             string `json:"name"`
		CryptoProperties *struct {
			AssetType           string `json:"assetType"`
			AlgorithmProperties *struct {
				Primitive string `json:"primitive"`
			} `json:"algorithmProperties"`
			RelatedCryptoMaterialProperties *struct {
				Type string `json:"type"`
			} `json:"relatedCryptoMaterialProperties"`
		} `json:"cryptoProperties"`
		Evidence *struct {
			Occurrences []struct {
				Location string `json:"location"`
			} `json:"occurrences"`
		} `json:"evidence"`
	} `json:"components"`
}

func generateCBOM(t *testing.T, results *scanner.Results) parsedCBOM {
	t.Helper()

	out, err := NewCBOMReporter().Generate(results)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var doc parsedCBOM
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("CBOM is not valid JSON: %v", err)
	}
	return doc
}

func resultsWith(scanTarget string, findings ...scanner.Finding) *scanner.Results {
	return &scanner.Results{
		Findings:   findings,
		ScanTarget: scanTarget,
		ScanTime:   time.Now(),
	}
}

// TestSerialNumberIsAUUID is the regression guard for the first half of issue
// #1. The serial number was built from a timestamp
// (time.Now().Format("20060102-150405-000000000")), which is not a UUID and
// fails the CycloneDX serialNumber pattern, so every emitted document was
// invalid on that field alone.
func TestSerialNumberIsAUUID(t *testing.T) {
	first := generateCBOM(t, resultsWith("/tmp/project", scanner.Finding{
		ID: "RSA-001", Algorithm: "RSA", Category: "asymmetric",
		File: "/tmp/project/main.go", Line: 10, Match: "rsa.GenerateKey",
	}))
	second := generateCBOM(t, resultsWith("/tmp/project", scanner.Finding{
		ID: "RSA-001", Algorithm: "RSA", Category: "asymmetric",
		File: "/tmp/project/main.go", Line: 10, Match: "rsa.GenerateKey",
	}))

	if !cbomSerialPattern.MatchString(first.SerialNumber) {
		t.Errorf("serialNumber %q does not match the CycloneDX urn:uuid pattern",
			first.SerialNumber)
	}
	if first.SerialNumber == second.SerialNumber {
		t.Error("two separate CBOMs share a serial number")
	}
}

// TestPrimitivesAreInCycloneDXEnum guards the second half of issue #1. The
// mapper emitted "hybrid" for hybrid constructions and "key-agreement" for key
// agreement, neither of which is in the spec enum, and a single non-member
// value fails validation for the whole document.
func TestPrimitivesAreInCycloneDXEnum(t *testing.T) {
	algorithms := []string{
		"RSA", "ECDSA", "DSA", "Ed25519", "DH", "ECDH", "X25519",
		"AES", "DES", "3DES", "Blowfish", "RC4", "ChaCha20",
		"SHA-256", "MD5", "HMAC-SHA256", "PBKDF2",
		"ML-KEM-768", "ML-DSA-65", "SLH-DSA", "Kyber", "Dilithium", "Falcon",
		"X25519MLKEM768", "Hybrid-RSA-ML-DSA", "Composite-ECDSA",
		"SomethingUnrecognized",
	}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			got := algorithmToPrimitive(algo)
			if !cycloneDXPrimitiveEnum[got] {
				t.Errorf("algorithmToPrimitive(%q) = %q, which is not in the CycloneDX enum",
					algo, got)
			}
		})
	}

	// Spot-check that hybrids and key agreement map to the right members
	// rather than merely to something valid.
	if got := algorithmToPrimitive("Hybrid-X25519-ML-KEM-768"); got != "combiner" {
		t.Errorf("hybrid construction mapped to %q, want combiner", got)
	}
	if got := algorithmToPrimitive("ECDH"); got != "key-agree" {
		t.Errorf("ECDH mapped to %q, want key-agree", got)
	}
}

// TestAssetTypesAreInCycloneDXEnum checks the asset type mapping, which was
// matching lowercase names no pattern actually uses.
func TestAssetTypesAreInCycloneDXEnum(t *testing.T) {
	categories := []string{
		"Secret Detection", "Certificate", "asymmetric", "symmetric", "hash",
		"TLS", "Protocol", "library", "Key Material", "Anything Else", "",
	}

	for _, category := range categories {
		got := categoryToAssetType(category)
		if !cycloneDXAssetTypeEnum[got] {
			t.Errorf("categoryToAssetType(%q) = %q, which is not a CycloneDX asset type",
				category, got)
		}
	}

	// The categories the patterns actually use must map meaningfully rather
	// than falling through to the default.
	if got := categoryToAssetType("Secret Detection"); got != "related-crypto-material" {
		t.Errorf("Secret Detection mapped to %q, want related-crypto-material", got)
	}
	if got := categoryToAssetType("Certificate"); got != "certificate" {
		t.Errorf("Certificate mapped to %q, want certificate", got)
	}
}

// TestKeyMaterialIsRelatedCryptoMaterial covers the reporter's first point,
// incomplete key material representation. A detected private key was emitted as
// assetType "algorithm" named after the PEM header, losing the fact that it was
// key material at all.
func TestKeyMaterialIsRelatedCryptoMaterial(t *testing.T) {
	doc := generateCBOM(t, resultsWith("/tmp/project", scanner.Finding{
		ID:       "KEY-001",
		Type:     "Private Key Header",
		Category: "Secret Detection",
		File:     "/tmp/project/id_rsa.pem",
		Line:     1,
		Match:    "-----BEGIN RSA PRIVATE KEY-----",
		Severity: types.SeverityCritical,
	}))

	if len(doc.Components) == 0 {
		t.Fatal("no components emitted for a detected private key")
	}

	var found bool
	for _, c := range doc.Components {
		cp := c.CryptoProperties
		if cp == nil || cp.AssetType != "related-crypto-material" {
			continue
		}
		found = true
		if cp.RelatedCryptoMaterialProperties == nil {
			t.Errorf("component %q is related-crypto-material but carries no properties", c.Name)
			continue
		}
		materialType := cp.RelatedCryptoMaterialProperties.Type
		if !cycloneDXRelatedCryptoMaterialTypes[materialType] {
			t.Errorf("material type %q is not in the CycloneDX enum", materialType)
		}
		if materialType != "private-key" {
			t.Errorf("detected private key classified as %q, want private-key", materialType)
		}
	}

	if !found {
		t.Error("a detected private key was not emitted as related-crypto-material")
	}
}

// TestEvidenceLocationsAreRelative checks that CBOMs do not embed the scanning
// machine's absolute directory layout, which leaks the operator's username and
// makes identical scans differ between machines.
func TestEvidenceLocationsAreRelative(t *testing.T) {
	doc := generateCBOM(t, resultsWith("/tmp/project", scanner.Finding{
		ID: "RSA-001", Algorithm: "RSA", Category: "asymmetric",
		File: "/tmp/project/internal/crypto/keys.go", Line: 42, Match: "rsa.GenerateKey",
	}))

	var checked bool
	for _, c := range doc.Components {
		if c.Evidence == nil {
			continue
		}
		for _, occ := range c.Evidence.Occurrences {
			checked = true
			if strings.HasPrefix(occ.Location, "/") {
				t.Errorf("evidence location %q is an absolute path", occ.Location)
			}
			if occ.Location != "internal/crypto/keys.go" {
				t.Errorf("evidence location = %q, want internal/crypto/keys.go", occ.Location)
			}
		}
	}
	if !checked {
		t.Error("no evidence occurrences were emitted")
	}
}

// TestRelativeLocationFallsBackSafely checks that a file outside the scan root
// keeps its original path rather than producing a confusing ../.. chain.
func TestRelativeLocationFallsBackSafely(t *testing.T) {
	got := relativeLocation("/tmp/project", "/etc/passwd")
	if strings.HasPrefix(got, "..") {
		t.Errorf("relativeLocation returned a parent-traversing path %q", got)
	}
	if got != "/etc/passwd" {
		t.Errorf("relativeLocation = %q, want the original path as fallback", got)
	}

	if got := relativeLocation("", "/tmp/x.go"); got != "/tmp/x.go" {
		t.Errorf("empty scan target should pass the path through, got %q", got)
	}
}
