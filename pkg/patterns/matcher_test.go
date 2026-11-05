// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns

import (
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/types"
)

func TestNewMatcher(t *testing.T) {
	m := NewMatcher()
	if m == nil {
		t.Fatal("NewMatcher returned nil")
	}
	if len(m.patterns) == 0 {
		t.Error("Matcher has no patterns")
	}
}

// The pattern catalogue reads Patterns, so it has to return the patterns
// Match runs, in the same order, without letting a caller change them.
func TestPatternsReturnsACopyOfWhatMatchRuns(t *testing.T) {
	m := NewMatcher()
	got := m.Patterns()
	if len(got) != len(m.patterns) {
		t.Fatalf("Patterns() returned %d patterns, the matcher runs %d", len(got), len(m.patterns))
	}
	for i := range got {
		if got[i].ID != m.patterns[i].ID {
			t.Errorf("Patterns()[%d].ID = %q, the matcher runs %q at that position", i, got[i].ID, m.patterns[i].ID)
		}
	}

	first := m.patterns[0].ID
	got[0] = Pattern{ID: "CHANGED-BY-CALLER"}
	if m.patterns[0].ID != first {
		t.Errorf("changing the slice Patterns() returned changed the matcher's first pattern to %q", m.patterns[0].ID)
	}
}

func TestMatchRSA(t *testing.T) {
	m := NewMatcher()
	tests := []struct {
		name     string
		content  string
		wantHits bool
	}{
		{"RSA 1024", "rsa := NewRSAKey(1024)", true},
		{"RSA 2048", "key = RSA.generate(2048)", true},
		{"No RSA", "aes.NewCipher(key)", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, "test.go", 1)
			hasRSA := false
			for _, match := range matches {
				if strings.Contains(match.Type, "RSA") {
					hasRSA = true
					break
				}
			}
			if hasRSA != tt.wantHits {
				t.Errorf("Match() RSA = %v, want %v", hasRSA, tt.wantHits)
			}
		})
	}
}

func TestMatchAES(t *testing.T) {
	m := NewMatcher()
	tests := []struct {
		name     string
		content  string
		wantHits bool
	}{
		{"AES cipher", "cipher = AES.new(key, AES.MODE_CBC)", true},
		{"AES ECB mode", "cipher = AES.new(key, AES.MODE_ECB)", true},
		{"No AES", "sha256.Sum256(data)", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, "test.go", 1)
			hasAES := false
			for _, match := range matches {
				if strings.Contains(match.Type, "AES") {
					hasAES = true
					break
				}
			}
			if hasAES != tt.wantHits {
				t.Errorf("Match() AES = %v, want %v", hasAES, tt.wantHits)
			}
		})
	}
}

func TestMatchPrivateKeys(t *testing.T) {
	m := NewMatcher()
	tests := []struct {
		name        string
		content     string
		expectMatch bool
	}{
		{
			name:        "RSA Private Key",
			content:     "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...",
			expectMatch: true,
		},
		{
			name:        "EC Private Key",
			content:     "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...",
			expectMatch: true,
		},
		{
			name:        "OpenSSH Private Key",
			content:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXkt...",
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, "key.pem", 1)
			if tt.expectMatch && len(matches) == 0 {
				t.Errorf("Expected to match %s", tt.name)
				return
			}
			if !tt.expectMatch && len(matches) > 0 {
				t.Errorf("Did not expect match for %s", tt.name)
				return
			}
			// Verify private keys are high severity or above
			if tt.expectMatch && len(matches) > 0 {
				if matches[0].Severity < types.SeverityHigh {
					t.Errorf("Severity = %v, want HIGH or CRITICAL", matches[0].Severity)
				}
			}
		})
	}
}

func TestMatchQuantumVulnerable(t *testing.T) {
	m := NewMatcher()
	tests := []struct {
		name        string
		content     string
		wantQuantum types.QuantumRisk
	}{
		{"RSA", "RSA.generate(2048)", types.QuantumVulnerable},
		{"ECC", "ECDSA.generate(curve='P-256')", types.QuantumVulnerable},
		{"AES", "AES.new(key, mode)", types.QuantumPartial},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, "crypto.go", 1)
			if len(matches) == 0 {
				t.Fatalf("Expected a match for %q, got none", tt.content)
			}
			if matches[0].Quantum != tt.wantQuantum {
				t.Errorf("Quantum = %v, want %v", matches[0].Quantum, tt.wantQuantum)
			}
		})
	}
}

func TestMatchHashFunctions(t *testing.T) {
	m := NewMatcher()
	tests := []struct {
		name       string
		content    string
		matchName  string
		wantExists bool
	}{
		{"MD5", "digest = MD5.new()", "MD5", true},
		{"SHA1", "hash = SHA1.new()", "SHA-1", true},
		{"SHA256", "h = hashlib.sha256()", "SHA", true},
		{"SHA512", "SHA512.digest(data)", "SHA", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, "hash.go", 1)
			found := false
			for _, match := range matches {
				if strings.Contains(match.Type, tt.matchName) {
					found = true
					break
				}
			}
			if found != tt.wantExists {
				t.Errorf("Match for %s = %v, want %v", tt.matchName, found, tt.wantExists)
			}
		})
	}
}

func TestMatchCryptoImports(t *testing.T) {
	m := NewMatcher()
	tests := []struct {
		name    string
		content string
		file    string
	}{
		{"Go crypto", `import "crypto/tls"`, "test.go"},
		{"Python cryptography", "from cryptography.fernet import Fernet", "test.py"},
		{"Java crypto", "import javax.crypto.Cipher;", "Test.java"},
		{"Node crypto", "const crypto = require('crypto');", "app.js"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, tt.file, 1)
			if len(matches) == 0 {
				t.Errorf("Expected to match crypto import for %s", tt.name)
			}
		})
	}
}

func TestPatternCount(t *testing.T) {
	m := NewMatcher()
	// We should have a substantial number of patterns
	minPatterns := 30
	if len(m.patterns) < minPatterns {
		t.Errorf("Expected at least %d patterns, got %d", minPatterns, len(m.patterns))
	}
}

func TestMatchDESPatterns(t *testing.T) {
	m := NewMatcher()
	tests := []struct {
		name    string
		content string
	}{
		{"DES algorithm", "cipher = DES.new(key, DES.MODE_CBC)"},
		{"Triple DES", "3DES.encrypt(data)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, "crypto.go", 1)
			hasDES := false
			for _, match := range matches {
				if strings.Contains(match.Type, "DES") {
					hasDES = true
					break
				}
			}
			if !hasDES {
				t.Errorf("Expected to match %s", tt.name)
			}
		})
	}
}

func TestMatchTLSPatterns(t *testing.T) {
	m := NewMatcher()
	tests := []struct {
		name    string
		content string
	}{
		{"TLS 1.0", "MinVersion: TLS_1_0"},
		{"TLS version", "TLS_VERSION = 1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, "config.go", 1)
			hasTLS := false
			for _, match := range matches {
				if strings.Contains(match.Type, "TLS") || strings.Contains(match.Type, "SSL") {
					hasTLS = true
					break
				}
			}
			if !hasTLS {
				t.Errorf("Expected to match TLS pattern for %s", tt.name)
			}
		})
	}
}

func TestMatchCloudKMSPatterns(t *testing.T) {
	m := NewMatcher()
	tests := []struct {
		name    string
		content string
	}{
		{"AWS KMS", "arn:aws:kms:us-east-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
		{"Azure Key Vault", "https://myvault.vault.azure.net/keys/mykey"},
		{"HashiCorp Vault", "vault:secret/data/myapp/config"},
		{"GCP KMS", "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, "config.yaml", 1)
			if len(matches) == 0 {
				t.Errorf("Expected to match %s pattern", tt.name)
			}
		})
	}
}

func TestMatchSecretPatterns(t *testing.T) {
	m := NewMatcher()
	tests := []struct {
		name    string
		content string
	}{
		{"JWT Secret", `JWT_SECRET = "mysupersecretkey123"`},
		{"HMAC Secret", `hmac_secret = "secretkey"`},
		{"Encryption Key", `encryption_key = "base64encodedkey=="`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, "config.py", 1)
			if len(matches) == 0 {
				t.Errorf("Expected to match %s pattern", tt.name)
			}
		})
	}
}

func TestMatchWithContext(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name          string
		line          string
		file          string
		fileCtx       *analyzer.FileContext
		lineCtx       *analyzer.LineContext
		expectMatch   bool
		expectLowConf bool
	}{
		{
			name:        "RSA in code file",
			line:        "key := rsa.GenerateKey(rand.Reader, 2048)",
			file:        "crypto.go",
			fileCtx:     &analyzer.FileContext{Language: analyzer.LangGo, FileType: analyzer.FileTypeCode},
			lineCtx:     &analyzer.LineContext{IsComment: false, Confidence: types.ConfidenceHigh},
			expectMatch: true,
		},
		{
			name:          "RSA in documentation",
			line:          "Example: rsa.GenerateKey(rand.Reader, 2048)",
			file:          "README.md",
			fileCtx:       &analyzer.FileContext{Language: analyzer.LangMarkdown, FileType: analyzer.FileTypeDocumentation},
			lineCtx:       &analyzer.LineContext{IsComment: false},
			expectMatch:   true,
			expectLowConf: true,
		},
		{
			name:        "RSA in test file",
			line:        "key := rsa.GenerateKey(rand.Reader, 2048)",
			file:        "crypto_test.go",
			fileCtx:     &analyzer.FileContext{Language: analyzer.LangGo, FileType: analyzer.FileTypeTest},
			lineCtx:     &analyzer.LineContext{IsComment: false},
			expectMatch: true,
		},
		{
			name:          "RSA in comment",
			line:          "// Use rsa.GenerateKey for RSA keys",
			file:          "crypto.go",
			fileCtx:       &analyzer.FileContext{Language: analyzer.LangGo, FileType: analyzer.FileTypeCode},
			lineCtx:       &analyzer.LineContext{IsComment: true},
			expectMatch:   true,
			expectLowConf: true,
		},
		{
			name:        "RSA in vendor file",
			line:        "key := rsa.GenerateKey(rand.Reader, 2048)",
			file:        "vendor/crypto/rsa.go",
			fileCtx:     &analyzer.FileContext{Language: analyzer.LangGo, FileType: analyzer.FileTypeCode, IsVendor: true},
			lineCtx:     &analyzer.LineContext{IsComment: false},
			expectMatch: true,
		},
		{
			name:        "RSA in generated file",
			line:        "key := rsa.GenerateKey(rand.Reader, 2048)",
			file:        "crypto.gen.go",
			fileCtx:     &analyzer.FileContext{Language: analyzer.LangGo, FileType: analyzer.FileTypeCode, IsGenerated: true},
			lineCtx:     &analyzer.LineContext{IsComment: false},
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := m.MatchWithContext(tt.line, tt.file, 1, tt.fileCtx, tt.lineCtx)
			hasMatch := len(findings) > 0
			if hasMatch != tt.expectMatch {
				t.Errorf("MatchWithContext() match = %v, want %v", hasMatch, tt.expectMatch)
			}
			if hasMatch && tt.expectLowConf {
				if findings[0].Confidence != types.ConfidenceLow {
					t.Errorf("Expected low confidence, got %v", findings[0].Confidence)
				}
			}
		})
	}
}

func TestMatchWithContextNilContexts(t *testing.T) {
	m := NewMatcher()
	findings := m.MatchWithContext("rsa.GenerateKey(rand.Reader, 2048)", "test.go", 1, nil, nil)
	if len(findings) == 0 {
		t.Error("Expected match with nil contexts")
	}
	// Should default to high confidence
	if findings[0].Confidence != types.ConfidenceHigh {
		t.Errorf("Expected high confidence default, got %v", findings[0].Confidence)
	}
}

func TestTruncateContext(t *testing.T) {
	m := NewMatcher()
	longLine := strings.Repeat("a", 200)
	findings := m.Match(longLine+" RSA.generate(2048)", "test.go", 1)
	if len(findings) > 0 {
		if len(findings[0].Context) > 123 { // 120 + "..."
			t.Errorf("Context not truncated properly, len = %d", len(findings[0].Context))
		}
	}
}

func TestMultipleMatchesPerLine(t *testing.T) {
	m := NewMatcher()
	// Line with multiple crypto patterns
	line := "RSA.generate(2048) and MD5.digest(data) and SHA1.hash(input)"
	findings := m.Match(line, "test.go", 1)
	if len(findings) < 2 {
		t.Errorf("Expected multiple matches, got %d", len(findings))
	}
}

func TestFindingFields(t *testing.T) {
	m := NewMatcher()
	findings := m.MatchWithContext(
		"key := rsa.GenerateKey(rand.Reader, 2048)",
		"crypto.go",
		42,
		&analyzer.FileContext{Language: analyzer.LangGo, FileType: analyzer.FileTypeCode},
		&analyzer.LineContext{Purpose: "encryption"},
	)

	if len(findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	f := findings[0]
	if f.Line != 42 {
		t.Errorf("Line = %d, want 42", f.Line)
	}
	if f.File != "crypto.go" {
		t.Errorf("File = %s, want crypto.go", f.File)
	}
	if f.Language != "go" {
		t.Errorf("Language = %s, want go", f.Language)
	}
	if f.Purpose != "encryption" {
		t.Errorf("Purpose = %s, want encryption", f.Purpose)
	}
	if f.Impact == "" {
		t.Error("Impact should not be empty")
	}
	if f.Effort == "" {
		t.Error("Effort should not be empty")
	}
}

func TestMatchCertificatePatterns(t *testing.T) {
	m := NewMatcher()
	tests := []struct {
		name       string
		content    string
		expectID   string
		shouldFind bool
	}{
		// X.509 Certificate
		{"X.509 Certificate PEM", "-----BEGIN CERTIFICATE-----", "CERT-001", true},
		{"X.509 Certificate in file", "cert := `-----BEGIN CERTIFICATE-----`", "CERT-001", true},

		// Certificate Signing Request
		{"CSR PEM", "-----BEGIN CERTIFICATE REQUEST-----", "CERT-CSR-001", true},
		{"New CSR PEM", "-----BEGIN NEW CERTIFICATE REQUEST-----", "CERT-CSR-001", true},

		// PKCS#12/PFX
		{"PKCS12 file reference", "certFile := \"server.p12\"", "CERT-PKCS12-001", true},
		{"PFX file reference", "loadCert(\"certificate.pfx\")", "CERT-PKCS12-001", true},
		{"PKCS12 type", "keyStore := PKCS12.load(data)", "CERT-PKCS12-001", true},

		// Certificate Chain
		{"Cert chain reference", "ca_bundle := loadCertChain()", "CERT-CHAIN-001", true},
		{"Root CA reference", "rootCA := getRootCA()", "CERT-CHAIN-001", true},
		{"Intermediate CA", "intermediate_ca := loadIntermediateCA()", "CERT-CHAIN-001", true},
		{"Trust anchor", "trust_anchor := getTrustAnchor()", "CERT-CHAIN-001", true},

		// Trusted Certificate
		{"Trusted cert PEM", "-----BEGIN TRUSTED CERTIFICATE-----", "CERT-TRUSTED-001", true},

		// Certificate Validity/Expiration
		{"NotAfter check", "if cert.NotAfter.Before(time.Now())", "CERT-EXPIRY-001", true},
		{"Expiration check", "cert.expiration_date", "CERT-EXPIRY-001", true},
		{"Valid until", "validUntil := cert.getValidUntil()", "CERT-EXPIRY-001", true},

		// Certificate Subject/Issuer
		{"Subject DN", "subjectDN := cert.getSubjectDN()", "CERT-SUBJECT-001", true},
		{"Issuer DN", "issuerDN := cert.getIssuerDN()", "CERT-SUBJECT-001", true},
		{"CN attribute", "CN=example.com, O=Example Inc", "CERT-SUBJECT-001", true},

		// Certificate Signature Algorithm
		{"SHA256 with RSA", "signatureAlgorithm: sha256WithRSA", "CERT-SIGALG-001", true},
		{"ECDSA with SHA", "sigAlg := ecdsa-with-sha256", "CERT-SIGALG-001", true},

		// Weak Certificate Signature
		{"SHA1 with RSA (weak)", "signatureAlgorithm: sha1WithRSA", "CERT-SIGALG-WEAK-001", true},
		{"MD5 with RSA (weak)", "md5WithRSA", "CERT-SIGALG-WEAK-001", true},

		// Certificate Key Usage
		{"Key usage extension", "keyUsage := digitalSignature | keyEncipherment", "CERT-KEYUSAGE-001", true},
		{"Extended key usage", "extendedKeyUsage: serverAuth, clientAuth", "CERT-KEYUSAGE-001", true},

		// Subject Alternative Name
		{"SAN extension", "subjectAltName := []string{\"dns:example.com\"}", "CERT-SAN-001", true},
		{"DNS names in SAN", "dnsNames: [\"*.example.com\"]", "CERT-SAN-001", true},

		// Certificate Parsing
		{"Go x509 parse", "cert, _ := x509.ParseCertificate(data)", "CERT-PARSE-001", true},
		{"Python load cert", "cert = load_certificate(FILETYPE_PEM, data)", "CERT-PARSE-001", true},
		{"Java X509", "X509Certificate cert = factory.generateCertificate()", "CERT-PARSE-001", true},

		// Certificate Validation Bypass (CRITICAL)
		{"Go InsecureSkipVerify", "InsecureSkipVerify: true", "CERT-VALIDATION-BYPASS-001", true},
		{"Python verify false", "verify=false", "CERT-VALIDATION-BYPASS-001", true},
		{"SSL VERIFY_NONE", "ssl.VERIFY_NONE", "CERT-VALIDATION-BYPASS-001", true},
		{"CERT_NONE", "verify_mode = CERT_NONE", "CERT-VALIDATION-BYPASS-001", true},

		// Self-Signed Certificate
		{"Self signed gen", "cert := generateSelfSignedCert()", "CERT-SELFSIGNED-001", true},
		{"Self-signed reference", "self_signed := true", "CERT-SELFSIGNED-001", true},

		// mTLS
		{"Mutual TLS config", "mutualTLS := true", "CERT-MTLS-001", true},
		{"Client cert required", "requireClientCert: true", "CERT-MTLS-001", true},
		{"mTLS enabled", "mtls_enabled := true", "CERT-MTLS-001", true},

		// Certificate Revocation
		{"OCSP stapling", "ocsp_stapling := true", "CERT-REVOCATION-001", true},
		{"CRL distribution", "CRLDistributionPoints := []string{url}", "CERT-REVOCATION-001", true},
		{"Revocation check", "checkRevocation(cert)", "CERT-REVOCATION-001", true},

		// Certificate Pinning
		{"Cert pinning", "cert_pin := sha256(cert.PublicKey)", "CERT-PINNING-001", true},
		{"SSL pinning", "ssl_pin_set := [\"sha256/abc...\"]", "CERT-PINNING-001", true},
		{"TrustManager", "TrustManagerFactory.getInstance()", "CERT-PINNING-001", true},

		// ACME/Let's Encrypt
		{"Let's Encrypt", "acmeProvider := \"letsencrypt\"", "CERT-ACME-001", true},
		{"Certbot", "certbot certonly --webroot", "CERT-ACME-001", true},
		{"ACME challenge", "acme_challenge := token", "CERT-ACME-001", true},

		// JWK
		{"JWK RSA key type", `{"kty": "RSA", "use": "sig"}`, "KEY-JWK-001", true},
		{"JWK EC key type", `"kty":"EC"`, "KEY-JWK-001", true},
		{"JWKS endpoint", "/.well-known/jwks.json", "KEY-JWK-001", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, "config.go", 1)
			found := false
			for _, match := range matches {
				if strings.HasPrefix(match.ID, tt.expectID) {
					found = true
					break
				}
			}
			if found != tt.shouldFind {
				if tt.shouldFind {
					t.Errorf("Expected to find pattern %s in: %s", tt.expectID, tt.content)
					t.Errorf("Found patterns: %v", func() []string {
						ids := make([]string, len(matches))
						for i, m := range matches {
							ids[i] = m.ID
						}
						return ids
					}())
				} else {
					t.Errorf("Did not expect to find pattern %s in: %s", tt.expectID, tt.content)
				}
			}
		})
	}
}

func TestCertificateValidationBypassIsCritical(t *testing.T) {
	m := NewMatcher()
	testCases := []string{
		"InsecureSkipVerify: true",
		"verify = false",
		"ssl.VERIFY_NONE",
		"CERT_NONE",
	}

	for _, tc := range testCases {
		matches := m.Match(tc, "tls_config.go", 1)
		for _, match := range matches {
			if strings.Contains(match.ID, "VALIDATION-BYPASS") {
				if match.Severity != types.SeverityCritical {
					t.Errorf("Certificate validation bypass should be CRITICAL severity, got %v for: %s", match.Severity, tc)
				}
			}
		}
	}
}

func TestWeakCertSignatureIsCritical(t *testing.T) {
	m := NewMatcher()
	testCases := []string{
		"sha1WithRSA",
		"md5WithRSA",
		"ecdsa-with-sha1",
	}

	for _, tc := range testCases {
		matches := m.Match(tc, "cert.go", 1)
		foundWeakSig := false
		for _, match := range matches {
			if strings.Contains(match.ID, "SIGALG-WEAK") {
				foundWeakSig = true
				if match.Severity != types.SeverityCritical {
					t.Errorf("Weak certificate signature should be CRITICAL severity, got %v for: %s", match.Severity, tc)
				}
			}
		}
		if !foundWeakSig {
			t.Errorf("Expected to detect weak signature algorithm in: %s", tc)
		}
	}
}

// findingFromPattern builds the finding MatchWithContext would build for a
// match of p at line 1, before any context adjustment.
func findingFromPattern(p Pattern) types.Finding {
	return types.Finding{
		ID:          p.ID + "-1-0",
		Type:        p.Name,
		FindingType: determineFindingType(p),
		Category:    p.Category,
		Algorithm:   p.Algorithm,
		Severity:    p.Severity,
		Quantum:     p.Quantum,
		Remediation: p.Remediation,
	}
}

// MD5, SHA-1, DES, 3DES, RC4 and Blowfish fall to classical attacks today.
// Their Impact says so instead of borrowing the harvest-now-decrypt-later
// sentence, which is about quantum-vulnerable key establishment.
func TestImpactNamesClassicalBreaks(t *testing.T) {
	m := NewMatcher()
	want := map[string]bool{"MD5": false, "SHA-1": false, "DES": false, "3DES": false, "RC4": false, "Blowfish": false}

	for _, p := range m.patterns {
		if _, ok := want[p.Algorithm]; !ok {
			continue
		}
		want[p.Algorithm] = true
		f := findingFromPattern(p)
		for _, sev := range []types.Severity{p.Severity, types.SeverityMedium} {
			f.Severity = sev
			impact := determineImpact(f)
			if !strings.HasPrefix(impact, "Broken by classical attacks today") {
				t.Errorf("%s (%s, %s): Impact = %q, want the classical-break wording", p.ID, p.Algorithm, sev, impact)
			}
			if strings.Contains(strings.ToLower(impact), "harvest") || strings.Contains(strings.ToLower(impact), "quantum computing advances") {
				t.Errorf("%s (%s, %s): Impact = %q, carries quantum wording for a classical break", p.ID, p.Algorithm, sev, impact)
			}
			if !strings.Contains(impact, "without a quantum computer") {
				t.Errorf("%s (%s, %s): Impact = %q, want it to say no quantum computer is needed", p.ID, p.Algorithm, sev, impact)
			}
		}
	}

	for alg, seen := range want {
		if !seen {
			t.Errorf("no pattern carries Algorithm %q; the classical-break list is out of date", alg)
		}
	}
}

// RSA, ECC, DH and DSA keep the harvest-now-decrypt-later sentence at
// CRITICAL: that risk is real for quantum-vulnerable key establishment.
func TestImpactKeepsHarvestNowForAsymmetric(t *testing.T) {
	for _, alg := range []string{"RSA", "ECC", "DH", "DSA"} {
		f := types.Finding{
			ID:          alg + "-001-1-0",
			FindingType: types.FindingTypeAlgorithm,
			Category:    "Asymmetric Encryption",
			Algorithm:   alg,
			Severity:    types.SeverityCritical,
			Quantum:     types.QuantumVulnerable,
		}
		if impact := determineImpact(f); !strings.Contains(impact, "harvest-now-decrypt-later") {
			t.Errorf("%s: Impact = %q, want the harvest-now-decrypt-later sentence", alg, impact)
		}
	}
}

// "Assessment needed" told a reader nothing and gave no next step. A
// category with no effort estimate now carries no Effort line at all.
func TestEffortNeverSaysAssessmentNeeded(t *testing.T) {
	m := NewMatcher()
	for _, p := range m.patterns {
		f := findingFromPattern(p)
		if effort := determineEffort(f); effort == "Assessment needed" {
			t.Errorf("%s (%s): Effort = %q", p.ID, p.Category, effort)
		}
	}
}

// The tests below hold the API misuse checks ported from cryptoserve
// (github.com/ecolibria/cryptoserve, the misuse rules in
// sdk/javascript/lib/scanner.mjs at commit fa3e822d). An input whose source is
// a file and line came from that cryptoserve test file under
// sdk/javascript/test; any other input says what it checks.

// misuseInput is the text of a file, one line or several separated by "\n",
// and where it came from.
type misuseInput struct {
	source string
	file   string
	text   string
}

// reportsPattern reports whether Match reports a finding of pattern id on any
// line of text.
func reportsPattern(m *Matcher, file, text, id string) bool {
	for _, line := range strings.Split(text, "\n") {
		for _, f := range m.Match(line, file, 1) {
			if strings.HasPrefix(f.ID, id+"-1-") {
				return true
			}
		}
	}
	return false
}

// CERT-VALIDATION-BYPASS-001 reports the four ways of turning certificate
// verification off that cryptoserve reports and it did not:
// rejectUnauthorized: false (misuse/tls-verify-disabled), the
// NODE_TLS_REJECT_UNAUTHORIZED override set to 0
// (misuse/node-tls-reject-unauthorized), ssl._create_unverified_context
// (misuse/python-unverified-context), and a checkServerIdentity that checks
// nothing (misuse/js-check-server-identity).
func TestCertValidationBypassReportsJavaScriptAndPythonSpellings(t *testing.T) {
	m := NewMatcher()
	for _, in := range []misuseInput{
		{"gate.test.mjs:157", "app.js", "const opts = { rejectUnauthorized: false };"},

		{"scanner.test.mjs:500", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"},
		{"scanner.test.mjs:501", "app.js", "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';"},
		{"scanner.test.mjs:502", "app.js", `process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;`},
		{"scanner.test.mjs:503", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED ||= '0';"},
		{"scanner.test.mjs:504", "app.js", "process . env . NODE_TLS_REJECT_UNAUTHORIZED = '0';"},

		{"gate.test.mjs:768", "unverified.py", "import ssl\nctx = ssl._create_unverified_context()"},
		{"scanner.test.mjs:629", "app.py", "import ssl\nssl._create_default_https_context = ssl._create_unverified_context"},

		{"scanner.test.mjs:673", "app.js", "const a = new https.Agent({ checkServerIdentity: () => undefined });"},
		{"scanner.test.mjs:674", "app.js", "const a = new https.Agent({ checkServerIdentity: () => {} });"},
		{"scanner.test.mjs:675", "app.js", "const a = new https.Agent({ checkServerIdentity: (host, cert) => null });"},
		{"scanner.test.mjs:676", "app.js", "const a = new https.Agent({ checkServerIdentity: function (h, c) { return undefined; } });"},
		{"scanner.test.mjs:677", "app.js", "const a = new https.Agent({ checkServerIdentity: () => true });"},
		{"scanner.test.mjs:678", "app.js", "const a = new https.Agent({ checkServerIdentity: (h, c) => { return true; } });"},
	} {
		if !reportsPattern(m, in.file, in.text, "CERT-VALIDATION-BYPASS-001") {
			t.Errorf("%s: %q reports no CERT-VALIDATION-BYPASS-001 finding", in.source, in.text)
		}
	}
}

// cryptoserve ends the override's value with the lookahead (?![\w.])
// (lib/scanner.mjs:129), so that a 0 which only starts a longer value is not
// taken for the 0 that turns verification off. Go's regexp has no lookahead,
// so the port requires a character that is neither a word character nor a dot
// after the value, or the end of the line. These hold both sides of that
// boundary.
func TestNodeTLSOverrideValueBoundary(t *testing.T) {
	m := NewMatcher()
	for _, in := range []misuseInput{
		{"not a cryptoserve input: quoted 0 at the end of the line", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"},
		{"not a cryptoserve input: bare 0 at the end of the line", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0"},
		{"not a cryptoserve input: 0 in a template literal", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = `0`;"},
		{"not a cryptoserve input: a carriage return after the value", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'\r"},
		{"not a cryptoserve input: a comma after the value", "app.js", "if (insecure) process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0, start();"},
	} {
		if !reportsPattern(m, in.file, in.text, "CERT-VALIDATION-BYPASS-001") {
			t.Errorf("%s: %q reports no CERT-VALIDATION-BYPASS-001 finding", in.source, in.text)
		}
	}
	for _, in := range []misuseInput{
		{"scanner.test.mjs:594", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0.5;"},
		{"scanner.test.mjs:595", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0x1;"},
		{"scanner.test.mjs:596", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '00';"},
		{"scanner.test.mjs:601", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 10;"},
		{"not a cryptoserve input: 0.5 at the end of the line", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0.5"},
		{"not a cryptoserve input: 00 at the end of the line", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 00"},
	} {
		if reportsPattern(m, in.file, in.text, "CERT-VALIDATION-BYPASS-001") {
			t.Errorf("%s: %q reports CERT-VALIDATION-BYPASS-001; a 0 that starts a longer value is not the value that turns verification off", in.source, in.text)
		}
	}
}

// Lines that name the override, or a checkServerIdentity, without turning
// verification off. cryptoserve documents the first five as non-defects
// (lib/scanner.mjs:103-107), and its tests hold each of its inputs here
// unreported.
func TestCertValidationBypassLeavesNonDefectsUnreported(t *testing.T) {
	m := NewMatcher()
	for _, in := range []misuseInput{
		{"scanner.test.mjs:523", "app.js", "// Never write NODE_TLS_REJECT_UNAUTHORIZED: 0 anywhere."},
		{"scanner.test.mjs:524", "app.js", "module.exports = { rules: { NODE_TLS_REJECT_UNAUTHORIZED: 0 } };"},
		{"scanner.test.mjs:525", "app.js", "const SEVERITY = { NODE_TLS_REJECT_UNAUTHORIZED: 0, OTHER: 2 };"},
		{"scanner.test.mjs:526", "app.js", "counts.NODE_TLS_REJECT_UNAUTHORIZED = 0;"},
		{"scanner.test.mjs:527", "app.js", "class A { constructor(){ this.NODE_TLS_REJECT_UNAUTHORIZED = 0; } }"},

		{"scanner.test.mjs:578", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';"},
		{"scanner.test.mjs:579", "app.js", "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '1';"},
		{"scanner.test.mjs:580", "app.js", "const { env } = process;\nenv.NODE_TLS_REJECT_UNAUTHORIZED = '1';"},
		{"scanner.test.mjs:581", "app.js", "Object.assign(process.env, { NODE_TLS_REJECT_UNAUTHORIZED: '1' });"},

		{"scanner.test.mjs:615", "guide.js", "// never set NODE_TLS_REJECT_UNAUTHORIZED=0 in production"},
		{"scanner.test.mjs:616", "guide.js", "const RULES = [{ bad: 'NODE_TLS_REJECT_UNAUTHORIZED=0', why: 'disables TLS' }];"},
		{"scanner.test.mjs:617", "guide.js", "const issue = 'TLS disabled process-wide (NODE_TLS_REJECT_UNAUTHORIZED=0)';"},

		{"not a cryptoserve input: a comparison reads the override", "app.js", "if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') warn();"},

		{"scanner.test.mjs:662", "app.py", "import ssl\nctx.check_hostname = True"},
		{"scanner.test.mjs:688", "app.js", "const a = new https.Agent({ checkServerIdentity: (host, cert) => tls.checkServerIdentity(host, cert) });"},
	} {
		if reportsPattern(m, in.file, in.text, "CERT-VALIDATION-BYPASS-001") {
			t.Errorf("%s: %q reports CERT-VALIDATION-BYPASS-001, and nothing on it turns verification off", in.source, in.text)
		}
	}
}

// Ways of setting the override to 0 that cryptoserve's rule does not reach,
// left unreported as cryptoserve leaves them (its test at
// scanner.test.mjs:553 records them as known gaps). The last is listed with
// the prefix values there, but Node.js stores the number 0x0 as the string
// "0", which does turn verification off; the value boundary that keeps 0x1
// unreported keeps 0x0 unreported too. A change that starts reporting one of
// these updates the list of spellings not reported in PATTERNS.md with it.
func TestNodeTLSOverrideSpellingsNotReached(t *testing.T) {
	m := NewMatcher()
	for _, in := range []misuseInput{
		{"scanner.test.mjs:559", "app.js", "const { env } = process;\nenv.NODE_TLS_REJECT_UNAUTHORIZED = '0';"},
		{"scanner.test.mjs:560", "app.js", "const e = process.env;\ne.NODE_TLS_REJECT_UNAUTHORIZED = '0';"},
		{"scanner.test.mjs:561", "app.js", "Bun.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"},
		{"scanner.test.mjs:562", "app.js", "spawn('node', ['x.js'], { env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '0' } });"},
		{"scanner.test.mjs:563", "app.js", "Object.assign(process.env, { NODE_TLS_REJECT_UNAUTHORIZED: '0' });"},
		{"scanner.test.mjs:564", "app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED ??= '0';"},
		{"scanner.test.mjs:565", "app.js", "Deno.env.set('NODE_TLS_REJECT_UNAUTHORIZED', '0');"},
		{"scanner.test.mjs:597", "app.js", "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0x0;"},
	} {
		if reportsPattern(m, in.file, in.text, "CERT-VALIDATION-BYPASS-001") {
			t.Errorf("%s: %q is now reported; move it to the reported spellings and update the list in PATTERNS.md", in.source, in.text)
		}
	}
}

// IV-DERIVED-001: Node.js crypto.createCipher derives the IV from its
// password argument (misuse/create-cipher). createCipheriv takes the IV from
// the caller and is not reported.
func TestIVDerivedFromKey(t *testing.T) {
	m := NewMatcher()
	for _, in := range []misuseInput{
		{"scanner.test.mjs:72", "old.js", "\n      const h = crypto.createCipher('des', password);\n    "},
		{"scanner.test.mjs:1168", "big0.js", "const cx = crypto.createCipher('aes-256-cbc', key);"},
		{"not a cryptoserve input: a double-quoted algorithm", "app.js", `const c = crypto.createCipher("aes-256-cbc", key);`},
		{"not a cryptoserve input: an algorithm in a template literal", "app.js", "const c = crypto.createCipher(`aes-256-cbc`, key);"},
		{"not a cryptoserve input: spaces inside the parenthesis", "app.js", "const c = createCipher ( 'aes-128-cbc', key);"},
	} {
		if !reportsPattern(m, in.file, in.text, "IV-DERIVED-001") {
			t.Errorf("%s: %q reports no IV-DERIVED-001 finding", in.source, in.text)
		}
	}
	for _, in := range []misuseInput{
		{"scanner.test.mjs:43", "crypto.js", "      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);"},
		{"scanner.test.mjs:54", "crypto.js", "      const cipher = createCipheriv('aes-256-gcm', key, iv);"},
		{"gate.test.mjs:152", "app.js", "const c = require(\"crypto\");\nconst ci = c.createCipheriv(\"aes-256-cbc\", k, iv);"},
	} {
		if reportsPattern(m, in.file, in.text, "IV-DERIVED-001") {
			t.Errorf("%s: %q reports IV-DERIVED-001, and createCipheriv takes the IV from the caller", in.source, in.text)
		}
	}
}

// RNG-WEAK-001: Math.random in JavaScript (misuse/insecure-random-js) and
// Python's random module (misuse/insecure-random-python), followed on the line
// by the name of a secret value. One ID holds both, and the finding carries
// the language. No cryptoserve test names the Python rule, so its inputs are
// built from the rule (lib/scanner.mjs:64), one for each function it names.
func TestWeakRandomForSecrets(t *testing.T) {
	m := NewMatcher()
	for _, in := range []misuseInput{
		{"scanner.test.mjs:789, with its DEL and U+009B", "rng.js", "const t = Math.random() + \"\x7f\u009b2K\" + token;"},
		{"scanner.test.mjs:789, without its DEL and U+009B", "rng.js", `const t = Math.random() + "2K" + token;`},
		{"not a cryptoserve input: the name in another case, as the rule's i flag allows", "app.js", "const id = Math.random().toString(36) + apiKey;"},
		{"not a cryptoserve input: built from lib/scanner.mjs:64", "app.py", "import random\nt = str(random.random()) + token"},
		{"not a cryptoserve input: built from lib/scanner.mjs:64", "app.py", "n = random.randint(0, 2**32) ^ secret"},
		{"not a cryptoserve input: built from lib/scanner.mjs:64", "app.py", "c = random.choice(alphabet) + nonce"},
	} {
		if !reportsPattern(m, in.file, in.text, "RNG-WEAK-001") {
			t.Errorf("%s: %q reports no RNG-WEAK-001 finding", in.source, in.text)
		}
	}
	for _, in := range []misuseInput{
		{"not a cryptoserve input: the fix the JavaScript rule prints (lib/scanner.mjs:58)", "app.js", "const token = crypto.randomBytes(32).toString('hex');"},
		{"not a cryptoserve input: the fix the JavaScript rule prints (lib/scanner.mjs:58)", "app.js", "crypto.getRandomValues(new Uint8Array(32));"},
		{"not a cryptoserve input: the fix the Python rule prints (lib/scanner.mjs:66)", "app.py", "token = secrets.token_bytes(32)"},
		{"not a cryptoserve input: the name more than 40 characters after the call", "app.js", "const x = Math.random() * 100; /* ........................................ token */"},
		{"not a cryptoserve input: no secret named after the call", "app.py", "delay = random.random() * 5"},
	} {
		if reportsPattern(m, in.file, in.text, "RNG-WEAK-001") {
			t.Errorf("%s: %q reports RNG-WEAK-001", in.source, in.text)
		}
	}
}

// The severity and category of each ported check: CRITICAL for the IV and the
// verification bypass and HIGH for the random number generator, as cryptoserve
// reports them (lib/scanner.mjs:46-171). Each ID is defined once.
func TestMisuseCheckSeverityAndCategory(t *testing.T) {
	want := map[string]struct {
		severity types.Severity
		category string
	}{
		"IV-DERIVED-001":             {types.SeverityCritical, "Insecure Mode"},
		"RNG-WEAK-001":               {types.SeverityHigh, "Random Number Generation"},
		"CERT-VALIDATION-BYPASS-001": {types.SeverityCritical, "Configuration"},
	}
	defined := make(map[string]int)
	for _, p := range NewMatcher().patterns {
		w, ok := want[p.ID]
		if !ok {
			continue
		}
		defined[p.ID]++
		if p.Severity != w.severity || p.Category != w.category {
			t.Errorf("%s: severity %v, category %q; want %v, %q", p.ID, p.Severity, p.Category, w.severity, w.category)
		}
	}
	for id := range want {
		if defined[id] != 1 {
			t.Errorf("%s is defined %d times, want once", id, defined[id])
		}
	}
}

// The effort line of CERT-VALIDATION-BYPASS-001 named Go's InsecureSkipVerify
// on every finding of the ID, Python and JavaScript ones included. It names no
// language's setting now.
func TestCertValidationBypassEffortNamesNoGoSetting(t *testing.T) {
	m := NewMatcher()
	for _, in := range []struct {
		file string
		lang analyzer.Language
		line string
	}{
		{"app.py", analyzer.LangPython, "r = requests.get(url, verify=False)"},
		{"app.js", analyzer.LangJavaScript, "const opts = { rejectUnauthorized: false };"},
		{"app.py", analyzer.LangPython, "ctx = ssl._create_unverified_context()"},
	} {
		fileCtx := &analyzer.FileContext{Language: in.lang, FileType: analyzer.FileTypeCode}
		reported := false
		for _, f := range m.MatchWithContext(in.line, in.file, 1, fileCtx, &analyzer.LineContext{}) {
			if !strings.HasPrefix(f.ID, "CERT-VALIDATION-BYPASS-001-") {
				continue
			}
			reported = true
			if f.Effort == "" || strings.Contains(f.Effort, "InsecureSkipVerify") {
				t.Errorf("%s (%s): Effort = %q, want a line that names no Go setting", in.line, in.lang, f.Effort)
			}
		}
		if !reported {
			t.Errorf("%s (%s): no CERT-VALIDATION-BYPASS-001 finding", in.line, in.lang)
		}
	}
}

// A finding of either new ID says what the misuse exposes, not the general
// maintenance sentence a pattern with no specific impact gets.
func TestMisuseImpactNamesTheRisk(t *testing.T) {
	const general = "Standard cryptographic maintenance recommended"
	seen := make(map[string]bool)
	for _, p := range NewMatcher().patterns {
		if p.ID != "IV-DERIVED-001" && p.ID != "RNG-WEAK-001" {
			continue
		}
		seen[p.ID] = true
		if impact := determineImpact(findingFromPattern(p)); impact == "" || impact == general {
			t.Errorf("%s: Impact = %q", p.ID, impact)
		}
	}
	for _, id := range []string{"IV-DERIVED-001", "RNG-WEAK-001"} {
		if !seen[id] {
			t.Errorf("no pattern %s", id)
		}
	}
}
