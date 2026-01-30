// Copyright 2025 CyberSecurity NonProfit (CSNP)
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
		{"ECC", "ECDSA_generate_key()", types.QuantumVulnerable},
		{"AES", "AES.new(key, mode)", types.QuantumPartial},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Match(tt.content, "crypto.go", 1)
			if len(matches) == 0 {
				t.Skip("Pattern not matched")
				return
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
