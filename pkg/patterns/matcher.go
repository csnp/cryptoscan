// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/csnp/qramm-cryptoscan/pkg/types"
)

// Pattern defines a cryptographic pattern to match
type Pattern struct {
	ID          string
	Name        string
	Category    string
	Regex       *regexp.Regexp
	Severity    types.Severity
	Quantum     types.QuantumRisk
	Description string
	Remediation string
	References  []string
	Tags        []string
	KeySize     int // If pattern detects specific key size
	Algorithm   string
}

// Matcher holds all patterns and performs matching
type Matcher struct {
	patterns []Pattern
}

// NewMatcher creates a new pattern matcher with all crypto patterns
func NewMatcher() *Matcher {
	m := &Matcher{
		patterns: make([]Pattern, 0),
	}
	m.loadPatterns()
	return m
}

// Match checks a line against all patterns and returns findings
func (m *Matcher) Match(line, file string, lineNum int) []types.Finding {
	var findings []types.Finding

	for _, p := range m.patterns {
		matches := p.Regex.FindAllStringIndex(line, -1)
		for _, match := range matches {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("%s-%d-%d", p.ID, lineNum, match[0]),
				Type:        p.Name,
				Category:    p.Category,
				Algorithm:   p.Algorithm,
				KeySize:     p.KeySize,
				File:        file,
				Line:        lineNum,
				Column:      match[0] + 1,
				Match:       line[match[0]:match[1]],
				Context:     truncateContext(line, 120),
				Severity:    p.Severity,
				Quantum:     p.Quantum,
				Description: p.Description,
				Remediation: p.Remediation,
				References:  p.References,
				Tags:        p.Tags,
			})
		}
	}

	return findings
}

func truncateContext(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func (m *Matcher) loadPatterns() {
	// ============================================
	// ASYMMETRIC ALGORITHMS (Quantum Vulnerable)
	// ============================================

	// RSA Detection
	m.patterns = append(m.patterns, Pattern{
		ID:          "RSA-001",
		Name:        "RSA Algorithm",
		Category:    "Asymmetric Encryption",
		Regex:       regexp.MustCompile(`(?i)\b(RSA|rsa)[-_]?(1024|2048|3072|4096|8192)?\b`),
		Severity:    types.SeverityHigh,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "RSA",
		Description: "RSA algorithm detected. RSA is vulnerable to Shor's algorithm and will be broken by cryptographically relevant quantum computers.",
		Remediation: "Migrate to ML-KEM (FIPS 203) for key encapsulation or use hybrid RSA + ML-KEM during transition.",
		References:  []string{"https://csrc.nist.gov/pubs/fips/203/final", "https://qramm.org/learn/pqc-migration-planning"},
		Tags:        []string{"asymmetric", "quantum-vulnerable", "key-exchange"},
	})

	// RSA Key Sizes
	m.patterns = append(m.patterns, Pattern{
		ID:          "RSA-1024",
		Name:        "RSA-1024 Key Size",
		Category:    "Weak Key Size",
		Regex:       regexp.MustCompile(`(?i)\b(RSA|rsa)[-_]?1024\b|KeySize\s*[=:]\s*1024|keysize.*1024`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "RSA",
		KeySize:     1024,
		Description: "RSA-1024 is considered weak even against classical attacks. NIST deprecated 1024-bit RSA in 2013.",
		Remediation: "Immediately upgrade to RSA-3072 minimum, or preferably migrate to ML-KEM.",
		References:  []string{"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf"},
		Tags:        []string{"weak-key", "deprecated", "critical"},
	})

	m.patterns = append(m.patterns, Pattern{
		ID:          "RSA-2048",
		Name:        "RSA-2048 Key Size",
		Category:    "Key Size",
		Regex:       regexp.MustCompile(`(?i)\b(RSA|rsa)[-_]?2048\b|modulus.*2048`),
		Severity:    types.SeverityMedium,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "RSA",
		KeySize:     2048,
		Description: "RSA-2048 provides 112-bit classical security but is vulnerable to quantum attacks.",
		Remediation: "Plan migration to ML-KEM (FIPS 203). RSA-2048 is acceptable until 2030 for non-sensitive data.",
		Tags:        []string{"quantum-vulnerable", "transition-needed"},
	})

	// ECDSA/ECC Detection
	m.patterns = append(m.patterns, Pattern{
		ID:          "ECC-001",
		Name:        "Elliptic Curve Cryptography",
		Category:    "Asymmetric Encryption",
		Regex:       regexp.MustCompile(`(?i)\b(ECDSA|ECDH|ECC|secp256r1|secp384r1|secp521r1|P-256|P-384|P-521|prime256v1|nistp256|nistp384|nistp521|curve25519|ed25519)\b`),
		Severity:    types.SeverityHigh,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "ECC",
		Description: "Elliptic curve cryptography detected. ECC is vulnerable to Shor's algorithm on quantum computers.",
		Remediation: "Migrate to ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) for key exchange.",
		References:  []string{"https://csrc.nist.gov/pubs/fips/204/final"},
		Tags:        []string{"asymmetric", "quantum-vulnerable", "digital-signature"},
	})

	// DSA Detection
	m.patterns = append(m.patterns, Pattern{
		ID:          "DSA-001",
		Name:        "DSA Algorithm",
		Category:    "Asymmetric Encryption",
		Regex:       regexp.MustCompile(`(?i)\bDSA[-_]?(1024|2048|3072)?\b`),
		Severity:    types.SeverityHigh,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "DSA",
		Description: "DSA (Digital Signature Algorithm) detected. DSA is vulnerable to quantum attacks.",
		Remediation: "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for digital signatures.",
		Tags:        []string{"asymmetric", "quantum-vulnerable", "digital-signature", "deprecated"},
	})

	// Diffie-Hellman
	m.patterns = append(m.patterns, Pattern{
		ID:          "DH-001",
		Name:        "Diffie-Hellman Key Exchange",
		Category:    "Key Exchange",
		Regex:       regexp.MustCompile(`(?i)\b(DiffieHellman|Diffie[-_]?Hellman|DHE|ECDHE|DH[-_]?(1024|2048|3072|4096)?)\b`),
		Severity:    types.SeverityHigh,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "DH",
		Description: "Diffie-Hellman key exchange detected. DH/ECDH are vulnerable to Shor's algorithm.",
		Remediation: "Migrate to ML-KEM (FIPS 203) for key encapsulation.",
		Tags:        []string{"key-exchange", "quantum-vulnerable"},
	})

	// ============================================
	// SYMMETRIC ALGORITHMS
	// ============================================

	// AES Detection
	m.patterns = append(m.patterns, Pattern{
		ID:          "AES-001",
		Name:        "AES Algorithm",
		Category:    "Symmetric Encryption",
		Regex:       regexp.MustCompile(`(?i)\bAES[-_]?(128|192|256)?([-_]?(CBC|GCM|CTR|ECB|CFB|OFB))?\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "AES",
		Description: "AES detected. AES-256 provides adequate quantum resistance. AES-128 security is reduced to 64-bit against Grover's algorithm.",
		Remediation: "Use AES-256 for quantum resistance. Avoid AES-ECB mode.",
		Tags:        []string{"symmetric", "quantum-partial"},
	})

	// AES-ECB (Insecure mode)
	m.patterns = append(m.patterns, Pattern{
		ID:          "AES-ECB",
		Name:        "AES-ECB Mode",
		Category:    "Insecure Mode",
		Regex:       regexp.MustCompile(`(?i)\bAES[-_/]?ECB\b|ECB[-_]?mode|Mode\s*[=:]\s*['"]?ECB`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumPartial,
		Algorithm:   "AES-ECB",
		Description: "AES in ECB mode detected. ECB mode is insecure as identical plaintext blocks produce identical ciphertext.",
		Remediation: "Use AES-GCM (preferred) or AES-CBC with proper IV handling.",
		Tags:        []string{"insecure-mode", "critical"},
	})

	// DES/3DES (Deprecated)
	m.patterns = append(m.patterns, Pattern{
		ID:          "DES-001",
		Name:        "DES Algorithm",
		Category:    "Deprecated Algorithm",
		Regex:       regexp.MustCompile(`(?i)\bDES[-_]?(CBC|ECB|CFB|OFB)?\b`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "DES",
		Description: "DES (56-bit) detected. DES is completely broken and must not be used.",
		Remediation: "Replace with AES-256-GCM immediately.",
		Tags:        []string{"deprecated", "broken", "critical"},
	})

	m.patterns = append(m.patterns, Pattern{
		ID:          "3DES-001",
		Name:        "Triple DES Algorithm",
		Category:    "Deprecated Algorithm",
		Regex:       regexp.MustCompile(`(?i)\b(3DES|Triple[-_]?DES|DESede|TDEA)\b`),
		Severity:    types.SeverityHigh,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "3DES",
		Description: "3DES detected. 3DES is deprecated by NIST and provides only 112-bit security.",
		Remediation: "Replace with AES-256-GCM.",
		References:  []string{"https://csrc.nist.gov/News/2017/Update-to-Current-Use-and-Deprecation-of-TDEA"},
		Tags:        []string{"deprecated", "weak"},
	})

	// RC4 (Broken)
	m.patterns = append(m.patterns, Pattern{
		ID:          "RC4-001",
		Name:        "RC4 Stream Cipher",
		Category:    "Broken Algorithm",
		Regex:       regexp.MustCompile(`(?i)\b(RC4|ARC4|ARCFOUR)\b`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "RC4",
		Description: "RC4 detected. RC4 has multiple known vulnerabilities and is prohibited in TLS.",
		Remediation: "Replace with ChaCha20-Poly1305 or AES-256-GCM.",
		Tags:        []string{"broken", "prohibited", "critical"},
	})

	// Blowfish
	m.patterns = append(m.patterns, Pattern{
		ID:          "BLOWFISH-001",
		Name:        "Blowfish Algorithm",
		Category:    "Legacy Algorithm",
		Regex:       regexp.MustCompile(`(?i)\bBlowfish\b`),
		Severity:    types.SeverityMedium,
		Quantum:     types.QuantumPartial,
		Algorithm:   "Blowfish",
		Description: "Blowfish detected. Blowfish has a 64-bit block size which is vulnerable to birthday attacks.",
		Remediation: "Replace with AES-256 or ChaCha20.",
		Tags:        []string{"legacy", "small-block"},
	})

	// ============================================
	// HASH FUNCTIONS
	// ============================================

	// MD5 (Broken)
	m.patterns = append(m.patterns, Pattern{
		ID:          "MD5-001",
		Name:        "MD5 Hash Function",
		Category:    "Broken Hash",
		Regex:       regexp.MustCompile(`(?i)\bMD5\b|\.md5\(|hashlib\.md5|MessageDigest.*MD5|Digest::MD5`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "MD5",
		Description: "MD5 detected. MD5 is cryptographically broken with practical collision attacks.",
		Remediation: "Replace with SHA-256 or SHA-3 for integrity, or use HMAC for authentication.",
		Tags:        []string{"broken", "collision-vulnerable", "critical"},
	})

	// SHA-1 (Deprecated)
	m.patterns = append(m.patterns, Pattern{
		ID:          "SHA1-001",
		Name:        "SHA-1 Hash Function",
		Category:    "Deprecated Hash",
		Regex:       regexp.MustCompile(`(?i)\bSHA[-_]?1\b|\.sha1\(|hashlib\.sha1|MessageDigest.*SHA-?1|Digest::SHA1`),
		Severity:    types.SeverityHigh,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "SHA-1",
		Description: "SHA-1 detected. SHA-1 has practical collision attacks (SHAttered) and is deprecated.",
		Remediation: "Replace with SHA-256 or SHA-3.",
		References:  []string{"https://shattered.io/"},
		Tags:        []string{"deprecated", "collision-vulnerable"},
	})

	// SHA-256/384/512 (Quantum Partial)
	m.patterns = append(m.patterns, Pattern{
		ID:          "SHA2-001",
		Name:        "SHA-2 Hash Function",
		Category:    "Hash Function",
		Regex:       regexp.MustCompile(`(?i)\bSHA[-_]?(256|384|512)\b|hashlib\.sha(256|384|512)|MessageDigest.*SHA-?(256|384|512)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "SHA-2",
		Description: "SHA-2 family hash detected. SHA-256 security is reduced to 128-bit against Grover's algorithm, which remains secure.",
		Remediation: "SHA-256 is acceptable. For maximum quantum resistance, consider SHA-384 or SHA-3-256.",
		Tags:        []string{"hash", "quantum-partial"},
	})

	// ============================================
	// TLS/SSL CONFIGURATIONS
	// ============================================

	// TLS Versions
	m.patterns = append(m.patterns, Pattern{
		ID:          "TLS-001",
		Name:        "TLS 1.0/1.1 Protocol",
		Category:    "Deprecated Protocol",
		Regex:       regexp.MustCompile(`(?i)\b(TLS[-_]?1[._]?[01]|TLSv1[._]?[01]|SSLv[23]|SSL[-_]?[23])\b|TLS_VERSION.*1\.[01]`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Algorithm:   "TLS",
		Description: "Deprecated TLS/SSL version detected. TLS 1.0, 1.1, and SSL 2/3 have known vulnerabilities.",
		Remediation: "Use TLS 1.3 (preferred) or TLS 1.2 with strong cipher suites only.",
		Tags:        []string{"protocol", "deprecated", "critical"},
	})

	m.patterns = append(m.patterns, Pattern{
		ID:          "TLS-002",
		Name:        "TLS Configuration",
		Category:    "TLS/SSL",
		Regex:       regexp.MustCompile(`(?i)\b(TLS[-_]?1[._]?[23]|TLSv1[._]?[23])\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "TLS",
		Description: "TLS 1.2/1.3 detected. TLS 1.3 cipher suites using ECDHE are quantum-vulnerable for key exchange.",
		Remediation: "Monitor for hybrid TLS implementations with ML-KEM when available.",
		Tags:        []string{"protocol", "monitor"},
	})

	// Weak Cipher Suites
	m.patterns = append(m.patterns, Pattern{
		ID:          "CIPHER-001",
		Name:        "Weak Cipher Suite",
		Category:    "Weak Cipher",
		Regex:       regexp.MustCompile(`(?i)(NULL|EXPORT|DES[-_]CBC|RC4|MD5)[-_]?(SHA|MD5)?|CIPHER.*NULL|anon[-_]?DH`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Description: "Weak or export-grade cipher suite detected. These provide inadequate security.",
		Remediation: "Use only strong cipher suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.",
		Tags:        []string{"cipher", "weak", "critical"},
	})

	// ============================================
	// CRYPTO LIBRARY IMPORTS
	// ============================================

	// Python Cryptography
	m.patterns = append(m.patterns, Pattern{
		ID:          "LIB-PY-001",
		Name:        "Python Crypto Import",
		Category:    "Library Import",
		Regex:       regexp.MustCompile(`(?i)(from\s+)?cryptography(\.|import)|from\s+Crypto(dome)?\.|(import|from)\s+hashlib|import\s+ssl`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Python cryptography library import detected. Review usage for quantum-vulnerable algorithms.",
		Remediation: "Audit crypto operations in this file for quantum vulnerability.",
		Tags:        []string{"library", "python", "audit"},
	})

	// Java Crypto
	m.patterns = append(m.patterns, Pattern{
		ID:          "LIB-JAVA-001",
		Name:        "Java Crypto Import",
		Category:    "Library Import",
		Regex:       regexp.MustCompile(`import\s+(javax\.crypto|java\.security|org\.bouncycastle)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Java cryptography import detected. Review usage for quantum-vulnerable algorithms.",
		Tags:        []string{"library", "java", "audit"},
	})

	// Go Crypto
	m.patterns = append(m.patterns, Pattern{
		ID:          "LIB-GO-001",
		Name:        "Go Crypto Import",
		Category:    "Library Import",
		Regex:       regexp.MustCompile(`"crypto/(rsa|ecdsa|dsa|elliptic|aes|des|rc4|md5|sha1|sha256|sha512|tls)"`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Go cryptography package import detected. Review usage for quantum-vulnerable algorithms.",
		Tags:        []string{"library", "go", "audit"},
	})

	// Node.js Crypto
	m.patterns = append(m.patterns, Pattern{
		ID:          "LIB-NODE-001",
		Name:        "Node.js Crypto Import",
		Category:    "Library Import",
		Regex:       regexp.MustCompile(`require\s*\(\s*['"]crypto['"]\s*\)|from\s+['"]crypto['"]|import.*['"]crypto['"]`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Node.js crypto module import detected. Review usage for quantum-vulnerable algorithms.",
		Tags:        []string{"library", "nodejs", "audit"},
	})

	// OpenSSL
	m.patterns = append(m.patterns, Pattern{
		ID:          "LIB-OPENSSL-001",
		Name:        "OpenSSL Usage",
		Category:    "Library Import",
		Regex:       regexp.MustCompile(`#include\s*<openssl/|EVP_|RSA_|EC_KEY|SSL_CTX`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "OpenSSL usage detected. Review for quantum-vulnerable algorithm usage.",
		Tags:        []string{"library", "openssl", "c", "audit"},
	})

	// ============================================
	// KEY/CERTIFICATE PATTERNS
	// ============================================

	// Private Key Detection
	m.patterns = append(m.patterns, Pattern{
		ID:          "KEY-001",
		Name:        "Private Key Header",
		Category:    "Secret Detection",
		Regex:       regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Description: "Private key found in source code. This is a critical security issue.",
		Remediation: "Remove private keys from source code. Use secure key management (HSM, vault).",
		Tags:        []string{"secret", "key", "critical"},
	})

	// EC Private Key
	m.patterns = append(m.patterns, Pattern{
		ID:          "KEY-002",
		Name:        "EC Private Key Header",
		Category:    "Secret Detection",
		Regex:       regexp.MustCompile(`-----BEGIN\s+EC\s+PRIVATE\s+KEY-----`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Description: "EC private key found in source code. Both a secret exposure and quantum-vulnerable algorithm.",
		Remediation: "Remove from source. Plan migration to ML-DSA keys.",
		Tags:        []string{"secret", "key", "quantum-vulnerable", "critical"},
	})

	// Certificate Detection
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-001",
		Name:        "Certificate Header",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`-----BEGIN\s+CERTIFICATE-----`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "X.509 certificate detected. Certificate algorithm should be verified for quantum safety.",
		Remediation: "Verify certificate uses acceptable algorithms. Plan for PQC certificate migration.",
		Tags:        []string{"certificate", "audit"},
	})

	// ============================================
	// HARDCODED VALUES
	// ============================================

	// Hardcoded Key Sizes
	m.patterns = append(m.patterns, Pattern{
		ID:          "KEYSIZE-001",
		Name:        "Hardcoded Key Size",
		Category:    "Configuration",
		Regex:       regexp.MustCompile(`(?i)(key[-_]?size|keySize|KeyLength|key[-_]?length)\s*[=:]\s*(512|768|1024|2048|3072|4096)`),
		Severity:    types.SeverityLow,
		Quantum:     types.QuantumUnknown,
		Description: "Hardcoded key size detected. Review to ensure adequate security level.",
		Remediation: "Ensure key sizes meet current requirements. Use configuration for flexibility.",
		Tags:        []string{"configuration", "key-size"},
	})
}
