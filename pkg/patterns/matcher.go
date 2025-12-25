// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/csnp/qramm-cryptoscan/pkg/analyzer"
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

// MatchWithContext checks a line against all patterns with file and line context
func (m *Matcher) MatchWithContext(line, file string, lineNum int, fileCtx *analyzer.FileContext, lineCtx *analyzer.LineContext) []types.Finding {
	var findings []types.Finding

	for _, p := range m.patterns {
		matches := p.Regex.FindAllStringIndex(line, -1)
		for _, match := range matches {
			finding := types.Finding{
				ID:          fmt.Sprintf("%s-%d-%d", p.ID, lineNum, match[0]),
				Type:        p.Name,
				FindingType: determineFindingType(p),
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
			}

			// Apply context-aware enhancements
			if fileCtx != nil {
				finding.Language = string(fileCtx.Language)
				finding.FileType = string(fileCtx.FileType)

				// Reduce severity for documentation and test files
				if fileCtx.FileType == analyzer.FileTypeDocumentation {
					finding.Severity = adjustSeverityDown(finding.Severity, 2)
					finding.Confidence = types.ConfidenceLow
				} else if fileCtx.FileType == analyzer.FileTypeTest {
					finding.Severity = adjustSeverityDown(finding.Severity, 1)
					finding.Confidence = types.ConfidenceMedium
				} else if fileCtx.IsVendor || fileCtx.IsGenerated {
					finding.Confidence = types.ConfidenceMedium
				}
			}

			if lineCtx != nil {
				finding.Purpose = lineCtx.Purpose
				// Override confidence from line context if not already set
				if finding.Confidence == "" {
					finding.Confidence = lineCtx.Confidence
				}
				// Reduce confidence for comments
				if lineCtx.IsComment {
					finding.Confidence = types.ConfidenceLow
					finding.Severity = adjustSeverityDown(finding.Severity, 2)
				}
			}

			// Default confidence if still not set
			if finding.Confidence == "" {
				finding.Confidence = types.ConfidenceHigh
			}

			// Set impact and effort based on finding characteristics
			finding.Impact = determineImpact(finding)
			finding.Effort = determineEffort(finding)

			findings = append(findings, finding)
		}
	}

	return findings
}

// determineFindingType categorizes the pattern type
func determineFindingType(p Pattern) types.FindingType {
	switch p.Category {
	case "Secret Detection":
		return types.FindingTypeSecret
	case "Library Import":
		return types.FindingTypeAlgorithm
	case "Deprecated Protocol", "TLS/SSL":
		return types.FindingTypeProtocol
	case "Configuration":
		return types.FindingTypeConfig
	default:
		return types.FindingTypeAlgorithm
	}
}

// adjustSeverityDown reduces severity by n levels
func adjustSeverityDown(s types.Severity, n int) types.Severity {
	newSev := int(s) - n
	if newSev < 0 {
		return types.SeverityInfo
	}
	return types.Severity(newSev)
}

// determineImpact returns business impact description
func determineImpact(f types.Finding) string {
	if f.FindingType == types.FindingTypeSecret {
		return "Critical: Exposed cryptographic secrets can lead to complete system compromise"
	}
	switch f.Quantum {
	case types.QuantumVulnerable:
		switch f.Severity {
		case types.SeverityCritical:
			return "Data protected by this algorithm is vulnerable to harvest-now-decrypt-later attacks"
		case types.SeverityHigh:
			return "Long-term data confidentiality at risk from quantum computing advances"
		default:
			return "Algorithm requires migration before quantum computers become practical"
		}
	case types.QuantumPartial:
		return "Reduced security margin against quantum attacks; acceptable with increased key sizes"
	}
	return "Standard cryptographic maintenance recommended"
}

// determineEffort returns migration effort estimate
func determineEffort(f types.Finding) string {
	if f.FindingType == types.FindingTypeSecret {
		return "Immediate action required - rotate secrets and remove from code"
	}
	if f.FindingType == types.FindingTypeConfig {
		return "Configuration change - low effort"
	}
	if f.FindingType == types.FindingTypeDependency {
		return "Library upgrade - medium effort, requires testing"
	}
	switch f.Category {
	case "Asymmetric Encryption", "Key Exchange":
		return "Algorithm replacement - high effort, requires PKI changes"
	case "Symmetric Encryption", "Hash Function":
		return "Algorithm replacement - medium effort"
	case "Deprecated Protocol":
		return "Protocol upgrade - medium to high effort depending on infrastructure"
	}
	return "Assessment needed"
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
		Regex:       regexp.MustCompile(`(?i)\b(DiffieHellman|Diffie[-_]?Hellman|DHE[-_]|ECDHE[-_]?|DH[-_](1024|2048|3072|4096)|KeyExchange.*DH|DH.*KeyExchange)\b`),
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
		Regex:       regexp.MustCompile(`(?i)\b(EXP[-_]|EXPORT[-_]|TLS_.*EXPORT|SSL_.*EXPORT|NULL[-_]?(SHA|MD5)|DES[-_]CBC[-_]?(SHA|MD5)?|anon[-_]?DH|ADH[-_]|AECDH[-_])\b|CIPHER.*NULL`),
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

	// ============================================
	// CRYPTO-SPECIFIC SECRETS
	// ============================================
	// Note: These are NOT general secrets like TruffleHog detects.
	// These are specifically cryptographic secrets relevant to
	// quantum readiness and cryptographic inventory.

	// DSA Private Key
	m.patterns = append(m.patterns, Pattern{
		ID:          "KEY-003",
		Name:        "DSA Private Key",
		Category:    "Secret Detection",
		Regex:       regexp.MustCompile(`-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Description: "DSA private key found in source code. DSA is deprecated and quantum-vulnerable.",
		Remediation: "Remove from source. Migrate to ML-DSA for signatures.",
		Tags:        []string{"secret", "key", "quantum-vulnerable", "critical", "deprecated"},
	})

	// OpenSSH Private Key
	m.patterns = append(m.patterns, Pattern{
		ID:          "KEY-004",
		Name:        "OpenSSH Private Key",
		Category:    "Secret Detection",
		Regex:       regexp.MustCompile(`-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Description: "OpenSSH private key found in source code. SSH keys should never be in code.",
		Remediation: "Remove from source. Use SSH agent or secure key management.",
		Tags:        []string{"secret", "key", "ssh", "critical"},
	})

	// PGP Private Key
	m.patterns = append(m.patterns, Pattern{
		ID:          "KEY-005",
		Name:        "PGP Private Key",
		Category:    "Secret Detection",
		Regex:       regexp.MustCompile(`-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Description: "PGP private key found in source code. PGP keys (RSA/ECC) are quantum-vulnerable.",
		Remediation: "Remove from source. Plan migration to PQC-enabled PGP when available.",
		Tags:        []string{"secret", "key", "pgp", "quantum-vulnerable", "critical"},
	})

	// PKCS#8 Private Key
	m.patterns = append(m.patterns, Pattern{
		ID:          "KEY-006",
		Name:        "PKCS#8 Private Key",
		Category:    "Secret Detection",
		Regex:       regexp.MustCompile(`-----BEGIN\s+(ENCRYPTED\s+)?PRIVATE\s+KEY-----`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Description: "PKCS#8 private key found in source code. This is a critical security issue.",
		Remediation: "Remove private keys from source code. Use secure key management.",
		Tags:        []string{"secret", "key", "pkcs8", "critical"},
	})

	// AWS KMS Key ID (crypto service)
	m.patterns = append(m.patterns, Pattern{
		ID:          "SECRET-KMS-001",
		Name:        "AWS KMS Key Reference",
		Category:    "Crypto Service",
		Regex:       regexp.MustCompile(`(?i)(arn:aws:kms:[a-z0-9-]+:\d{12}:key/[a-f0-9-]{36}|alias/[a-zA-Z0-9/_-]+)`),
		Severity:    types.SeverityMedium,
		Quantum:     types.QuantumUnknown,
		Description: "AWS KMS key reference detected. Verify KMS key algorithm for quantum readiness.",
		Remediation: "Audit KMS key configuration. AWS KMS currently uses RSA/ECC which are quantum-vulnerable.",
		Tags:        []string{"crypto-service", "aws", "kms", "audit"},
	})

	// Azure Key Vault Reference
	m.patterns = append(m.patterns, Pattern{
		ID:          "SECRET-VAULT-001",
		Name:        "Azure Key Vault Reference",
		Category:    "Crypto Service",
		Regex:       regexp.MustCompile(`(?i)https://[a-zA-Z0-9-]+\.vault\.azure\.net/(keys|secrets|certificates)/[a-zA-Z0-9-]+`),
		Severity:    types.SeverityMedium,
		Quantum:     types.QuantumUnknown,
		Description: "Azure Key Vault reference detected. Review key algorithms for quantum readiness.",
		Remediation: "Audit Key Vault key types. Plan migration when Azure supports PQC.",
		Tags:        []string{"crypto-service", "azure", "keyvault", "audit"},
	})

	// HashiCorp Vault Reference
	m.patterns = append(m.patterns, Pattern{
		ID:          "SECRET-VAULT-002",
		Name:        "HashiCorp Vault Path",
		Category:    "Crypto Service",
		Regex:       regexp.MustCompile(`(?i)(vault\s+read|vault\s+write|VAULT_ADDR|secret/data/|transit/encrypt|transit/decrypt)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "HashiCorp Vault usage detected. Review transit encryption keys for quantum readiness.",
		Remediation: "Audit Vault transit keys. Monitor HashiCorp for PQC support.",
		Tags:        []string{"crypto-service", "vault", "hashicorp", "audit"},
	})

	// GCP KMS Reference
	m.patterns = append(m.patterns, Pattern{
		ID:          "SECRET-KMS-002",
		Name:        "GCP KMS Reference",
		Category:    "Crypto Service",
		Regex:       regexp.MustCompile(`projects/[a-zA-Z0-9-]+/locations/[a-zA-Z0-9-]+/keyRings/[a-zA-Z0-9-]+/cryptoKeys/[a-zA-Z0-9-]+`),
		Severity:    types.SeverityMedium,
		Quantum:     types.QuantumUnknown,
		Description: "GCP Cloud KMS reference detected. Review key algorithms for quantum readiness.",
		Remediation: "Audit GCP KMS key configurations. Plan for PQC migration.",
		Tags:        []string{"crypto-service", "gcp", "kms", "audit"},
	})

	// JWT Secret in Code
	m.patterns = append(m.patterns, Pattern{
		ID:          "SECRET-JWT-001",
		Name:        "JWT Secret Pattern",
		Category:    "Secret Detection",
		Regex:       regexp.MustCompile(`(?i)(jwt[-_]?secret|JWT_SECRET|jwtSecret)\s*[=:]\s*['"][^'"]{8,}['"]`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumPartial,
		Description: "JWT secret appears to be hardcoded. This enables token forgery if exposed.",
		Remediation: "Move JWT secrets to secure key management. Use asymmetric JWT (RS256/ES256) with proper key rotation.",
		Tags:        []string{"secret", "jwt", "authentication", "critical"},
	})

	// Encryption Key Variable
	m.patterns = append(m.patterns, Pattern{
		ID:          "SECRET-KEY-001",
		Name:        "Hardcoded Encryption Key",
		Category:    "Secret Detection",
		Regex:       regexp.MustCompile(`(?i)(encryption[-_]?key|ENCRYPTION_KEY|encryptionKey|aes[-_]?key|AES_KEY|secret[-_]?key|SECRET_KEY|master[-_]?key|MASTER_KEY)\s*[=:]\s*['"][a-zA-Z0-9+/=]{16,}['"]`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumPartial,
		Description: "Possible encryption key hardcoded in source code.",
		Remediation: "Remove hardcoded keys. Use secure key management (HSM, KMS, Vault).",
		Tags:        []string{"secret", "encryption-key", "critical"},
	})

	// Base64-encoded Key Material (high entropy strings in key context)
	m.patterns = append(m.patterns, Pattern{
		ID:          "SECRET-KEY-002",
		Name:        "Base64 Key Material",
		Category:    "Secret Detection",
		Regex:       regexp.MustCompile(`(?i)(private[-_]?key|PRIVATE_KEY|privateKey)\s*[=:]\s*['"][a-zA-Z0-9+/]{40,}={0,2}['"]`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Description: "Possible base64-encoded private key material in source code.",
		Remediation: "Remove key material from source. Use secure key storage.",
		Tags:        []string{"secret", "key-material", "critical"},
	})

	// HMAC Secret
	m.patterns = append(m.patterns, Pattern{
		ID:          "SECRET-HMAC-001",
		Name:        "HMAC Secret Pattern",
		Category:    "Secret Detection",
		Regex:       regexp.MustCompile(`(?i)(hmac[-_]?secret|HMAC_SECRET|hmacSecret|signing[-_]?key|SIGNING_KEY)\s*[=:]\s*['"][^'"]{8,}['"]`),
		Severity:    types.SeverityHigh,
		Quantum:     types.QuantumPartial,
		Description: "HMAC/signing secret appears to be hardcoded.",
		Remediation: "Move HMAC secrets to secure configuration. Ensure key length >= 256 bits.",
		Tags:        []string{"secret", "hmac", "signing"},
	})

	// Password-Based Key Derivation (weak)
	m.patterns = append(m.patterns, Pattern{
		ID:          "PBKDF-001",
		Name:        "Weak PBKDF Usage",
		Category:    "Key Derivation",
		Regex:       regexp.MustCompile(`(?i)(PBKDF1|pbkdf1|MD5.*iterations|SHA1.*iterations|iterations\s*[=:]\s*[0-9]{1,4}\b)`),
		Severity:    types.SeverityHigh,
		Quantum:     types.QuantumPartial,
		Description: "Weak password-based key derivation detected. Low iteration counts or weak hashes reduce security.",
		Remediation: "Use Argon2id, scrypt, or PBKDF2-SHA256 with >= 600,000 iterations.",
		References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"},
		Tags:        []string{"key-derivation", "password", "weak"},
	})
}
