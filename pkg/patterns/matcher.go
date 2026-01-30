// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/types"
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

			// Check for help text / documentation context (high false positive rate)
			if analyzer.IsHelpText(line) {
				finding.Confidence = types.ConfidenceLow
				finding.Severity = adjustSeverityDown(finding.Severity, 2)
			}

			// Check if match is in a URL or file path (not actionable)
			if analyzer.IsURLOrPath(line, finding.Match) {
				finding.Confidence = types.ConfidenceLow
				finding.Severity = adjustSeverityDown(finding.Severity, 2)
			}

			// Check if match is part of a variable/function name (less actionable)
			if analyzer.IsVariableOrFunctionName(line, finding.Match) {
				if finding.Confidence == types.ConfidenceHigh {
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
	// Certificate-specific impact based on pattern ID (check before generic quantum status)
	if f.Category == "Certificate" || strings.HasPrefix(f.ID, "CERT-") {
		switch {
		case strings.HasPrefix(f.ID, "CERT-VALIDATION-BYPASS"):
			return "Critical: Certificate validation disabled - vulnerable to MITM attacks"
		case strings.HasPrefix(f.ID, "CERT-SIGALG-WEAK"):
			return "High: Weak signature algorithm undermines certificate trust chain integrity"
		case strings.HasPrefix(f.ID, "CERT-SELFSIGNED"):
			return "Medium: Self-signed certificates lack third-party trust verification"
		case strings.HasPrefix(f.ID, "CERT-EXPIRY"):
			return "Important: Certificate expiration must be monitored to prevent service disruption"
		case strings.HasPrefix(f.ID, "CERT-PKCS12"):
			return "Note: PKCS#12 files contain private keys - ensure proper access controls"
		case strings.HasPrefix(f.ID, "CERT-PINNING"):
			return "Security hardening: Certificate pinning protects against CA compromise"
		case strings.HasPrefix(f.ID, "CERT-MTLS"):
			return "Strong auth: mTLS provides mutual authentication for zero-trust architecture"
		default:
			return "PKI infrastructure - include in cryptographic inventory"
		}
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
	// Certificate-specific effort guidance with clear next steps (check before generic types)
	if f.Category == "Certificate" || strings.HasPrefix(f.ID, "CERT-") {
		switch {
		case strings.HasPrefix(f.ID, "CERT-VALIDATION-BYPASS"):
			return "URGENT: Remove InsecureSkipVerify, configure proper CA trust store"
		case strings.HasPrefix(f.ID, "CERT-SIGALG-WEAK"):
			return "Replace certificate: Request new cert with SHA-256+ from your CA"
		case strings.HasPrefix(f.ID, "CERT-SELFSIGNED"):
			return "For production: Obtain certificate from trusted CA (e.g., Let's Encrypt)"
		case strings.HasPrefix(f.ID, "CERT-EXPIRY"):
			return "Add to monitoring: Set up certificate expiration alerts (e.g., certbot renew)"
		case strings.HasPrefix(f.ID, "CERT-PKCS12"):
			return "Audit: Verify file permissions, consider HSM for production keys"
		case strings.HasPrefix(f.ID, "CERT-CHAIN"):
			return "Document: Map certificate chain hierarchy for PQC migration planning"
		case strings.HasPrefix(f.ID, "CERT-001"), strings.HasPrefix(f.ID, "CERT-CSR"):
			return "Inventory: Add to CBOM, verify algorithm meets requirements"
		case strings.HasPrefix(f.ID, "CERT-PINNING"):
			return "Best practice: Ensure pin rotation strategy is documented"
		case strings.HasPrefix(f.ID, "CERT-REVOCATION"):
			return "Verify: Confirm OCSP/CRL checking is enabled in production"
		case strings.HasPrefix(f.ID, "CERT-MTLS"):
			return "Document: Map client certificate requirements for API consumers"
		default:
			return "Inventory: Add to cryptographic bill of materials (CBOM)"
		}
	}
	// FindingType-based effort
	if f.FindingType == types.FindingTypeConfig {
		return "Configuration change - low effort"
	}
	if f.FindingType == types.FindingTypeDependency {
		return "Library upgrade - medium effort, requires testing"
	}
	// Category-based effort
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
	// Note: Require key size suffix or crypto context to avoid false positives
	m.patterns = append(m.patterns, Pattern{
		ID:          "DSA-001",
		Name:        "DSA Algorithm",
		Category:    "Asymmetric Encryption",
		Regex:       regexp.MustCompile(`(?i)\bDSA[-_](1024|2048|3072)\b|KeyPairGenerator\.getInstance\s*\(\s*["']DSA["']|ssh-dss\b|-----BEGIN\s+DSA|"crypto/dsa"`),
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
	// Note: Require mode suffix (CBC/ECB/CFB/OFB) or crypto context to avoid false positives
	m.patterns = append(m.patterns, Pattern{
		ID:          "DES-001",
		Name:        "DES Algorithm",
		Category:    "Deprecated Algorithm",
		Regex:       regexp.MustCompile(`(?i)\bDES[-_](CBC|ECB|CFB|OFB)\b|\bDESede\b|Cipher\.getInstance\s*\(\s*["']DES["']|createCipher\s*\(\s*["']des|crypto\.createCipher.*["']des|\bDES\.(new|encrypt|decrypt)\b|\bDES\.MODE_`),
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
	// Note: Removed bare EXP[-_] and EXPORT[-_] as they cause false positives with JS export statements
	// Only match these in proper cipher suite context (TLS_/SSL_ prefix)
	m.patterns = append(m.patterns, Pattern{
		ID:          "CIPHER-001",
		Name:        "Weak Cipher Suite",
		Category:    "Weak Cipher",
		Regex:       regexp.MustCompile(`(?i)\b(TLS_[A-Z0-9_]*EXPORT[A-Z0-9_]*|SSL_[A-Z0-9_]*EXPORT[A-Z0-9_]*|TLS_NULL[A-Z0-9_]*|SSL_NULL[A-Z0-9_]*|TLS_[A-Z0-9_]*_anon_|SSL_[A-Z0-9_]*_anon_|TLS_RSA_WITH_NULL|ADH[-_][A-Z0-9]+|AECDH[-_][A-Z0-9]+)\b|(?i)\bCIPHER\s*[:=].*NULL`),
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

	// ============================================
	// CERTIFICATE PATTERNS
	// ============================================
	// X.509 certificates, chains, CSRs, and certificate attributes

	// X.509 Certificate Header
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-001",
		Name:        "X.509 Certificate",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`-----BEGIN\s+CERTIFICATE-----`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "X.509 certificate detected. Certificate algorithm and key size should be verified for quantum safety.",
		Remediation: "Verify certificate uses RSA-3072+ or ECC-P256+. Plan migration to PQC certificates when standards finalize.",
		Tags:        []string{"certificate", "x509", "audit"},
	})

	// Certificate Signing Request (CSR)
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-CSR-001",
		Name:        "Certificate Signing Request",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`-----BEGIN\s+(NEW\s+)?CERTIFICATE\s+REQUEST-----`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Certificate Signing Request (CSR) detected. Used to request certificate from CA.",
		Remediation: "Ensure CSR uses strong key sizes (RSA-3072+ or ECC-P256+). Verify private key is properly secured.",
		Tags:        []string{"certificate", "csr", "pki"},
	})

	// PKCS#12/PFX Certificate Container
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-PKCS12-001",
		Name:        "PKCS#12 Certificate Container",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(\.p12|\.pfx|PKCS12|PKCS#12|pkcs12[-_]?file|pfx[-_]?file)`),
		Severity:    types.SeverityMedium,
		Quantum:     types.QuantumUnknown,
		Description: "PKCS#12/PFX certificate container detected. Contains private key and certificate chain.",
		Remediation: "Ensure PKCS#12 files are properly secured. Verify contained certificates use strong algorithms.",
		Tags:        []string{"certificate", "pkcs12", "pfx", "key-container"},
	})

	// Certificate Chain Detection
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-CHAIN-001",
		Name:        "Certificate Chain",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(cert[-_]?chain|certificate[-_]?chain|chain[-_]?file|ca[-_]?bundle|ca[-_]?cert|root[-_]?ca|intermediate[-_]?ca|trust[-_]?anchor)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Certificate chain or trust anchor reference detected. Part of PKI infrastructure.",
		Remediation: "Audit entire certificate chain for quantum-vulnerable algorithms. Plan chain-wide PQC migration.",
		Tags:        []string{"certificate", "chain", "pki", "trust-anchor"},
	})

	// Trusted Certificate
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-TRUSTED-001",
		Name:        "Trusted Certificate",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`-----BEGIN\s+TRUSTED\s+CERTIFICATE-----`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Trusted certificate with trust settings detected. OpenSSL extended format.",
		Remediation: "Review trust settings and verify certificate algorithm is quantum-safe.",
		Tags:        []string{"certificate", "trusted", "openssl"},
	})

	// Certificate Validity/Expiration
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-EXPIRY-001",
		Name:        "Certificate Expiration Check",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(notAfter|notBefore|valid[-_]?(until|from|to)|expir(y|ation|es)|cert.*expir|validityPeriod)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Certificate validity period handling detected. Important for certificate lifecycle management.",
		Remediation: "Ensure certificate expiration is monitored. Plan renewal with PQC algorithms when available.",
		Tags:        []string{"certificate", "expiration", "lifecycle"},
	})

	// Certificate Subject/Issuer
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-SUBJECT-001",
		Name:        "Certificate Subject/Issuer",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(subject[-_]?name|issuer[-_]?name|CN\s*=\s*[a-zA-Z]|OU\s*=\s*[a-zA-Z]|subjectDN|issuerDN|getSubject|getIssuer|\.Subject\.|\.Issuer\.)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Certificate subject or issuer information handling detected.",
		Remediation: "Document certificate issuers for PKI inventory. Verify issuer CA supports PQC migration path.",
		Tags:        []string{"certificate", "subject", "issuer", "pki"},
	})

	// Certificate Signature Algorithm
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-SIGALG-001",
		Name:        "Certificate Signature Algorithm",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(signatureAlgorithm|signature[-_]?algorithm|sigAlg|sha256WithRSA|sha384WithRSA|sha512WithRSA|ecdsa[-_]?with[-_]?sha|sha1WithRSA)`),
		Severity:    types.SeverityMedium,
		Quantum:     types.QuantumVulnerable,
		Description: "Certificate signature algorithm detected. RSA and ECDSA signatures are quantum-vulnerable.",
		Remediation: "Current signature algorithms will need migration to ML-DSA or SLH-DSA for quantum safety.",
		Tags:        []string{"certificate", "signature", "quantum-vulnerable"},
	})

	// Weak Certificate Signature (SHA-1)
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-SIGALG-WEAK-001",
		Name:        "Weak Certificate Signature (SHA-1)",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(sha1WithRSA|sha1[-_]?with[-_]?rsa|ecdsa[-_]?with[-_]?sha1|md5WithRSA)`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumVulnerable,
		Description: "Weak certificate signature algorithm (SHA-1 or MD5) detected. These are deprecated and insecure.",
		Remediation: "Immediately replace certificates using SHA-1 or MD5 signatures with SHA-256 or stronger.",
		Tags:        []string{"certificate", "signature", "weak", "deprecated", "critical"},
	})

	// Certificate Key Usage
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-KEYUSAGE-001",
		Name:        "Certificate Key Usage",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(keyUsage|key[-_]?usage|digitalSignature|keyEncipherment|dataEncipherment|keyAgreement|keyCertSign|cRLSign|extendedKeyUsage|serverAuth|clientAuth)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Certificate key usage extension detected. Defines permitted cryptographic operations.",
		Remediation: "Document key usage for cryptographic inventory. Ensure usage aligns with PQC migration plan.",
		Tags:        []string{"certificate", "key-usage", "extension"},
	})

	// Subject Alternative Name (SAN)
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-SAN-001",
		Name:        "Subject Alternative Name",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(subjectAltName|subject[-_]?alt[-_]?name|san[-_]?extension|dnsNames|ipAddresses|DNS:|IP:)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Subject Alternative Name (SAN) handling detected. Modern alternative to CN for identity.",
		Remediation: "Ensure SAN entries are documented for certificate inventory.",
		Tags:        []string{"certificate", "san", "identity"},
	})

	// Certificate Parsing (Code Pattern)
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-PARSE-001",
		Name:        "X.509 Certificate Parsing",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(x509\.Parse|ParseCertificate|ParseCertificateRequest|X509Certificate|load_certificate|FILETYPE_PEM|FILETYPE_ASN1)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "X.509 certificate parsing code detected. Verify certificates being parsed use strong algorithms.",
		Remediation: "Audit parsed certificates for algorithm strength and quantum vulnerability.",
		Tags:        []string{"certificate", "parsing", "code"},
	})

	// Certificate Validation Bypass (CRITICAL)
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-VALIDATION-BYPASS-001",
		Name:        "Certificate Validation Bypass",
		Category:    "Configuration",
		Regex:       regexp.MustCompile(`(?i)(InsecureSkipVerify\s*[=:]\s*true|verify\s*[=:]\s*false|CERT_NONE|VERIFY_NONE|SSL_VERIFY_NONE|check_hostname\s*=\s*False|verify_mode\s*=\s*CERT_NONE)`),
		Severity:    types.SeverityCritical,
		Quantum:     types.QuantumUnknown,
		Description: "Certificate validation is disabled. Critical security vulnerability enabling MITM attacks.",
		Remediation: "Enable certificate validation immediately. Use proper CA certificates for verification.",
		References:  []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		Tags:        []string{"certificate", "validation", "critical", "mitm"},
	})

	// Self-Signed Certificate
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-SELFSIGNED-001",
		Name:        "Self-Signed Certificate",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(self[-_]?signed|selfSigned|generate[-_]?self[-_]?signed|createSelfSigned|makeSelfSignedCert)`),
		Severity:    types.SeverityMedium,
		Quantum:     types.QuantumUnknown,
		Description: "Self-signed certificate usage detected. Acceptable for development but not production.",
		Remediation: "Use CA-signed certificates in production. Ensure self-signed certs use strong algorithms.",
		Tags:        []string{"certificate", "self-signed", "development"},
	})

	// mTLS Configuration
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-MTLS-001",
		Name:        "Mutual TLS (mTLS)",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(mutual[-_]?tls|mtls|client[-_]?cert|client[-_]?certificate|requireClientCert|ClientAuth|VerifyClientCertIfGiven|RequestClientCert)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Description: "Mutual TLS (mTLS) configuration detected. Good practice for service authentication.",
		Remediation: "Ensure client certificates use strong algorithms. Plan for PQC certificate migration.",
		Tags:        []string{"certificate", "mtls", "authentication", "tls"},
	})

	// Certificate Revocation (OCSP/CRL)
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-REVOCATION-001",
		Name:        "Certificate Revocation Check",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(OCSP|ocsp[-_]?stapl|crl[-_]?distribution|revocation[-_]?check|isRevoked|checkRevocation|CRLDistributionPoints)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Certificate revocation checking detected (OCSP or CRL). Important for PKI security.",
		Remediation: "Ensure revocation checking is enabled. Verify OCSP/CRL endpoints are accessible.",
		Tags:        []string{"certificate", "revocation", "ocsp", "crl", "pki"},
	})

	// Certificate Pinning
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-PINNING-001",
		Name:        "Certificate Pinning",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(cert[-_]?pin|certificate[-_]?pin|public[-_]?key[-_]?pin|pin[-_]?set|ssl[-_]?pin|TrustManagerFactory|X509TrustManager)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumUnknown,
		Description: "Certificate or public key pinning detected. Provides additional TLS security.",
		Remediation: "Document pinned certificates/keys. Plan pin rotation during PQC migration.",
		Tags:        []string{"certificate", "pinning", "security"},
	})

	// Let's Encrypt / ACME
	m.patterns = append(m.patterns, Pattern{
		ID:          "CERT-ACME-001",
		Name:        "ACME/Let's Encrypt",
		Category:    "Certificate",
		Regex:       regexp.MustCompile(`(?i)(letsencrypt|lets[-_]?encrypt|acme[-_]?client|acme[-_]?challenge|certbot|acme\.sh|autocert)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumVulnerable,
		Description: "ACME protocol / Let's Encrypt certificate automation detected.",
		Remediation: "Current Let's Encrypt certificates use RSA/ECDSA. Monitor for PQC certificate support.",
		Tags:        []string{"certificate", "acme", "letsencrypt", "automation"},
	})

	// JWK (JSON Web Key)
	m.patterns = append(m.patterns, Pattern{
		ID:          "KEY-JWK-001",
		Name:        "JSON Web Key (JWK)",
		Category:    "Key Format",
		Regex:       regexp.MustCompile(`(?i)("kty"\s*:\s*"(RSA|EC|oct|OKP)"|"use"\s*:\s*"(sig|enc)"|\.well-known/jwks)`),
		Severity:    types.SeverityMedium,
		Quantum:     types.QuantumVulnerable,
		Description: "JSON Web Key (JWK) format detected. Used in OAuth2/OIDC. RSA/EC keys are quantum-vulnerable.",
		Remediation: "Audit JWK key types. Plan migration to PQC-compatible formats when JOSE PQC standards finalize.",
		Tags:        []string{"key-format", "jwk", "oauth2", "quantum-vulnerable"},
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

	// ============================================
	// POST-QUANTUM CRYPTOGRAPHY (Quantum Safe)
	// ============================================

	// ML-KEM (FIPS 203) - formerly Kyber
	m.patterns = append(m.patterns, Pattern{
		ID:          "PQC-MLKEM-001",
		Name:        "ML-KEM Key Encapsulation",
		Category:    "Post-Quantum Cryptography",
		Regex:       regexp.MustCompile(`(?i)\b(ML[-_]?KEM[-_]?(512|768|1024)?|MLKEM(512|768|1024)?|Kyber[-_]?(512|768|1024)?|CRYSTALS[-_]?Kyber|mlkem|kem\.ML[-_]?KEM|oqs\.KeyEncapsulation.*ML[-_]?KEM|liboqs.*kyber)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Algorithm:   "ML-KEM",
		Description: "ML-KEM (FIPS 203) post-quantum key encapsulation detected. This is quantum-safe.",
		Remediation: "ML-KEM is NIST-approved and quantum-safe. Recommended for key exchange.",
		References:  []string{"https://csrc.nist.gov/pubs/fips/203/final"},
		Tags:        []string{"pqc", "quantum-safe", "kem", "fips-203"},
	})

	// ML-DSA (FIPS 204) - formerly Dilithium
	m.patterns = append(m.patterns, Pattern{
		ID:          "PQC-MLDSA-001",
		Name:        "ML-DSA Digital Signature",
		Category:    "Post-Quantum Cryptography",
		Regex:       regexp.MustCompile(`(?i)\b(ML[-_]?DSA[-_]?(44|65|87)?|MLDSA(44|65|87)?|Dilithium[-_]?(2|3|5)?|CRYSTALS[-_]?Dilithium|mldsa|sign\.ML[-_]?DSA|oqs\.Signature.*ML[-_]?DSA|oqs\.Signature.*Dilithium|liboqs.*dilithium)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Algorithm:   "ML-DSA",
		Description: "ML-DSA (FIPS 204) post-quantum digital signature detected. This is quantum-safe.",
		Remediation: "ML-DSA is NIST-approved and quantum-safe. Recommended for digital signatures.",
		References:  []string{"https://csrc.nist.gov/pubs/fips/204/final"},
		Tags:        []string{"pqc", "quantum-safe", "signature", "fips-204"},
	})

	// SLH-DSA (FIPS 205) - formerly SPHINCS+
	m.patterns = append(m.patterns, Pattern{
		ID:          "PQC-SLHDSA-001",
		Name:        "SLH-DSA Hash-Based Signature",
		Category:    "Post-Quantum Cryptography",
		Regex:       regexp.MustCompile(`(?i)\b(SLH[-_]?DSA[-_]?(128|192|256)?(f|s)?|SLHDSA|SPHINCS\+?[-_]?(128|192|256)?(f|s)?|sphincsplus|oqs\.Signature.*SPHINCS|oqs\.Signature.*SLH[-_]?DSA)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Algorithm:   "SLH-DSA",
		Description: "SLH-DSA (FIPS 205) stateless hash-based signature detected. This is quantum-safe.",
		Remediation: "SLH-DSA is NIST-approved and quantum-safe. Good backup option for ML-DSA.",
		References:  []string{"https://csrc.nist.gov/pubs/fips/205/final"},
		Tags:        []string{"pqc", "quantum-safe", "signature", "hash-based", "fips-205"},
	})

	// FN-DSA (FIPS 206 draft) - formerly Falcon
	m.patterns = append(m.patterns, Pattern{
		ID:          "PQC-FNDSA-001",
		Name:        "FN-DSA Digital Signature",
		Category:    "Post-Quantum Cryptography",
		Regex:       regexp.MustCompile(`(?i)\b(FN[-_]?DSA[-_]?(512|1024)?|FNDSA|Falcon[-_]?(512|1024)?|oqs\.Signature.*Falcon|pqcrypto.*falcon)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Algorithm:   "FN-DSA",
		Description: "FN-DSA (Falcon) post-quantum signature detected. Expected in FIPS 206.",
		Remediation: "FN-DSA is quantum-safe. FIPS 206 standardization expected in 2025.",
		References:  []string{"https://csrc.nist.gov/projects/post-quantum-cryptography"},
		Tags:        []string{"pqc", "quantum-safe", "signature", "draft"},
	})

	// XMSS (SP 800-208) - Stateful hash-based signatures
	m.patterns = append(m.patterns, Pattern{
		ID:          "PQC-XMSS-001",
		Name:        "XMSS Stateful Signature",
		Category:    "Post-Quantum Cryptography",
		Regex:       regexp.MustCompile(`(?i)\b(XMSS([-_]?(MT|SHA2|SHAKE))?[-_]?(10|16|20)?|xmss_sign|xmss_keypair|XMSS\^MT)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Algorithm:   "XMSS",
		Description: "XMSS stateful hash-based signature detected (SP 800-208). Quantum-safe but requires careful state management.",
		Remediation: "XMSS is NIST-approved (SP 800-208). Ensure proper state management to prevent key reuse.",
		References:  []string{"https://csrc.nist.gov/pubs/sp/800/208/final", "https://datatracker.ietf.org/doc/html/rfc8391"},
		Tags:        []string{"pqc", "quantum-safe", "signature", "stateful", "sp800-208"},
	})

	// LMS/HSS (SP 800-208) - Stateful hash-based signatures
	m.patterns = append(m.patterns, Pattern{
		ID:          "PQC-LMS-001",
		Name:        "LMS/HSS Stateful Signature",
		Category:    "Post-Quantum Cryptography",
		Regex:       regexp.MustCompile(`(?i)\b(LMS[-_]?(SHA256)?[-_]?(H5|H10|H15|H20|H25)?|HSS[-_]?LMS|lms_sign|lms_keypair|Leighton[-_]?Micali)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Algorithm:   "LMS",
		Description: "LMS/HSS stateful hash-based signature detected (SP 800-208). Quantum-safe but requires careful state management.",
		Remediation: "LMS is NIST-approved (SP 800-208). Ensure proper state management to prevent key reuse.",
		References:  []string{"https://csrc.nist.gov/pubs/sp/800/208/final", "https://datatracker.ietf.org/doc/html/rfc8554"},
		Tags:        []string{"pqc", "quantum-safe", "signature", "stateful", "sp800-208"},
	})

	// PQC Library Imports
	m.patterns = append(m.patterns, Pattern{
		ID:          "PQC-LIB-001",
		Name:        "Post-Quantum Crypto Library",
		Category:    "PQC Library Import",
		Regex:       regexp.MustCompile(`(?i)(liboqs[-_]?(python|go|java)?|oqs\.(KeyEncapsulation|Signature)|circl/(kem|sign)/(mlkem|mldsa|kyber|dilithium)|pqcrypto[-_]?(mlkem|mldsa|kyber|dilithium|sphincs|falcon)|github\.com/cloudflare/circl|github\.com/open-quantum-safe|org\.bouncycastle\.pqc)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Description: "Post-quantum cryptography library detected. Good practice for quantum-safe migration.",
		Remediation: "Continue using PQC libraries. Ensure you're using NIST-approved algorithms (ML-KEM, ML-DSA, SLH-DSA).",
		Tags:        []string{"pqc", "library", "quantum-safe"},
	})

	// Hybrid Key Exchange Detection
	m.patterns = append(m.patterns, Pattern{
		ID:          "HYBRID-001",
		Name:        "Hybrid Key Exchange",
		Category:    "Hybrid Cryptography",
		Regex:       regexp.MustCompile(`(?i)\b(X25519[-_]?MLKEM[-_]?768|P256[-_]?MLKEM[-_]?768|ECDH[-_]?MLKEM|RSA[-_]?MLKEM|hybrid[-_]?(kem|key[-_]?exchange)|X25519Kyber768|P256Kyber768|secp256r1[-_]?kyber|x25519[-_]?kyber)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Algorithm:   "Hybrid-KEM",
		Description: "Hybrid key exchange detected (classical + PQC). Excellent transition strategy.",
		Remediation: "Hybrid cryptography is recommended during PQC transition. Provides security from both classical and quantum threats.",
		References:  []string{"https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/"},
		Tags:        []string{"hybrid", "quantum-safe", "transition", "best-practice"},
	})

	// Hybrid TLS Configuration
	m.patterns = append(m.patterns, Pattern{
		ID:          "HYBRID-TLS-001",
		Name:        "Hybrid TLS Configuration",
		Category:    "Hybrid Cryptography",
		Regex:       regexp.MustCompile(`(?i)(CurvePreferences.*X25519MLKEM|ssl_groups.*X25519MLKEM|NamedGroup::X25519MLKEM|TLS_.*_WITH_.*KYBER|kem[-_]?groups.*mlkem)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Algorithm:   "Hybrid-TLS",
		Description: "Hybrid TLS key exchange configuration detected. Excellent quantum-safe practice.",
		Remediation: "Continue using hybrid TLS configuration for quantum-safe key exchange.",
		Tags:        []string{"hybrid", "tls", "quantum-safe", "configuration"},
	})

	// ============================================
	// MESSAGE AUTHENTICATION CODES (MACs)
	// ============================================

	// HMAC-SHA256/384/512 (NIST Approved)
	m.patterns = append(m.patterns, Pattern{
		ID:          "MAC-HMAC-SHA2-001",
		Name:        "HMAC-SHA2",
		Category:    "Message Authentication Code",
		Regex:       regexp.MustCompile(`(?i)\b(HMAC[-_]?SHA[-_]?(256|384|512)|hmacSha(256|384|512)|HmacSHA(256|384|512)|HMAC\.SHA(256|384|512)|createHmac\s*\(\s*['"]sha(256|384|512)['"])\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "HMAC-SHA2",
		Description: "HMAC with SHA-2 detected. NIST-approved (FIPS 198-1). Quantum-partial - security reduced by Grover's algorithm.",
		Remediation: "HMAC-SHA256 is acceptable. For maximum quantum resistance, consider KMAC-256.",
		References:  []string{"https://csrc.nist.gov/pubs/fips/198-1/final"},
		Tags:        []string{"mac", "hmac", "sha2", "nist-approved"},
	})

	// HMAC-SHA3 (NIST Approved)
	m.patterns = append(m.patterns, Pattern{
		ID:          "MAC-HMAC-SHA3-001",
		Name:        "HMAC-SHA3",
		Category:    "Message Authentication Code",
		Regex:       regexp.MustCompile(`(?i)\b(HMAC[-_]?SHA[-_]?3[-_]?(224|256|384|512)?|hmacSha3|HmacSHA3|HMAC\.SHA3)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "HMAC-SHA3",
		Description: "HMAC with SHA-3 detected. NIST-approved. Good choice for modern applications.",
		Remediation: "HMAC-SHA3 is a good choice. For SHA-3 native MAC, consider KMAC instead.",
		References:  []string{"https://csrc.nist.gov/pubs/fips/198-1/final", "https://csrc.nist.gov/pubs/fips/202/final"},
		Tags:        []string{"mac", "hmac", "sha3", "nist-approved"},
	})

	// HMAC-SHA1 (Deprecated)
	m.patterns = append(m.patterns, Pattern{
		ID:          "MAC-HMAC-SHA1-001",
		Name:        "HMAC-SHA1",
		Category:    "Message Authentication Code",
		Regex:       regexp.MustCompile(`(?i)\b(HMAC[-_]?SHA[-_]?1|hmacSha1|HmacSHA1|HMAC\.SHA1|createHmac\s*\(\s*['"]sha1['"])\b`),
		Severity:    types.SeverityMedium,
		Quantum:     types.QuantumPartial,
		Algorithm:   "HMAC-SHA1",
		Description: "HMAC-SHA1 detected. SHA-1 is deprecated for new applications.",
		Remediation: "Migrate to HMAC-SHA256 or KMAC-256.",
		Tags:        []string{"mac", "hmac", "sha1", "legacy"},
	})

	// HMAC-MD5 (Not Approved)
	m.patterns = append(m.patterns, Pattern{
		ID:          "MAC-HMAC-MD5-001",
		Name:        "HMAC-MD5",
		Category:    "Message Authentication Code",
		Regex:       regexp.MustCompile(`(?i)\b(HMAC[-_]?MD5|hmacMd5|HmacMD5|HMAC\.MD5|createHmac\s*\(\s*['"]md5['"])\b`),
		Severity:    types.SeverityHigh,
		Quantum:     types.QuantumPartial,
		Algorithm:   "HMAC-MD5",
		Description: "HMAC-MD5 detected. MD5 is cryptographically broken. Not NIST-approved.",
		Remediation: "Replace with HMAC-SHA256 or KMAC-256 immediately.",
		Tags:        []string{"mac", "hmac", "md5", "weak", "not-approved"},
	})

	// KMAC (NIST SP 800-185 - Keccak MAC)
	m.patterns = append(m.patterns, Pattern{
		ID:          "MAC-KMAC-001",
		Name:        "KMAC",
		Category:    "Message Authentication Code",
		Regex:       regexp.MustCompile(`(?i)\b(KMAC[-_]?(128|256)?|keccak[-_]?mac|KECCAK[-_]?MAC)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Algorithm:   "KMAC",
		Description: "KMAC detected (SP 800-185). NIST-approved SHA-3 based MAC. KMAC-256 is quantum-safe.",
		Remediation: "KMAC is an excellent choice. KMAC-256 provides quantum-safe authentication.",
		References:  []string{"https://csrc.nist.gov/pubs/sp/800/185/final"},
		Tags:        []string{"mac", "kmac", "sha3", "nist-approved", "quantum-safe"},
	})

	// CMAC (NIST SP 800-38B - Cipher-based MAC)
	m.patterns = append(m.patterns, Pattern{
		ID:          "MAC-CMAC-001",
		Name:        "CMAC",
		Category:    "Message Authentication Code",
		Regex:       regexp.MustCompile(`(?i)\b(CMAC|AES[-_]?CMAC|cipher[-_]?based[-_]?mac)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "CMAC",
		Description: "CMAC detected (SP 800-38B). NIST-approved cipher-based MAC using AES.",
		Remediation: "CMAC with AES-256 is acceptable. For maximum quantum resistance, consider KMAC-256.",
		References:  []string{"https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final"},
		Tags:        []string{"mac", "cmac", "aes", "nist-approved"},
	})

	// GMAC (NIST SP 800-38D - GCM authentication only)
	m.patterns = append(m.patterns, Pattern{
		ID:          "MAC-GMAC-001",
		Name:        "GMAC",
		Category:    "Message Authentication Code",
		Regex:       regexp.MustCompile(`(?i)\b(GMAC|AES[-_]?GMAC|galois[-_]?mac)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "GMAC",
		Description: "GMAC detected (SP 800-38D). NIST-approved authentication mode of GCM.",
		Remediation: "GMAC is acceptable for authentication. Typically used as part of AES-GCM.",
		References:  []string{"https://csrc.nist.gov/pubs/sp/800/38/d/final"},
		Tags:        []string{"mac", "gmac", "gcm", "nist-approved"},
	})

	// Poly1305 (IETF RFC 8439)
	m.patterns = append(m.patterns, Pattern{
		ID:          "MAC-POLY1305-001",
		Name:        "Poly1305",
		Category:    "Message Authentication Code",
		Regex:       regexp.MustCompile(`(?i)\b(Poly1305|poly[-_]?1305)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "Poly1305",
		Description: "Poly1305 one-time MAC detected (RFC 8439). Used with ChaCha20 for AEAD.",
		Remediation: "Poly1305 is secure when used correctly as a one-time MAC with ChaCha20.",
		References:  []string{"https://www.rfc-editor.org/rfc/rfc8439.html"},
		Tags:        []string{"mac", "poly1305", "ietf"},
	})

	// CBC-MAC (Legacy - not standalone approved)
	m.patterns = append(m.patterns, Pattern{
		ID:          "MAC-CBCMAC-001",
		Name:        "CBC-MAC",
		Category:    "Message Authentication Code",
		Regex:       regexp.MustCompile(`(?i)\b(CBC[-_]?MAC|cbc[-_]?mac)\b`),
		Severity:    types.SeverityMedium,
		Quantum:     types.QuantumPartial,
		Algorithm:   "CBC-MAC",
		Description: "CBC-MAC detected. Not a standalone NIST-approved MAC. Use CMAC instead.",
		Remediation: "Migrate to CMAC (SP 800-38B) which addresses CBC-MAC vulnerabilities.",
		Tags:        []string{"mac", "cbc-mac", "legacy"},
	})

	// ============================================
	// KEY DERIVATION FUNCTIONS (KDFs)
	// ============================================

	// HKDF (NIST SP 800-56C)
	m.patterns = append(m.patterns, Pattern{
		ID:          "KDF-HKDF-001",
		Name:        "HKDF",
		Category:    "Key Derivation Function",
		Regex:       regexp.MustCompile(`(?i)\b(HKDF|hkdf[-_]?(extract|expand)?|HMAC[-_]?based[-_]?KDF|HKDFExpand|HKDFExtract)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "HKDF",
		Description: "HKDF detected (SP 800-56C). NIST-approved KDF for high-entropy inputs.",
		Remediation: "HKDF is appropriate for key derivation from high-entropy secrets. Not for passwords.",
		References:  []string{"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf", "https://datatracker.ietf.org/doc/html/rfc5869"},
		Tags:        []string{"kdf", "hkdf", "nist-approved"},
	})

	// PBKDF2 (NIST SP 800-132)
	m.patterns = append(m.patterns, Pattern{
		ID:          "KDF-PBKDF2-001",
		Name:        "PBKDF2",
		Category:    "Key Derivation Function",
		Regex:       regexp.MustCompile(`(?i)\b(PBKDF2|pbkdf2[-_]?(sha256|sha512|hmac)?|Password[-_]?Based[-_]?KDF[-_]?2)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "PBKDF2",
		Description: "PBKDF2 detected (SP 800-132). NIST-approved password-based KDF.",
		Remediation: "Ensure iteration count >= 600,000 (OWASP 2024). Consider Argon2id for new applications.",
		References:  []string{"https://csrc.nist.gov/pubs/sp/800/132/final", "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"},
		Tags:        []string{"kdf", "pbkdf2", "password", "nist-approved"},
	})

	// Argon2 (RFC 9106 - Password Hashing Competition winner)
	m.patterns = append(m.patterns, Pattern{
		ID:          "KDF-ARGON2-001",
		Name:        "Argon2",
		Category:    "Key Derivation Function",
		Regex:       regexp.MustCompile(`(?i)\b(Argon2(id|i|d)?|argon2[-_]?(id|i|d)?|PasswordHasher\(\).*argon|argon2\.IDKey)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "Argon2",
		Description: "Argon2 detected (RFC 9106). Password Hashing Competition winner. Recommended for password hashing.",
		Remediation: "Argon2id is the recommended variant. Use memory >= 64MB, iterations >= 3, parallelism >= 4.",
		References:  []string{"https://datatracker.ietf.org/doc/html/rfc9106", "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"},
		Tags:        []string{"kdf", "argon2", "password", "recommended"},
	})

	// scrypt (RFC 7914)
	m.patterns = append(m.patterns, Pattern{
		ID:          "KDF-SCRYPT-001",
		Name:        "scrypt",
		Category:    "Key Derivation Function",
		Regex:       regexp.MustCompile(`(?i)\b(scrypt|Scrypt)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "scrypt",
		Description: "scrypt detected (RFC 7914). Memory-hard password-based KDF.",
		Remediation: "scrypt is acceptable. For new applications, prefer Argon2id.",
		References:  []string{"https://datatracker.ietf.org/doc/html/rfc7914"},
		Tags:        []string{"kdf", "scrypt", "password"},
	})

	// bcrypt
	m.patterns = append(m.patterns, Pattern{
		ID:          "KDF-BCRYPT-001",
		Name:        "bcrypt",
		Category:    "Key Derivation Function",
		Regex:       regexp.MustCompile(`(?i)\b(bcrypt|BCrypt|Bcrypt)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "bcrypt",
		Description: "bcrypt detected. Industry-standard password hashing function.",
		Remediation: "bcrypt is acceptable with cost >= 12. For new applications, prefer Argon2id.",
		Tags:        []string{"kdf", "bcrypt", "password"},
	})

	// ============================================
	// MODERN HASH FUNCTIONS
	// ============================================

	// SHA-3 Family (FIPS 202)
	m.patterns = append(m.patterns, Pattern{
		ID:          "HASH-SHA3-001",
		Name:        "SHA-3 Hash Function",
		Category:    "Hash Function",
		Regex:       regexp.MustCompile(`(?i)\b(SHA[-_]?3[-_]?(224|256|384|512)|sha3_(224|256|384|512)|Keccak[-_]?(224|256|384|512))\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "SHA-3",
		Description: "SHA-3 hash function detected (FIPS 202). NIST-approved alternative to SHA-2.",
		Remediation: "SHA-3 is an excellent choice. SHA-3-256 provides 128-bit quantum security.",
		References:  []string{"https://csrc.nist.gov/pubs/fips/202/final"},
		Tags:        []string{"hash", "sha3", "nist-approved", "fips-202"},
	})

	// SHAKE (FIPS 202 - XOF)
	m.patterns = append(m.patterns, Pattern{
		ID:          "HASH-SHAKE-001",
		Name:        "SHAKE Extendable Output Function",
		Category:    "Hash Function",
		Regex:       regexp.MustCompile(`(?i)\b(SHAKE[-_]?(128|256)|shake(128|256)|cSHAKE[-_]?(128|256))\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Algorithm:   "SHAKE",
		Description: "SHAKE XOF detected (FIPS 202). NIST-approved extendable output function. SHAKE256 is quantum-safe.",
		Remediation: "SHAKE256 provides quantum-safe security with variable output length.",
		References:  []string{"https://csrc.nist.gov/pubs/fips/202/final"},
		Tags:        []string{"hash", "xof", "shake", "nist-approved", "quantum-safe"},
	})

	// BLAKE2 (RFC 7693)
	m.patterns = append(m.patterns, Pattern{
		ID:          "HASH-BLAKE2-001",
		Name:        "BLAKE2 Hash Function",
		Category:    "Hash Function",
		Regex:       regexp.MustCompile(`(?i)\b(BLAKE2(b|s)?[-_]?(256|384|512)?|blake2(b|s)?)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "BLAKE2",
		Description: "BLAKE2 detected (RFC 7693). Fast, secure hash function. Not NIST-approved but widely used.",
		Remediation: "BLAKE2 is secure and fast. For NIST compliance, use SHA-256 or SHA-3.",
		References:  []string{"https://www.rfc-editor.org/rfc/rfc7693"},
		Tags:        []string{"hash", "blake2", "ietf"},
	})

	// BLAKE3
	m.patterns = append(m.patterns, Pattern{
		ID:          "HASH-BLAKE3-001",
		Name:        "BLAKE3 Hash Function",
		Category:    "Hash Function",
		Regex:       regexp.MustCompile(`(?i)\b(BLAKE3|blake3)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "BLAKE3",
		Description: "BLAKE3 detected. Modern, parallelizable hash function. Not yet standardized.",
		Remediation: "BLAKE3 is secure and very fast. For compliance requirements, use SHA-256 or SHA-3.",
		Tags:        []string{"hash", "blake3"},
	})

	// ============================================
	// MODERN SYMMETRIC ENCRYPTION
	// ============================================

	// ChaCha20-Poly1305 (RFC 8439)
	m.patterns = append(m.patterns, Pattern{
		ID:          "SYM-CHACHA-001",
		Name:        "ChaCha20-Poly1305",
		Category:    "Symmetric Encryption",
		Regex:       regexp.MustCompile(`(?i)\b(ChaCha20[-_]?Poly1305|chacha20[-_]?poly1305|CHACHA20_POLY1305|TLS_CHACHA20_POLY1305)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "ChaCha20-Poly1305",
		Description: "ChaCha20-Poly1305 AEAD detected (RFC 8439). Fast, secure authenticated encryption.",
		Remediation: "ChaCha20-Poly1305 is an excellent choice. Included in TLS 1.3.",
		References:  []string{"https://www.rfc-editor.org/rfc/rfc8439.html"},
		Tags:        []string{"symmetric", "aead", "chacha20", "ietf", "tls13"},
	})

	// ChaCha20 (standalone stream cipher)
	m.patterns = append(m.patterns, Pattern{
		ID:          "SYM-CHACHA20-001",
		Name:        "ChaCha20 Stream Cipher",
		Category:    "Symmetric Encryption",
		Regex:       regexp.MustCompile(`(?i)\b(ChaCha20|chacha20|ChaCha[-_]?20)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "ChaCha20",
		Description: "ChaCha20 stream cipher detected. Fast software cipher, alternative to AES.",
		Remediation: "ChaCha20 should be used with Poly1305 for authenticated encryption (ChaCha20-Poly1305).",
		Tags:        []string{"symmetric", "stream-cipher", "chacha20"},
	})

	// XChaCha20 (extended nonce)
	m.patterns = append(m.patterns, Pattern{
		ID:          "SYM-XCHACHA-001",
		Name:        "XChaCha20",
		Category:    "Symmetric Encryption",
		Regex:       regexp.MustCompile(`(?i)\b(XChaCha20[-_]?Poly1305|xchacha20)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "XChaCha20",
		Description: "XChaCha20 detected. Extended nonce variant of ChaCha20 for random nonce generation.",
		Remediation: "XChaCha20-Poly1305 is excellent when random nonces are preferred over counters.",
		Tags:        []string{"symmetric", "aead", "xchacha20"},
	})

	// AES-GCM (NIST SP 800-38D) - explicit detection for good practice
	m.patterns = append(m.patterns, Pattern{
		ID:          "SYM-AESGCM-001",
		Name:        "AES-GCM Authenticated Encryption",
		Category:    "Symmetric Encryption",
		Regex:       regexp.MustCompile(`(?i)\b(AES[-_]?(128|192|256)[-_]?GCM|AES[-/]GCM|GCM[-_]?AES|TLS_AES_(128|256)_GCM)\b`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumPartial,
		Algorithm:   "AES-GCM",
		Description: "AES-GCM AEAD detected (SP 800-38D). NIST-approved authenticated encryption.",
		Remediation: "AES-256-GCM is recommended. Provides confidentiality and integrity.",
		References:  []string{"https://csrc.nist.gov/pubs/sp/800/38/d/final"},
		Tags:        []string{"symmetric", "aead", "aes", "gcm", "nist-approved"},
	})

	// ============================================
	// COMPOSITE/HYBRID SIGNATURES
	// ============================================

	// Composite Signature OIDs (draft standards)
	m.patterns = append(m.patterns, Pattern{
		ID:          "HYBRID-SIG-001",
		Name:        "Composite Digital Signature",
		Category:    "Hybrid Cryptography",
		Regex:       regexp.MustCompile(`(?i)(MLDSA44[-_]?RSA2048|MLDSA65[-_]?ECDSA[-_]?P256|MLDSA65[-_]?Ed25519|composite[-_]?signature|dual[-_]?signature|id[-_]?MLDSA.*RSA|id[-_]?MLDSA.*ECDSA)`),
		Severity:    types.SeverityInfo,
		Quantum:     types.QuantumSafe,
		Algorithm:   "Composite-Signature",
		Description: "Composite/hybrid digital signature detected. Combines classical and PQC signatures.",
		Remediation: "Composite signatures are excellent for PQC transition. Both signatures must verify.",
		Tags:        []string{"hybrid", "signature", "quantum-safe", "composite"},
	})
}
