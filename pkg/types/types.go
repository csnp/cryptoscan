// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package types contains shared type definitions
package types

// Severity levels for findings
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// MigrationStatus represents the quantum migration status of a finding
type MigrationStatus string

const (
	MigrationStatusSafe       MigrationStatus = "SAFE"       // Quantum-safe (PQC algorithms)
	MigrationStatusHybrid     MigrationStatus = "HYBRID"     // Classical + PQC combined
	MigrationStatusPartial    MigrationStatus = "PARTIAL"    // Quantum-weakened but acceptable
	MigrationStatusVulnerable MigrationStatus = "VULNERABLE" // Needs migration
	MigrationStatusCritical   MigrationStatus = "CRITICAL"   // Already broken, immediate action
)

// QRAMMDimension represents QRAMM framework dimensions
type QRAMMDimension string

const (
	QRAMMDimensionCVI  QRAMMDimension = "CVI"  // Cryptographic Visibility & Inventory
	QRAMMDimensionSGRM QRAMMDimension = "SGRM" // Strategic Governance & Risk Management
	QRAMMDimensionDPE  QRAMMDimension = "DPE"  // Data Protection Engineering
	QRAMMDimensionITR  QRAMMDimension = "ITR"  // Implementation & Technical Readiness
)

// QRAMMPractice represents specific QRAMM practices
type QRAMMPractice string

const (
	// CVI Practices
	QRAMMPracticeCVI11 QRAMMPractice = "1.1" // Cryptographic Discovery & Inventory Management
	QRAMMPracticeCVI12 QRAMMPractice = "1.2" // Vulnerability Assessment & Classification
	QRAMMPracticeCVI13 QRAMMPractice = "1.3" // Cryptographic Dependency Mapping
)

// AlgorithmPrimitive categorizes algorithm types
type AlgorithmPrimitive string

const (
	PrimitiveKEM          AlgorithmPrimitive = "kem"       // Key Encapsulation Mechanism
	PrimitiveSignature    AlgorithmPrimitive = "signature" // Digital Signature
	PrimitiveHash         AlgorithmPrimitive = "hash"      // Hash Function
	PrimitiveXOF          AlgorithmPrimitive = "xof"       // Extendable Output Function
	PrimitiveMAC          AlgorithmPrimitive = "mac"       // Message Authentication Code
	PrimitiveKDF          AlgorithmPrimitive = "kdf"       // Key Derivation Function
	PrimitiveBlockCipher  AlgorithmPrimitive = "block-cipher"
	PrimitiveStreamCipher AlgorithmPrimitive = "stream-cipher"
	PrimitiveAEAD         AlgorithmPrimitive = "aead" // Authenticated Encryption
	PrimitiveKeyExchange  AlgorithmPrimitive = "key-exchange"
	PrimitivePKE          AlgorithmPrimitive = "pke" // Public Key Encryption
)

// SecurityLevel contains classical and quantum security information
type SecurityLevel struct {
	ClassicalBits       int `json:"classicalBits,omitempty"`       // Classical security in bits
	NISTQuantumLevel    int `json:"nistQuantumLevel,omitempty"`    // NIST PQC level (1-5, 0 if not PQC)
	QuantumSecurityBits int `json:"quantumSecurityBits,omitempty"` // Security bits against quantum (Grover)
}

// QRAMMMapping contains QRAMM framework mapping information
type QRAMMMapping struct {
	Dimension QRAMMDimension `json:"dimension"`          // Which QRAMM dimension this relates to
	Practice  QRAMMPractice  `json:"practice"`           // Which practice within the dimension
	Evidence  string         `json:"evidence,omitempty"` // How this finding serves as evidence
}

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// QuantumRisk indicates quantum vulnerability status
type QuantumRisk string

const (
	QuantumVulnerable QuantumRisk = "VULNERABLE" // Broken by quantum computers
	QuantumPartial    QuantumRisk = "PARTIAL"    // Weakened but not fully broken
	QuantumSafe       QuantumRisk = "SAFE"       // Quantum-resistant
	QuantumUnknown    QuantumRisk = "UNKNOWN"    // Cannot determine
)

// Confidence indicates how confident we are in the finding
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// FindingType categorizes the type of finding
type FindingType string

const (
	FindingTypeAlgorithm  FindingType = "algorithm"  // Direct algorithm usage
	FindingTypeDependency FindingType = "dependency" // Crypto library in dependencies
	FindingTypeConfig     FindingType = "config"     // Configuration setting
	FindingTypeSecret     FindingType = "secret"     // Exposed key/secret
	FindingTypeProtocol   FindingType = "protocol"   // Protocol configuration (TLS, etc.)
)

// SourceContext represents lines of source code around a finding
type SourceContext struct {
	Lines     []SourceLine `json:"lines"`
	StartLine int          `json:"startLine"`
	EndLine   int          `json:"endLine"`
	MatchLine int          `json:"matchLine"` // The line number where the match occurred
}

// SourceLine represents a single line of source code
type SourceLine struct {
	Number  int    `json:"number"`
	Content string `json:"content"`
	IsMatch bool   `json:"isMatch"` // True if this is the line with the finding
}

// Finding represents a single cryptographic finding
type Finding struct {
	ID              string             `json:"id"`
	Type            string             `json:"type"`
	FindingType     FindingType        `json:"findingType"`
	Category        string             `json:"category"`
	Algorithm       string             `json:"algorithm,omitempty"`
	Primitive       AlgorithmPrimitive `json:"primitive,omitempty"` // Algorithm primitive type
	KeySize         int                `json:"keySize,omitempty"`
	SecurityLevel   *SecurityLevel     `json:"securityLevel,omitempty"`   // Classical and quantum security
	MigrationStatus MigrationStatus    `json:"migrationStatus,omitempty"` // Quantum migration status
	QRAMMMapping    *QRAMMMapping      `json:"qrammMapping,omitempty"`    // QRAMM framework mapping
	OID             string             `json:"oid,omitempty"`             // Algorithm OID for CBOM
	File            string             `json:"file"`
	Line            int                `json:"line"`
	Column          int                `json:"column,omitempty"`
	Match           string             `json:"match"`
	Context         string             `json:"context,omitempty"`
	SourceContext   *SourceContext     `json:"sourceContext,omitempty"` // Actual source code lines
	Severity        Severity           `json:"severity"`
	Quantum         QuantumRisk        `json:"quantumRisk"`
	Confidence      Confidence         `json:"confidence"`
	Purpose         string             `json:"purpose,omitempty"`  // What the crypto is used for
	Language        string             `json:"language,omitempty"` // Programming language
	FileType        string             `json:"fileType,omitempty"` // code, config, docs, etc.
	Description     string             `json:"description"`
	Remediation     string             `json:"remediation,omitempty"`
	Impact          string             `json:"impact,omitempty"` // Business impact description
	Effort          string             `json:"effort,omitempty"` // Migration effort estimate
	References      []string           `json:"references,omitempty"`
	Tags            []string           `json:"tags,omitempty"`
	Metadata        map[string]string  `json:"metadata,omitempty"`
	Ignored         bool               `json:"ignored,omitempty"` // True if cryptoscan:ignore comment found
}

// Priority calculates a priority score for sorting (higher = more urgent)
func (f *Finding) Priority() int {
	score := 0

	// Severity weight
	switch f.Severity {
	case SeverityCritical:
		score += 100
	case SeverityHigh:
		score += 75
	case SeverityMedium:
		score += 50
	case SeverityLow:
		score += 25
	}

	// Quantum risk weight
	switch f.Quantum {
	case QuantumVulnerable:
		score += 50
	case QuantumPartial:
		score += 20
	}

	// Confidence weight
	switch f.Confidence {
	case ConfidenceHigh:
		score += 30
	case ConfidenceMedium:
		score += 15
	}

	// Finding type weight (actual code > dependencies > configs > docs)
	switch f.FindingType {
	case FindingTypeSecret:
		score += 40
	case FindingTypeAlgorithm:
		score += 25
	case FindingTypeDependency:
		score += 20
	case FindingTypeConfig:
		score += 15
	}

	// File type weight
	switch f.FileType {
	case "code":
		score += 20
	case "config":
		score += 15
	case "test":
		score -= 10 // Deprioritize test files
	case "documentation":
		score -= 20 // Deprioritize docs
	}

	return score
}

// MigrationScore represents the overall quantum migration readiness
type MigrationScore struct {
	Score           float64         `json:"score"`                    // 0-100 percentage
	Level           string          `json:"level"`                    // Risk level: CRITICAL, HIGH, MEDIUM, LOW
	SafeCount       int             `json:"safeCount"`                // Quantum-safe findings
	HybridCount     int             `json:"hybridCount"`              // Hybrid crypto findings
	PartialCount    int             `json:"partialCount"`             // Quantum-partial findings
	VulnerableCount int             `json:"vulnerableCount"`          // Quantum-vulnerable findings
	CriticalCount   int             `json:"criticalCount"`            // Already broken findings
	TotalCount      int             `json:"totalCount"`               // Total findings
	ByPrimitive     map[string]int  `json:"byPrimitive,omitempty"`    // Count by algorithm primitive
	ByAlgorithm     map[string]int  `json:"byAlgorithm,omitempty"`    // Count by algorithm name
	TopRiskFiles    []FileRiskScore `json:"topRiskFiles,omitempty"`   // Highest risk files
	QRAMMReadiness  *QRAMMReadiness `json:"qrammReadiness,omitempty"` // QRAMM dimension readiness
}

// FileRiskScore represents risk score for a single file
type FileRiskScore struct {
	File            string `json:"file"`
	VulnerableCount int    `json:"vulnerableCount"`
	CriticalCount   int    `json:"criticalCount"`
	TotalFindings   int    `json:"totalFindings"`
	RiskScore       int    `json:"riskScore"`
}

// QRAMMReadiness represents readiness scores mapped to QRAMM dimensions
type QRAMMReadiness struct {
	CVIScore        float64  `json:"cviScore"`        // Dimension 1: Cryptographic Visibility & Inventory
	DiscoveryLevel  int      `json:"discoveryLevel"`  // Practice 1.1 maturity indicator (1-5)
	AssessmentLevel int      `json:"assessmentLevel"` // Practice 1.2 maturity indicator (1-5)
	MappingLevel    int      `json:"mappingLevel"`    // Practice 1.3 maturity indicator (1-5)
	Recommendations []string `json:"recommendations,omitempty"`
}

// AlgorithmOIDs maps algorithm names to their OIDs
var AlgorithmOIDs = map[string]string{
	// ML-KEM (FIPS 203)
	"ML-KEM-512":  "2.16.840.1.101.3.4.4.1",
	"ML-KEM-768":  "2.16.840.1.101.3.4.4.2",
	"ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
	// ML-DSA (FIPS 204)
	"ML-DSA-44": "2.16.840.1.101.3.4.3.17",
	"ML-DSA-65": "2.16.840.1.101.3.4.3.18",
	"ML-DSA-87": "2.16.840.1.101.3.4.3.19",
	// SLH-DSA (FIPS 205)
	"SLH-DSA-128f": "2.16.840.1.101.3.4.3.20",
	"SLH-DSA-128s": "2.16.840.1.101.3.4.3.21",
	"SLH-DSA-192f": "2.16.840.1.101.3.4.3.22",
	"SLH-DSA-192s": "2.16.840.1.101.3.4.3.23",
	"SLH-DSA-256f": "2.16.840.1.101.3.4.3.24",
	"SLH-DSA-256s": "2.16.840.1.101.3.4.3.25",
	// AES
	"AES-128-GCM": "2.16.840.1.101.3.4.1.6",
	"AES-192-GCM": "2.16.840.1.101.3.4.1.26",
	"AES-256-GCM": "2.16.840.1.101.3.4.1.46",
	"AES-128-CBC": "2.16.840.1.101.3.4.1.2",
	"AES-192-CBC": "2.16.840.1.101.3.4.1.22",
	"AES-256-CBC": "2.16.840.1.101.3.4.1.42",
	// SHA-2
	"SHA-256": "2.16.840.1.101.3.4.2.1",
	"SHA-384": "2.16.840.1.101.3.4.2.2",
	"SHA-512": "2.16.840.1.101.3.4.2.3",
	// SHA-3
	"SHA3-256": "2.16.840.1.101.3.4.2.8",
	"SHA3-384": "2.16.840.1.101.3.4.2.9",
	"SHA3-512": "2.16.840.1.101.3.4.2.10",
	// SHAKE
	"SHAKE128": "2.16.840.1.101.3.4.2.11",
	"SHAKE256": "2.16.840.1.101.3.4.2.12",
	// HMAC
	"HMAC-SHA256": "1.2.840.113549.2.9",
	"HMAC-SHA384": "1.2.840.113549.2.10",
	"HMAC-SHA512": "1.2.840.113549.2.11",
	// KMAC
	"KMAC128": "2.16.840.1.101.3.4.2.19",
	"KMAC256": "2.16.840.1.101.3.4.2.20",
	// RSA
	"RSA":   "1.2.840.113549.1.1.1",
	"ECDSA": "1.2.840.10045.4.3.2",
}
