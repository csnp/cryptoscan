// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/types"
)

// CBOMReporter generates Cryptographic Bill of Materials output
// Based on CycloneDX CBOM 1.6 specification
type CBOMReporter struct {
	remediationEngine *analyzer.RemediationEngine
}

// NewCBOMReporter creates a new CBOM reporter
func NewCBOMReporter() *CBOMReporter {
	return &CBOMReporter{
		remediationEngine: analyzer.NewRemediationEngine(),
	}
}

// CBOM structures following CycloneDX CBOM format
type cbomReport struct {
	BOMFormat    string           `json:"bomFormat"`
	SpecVersion  string           `json:"specVersion"`
	SerialNumber string           `json:"serialNumber"`
	Version      int              `json:"version"`
	Metadata     cbomMetadata     `json:"metadata"`
	Components   []cbomComponent  `json:"components"`
	Services     []cbomService    `json:"services,omitempty"`
	Dependencies []cbomDependency `json:"dependencies,omitempty"`
}

type cbomMetadata struct {
	Timestamp string         `json:"timestamp"`
	Tools     []cbomTool     `json:"tools"`
	Component *cbomComponent `json:"component,omitempty"`
}

type cbomTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cbomComponent struct {
	Type             string                `json:"type"`
	BOMRef           string                `json:"bom-ref,omitempty"`
	Name             string                `json:"name"`
	Version          string                `json:"version,omitempty"`
	Description      string                `json:"description,omitempty"`
	CryptoProperties *cbomCryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *cbomEvidence         `json:"evidence,omitempty"`
}

type cbomCryptoProperties struct {
	AssetType             string           `json:"assetType"`
	AlgorithmProperties   *cbomAlgorithm   `json:"algorithmProperties,omitempty"`
	CertificateProperties *cbomCertificate `json:"certificateProperties,omitempty"`
	ProtocolProperties    *cbomProtocol    `json:"protocolProperties,omitempty"`
	OID                   string           `json:"oid,omitempty"`
}

type cbomAlgorithm struct {
	Primitive                string   `json:"primitive,omitempty"`
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	ExecutionEnvironment     string   `json:"executionEnvironment,omitempty"`
	ImplementationPlatform   string   `json:"implementationPlatform,omitempty"`
	CertificationLevel       []string `json:"certificationLevel,omitempty"`
	Mode                     string   `json:"mode,omitempty"`
	Padding                  string   `json:"padding,omitempty"`
	CryptoFunctions          []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   int      `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel int      `json:"nistQuantumSecurityLevel,omitempty"`
}

type cbomCertificate struct {
	SubjectName           string `json:"subjectName,omitempty"`
	IssuerName            string `json:"issuerName,omitempty"`
	NotValidBefore        string `json:"notValidBefore,omitempty"`
	NotValidAfter         string `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
}

type cbomProtocol struct {
	Type         string            `json:"type,omitempty"`
	Version      string            `json:"version,omitempty"`
	CipherSuites []cbomCipherSuite `json:"cipherSuites,omitempty"`
}

type cbomCipherSuite struct {
	Name        string   `json:"name,omitempty"`
	Algorithms  []string `json:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

type cbomEvidence struct {
	Occurrences []cbomOccurrence `json:"occurrences,omitempty"`
}

type cbomOccurrence struct {
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
}

type cbomService struct {
	BOMRef    string   `json:"bom-ref,omitempty"`
	Name      string   `json:"name,omitempty"`
	Endpoints []string `json:"endpoints,omitempty"`
}

type cbomDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func categoryToAssetType(category string) string {
	switch category {
	case "asymmetric", "key-exchange":
		return "algorithm"
	case "symmetric":
		return "algorithm"
	case "hash":
		return "algorithm"
	case "tls", "protocol":
		return "protocol"
	case "certificate", "key":
		return "certificate"
	case "library":
		return "related-crypto-material"
	default:
		return "algorithm"
	}
}

func algorithmToPrimitive(algo string) string {
	algoUpper := strings.ToUpper(algo)
	switch {
	// MACs - check before hashes because HMAC-SHA256 contains SHA
	case strings.Contains(algoUpper, "HMAC"), strings.Contains(algoUpper, "KMAC"),
		strings.Contains(algoUpper, "CMAC"), strings.Contains(algoUpper, "GMAC"),
		strings.Contains(algoUpper, "POLY1305"):
		return "mac"
	// KDFs - check before hashes because some KDFs use hash names
	case strings.Contains(algoUpper, "HKDF"), strings.Contains(algoUpper, "PBKDF"),
		strings.Contains(algoUpper, "ARGON"), strings.Contains(algoUpper, "SCRYPT"),
		strings.Contains(algoUpper, "BCRYPT"):
		return "kdf"
	// Post-Quantum KEMs
	case strings.Contains(algoUpper, "ML-KEM"), strings.Contains(algoUpper, "MLKEM"),
		strings.Contains(algoUpper, "KYBER"):
		return "kem"
	// Post-Quantum Signatures
	case strings.Contains(algoUpper, "ML-DSA"), strings.Contains(algoUpper, "MLDSA"),
		strings.Contains(algoUpper, "DILITHIUM"),
		strings.Contains(algoUpper, "SLH-DSA"), strings.Contains(algoUpper, "SLHDSA"),
		strings.Contains(algoUpper, "SPHINCS"),
		strings.Contains(algoUpper, "FN-DSA"), strings.Contains(algoUpper, "FNDSA"),
		strings.Contains(algoUpper, "FALCON"),
		strings.Contains(algoUpper, "XMSS"), strings.Contains(algoUpper, "LMS"):
		return "signature"
	// Hybrid
	case strings.Contains(algoUpper, "HYBRID"), strings.Contains(algoUpper, "COMPOSITE"):
		return "hybrid"
	// Classical asymmetric
	case algo == "RSA":
		return "pke"
	case algo == "ECDSA", algo == "DSA", algo == "Ed25519":
		return "signature"
	case algo == "DH", algo == "ECDH", algo == "X25519":
		return "key-agreement"
	// Symmetric
	case algo == "AES", algo == "DES", algo == "3DES", algo == "Blowfish", algo == "RC4":
		return "block-cipher"
	case strings.Contains(algoUpper, "CHACHA"):
		return "stream-cipher"
	// Hashes
	case strings.Contains(algoUpper, "MD5"), strings.Contains(algoUpper, "SHA"),
		strings.Contains(algoUpper, "SHAKE"), strings.Contains(algoUpper, "BLAKE"):
		return "hash"
	default:
		return "other"
	}
}

// getAlgorithmOID returns the OID for known algorithms
func getAlgorithmOID(algo string) string {
	if oid, ok := types.AlgorithmOIDs[algo]; ok {
		return oid
	}
	// Try uppercase
	if oid, ok := types.AlgorithmOIDs[strings.ToUpper(algo)]; ok {
		return oid
	}
	return ""
}

// getNISTQuantumLevel returns the NIST quantum security level (1-5) for an algorithm
func getNISTQuantumLevel(algo string, quantum types.QuantumRisk) int {
	algoUpper := strings.ToUpper(algo)

	// PQC algorithms have explicit NIST levels
	switch {
	case strings.Contains(algoUpper, "512"):
		if strings.Contains(algoUpper, "ML-KEM") || strings.Contains(algoUpper, "KYBER") {
			return 1
		}
		if strings.Contains(algoUpper, "FALCON") || strings.Contains(algoUpper, "FN-DSA") {
			return 1
		}
	case strings.Contains(algoUpper, "768"):
		return 3 // ML-KEM-768
	case strings.Contains(algoUpper, "1024"):
		if strings.Contains(algoUpper, "ML-KEM") || strings.Contains(algoUpper, "KYBER") {
			return 5
		}
		if strings.Contains(algoUpper, "FALCON") || strings.Contains(algoUpper, "FN-DSA") {
			return 5
		}
	case strings.Contains(algoUpper, "ML-DSA-44"), strings.Contains(algoUpper, "DILITHIUM2"):
		return 2
	case strings.Contains(algoUpper, "ML-DSA-65"), strings.Contains(algoUpper, "DILITHIUM3"):
		return 3
	case strings.Contains(algoUpper, "ML-DSA-87"), strings.Contains(algoUpper, "DILITHIUM5"):
		return 5
	case strings.Contains(algoUpper, "SLH-DSA-128"), strings.Contains(algoUpper, "SPHINCS+-128"):
		return 1
	case strings.Contains(algoUpper, "SLH-DSA-192"), strings.Contains(algoUpper, "SPHINCS+-192"):
		return 3
	case strings.Contains(algoUpper, "SLH-DSA-256"), strings.Contains(algoUpper, "SPHINCS+-256"):
		return 5
	case strings.Contains(algoUpper, "XMSS"), strings.Contains(algoUpper, "LMS"):
		return 1 // Stateful HBS are generally Level 1
	case strings.Contains(algoUpper, "KMAC"), strings.Contains(algoUpper, "SHA3"),
		strings.Contains(algoUpper, "SHAKE"):
		return 1 // Quantum-safe symmetric primitives
	}

	// For safe algorithms without explicit level
	if quantum == types.QuantumSafe {
		return 1
	}

	return 0 // Not quantum-safe
}

func keySizeToSecurityLevel(keySize int, algo string) int {
	switch algo {
	case "RSA":
		if keySize >= 4096 {
			return 192
		} else if keySize >= 3072 {
			return 128
		} else if keySize >= 2048 {
			return 112
		}
		return 80
	case "AES":
		return keySize
	default:
		return 0
	}
}

// Generate creates the CBOM report
func (r *CBOMReporter) Generate(results *scanner.Results) (string, error) {
	components := make([]cbomComponent, 0, len(results.Findings))
	componentMap := make(map[string]*cbomComponent)
	dependencies := make([]cbomDependency, 0)
	hybridComponents := make(map[string][]string) // Track hybrid -> component dependencies

	for _, f := range results.Findings {
		// Create unique component key
		compKey := f.Algorithm
		if compKey == "" {
			compKey = f.Type
		}

		// Generate a stable BOM reference
		bomRef := fmt.Sprintf("crypto-%s-%d", sanitizeBOMRef(compKey), len(componentMap))

		// Build component
		comp := cbomComponent{
			Type:        "cryptographic-asset",
			BOMRef:      bomRef,
			Name:        compKey,
			Description: f.Description,
			CryptoProperties: &cbomCryptoProperties{
				AssetType: categoryToAssetType(f.Category),
			},
			Evidence: &cbomEvidence{
				Occurrences: []cbomOccurrence{
					{
						Location: f.File,
						Line:     f.Line,
						Symbol:   f.Match,
					},
				},
			},
		}

		// Add OID if available
		if oid := getAlgorithmOID(f.Algorithm); oid != "" {
			comp.CryptoProperties.OID = oid
		}

		// Add algorithm properties
		if f.Algorithm != "" {
			primitive := algorithmToPrimitive(f.Algorithm)
			comp.CryptoProperties.AlgorithmProperties = &cbomAlgorithm{
				Primitive: primitive,
			}

			// Set parameter set identifier for PQC algorithms
			if paramSet := extractParameterSet(f.Algorithm); paramSet != "" {
				comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = paramSet
			}

			// Set classical security level
			if f.KeySize > 0 {
				comp.CryptoProperties.AlgorithmProperties.ClassicalSecurityLevel = keySizeToSecurityLevel(f.KeySize, f.Algorithm)
			} else {
				// Estimate from algorithm
				comp.CryptoProperties.AlgorithmProperties.ClassicalSecurityLevel = estimateClassicalSecurity(f.Algorithm)
			}

			// Set NIST quantum security level
			nistLevel := getNISTQuantumLevel(f.Algorithm, f.Quantum)
			if nistLevel > 0 {
				comp.CryptoProperties.AlgorithmProperties.NISTQuantumSecurityLevel = nistLevel
			}

			// Track hybrid dependencies
			if primitive == "hybrid" {
				classicalAlgo, pqcAlgo := extractHybridComponents(f.Algorithm)
				if classicalAlgo != "" {
					hybridComponents[bomRef] = append(hybridComponents[bomRef], classicalAlgo)
				}
				if pqcAlgo != "" {
					hybridComponents[bomRef] = append(hybridComponents[bomRef], pqcAlgo)
				}
			}
		}

		// Add protocol properties for TLS findings
		if f.Category == "tls" || f.Category == "protocol" {
			comp.CryptoProperties.ProtocolProperties = &cbomProtocol{
				Type: "tls",
			}
			// Extract TLS version if present
			if version := extractTLSVersion(f.Match); version != "" {
				comp.CryptoProperties.ProtocolProperties.Version = version
			}
		}

		// Deduplicate components by merging occurrences
		if existing, ok := componentMap[compKey]; ok {
			existing.Evidence.Occurrences = append(
				existing.Evidence.Occurrences,
				cbomOccurrence{
					Location: f.File,
					Line:     f.Line,
					Symbol:   f.Match,
				},
			)
		} else {
			componentMap[compKey] = &comp
			components = append(components, comp)
		}
	}

	// Build dependencies for hybrid components
	for hybridRef, depAlgos := range hybridComponents {
		dep := cbomDependency{
			Ref:       hybridRef,
			DependsOn: make([]string, 0),
		}
		for _, algoName := range depAlgos {
			// Find the component ref for this algorithm
			for _, c := range components {
				if c.Name == algoName {
					dep.DependsOn = append(dep.DependsOn, c.BOMRef)
					break
				}
			}
		}
		if len(dep.DependsOn) > 0 {
			dependencies = append(dependencies, dep)
		}
	}

	// Add migration score summary if available
	var summaryComponent *cbomComponent
	if results.MigrationScore != nil {
		summaryComponent = &cbomComponent{
			Type:        "cryptographic-asset",
			BOMRef:      "crypto-inventory-summary",
			Name:        "Cryptographic Inventory Summary",
			Description: fmt.Sprintf("Migration Readiness: %.1f%% (%s)", results.MigrationScore.Score, results.MigrationScore.Level),
		}
	}

	report := cbomReport{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + generateUUID(),
		Version:      1,
		Metadata: cbomMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cbomTool{
				{
					Vendor:  "CSNP",
					Name:    "CryptoScan",
					Version: "1.1.0",
				},
			},
			Component: summaryComponent,
		},
		Components:   components,
		Dependencies: dependencies,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// sanitizeBOMRef creates a valid BOM reference from a string
func sanitizeBOMRef(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, "+", "-")
	return s
}

// extractParameterSet extracts the parameter set from an algorithm name
func extractParameterSet(algo string) string {
	algoUpper := strings.ToUpper(algo)
	switch {
	case strings.Contains(algoUpper, "ML-KEM-512"), strings.Contains(algoUpper, "KYBER512"):
		return "ML-KEM-512"
	case strings.Contains(algoUpper, "ML-KEM-768"), strings.Contains(algoUpper, "KYBER768"):
		return "ML-KEM-768"
	case strings.Contains(algoUpper, "ML-KEM-1024"), strings.Contains(algoUpper, "KYBER1024"):
		return "ML-KEM-1024"
	case strings.Contains(algoUpper, "ML-DSA-44"), strings.Contains(algoUpper, "DILITHIUM2"):
		return "ML-DSA-44"
	case strings.Contains(algoUpper, "ML-DSA-65"), strings.Contains(algoUpper, "DILITHIUM3"):
		return "ML-DSA-65"
	case strings.Contains(algoUpper, "ML-DSA-87"), strings.Contains(algoUpper, "DILITHIUM5"):
		return "ML-DSA-87"
	case strings.Contains(algoUpper, "SLH-DSA-128"):
		return "SLH-DSA-128"
	case strings.Contains(algoUpper, "SLH-DSA-192"):
		return "SLH-DSA-192"
	case strings.Contains(algoUpper, "SLH-DSA-256"):
		return "SLH-DSA-256"
	}
	return ""
}

// estimateClassicalSecurity estimates classical security bits for algorithms
func estimateClassicalSecurity(algo string) int {
	algoUpper := strings.ToUpper(algo)
	switch {
	case strings.Contains(algoUpper, "256"):
		return 256
	case strings.Contains(algoUpper, "384"):
		return 384
	case strings.Contains(algoUpper, "512"):
		return 512
	case strings.Contains(algoUpper, "128"):
		return 128
	case strings.Contains(algoUpper, "192"):
		return 192
	case strings.Contains(algoUpper, "ML-KEM-768"), strings.Contains(algoUpper, "KYBER768"):
		return 192
	case strings.Contains(algoUpper, "ML-DSA-65"), strings.Contains(algoUpper, "DILITHIUM3"):
		return 192
	case strings.Contains(algoUpper, "AES"):
		return 256 // Assume AES-256
	case strings.Contains(algoUpper, "CHACHA"):
		return 256
	}
	return 0
}

// extractHybridComponents extracts the classical and PQC algorithm names from a hybrid
func extractHybridComponents(algo string) (classical string, pqc string) {
	algoUpper := strings.ToUpper(algo)
	switch {
	case strings.Contains(algoUpper, "X25519") && strings.Contains(algoUpper, "MLKEM"):
		return "X25519", "ML-KEM-768"
	case strings.Contains(algoUpper, "X25519") && strings.Contains(algoUpper, "KYBER"):
		return "X25519", "ML-KEM-768"
	case strings.Contains(algoUpper, "ECDSA") && strings.Contains(algoUpper, "MLDSA"):
		return "ECDSA", "ML-DSA-65"
	case strings.Contains(algoUpper, "ECDSA") && strings.Contains(algoUpper, "DILITHIUM"):
		return "ECDSA", "ML-DSA-65"
	case strings.Contains(algoUpper, "RSA") && strings.Contains(algoUpper, "MLDSA"):
		return "RSA", "ML-DSA-65"
	}
	return "", ""
}

// extractTLSVersion extracts the TLS version from a match string
func extractTLSVersion(match string) string {
	matchUpper := strings.ToUpper(match)
	switch {
	case strings.Contains(matchUpper, "1.3") || strings.Contains(matchUpper, "TLS13"):
		return "1.3"
	case strings.Contains(matchUpper, "1.2") || strings.Contains(matchUpper, "TLS12"):
		return "1.2"
	case strings.Contains(matchUpper, "1.1") || strings.Contains(matchUpper, "TLS11"):
		return "1.1"
	case strings.Contains(matchUpper, "1.0") || strings.Contains(matchUpper, "TLS10"):
		return "1.0"
	}
	return ""
}

// Simple UUID generator for CBOM serial numbers
func generateUUID() string {
	return time.Now().Format("20060102-150405-000000000")
}
