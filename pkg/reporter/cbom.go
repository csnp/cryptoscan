// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"time"

	"github.com/csnp/qramm-cryptoscan/pkg/scanner"
)

// CBOMReporter generates Cryptographic Bill of Materials output
// Based on CycloneDX CBOM specification
type CBOMReporter struct{}

// NewCBOMReporter creates a new CBOM reporter
func NewCBOMReporter() *CBOMReporter {
	return &CBOMReporter{}
}

// CBOM structures following CycloneDX CBOM format
type cbomReport struct {
	BOMFormat    string            `json:"bomFormat"`
	SpecVersion  string            `json:"specVersion"`
	SerialNumber string            `json:"serialNumber"`
	Version      int               `json:"version"`
	Metadata     cbomMetadata      `json:"metadata"`
	Components   []cbomComponent   `json:"components"`
	Services     []cbomService     `json:"services,omitempty"`
	Dependencies []cbomDependency  `json:"dependencies,omitempty"`
}

type cbomMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     []cbomTool   `json:"tools"`
	Component *cbomComponent `json:"component,omitempty"`
}

type cbomTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cbomComponent struct {
	Type               string                `json:"type"`
	BOMRef             string                `json:"bom-ref,omitempty"`
	Name               string                `json:"name"`
	Version            string                `json:"version,omitempty"`
	Description        string                `json:"description,omitempty"`
	CryptoProperties   *cbomCryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence           *cbomEvidence         `json:"evidence,omitempty"`
}

type cbomCryptoProperties struct {
	AssetType               string            `json:"assetType"`
	AlgorithmProperties     *cbomAlgorithm    `json:"algorithmProperties,omitempty"`
	CertificateProperties   *cbomCertificate  `json:"certificateProperties,omitempty"`
	ProtocolProperties      *cbomProtocol     `json:"protocolProperties,omitempty"`
	OID                     string            `json:"oid,omitempty"`
}

type cbomAlgorithm struct {
	Primitive            string   `json:"primitive,omitempty"`
	ParameterSetIdentifier string `json:"parameterSetIdentifier,omitempty"`
	Mode                 string   `json:"mode,omitempty"`
	Padding              string   `json:"padding,omitempty"`
	CryptoFunctions      []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel int    `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel int  `json:"nistQuantumSecurityLevel,omitempty"`
}

type cbomCertificate struct {
	SubjectName   string `json:"subjectName,omitempty"`
	IssuerName    string `json:"issuerName,omitempty"`
	NotValidBefore string `json:"notValidBefore,omitempty"`
	NotValidAfter  string `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
}

type cbomProtocol struct {
	Type          string   `json:"type,omitempty"`
	Version       string   `json:"version,omitempty"`
	CipherSuites  []cbomCipherSuite `json:"cipherSuites,omitempty"`
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
	BOMRef   string   `json:"bom-ref,omitempty"`
	Name     string   `json:"name,omitempty"`
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
	switch algo {
	case "RSA":
		return "pke"
	case "ECDSA", "DSA", "Ed25519":
		return "signature"
	case "DH", "ECDH", "X25519":
		return "kdf"
	case "AES", "DES", "3DES", "Blowfish", "ChaCha20", "RC4":
		return "block-cipher"
	case "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA-3":
		return "hash"
	default:
		return "other"
	}
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
	componentMap := make(map[string]bool)

	for i, f := range results.Findings {
		// Create unique component key
		compKey := f.Algorithm
		if compKey == "" {
			compKey = f.Type
		}

		// Build component
		comp := cbomComponent{
			Type:        "cryptographic-asset",
			BOMRef:      f.ID,
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

		// Add algorithm properties
		if f.Algorithm != "" {
			comp.CryptoProperties.AlgorithmProperties = &cbomAlgorithm{
				Primitive: algorithmToPrimitive(f.Algorithm),
			}
			if f.KeySize > 0 {
				comp.CryptoProperties.AlgorithmProperties.ClassicalSecurityLevel = keySizeToSecurityLevel(f.KeySize, f.Algorithm)
			}
			if f.Quantum == scanner.QuantumSafe {
				comp.CryptoProperties.AlgorithmProperties.NISTQuantumSecurityLevel = 1
			}
		}

		// Add protocol properties for TLS findings
		if f.Category == "tls" || f.Category == "protocol" {
			comp.CryptoProperties.ProtocolProperties = &cbomProtocol{
				Type: "tls",
			}
		}

		// Deduplicate components by merging occurrences
		if !componentMap[compKey] {
			componentMap[compKey] = true
			components = append(components, comp)
		} else {
			// Find existing component and add occurrence
			for j := range components {
				if components[j].Name == compKey {
					components[j].Evidence.Occurrences = append(
						components[j].Evidence.Occurrences,
						cbomOccurrence{
							Location: f.File,
							Line:     f.Line,
							Symbol:   f.Match,
						},
					)
					break
				}
			}
		}
		_ = i // suppress unused warning
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
					Version: "1.0.0",
				},
			},
		},
		Components: components,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Simple UUID generator for CBOM serial numbers
func generateUUID() string {
	return time.Now().Format("20060102-150405-000000000")
}
