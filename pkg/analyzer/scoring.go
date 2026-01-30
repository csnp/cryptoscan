// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"sort"
	"strings"

	"github.com/csnp/cryptoscan/pkg/types"
)

// CalculateMigrationScore computes the quantum migration readiness score
func CalculateMigrationScore(findings []types.Finding) *types.MigrationScore {
	score := &types.MigrationScore{
		ByPrimitive: make(map[string]int),
		ByAlgorithm: make(map[string]int),
	}

	fileRisks := make(map[string]*types.FileRiskScore)

	for i := range findings {
		f := &findings[i]

		// Classify the finding
		status := ClassifyMigrationStatus(f)
		f.MigrationStatus = status

		// Assign QRAMM mapping
		f.QRAMMMapping = GetQRAMMMapping(f)

		// Assign primitive type
		f.Primitive = GetAlgorithmPrimitive(f.Algorithm, f.Category)

		// Assign security level
		f.SecurityLevel = GetSecurityLevel(f.Algorithm, f.KeySize)

		// Assign OID if available
		if oid, ok := types.AlgorithmOIDs[f.Algorithm]; ok {
			f.OID = oid
		}

		// Count by status
		switch status {
		case types.MigrationStatusSafe:
			score.SafeCount++
		case types.MigrationStatusHybrid:
			score.HybridCount++
		case types.MigrationStatusPartial:
			score.PartialCount++
		case types.MigrationStatusVulnerable:
			score.VulnerableCount++
		case types.MigrationStatusCritical:
			score.CriticalCount++
		}
		score.TotalCount++

		// Count by primitive
		if f.Primitive != "" {
			score.ByPrimitive[string(f.Primitive)]++
		}

		// Count by algorithm
		if f.Algorithm != "" {
			score.ByAlgorithm[f.Algorithm]++
		}

		// Track file risks
		if _, ok := fileRisks[f.File]; !ok {
			fileRisks[f.File] = &types.FileRiskScore{File: f.File}
		}
		fr := fileRisks[f.File]
		fr.TotalFindings++
		if status == types.MigrationStatusVulnerable {
			fr.VulnerableCount++
			fr.RiskScore += 10
		}
		if status == types.MigrationStatusCritical {
			fr.CriticalCount++
			fr.RiskScore += 25
		}
	}

	// Calculate score: (Safe + Hybrid×0.8 + Partial×0.3) / Total × 100
	if score.TotalCount > 0 {
		numerator := float64(score.SafeCount) +
			float64(score.HybridCount)*0.8 +
			float64(score.PartialCount)*0.3
		score.Score = (numerator / float64(score.TotalCount)) * 100
	}

	// Determine risk level
	score.Level = DetermineRiskLevel(score)

	// Get top risk files
	var fileList []types.FileRiskScore
	for _, fr := range fileRisks {
		if fr.VulnerableCount > 0 || fr.CriticalCount > 0 {
			fileList = append(fileList, *fr)
		}
	}
	sort.Slice(fileList, func(i, j int) bool {
		return fileList[i].RiskScore > fileList[j].RiskScore
	})
	if len(fileList) > 5 {
		fileList = fileList[:5]
	}
	score.TopRiskFiles = fileList

	// Calculate QRAMM readiness
	score.QRAMMReadiness = CalculateQRAMMReadiness(score)

	return score
}

// ClassifyMigrationStatus determines the migration status of a finding
func ClassifyMigrationStatus(f *types.Finding) types.MigrationStatus {
	// Check tags for explicit classification
	for _, tag := range f.Tags {
		if tag == "quantum-safe" || tag == "pqc" {
			return types.MigrationStatusSafe
		}
		if tag == "hybrid" {
			return types.MigrationStatusHybrid
		}
	}

	// Check category
	if f.Category == "Post-Quantum Cryptography" || f.Category == "Hybrid Cryptography" {
		if strings.Contains(f.Category, "Hybrid") {
			return types.MigrationStatusHybrid
		}
		return types.MigrationStatusSafe
	}

	// Check quantum risk
	switch f.Quantum {
	case types.QuantumSafe:
		return types.MigrationStatusSafe
	case types.QuantumPartial:
		return types.MigrationStatusPartial
	case types.QuantumVulnerable:
		// Check if it's already broken (MD5, SHA-1, DES, RC4)
		algo := strings.ToUpper(f.Algorithm)
		if algo == "MD5" || algo == "DES" || algo == "RC4" || algo == "SHA-1" {
			return types.MigrationStatusCritical
		}
		if f.Severity == types.SeverityCritical {
			return types.MigrationStatusCritical
		}
		return types.MigrationStatusVulnerable
	}

	return types.MigrationStatusPartial
}

// GetQRAMMMapping returns the QRAMM framework mapping for a finding
func GetQRAMMMapping(f *types.Finding) *types.QRAMMMapping {
	mapping := &types.QRAMMMapping{
		Dimension: types.QRAMMDimensionCVI, // All CryptoScan findings map to CVI
	}

	// Determine which CVI practice this maps to
	switch f.FindingType {
	case types.FindingTypeAlgorithm:
		mapping.Practice = types.QRAMMPracticeCVI11 // Discovery & Inventory
		mapping.Evidence = "Automated cryptographic algorithm discovery"
	case types.FindingTypeDependency:
		mapping.Practice = types.QRAMMPracticeCVI13 // Dependency Mapping
		mapping.Evidence = "Cryptographic library dependency identification"
	case types.FindingTypeSecret:
		mapping.Practice = types.QRAMMPracticeCVI11 // Discovery & Inventory
		mapping.Evidence = "Cryptographic key material discovery"
	case types.FindingTypeConfig:
		mapping.Practice = types.QRAMMPracticeCVI12 // Vulnerability Assessment
		mapping.Evidence = "Cryptographic configuration assessment"
	case types.FindingTypeProtocol:
		mapping.Practice = types.QRAMMPracticeCVI12 // Vulnerability Assessment
		mapping.Evidence = "Protocol security assessment"
	default:
		mapping.Practice = types.QRAMMPracticeCVI11
		mapping.Evidence = "Cryptographic asset discovery"
	}

	// Adjust based on quantum risk assessment
	if f.Quantum == types.QuantumVulnerable || f.Quantum == types.QuantumPartial {
		mapping.Practice = types.QRAMMPracticeCVI12 // Vulnerability Assessment
		mapping.Evidence = "Quantum vulnerability assessment and classification"
	}

	return mapping
}

// GetAlgorithmPrimitive returns the primitive type for an algorithm
func GetAlgorithmPrimitive(algorithm, category string) types.AlgorithmPrimitive {
	algo := strings.ToUpper(algorithm)

	// KEMs
	if strings.Contains(algo, "KEM") || strings.Contains(algo, "KYBER") {
		return types.PrimitiveKEM
	}

	// Signatures
	sigAlgos := []string{"DSA", "DILITHIUM", "SPHINCS", "FALCON", "ED25519", "ECDSA"}
	for _, sig := range sigAlgos {
		if strings.Contains(algo, sig) {
			return types.PrimitiveSignature
		}
	}

	// Hashes
	hashAlgos := []string{"SHA", "MD5", "BLAKE", "KECCAK"}
	for _, hash := range hashAlgos {
		if strings.Contains(algo, hash) && !strings.Contains(algo, "HMAC") {
			if strings.Contains(algo, "SHAKE") {
				return types.PrimitiveXOF
			}
			return types.PrimitiveHash
		}
	}

	// MACs
	macAlgos := []string{"HMAC", "KMAC", "CMAC", "GMAC", "POLY1305", "CBC-MAC"}
	for _, mac := range macAlgos {
		if strings.Contains(algo, mac) {
			return types.PrimitiveMAC
		}
	}

	// KDFs
	kdfAlgos := []string{"HKDF", "PBKDF", "ARGON", "SCRYPT", "BCRYPT"}
	for _, kdf := range kdfAlgos {
		if strings.Contains(algo, kdf) {
			return types.PrimitiveKDF
		}
	}

	// AEAD
	if strings.Contains(algo, "GCM") || strings.Contains(algo, "POLY1305") ||
		strings.Contains(algo, "CCM") || strings.Contains(algo, "CHACHA20-POLY1305") {
		return types.PrimitiveAEAD
	}

	// Block ciphers
	blockCiphers := []string{"AES", "DES", "3DES", "BLOWFISH", "TWOFISH"}
	for _, bc := range blockCiphers {
		if strings.Contains(algo, bc) {
			return types.PrimitiveBlockCipher
		}
	}

	// Stream ciphers
	if strings.Contains(algo, "CHACHA") || strings.Contains(algo, "RC4") ||
		strings.Contains(algo, "SALSA") {
		return types.PrimitiveStreamCipher
	}

	// Key exchange
	if strings.Contains(algo, "DH") || strings.Contains(algo, "X25519") ||
		strings.Contains(algo, "ECDH") {
		return types.PrimitiveKeyExchange
	}

	// RSA is PKE
	if strings.Contains(algo, "RSA") {
		return types.PrimitivePKE
	}

	// Fall back to category
	switch strings.ToLower(category) {
	case "symmetric encryption":
		return types.PrimitiveBlockCipher
	case "asymmetric encryption":
		return types.PrimitivePKE
	case "hash function":
		return types.PrimitiveHash
	case "key exchange":
		return types.PrimitiveKeyExchange
	case "message authentication code":
		return types.PrimitiveMAC
	case "key derivation function":
		return types.PrimitiveKDF
	}

	return ""
}

// GetSecurityLevel returns the security level for an algorithm
func GetSecurityLevel(algorithm string, keySize int) *types.SecurityLevel {
	level := &types.SecurityLevel{}
	algo := strings.ToUpper(algorithm)

	// PQC algorithms with NIST levels
	switch {
	case strings.Contains(algo, "ML-KEM-512"), strings.Contains(algo, "KYBER512"):
		level.NISTQuantumLevel = 1
		level.ClassicalBits = 128
		level.QuantumSecurityBits = 128
	case strings.Contains(algo, "ML-KEM-768"), strings.Contains(algo, "KYBER768"):
		level.NISTQuantumLevel = 3
		level.ClassicalBits = 192
		level.QuantumSecurityBits = 192
	case strings.Contains(algo, "ML-KEM-1024"), strings.Contains(algo, "KYBER1024"):
		level.NISTQuantumLevel = 5
		level.ClassicalBits = 256
		level.QuantumSecurityBits = 256
	case strings.Contains(algo, "ML-DSA-44"), strings.Contains(algo, "DILITHIUM2"):
		level.NISTQuantumLevel = 2
		level.ClassicalBits = 128
		level.QuantumSecurityBits = 128
	case strings.Contains(algo, "ML-DSA-65"), strings.Contains(algo, "DILITHIUM3"):
		level.NISTQuantumLevel = 3
		level.ClassicalBits = 192
		level.QuantumSecurityBits = 192
	case strings.Contains(algo, "ML-DSA-87"), strings.Contains(algo, "DILITHIUM5"):
		level.NISTQuantumLevel = 5
		level.ClassicalBits = 256
		level.QuantumSecurityBits = 256
	case strings.Contains(algo, "SLH-DSA-128"), strings.Contains(algo, "SPHINCS-128"):
		level.NISTQuantumLevel = 1
		level.ClassicalBits = 128
		level.QuantumSecurityBits = 128
	case strings.Contains(algo, "SLH-DSA-192"), strings.Contains(algo, "SPHINCS-192"):
		level.NISTQuantumLevel = 3
		level.ClassicalBits = 192
		level.QuantumSecurityBits = 192
	case strings.Contains(algo, "SLH-DSA-256"), strings.Contains(algo, "SPHINCS-256"):
		level.NISTQuantumLevel = 5
		level.ClassicalBits = 256
		level.QuantumSecurityBits = 256
	}

	// If already set, return
	if level.NISTQuantumLevel > 0 {
		return level
	}

	// Classical algorithms
	switch {
	case strings.Contains(algo, "RSA"):
		if keySize >= 4096 {
			level.ClassicalBits = 152
		} else if keySize >= 3072 {
			level.ClassicalBits = 128
		} else if keySize >= 2048 {
			level.ClassicalBits = 112
		} else if keySize >= 1024 {
			level.ClassicalBits = 80
		}
		level.QuantumSecurityBits = 0 // Broken by Shor's

	case strings.Contains(algo, "AES"):
		if keySize > 0 {
			level.ClassicalBits = keySize
			level.QuantumSecurityBits = keySize / 2 // Grover's algorithm
		} else if strings.Contains(algo, "256") {
			level.ClassicalBits = 256
			level.QuantumSecurityBits = 128
		} else if strings.Contains(algo, "192") {
			level.ClassicalBits = 192
			level.QuantumSecurityBits = 96
		} else if strings.Contains(algo, "128") {
			level.ClassicalBits = 128
			level.QuantumSecurityBits = 64
		}

	case strings.Contains(algo, "SHA-256"), strings.Contains(algo, "SHA256"):
		level.ClassicalBits = 128      // Collision resistance
		level.QuantumSecurityBits = 85 // Grover for collision

	case strings.Contains(algo, "SHA-384"), strings.Contains(algo, "SHA384"):
		level.ClassicalBits = 192
		level.QuantumSecurityBits = 128

	case strings.Contains(algo, "SHA-512"), strings.Contains(algo, "SHA512"):
		level.ClassicalBits = 256
		level.QuantumSecurityBits = 170

	case strings.Contains(algo, "SHA3-256"):
		level.ClassicalBits = 128
		level.QuantumSecurityBits = 128

	case strings.Contains(algo, "SHA3-384"):
		level.ClassicalBits = 192
		level.QuantumSecurityBits = 192

	case strings.Contains(algo, "SHA3-512"):
		level.ClassicalBits = 256
		level.QuantumSecurityBits = 256

	case strings.Contains(algo, "SHAKE256"):
		level.ClassicalBits = 256
		level.QuantumSecurityBits = 256

	case strings.Contains(algo, "KMAC-256"), strings.Contains(algo, "KMAC256"):
		level.ClassicalBits = 256
		level.QuantumSecurityBits = 256

	case strings.Contains(algo, "CHACHA20"):
		level.ClassicalBits = 256
		level.QuantumSecurityBits = 128

	case strings.Contains(algo, "ED25519"), strings.Contains(algo, "X25519"):
		level.ClassicalBits = 128
		level.QuantumSecurityBits = 0 // Broken by Shor's

	case strings.Contains(algo, "P-256"), strings.Contains(algo, "SECP256"):
		level.ClassicalBits = 128
		level.QuantumSecurityBits = 0

	case strings.Contains(algo, "P-384"), strings.Contains(algo, "SECP384"):
		level.ClassicalBits = 192
		level.QuantumSecurityBits = 0

	case strings.Contains(algo, "P-521"), strings.Contains(algo, "SECP521"):
		level.ClassicalBits = 256
		level.QuantumSecurityBits = 0

	case strings.Contains(algo, "MD5"):
		level.ClassicalBits = 0 // Broken
		level.QuantumSecurityBits = 0

	case strings.Contains(algo, "SHA-1"), strings.Contains(algo, "SHA1"):
		level.ClassicalBits = 63 // Practical collision attacks
		level.QuantumSecurityBits = 0

	case strings.Contains(algo, "DES") && !strings.Contains(algo, "3DES"):
		level.ClassicalBits = 56
		level.QuantumSecurityBits = 28

	case strings.Contains(algo, "3DES"):
		level.ClassicalBits = 112
		level.QuantumSecurityBits = 56
	}

	if level.ClassicalBits == 0 && level.QuantumSecurityBits == 0 && level.NISTQuantumLevel == 0 {
		return nil
	}

	return level
}

// DetermineRiskLevel returns the risk level based on the migration score
func DetermineRiskLevel(score *types.MigrationScore) string {
	if score.CriticalCount > 0 {
		return "CRITICAL"
	}
	if score.Score < 25 {
		return "CRITICAL"
	}
	if score.Score < 50 {
		return "HIGH"
	}
	if score.Score < 75 {
		return "MEDIUM"
	}
	return "LOW"
}

// CalculateQRAMMReadiness calculates QRAMM CVI readiness based on findings
func CalculateQRAMMReadiness(score *types.MigrationScore) *types.QRAMMReadiness {
	readiness := &types.QRAMMReadiness{}

	// Calculate CVI score (0-100)
	// Having comprehensive discovery is the first step
	// Score based on:
	// - Having any findings = discovered crypto assets
	// - Classification completeness
	// - Risk identification

	if score.TotalCount == 0 {
		readiness.CVIScore = 0
		readiness.DiscoveryLevel = 1
		readiness.AssessmentLevel = 1
		readiness.MappingLevel = 1
		readiness.Recommendations = []string{
			"No cryptographic assets discovered. Run scan on additional directories.",
			"Consider scanning dependencies (package.json, go.mod, requirements.txt).",
		}
		return readiness
	}

	// Discovery level based on finding crypto at all
	readiness.DiscoveryLevel = 3 // Automated discovery = Established

	// Assessment level based on classification
	classified := score.SafeCount + score.HybridCount + score.PartialCount +
		score.VulnerableCount + score.CriticalCount
	if classified == score.TotalCount {
		readiness.AssessmentLevel = 3 // All classified = Established
	} else {
		readiness.AssessmentLevel = 2 // Partial classification = Developing
	}

	// Mapping level based on tracking multiple primitives
	if len(score.ByPrimitive) >= 3 {
		readiness.MappingLevel = 3 // Multiple primitives tracked = Established
	} else {
		readiness.MappingLevel = 2 // Limited tracking = Developing
	}

	// CVI score is minimum of the three (weakest link)
	minLevel := readiness.DiscoveryLevel
	if readiness.AssessmentLevel < minLevel {
		minLevel = readiness.AssessmentLevel
	}
	if readiness.MappingLevel < minLevel {
		minLevel = readiness.MappingLevel
	}
	readiness.CVIScore = float64(minLevel) / 5.0 * 100

	// Generate recommendations
	if score.CriticalCount > 0 {
		readiness.Recommendations = append(readiness.Recommendations,
			"CRITICAL: Remove broken algorithms (MD5, SHA-1, DES, RC4) immediately.")
	}
	if score.VulnerableCount > 0 {
		readiness.Recommendations = append(readiness.Recommendations,
			"Plan migration from quantum-vulnerable algorithms to PQC (ML-KEM, ML-DSA).")
	}
	if score.HybridCount == 0 && score.VulnerableCount > 0 {
		readiness.Recommendations = append(readiness.Recommendations,
			"Consider hybrid cryptography as a transition strategy.")
	}
	if score.SafeCount == 0 {
		readiness.Recommendations = append(readiness.Recommendations,
			"No quantum-safe algorithms detected. Begin PQC adoption planning.")
	}

	return readiness
}
