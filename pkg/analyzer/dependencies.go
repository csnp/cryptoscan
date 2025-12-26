// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"github.com/csnp/qramm-cryptoscan/pkg/types"
)

// CryptoLibrary represents a known cryptographic library
type CryptoLibrary struct {
	Name         string
	Package      string            // Package identifier (npm, pypi, maven, etc.)
	Language     Language
	Algorithms   []string          // Known algorithms provided
	QuantumSafe  bool              // Whether it provides PQC algorithms
	Description  string
	Migration    string            // Migration guidance
	Docs         string            // Documentation URL
}

// DependencyFinding represents a crypto library found in dependencies
type DependencyFinding struct {
	Library      CryptoLibrary
	Version      string
	File         string
	Severity     types.Severity
	Quantum      types.QuantumRisk
	Description  string
	Remediation  string
}

// KnownCryptoLibraries contains well-known cryptographic libraries
var KnownCryptoLibraries = []CryptoLibrary{
	// Python
	{Name: "cryptography", Package: "cryptography", Language: LangPython,
		Algorithms: []string{"RSA", "ECC", "AES", "ChaCha20"}, QuantumSafe: false,
		Description: "Python cryptographic recipes and primitives",
		Migration: "Add liboqs-python for PQC support alongside cryptography"},
	{Name: "PyCryptodome", Package: "pycryptodome", Language: LangPython,
		Algorithms: []string{"RSA", "ECC", "AES", "DES", "3DES"}, QuantumSafe: false,
		Description: "Self-contained Python crypto library"},
	{Name: "PyNaCl", Package: "pynacl", Language: LangPython,
		Algorithms: []string{"X25519", "Ed25519", "ChaCha20"}, QuantumSafe: false,
		Description: "Python binding to libsodium"},
	{Name: "liboqs-python", Package: "liboqs-python", Language: LangPython,
		Algorithms: []string{"ML-KEM", "ML-DSA", "SLH-DSA"}, QuantumSafe: true,
		Description: "Python bindings for liboqs (post-quantum algorithms)"},

	// JavaScript/Node.js
	{Name: "crypto-js", Package: "crypto-js", Language: LangJavaScript,
		Algorithms: []string{"AES", "DES", "3DES", "SHA", "MD5"}, QuantumSafe: false,
		Description: "JavaScript library of crypto standards",
		Migration: "Consider using Web Crypto API or node:crypto for better security"},
	{Name: "node-forge", Package: "node-forge", Language: LangJavaScript,
		Algorithms: []string{"RSA", "AES", "DES", "SHA", "MD5"}, QuantumSafe: false,
		Description: "JavaScript implementation of TLS and crypto"},
	{Name: "bcrypt", Package: "bcrypt", Language: LangJavaScript,
		Algorithms: []string{"bcrypt"}, QuantumSafe: true,
		Description: "bcrypt password hashing (quantum-resistant for passwords)"},
	{Name: "argon2", Package: "argon2", Language: LangJavaScript,
		Algorithms: []string{"Argon2"}, QuantumSafe: true,
		Description: "Argon2 password hashing (quantum-resistant)"},
	{Name: "tweetnacl", Package: "tweetnacl", Language: LangJavaScript,
		Algorithms: []string{"X25519", "Ed25519", "XSalsa20"}, QuantumSafe: false,
		Description: "Port of TweetNaCl cryptographic library"},
	{Name: "jose", Package: "jose", Language: LangJavaScript,
		Algorithms: []string{"RSA", "ECDSA", "EdDSA", "AES"}, QuantumSafe: false,
		Description: "JavaScript Object Signing and Encryption"},

	// Go
	{Name: "circl", Package: "github.com/cloudflare/circl", Language: LangGo,
		Algorithms: []string{"ML-KEM", "X25519", "P-256"}, QuantumSafe: true,
		Description: "Cloudflare Interoperable Reusable Cryptographic Library with PQC"},
	{Name: "go-jose", Package: "github.com/go-jose/go-jose", Language: LangGo,
		Algorithms: []string{"RSA", "ECDSA", "EdDSA"}, QuantumSafe: false,
		Description: "Go implementation of JOSE standards"},

	// Java
	{Name: "Bouncy Castle", Package: "org.bouncycastle", Language: LangJava,
		Algorithms: []string{"RSA", "ECC", "AES", "ML-KEM", "ML-DSA"}, QuantumSafe: true,
		Description: "Java crypto provider with PQC support in recent versions",
		Migration: "Upgrade to BC 1.78+ for ML-KEM and ML-DSA support"},
	{Name: "Google Tink", Package: "com.google.crypto.tink", Language: LangJava,
		Algorithms: []string{"AES-GCM", "ECDSA", "Ed25519"}, QuantumSafe: false,
		Description: "Multi-language, cross-platform crypto library"},

	// Rust
	{Name: "ring", Package: "ring", Language: LangRust,
		Algorithms: []string{"AES-GCM", "ChaCha20", "RSA", "ECDSA"}, QuantumSafe: false,
		Description: "Safe, fast, small crypto using Rust"},
	{Name: "rustcrypto", Package: "aes", Language: LangRust,
		Algorithms: []string{"AES", "ChaCha20"}, QuantumSafe: false,
		Description: "Pure Rust implementation of crypto algorithms"},
	{Name: "pqcrypto", Package: "pqcrypto", Language: LangRust,
		Algorithms: []string{"ML-KEM", "ML-DSA", "SLH-DSA"}, QuantumSafe: true,
		Description: "Post-quantum cryptography for Rust"},

	// Ruby
	{Name: "OpenSSL Ruby", Package: "openssl", Language: LangRuby,
		Algorithms: []string{"RSA", "ECC", "AES"}, QuantumSafe: false,
		Description: "Ruby OpenSSL bindings"},
	{Name: "RbNaCl", Package: "rbnacl", Language: LangRuby,
		Algorithms: []string{"X25519", "Ed25519", "XSalsa20"}, QuantumSafe: false,
		Description: "Ruby binding to libsodium"},
}

// ScanDependencies scans a dependency file for crypto libraries
func ScanDependencies(path string) ([]DependencyFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	name := strings.ToLower(path)
	var findings []DependencyFinding

	switch {
	case strings.HasSuffix(name, "package.json"):
		findings = scanPackageJSON(data, path)
	case strings.HasSuffix(name, "requirements.txt"):
		findings = scanRequirementsTxt(data, path)
	case strings.HasSuffix(name, "go.mod"):
		findings = scanGoMod(data, path)
	case strings.HasSuffix(name, "pom.xml"):
		findings = scanPomXML(data, path)
	case strings.HasSuffix(name, "cargo.toml"):
		findings = scanCargoToml(data, path)
	case strings.HasSuffix(name, "gemfile") || strings.HasSuffix(name, "gemfile.lock"):
		findings = scanGemfile(data, path)
	case strings.HasSuffix(name, "pyproject.toml"):
		findings = scanPyprojectToml(data, path)
	}

	return findings, nil
}

func scanPackageJSON(data []byte, path string) []DependencyFinding {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	var findings []DependencyFinding
	allDeps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	for dep, version := range allDeps {
		for _, lib := range KnownCryptoLibraries {
			if lib.Language == LangJavaScript && strings.EqualFold(dep, lib.Package) {
				finding := createDependencyFinding(lib, version, path)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func scanRequirementsTxt(data []byte, path string) []DependencyFinding {
	var findings []DependencyFinding
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse package==version or package>=version etc.
		re := regexp.MustCompile(`^([a-zA-Z0-9_-]+)`)
		match := re.FindStringSubmatch(line)
		if len(match) < 2 {
			continue
		}
		pkg := strings.ToLower(match[1])

		// Extract version if present
		version := ""
		if idx := strings.Index(line, "=="); idx > 0 {
			version = strings.TrimSpace(line[idx+2:])
		}

		for _, lib := range KnownCryptoLibraries {
			if lib.Language == LangPython && strings.EqualFold(pkg, lib.Package) {
				finding := createDependencyFinding(lib, version, path)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func scanGoMod(data []byte, path string) []DependencyFinding {
	var findings []DependencyFinding
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		for _, lib := range KnownCryptoLibraries {
			if lib.Language == LangGo && strings.Contains(line, lib.Package) {
				// Extract version
				parts := strings.Fields(line)
				version := ""
				if len(parts) >= 2 {
					version = parts[1]
				}
				finding := createDependencyFinding(lib, version, path)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func scanPomXML(data []byte, path string) []DependencyFinding {
	var findings []DependencyFinding
	content := string(data)

	for _, lib := range KnownCryptoLibraries {
		if lib.Language == LangJava && strings.Contains(content, lib.Package) {
			finding := createDependencyFinding(lib, "", path)
			findings = append(findings, finding)
		}
	}

	return findings
}

func scanCargoToml(data []byte, path string) []DependencyFinding {
	var findings []DependencyFinding
	content := string(data)

	for _, lib := range KnownCryptoLibraries {
		if lib.Language == LangRust && strings.Contains(content, lib.Package) {
			finding := createDependencyFinding(lib, "", path)
			findings = append(findings, finding)
		}
	}

	return findings
}

func scanGemfile(data []byte, path string) []DependencyFinding {
	var findings []DependencyFinding
	content := strings.ToLower(string(data))

	for _, lib := range KnownCryptoLibraries {
		if lib.Language == LangRuby && strings.Contains(content, lib.Package) {
			finding := createDependencyFinding(lib, "", path)
			findings = append(findings, finding)
		}
	}

	return findings
}

func scanPyprojectToml(data []byte, path string) []DependencyFinding {
	var findings []DependencyFinding
	content := strings.ToLower(string(data))

	for _, lib := range KnownCryptoLibraries {
		if lib.Language == LangPython && strings.Contains(content, lib.Package) {
			finding := createDependencyFinding(lib, "", path)
			findings = append(findings, finding)
		}
	}

	return findings
}

func createDependencyFinding(lib CryptoLibrary, version, path string) DependencyFinding {
	var severity types.Severity
	quantum := types.QuantumVulnerable
	remediation := ""

	if lib.QuantumSafe {
		severity = types.SeverityInfo
		quantum = types.QuantumSafe
		remediation = "This library supports post-quantum algorithms. Ensure you're using the PQC options."
	} else {
		severity = types.SeverityMedium
		remediation = lib.Migration
		if remediation == "" {
			remediation = "Plan migration to a PQC-capable library or enable hybrid mode when available."
		}
	}

	description := lib.Description
	if len(lib.Algorithms) > 0 {
		description += " (Algorithms: " + strings.Join(lib.Algorithms, ", ") + ")"
	}

	return DependencyFinding{
		Library:     lib,
		Version:     version,
		File:        path,
		Severity:    severity,
		Quantum:     quantum,
		Description: description,
		Remediation: remediation,
	}
}
