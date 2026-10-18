// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/csnp/cryptoscan/pkg/types"
)

// CryptoLibrary represents a known cryptographic library
type CryptoLibrary struct {
	Name        string
	Package     string // Package identifier (npm, pypi, maven, etc.)
	Language    Language
	Algorithms  []string // Known algorithms provided
	QuantumSafe bool     // Whether it provides PQC algorithms
	Description string
	Migration   string // Migration guidance
	Docs        string // Documentation URL
}

// DependencyFinding represents a crypto library found in dependencies
type DependencyFinding struct {
	Library     CryptoLibrary
	Version     string
	File        string
	Severity    types.Severity
	Quantum     types.QuantumRisk
	Description string
	Remediation string
}

// KnownCryptoLibraries contains well-known cryptographic libraries
var KnownCryptoLibraries = []CryptoLibrary{
	// Python
	{Name: "cryptography", Package: "cryptography", Language: LangPython,
		Algorithms: []string{"RSA", "ECC", "AES", "ChaCha20"}, QuantumSafe: false,
		Description: "Python cryptographic recipes and primitives",
		Migration:   "Add liboqs-python for PQC support alongside cryptography"},
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
		Migration:   "Replace crypto-js with node:crypto in Node.js or the Web Crypto API (crypto.subtle) in the browser, then remove crypto-js from package.json"},
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
		Migration:   "Upgrade to BC 1.78+ for ML-KEM and ML-DSA support"},
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

// utf8BOM is the UTF-8 byte order mark. It marks the file's encoding and is
// not part of the manifest, so it is removed before the manifest is parsed.
// npm reads a package.json that starts with one (checked with npm 11.20.0).
var utf8BOM = []byte("\xef\xbb\xbf")

// ManifestError reports a dependency manifest that was read but could not be
// decoded, so the dependencies it lists are not known.
type ManifestError struct {
	Path string
	// Line is the 1-based line where decoding stopped, or 0 when the decoder
	// gave no position.
	Line int
	// Reason says what is wrong with the file, in JSON terms rather than in
	// terms of the decoder's Go types.
	Reason string
}

func (e *ManifestError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", e.Path, e.Line, e.Reason)
	}
	return e.Path + ": " + e.Reason
}

// ScanDependencies scans a dependency file for crypto libraries. A
// package.json that cannot be decoded returns a *ManifestError. A file with
// no reader, which ReadsManifest reports, returns no findings and no error.
func ScanDependencies(path string) ([]DependencyFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	read := manifestReader(path)
	if read == nil {
		return nil, nil
	}
	return read(bytes.TrimPrefix(data, utf8BOM), path)
}

// ReadsManifest reports whether ScanDependencies has a reader for the
// dependency manifest at path. detectFileType names more files dependency
// manifests than have a reader, such as build.gradle and Pipfile.
func ReadsManifest(path string) bool {
	return manifestReader(path) != nil
}

// readManifestFunc returns the crypto libraries listed in data, the content
// of the dependency manifest at path.
type readManifestFunc func(data []byte, path string) ([]DependencyFinding, error)

// manifestReader returns the reader for the dependency manifest at path,
// chosen by the end of the path with case ignored, or nil when there is none.
func manifestReader(path string) readManifestFunc {
	name := strings.ToLower(path)
	switch {
	case strings.HasSuffix(name, "package.json"):
		return scanPackageJSON
	case strings.HasSuffix(name, "requirements.txt"):
		return withoutError(scanRequirementsTxt)
	case strings.HasSuffix(name, "go.mod"):
		return withoutError(scanGoMod)
	case strings.HasSuffix(name, "pom.xml"):
		return withoutError(scanPomXML)
	case strings.HasSuffix(name, "cargo.toml"):
		return withoutError(scanCargoToml)
	case strings.HasSuffix(name, "gemfile") || strings.HasSuffix(name, "gemfile.lock"):
		return withoutError(scanGemfile)
	case strings.HasSuffix(name, "pyproject.toml"):
		return withoutError(scanPyprojectToml)
	}
	return nil
}

// withoutError adapts a reader that cannot fail to readManifestFunc.
func withoutError(read func(data []byte, path string) []DependencyFinding) readManifestFunc {
	return func(data []byte, path string) ([]DependencyFinding, error) {
		return read(data, path), nil
	}
}

func scanPackageJSON(data []byte, path string) ([]DependencyFinding, error) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, manifestError(path, data, err)
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

	return findings, nil
}

// manifestError describes err, the error json.Unmarshal returned for the
// package.json at path holding data, with the line where decoding stopped.
func manifestError(path string, data []byte, err error) *ManifestError {
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return &ManifestError{
			Path:   path,
			Line:   lineAtOffset(data, syntaxErr.Offset),
			Reason: "not valid JSON: " + syntaxErr.Error(),
		}
	}
	// A value of the wrong JSON type is named by its type and by the key it
	// was found under, dependencies or devDependencies, which are the only
	// keys decoded.
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		reason := "unexpected JSON " + typeErr.Value + " at the top level"
		if typeErr.Field != "" {
			reason = fmt.Sprintf("unexpected JSON %s in %q", typeErr.Value, typeErr.Field)
		}
		return &ManifestError{
			Path:   path,
			Line:   lineAtOffset(data, typeErr.Offset),
			Reason: reason,
		}
	}
	return &ManifestError{Path: path, Reason: err.Error()}
}

// lineAtOffset returns the 1-based line of data holding the last byte a
// decoder read when it stopped after reading offset bytes, or 1 when it read
// none.
func lineAtOffset(data []byte, offset int64) int {
	end := int(offset) - 1
	if end < 0 {
		end = 0
	}
	if end > len(data) {
		end = len(data)
	}
	return 1 + bytes.Count(data[:end], []byte("\n"))
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
