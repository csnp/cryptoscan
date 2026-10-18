// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

func TestScanDependenciesPackageJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-deps")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := `{
  "name": "test-app",
  "dependencies": {
    "crypto-js": "^4.1.1",
    "express": "^4.18.0"
  },
  "devDependencies": {
    "bcrypt": "^5.0.0"
  }
}`
	path := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies failed: %v", err)
	}

	// Should find crypto-js and bcrypt
	if len(findings) < 2 {
		t.Errorf("Expected at least 2 crypto findings, got %d", len(findings))
	}

	foundCryptoJS := false
	foundBcrypt := false
	for _, f := range findings {
		if f.Library.Name == "crypto-js" {
			foundCryptoJS = true
			if f.Quantum != types.QuantumVulnerable {
				t.Error("crypto-js should be quantum vulnerable")
			}
		}
		if f.Library.Name == "bcrypt" {
			foundBcrypt = true
			if f.Quantum != types.QuantumSafe {
				t.Error("bcrypt should be quantum safe for passwords")
			}
		}
	}

	if !foundCryptoJS {
		t.Error("Should find crypto-js")
	}
	if !foundBcrypt {
		t.Error("Should find bcrypt")
	}
}

func TestScanDependenciesRequirementsTxt(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-deps")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := `# Python dependencies
cryptography==41.0.0
pynacl>=1.5.0
requests==2.28.0
pycryptodome
`
	path := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies failed: %v", err)
	}

	// Should find cryptography, pynacl, pycryptodome
	if len(findings) < 3 {
		t.Errorf("Expected at least 3 crypto findings, got %d", len(findings))
	}

	foundCryptography := false
	for _, f := range findings {
		if f.Library.Name == "cryptography" {
			foundCryptography = true
			if f.Version != "41.0.0" {
				t.Errorf("Expected version 41.0.0, got %s", f.Version)
			}
		}
	}

	if !foundCryptography {
		t.Error("Should find cryptography library")
	}
}

func TestScanDependenciesGoMod(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-deps")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := `module example.com/myapp

go 1.21

require (
    github.com/cloudflare/circl v1.3.7
    github.com/go-jose/go-jose/v3 v3.0.0
    github.com/gin-gonic/gin v1.9.0
)
`
	path := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies failed: %v", err)
	}

	// Should find circl (PQC) and go-jose
	if len(findings) < 2 {
		t.Errorf("Expected at least 2 crypto findings, got %d", len(findings))
	}

	foundCircl := false
	for _, f := range findings {
		if f.Library.Name == "circl" {
			foundCircl = true
			if !f.Library.QuantumSafe {
				t.Error("circl should be quantum safe")
			}
			if f.Quantum != types.QuantumSafe {
				t.Error("circl finding should be quantum safe")
			}
		}
	}

	if !foundCircl {
		t.Error("Should find circl library")
	}
}

func TestScanDependenciesPomXML(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-deps")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>1.10.0</version>
    </dependency>
  </dependencies>
</project>
`
	path := filepath.Join(tmpDir, "pom.xml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies failed: %v", err)
	}

	// Should find Bouncy Castle and Tink
	if len(findings) < 2 {
		t.Errorf("Expected at least 2 crypto findings, got %d", len(findings))
	}

	foundBC := false
	for _, f := range findings {
		if f.Library.Name == "Bouncy Castle" {
			foundBC = true
		}
	}

	if !foundBC {
		t.Error("Should find Bouncy Castle library")
	}
}

func TestScanDependenciesCargoToml(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-deps")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := `[package]
name = "myapp"
version = "0.1.0"

[dependencies]
ring = "0.17"
pqcrypto = "0.17"
tokio = "1.0"
`
	path := filepath.Join(tmpDir, "Cargo.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies failed: %v", err)
	}

	// Should find ring and pqcrypto
	foundRing := false
	foundPQCrypto := false
	for _, f := range findings {
		if f.Library.Name == "ring" {
			foundRing = true
		}
		if f.Library.Name == "pqcrypto" {
			foundPQCrypto = true
			if !f.Library.QuantumSafe {
				t.Error("pqcrypto should be quantum safe")
			}
		}
	}

	if !foundRing {
		t.Error("Should find ring library")
	}
	if !foundPQCrypto {
		t.Error("Should find pqcrypto library")
	}
}

func TestScanDependenciesGemfile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-deps")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := `source 'https://rubygems.org'

gem 'rails'
gem 'openssl'
gem 'rbnacl'
`
	path := filepath.Join(tmpDir, "Gemfile")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies failed: %v", err)
	}

	// Should find openssl and rbnacl
	foundOpenSSL := false
	for _, f := range findings {
		if f.Library.Name == "OpenSSL Ruby" {
			foundOpenSSL = true
		}
	}

	if !foundOpenSSL {
		t.Error("Should find OpenSSL Ruby library")
	}
}

func TestScanDependenciesPyprojectToml(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-deps")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := `[project]
name = "myapp"
dependencies = [
    "cryptography>=41.0.0",
    "pynacl",
    "requests",
]
`
	path := filepath.Join(tmpDir, "pyproject.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies failed: %v", err)
	}

	foundCryptography := false
	for _, f := range findings {
		if f.Library.Name == "cryptography" {
			foundCryptography = true
		}
	}

	if !foundCryptography {
		t.Error("Should find cryptography library")
	}
}

func TestScanDependenciesUnknownFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-deps")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "unknown.txt")
	if err := os.WriteFile(path, []byte("some content"), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies failed: %v", err)
	}

	// Unknown file type should return no findings
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for unknown file, got %d", len(findings))
	}
}

// detectFileType names more files dependency manifests than ScanDependencies
// has readers for. The scanner lists the others as skipped, so ReadsManifest
// has to say which names have a reader, ignoring case as detectFileType does.
func TestReadsManifest(t *testing.T) {
	read := map[string]bool{
		"package.json": true, "requirements.txt": true, "pyproject.toml": true, "go.mod": true,
		"pom.xml": true, "cargo.toml": true, "gemfile": true, "gemfile.lock": true,
	}
	for name := range dependencyFiles {
		if got := ReadsManifest(filepath.Join("repo", name)); got != read[name] {
			t.Errorf("ReadsManifest(%q) = %v, want %v", name, got, read[name])
		}
	}
	for name := range read {
		if !dependencyFiles[name] {
			t.Errorf("%s has a reader but is not classified as a dependency manifest", name)
		}
	}
	for name, want := range map[string]bool{
		"Cargo.toml": true, "Gemfile": true, "Pipfile": false, "BUILD.GRADLE": false, "build.gradle.kts": false,
	} {
		if got := ReadsManifest(filepath.Join("repo", name)); got != want {
			t.Errorf("ReadsManifest(%q) = %v, want %v", name, got, want)
		}
	}

	// ScanDependencies gives a manifest with no reader no findings and no
	// error, even when it names a known library.
	path := filepath.Join(t.TempDir(), "build.gradle")
	gradle := "dependencies {\n    implementation 'org.bouncycastle:bcprov-jdk18on:1.77'\n}\n"
	if err := os.WriteFile(path, []byte(gradle), 0o644); err != nil {
		t.Fatal(err)
	}
	if findings, err := ScanDependencies(path); err != nil || len(findings) != 0 {
		t.Errorf("ScanDependencies(%s) = %+v, %v; want no findings and no error", path, findings, err)
	}
}

func TestScanDependenciesNonexistent(t *testing.T) {
	_, err := ScanDependencies("/nonexistent/path/file.json")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// A UTF-8 byte order mark at the start of a manifest is not part of its
// content. Before it was removed, the package.json below failed to decode and
// the requirements.txt line did not match a package name.
func TestScanDependenciesRemovesAByteOrderMark(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantLibrary string
		wantVersion string
	}{
		{
			name:        "package.json",
			content:     "\xef\xbb\xbf" + `{"name": "fixture", "dependencies": {"crypto-js": "^4.2.0"}}` + "\n",
			wantLibrary: "crypto-js",
			wantVersion: "^4.2.0",
		},
		{
			name:        "requirements.txt",
			content:     "\xef\xbb\xbfcryptography==41.0.0\n",
			wantLibrary: "cryptography",
			wantVersion: "41.0.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.name)
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}

			findings, err := ScanDependencies(path)
			if err != nil {
				t.Fatalf("ScanDependencies failed: %v", err)
			}
			if len(findings) != 1 || findings[0].Library.Name != tt.wantLibrary || findings[0].Version != tt.wantVersion {
				t.Errorf("findings = %+v, want one for %s %s", findings, tt.wantLibrary, tt.wantVersion)
			}
		})
	}
}

// A package.json that cannot be decoded returns a *ManifestError with the
// line where decoding stopped. It used to return no findings and no error.
func TestScanDependenciesReportsPackageJSONThatCannotBeDecoded(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantLine int
		// wantReason is the reason for a value of the wrong type. When it is
		// empty the file is not valid JSON, and the reason is the decoder's
		// own message after "not valid JSON: ".
		wantReason string
	}{
		{name: "empty file", content: "", wantLine: 1},
		{name: "unclosed object", content: `{"dependencies": {"crypto-js": "^4.2.0"}` + "\n", wantLine: 1},
		{
			name:     "comma before a closing brace",
			content:  "{\n  \"dependencies\": {\n    \"crypto-js\": \"^4.2.0\",\n  }\n}\n",
			wantLine: 4,
		},
		{
			name:     "merge conflict marker",
			content:  "{\n<<<<<<< HEAD\n  \"dependencies\": {}\n}\n",
			wantLine: 2,
		},
		// Only the UTF-8 byte order mark is removed. A UTF-16 file is not
		// decoded.
		{name: "UTF-16 byte order mark", content: "\xff\xfe{\x00}\x00", wantLine: 1},
		{
			name:       "array at the top level",
			content:    "[]\n",
			wantLine:   1,
			wantReason: "unexpected JSON array at the top level",
		},
		{
			name:       "dependencies as an array",
			content:    "{\n  \"name\": \"fixture\",\n  \"dependencies\": [\"crypto-js\"]\n}\n",
			wantLine:   3,
			wantReason: `unexpected JSON array in "dependencies"`,
		},
		{
			name:       "version as a number",
			content:    "{\"devDependencies\": {\n  \"crypto-js\": 4\n}}\n",
			wantLine:   2,
			wantReason: `unexpected JSON number in "devDependencies"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "package.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			want := tt.wantReason
			if want == "" {
				var v any
				var syntaxErr *json.SyntaxError
				if err := json.Unmarshal([]byte(tt.content), &v); !errors.As(err, &syntaxErr) {
					t.Fatalf("fixture is not a JSON syntax error: %v", err)
				}
				want = "not valid JSON: " + syntaxErr.Error()
			}

			findings, err := ScanDependencies(path)

			var manifestErr *ManifestError
			if !errors.As(err, &manifestErr) {
				t.Fatalf("err = %v, want a *ManifestError", err)
			}
			if manifestErr.Path != path || manifestErr.Line != tt.wantLine || manifestErr.Reason != want {
				t.Errorf("error = %+v, want path %s, line %d and reason %q", *manifestErr, path, tt.wantLine, want)
			}
			if wantText := fmt.Sprintf("%s:%d: %s", path, tt.wantLine, want); err.Error() != wantText {
				t.Errorf("err.Error() = %q, want %q", err.Error(), wantText)
			}
			if len(findings) != 0 {
				t.Errorf("findings = %+v, want none", findings)
			}
		})
	}
}

func TestKnownCryptoLibraries(t *testing.T) {
	// Verify we have libraries for major languages
	languages := make(map[Language]int)
	for _, lib := range KnownCryptoLibraries {
		languages[lib.Language]++
	}

	expected := []Language{LangPython, LangJavaScript, LangGo, LangJava, LangRust, LangRuby}
	for _, lang := range expected {
		if languages[lang] == 0 {
			t.Errorf("No crypto libraries defined for %s", lang)
		}
	}

	// Verify we have at least one PQC library
	hasPQC := false
	for _, lib := range KnownCryptoLibraries {
		if lib.QuantumSafe {
			hasPQC = true
			break
		}
	}
	if !hasPQC {
		t.Error("Should have at least one quantum-safe library")
	}
}

func TestCreateDependencyFinding(t *testing.T) {
	// Test quantum-safe library
	pqcLib := CryptoLibrary{
		Name:        "pqcrypto",
		Package:     "pqcrypto",
		Language:    LangRust,
		Algorithms:  []string{"ML-KEM", "ML-DSA"},
		QuantumSafe: true,
		Description: "Post-quantum crypto",
	}

	finding := createDependencyFinding(pqcLib, "0.17.0", "/Cargo.toml")
	if finding.Severity != types.SeverityInfo {
		t.Errorf("PQC library severity should be INFO, got %v", finding.Severity)
	}
	if finding.Quantum != types.QuantumSafe {
		t.Errorf("PQC library quantum should be SAFE, got %v", finding.Quantum)
	}

	// Test non-quantum-safe library
	classicLib := CryptoLibrary{
		Name:        "crypto-js",
		Package:     "crypto-js",
		Language:    LangJavaScript,
		Algorithms:  []string{"AES", "RSA"},
		QuantumSafe: false,
		Description: "JS crypto",
		Migration:   "Use Web Crypto API",
	}

	finding = createDependencyFinding(classicLib, "4.1.1", "/package.json")
	if finding.Severity != types.SeverityMedium {
		t.Errorf("Classic library severity should be MEDIUM, got %v", finding.Severity)
	}
	if finding.Quantum != types.QuantumVulnerable {
		t.Errorf("Classic library quantum should be VULNERABLE, got %v", finding.Quantum)
	}
	if finding.Remediation != "Use Web Crypto API" {
		t.Errorf("Should use library migration guidance")
	}
}
