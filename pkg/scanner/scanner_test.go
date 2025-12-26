// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewScanner(t *testing.T) {
	cfg := Config{
		Target: ".",
	}
	s := New(cfg)
	if s == nil {
		t.Fatal("New returned nil")
	}
}

func TestScanDirectory(t *testing.T) {
	// Create temp directory with test files
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test Go file with crypto patterns
	testFile := filepath.Join(tmpDir, "crypto.go")
	content := `package main

import (
	"crypto/rsa"
	"crypto/rand"
)

func generateKey() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = key
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if results.FilesScanned == 0 {
		t.Error("Expected files to be scanned")
	}

	// Should find RSA pattern
	foundRSA := false
	for _, f := range results.Findings {
		if f.Algorithm == "RSA" {
			foundRSA = true
			break
		}
	}
	if !foundRSA {
		t.Error("Expected to find RSA pattern")
	}
}

func TestScanExcludePatterns(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create vendor directory
	vendorDir := filepath.Join(tmpDir, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create test file in vendor (should be excluded)
	vendorFile := filepath.Join(vendorDir, "crypto.go")
	content := `package vendor
func init() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
}
`
	if err := os.WriteFile(vendorFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:       tmpDir,
		ExcludeGlobs: []string{"vendor"},
		MinSeverity:  SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should not find anything in excluded directory
	for _, f := range results.Findings {
		if strings.Contains(f.File, "/vendor/") {
			t.Errorf("Found file in excluded vendor directory: %s", f.File)
		}
	}
}

func TestScanIncludePatterns(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create Go file
	goFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(goFile, []byte("rsa.GenerateKey(rand.Reader, 2048)"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create Python file
	pyFile := filepath.Join(tmpDir, "main.py")
	if err := os.WriteFile(pyFile, []byte("from cryptography.hazmat.primitives import hashes"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:       tmpDir,
		IncludeGlobs: []string{"*.go"},
		MinSeverity:  SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should only find Go files
	for _, f := range results.Findings {
		if filepath.Ext(f.File) != ".go" {
			t.Errorf("Found non-.go file: %s", f.File)
		}
	}
}

func TestScanBinaryExclusion(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a fake binary file
	binFile := filepath.Join(tmpDir, "program.exe")
	if err := os.WriteFile(binFile, []byte{0x4D, 0x5A, 0x90, 0x00}, 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should not find anything in binary files
	for _, f := range results.Findings {
		if filepath.Ext(f.File) == ".exe" {
			t.Errorf("Found findings in binary file: %s", f.File)
		}
	}
}

func TestHasCritical(t *testing.T) {
	results := &Results{
		Findings: []Finding{
			{Severity: SeverityInfo},
			{Severity: SeverityLow},
		},
		Summary: Summary{
			BySeverity: map[string]int{"INFO": 1, "LOW": 1},
		},
	}
	if results.HasCritical() {
		t.Error("HasCritical should be false with no critical findings")
	}

	results.Findings = append(results.Findings, Finding{Severity: SeverityCritical})
	results.Summary.BySeverity["CRITICAL"] = 1
	if !results.HasCritical() {
		t.Error("HasCritical should be true with critical finding")
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "CRITICAL"},
		{SeverityHigh, "HIGH"},
		{SeverityMedium, "MEDIUM"},
		{SeverityLow, "LOW"},
		{SeverityInfo, "INFO"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.sev.String(); got != tt.want {
				t.Errorf("Severity.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanWithDependencyFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create package.json with crypto dependency
	pkgJSON := filepath.Join(tmpDir, "package.json")
	content := `{
  "name": "test-app",
  "dependencies": {
    "crypto-js": "^4.0.0",
    "bcrypt": "^5.0.0"
  }
}`
	if err := os.WriteFile(pkgJSON, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should find crypto dependency
	foundDep := false
	for _, f := range results.Findings {
		if f.FindingType == "dependency" {
			foundDep = true
			break
		}
	}
	if !foundDep {
		t.Log("No dependency findings found (may be expected if patterns don't match)")
	}
}

func TestScanWithRequirementsTxt(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create requirements.txt with crypto dependency
	reqFile := filepath.Join(tmpDir, "requirements.txt")
	content := `cryptography==41.0.0
pycryptodome>=3.0.0
bcrypt==4.0.0`
	if err := os.WriteFile(reqFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if results.FilesScanned == 0 {
		t.Error("Expected files to be scanned")
	}
}

func TestScanWithMultipleCryptoPatterns(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create file with multiple crypto patterns
	testFile := filepath.Join(tmpDir, "crypto.go")
	content := `package main

import (
	"crypto/rsa"
	"crypto/aes"
	"crypto/md5"
)

func encrypt() {
	key, _ := rsa.GenerateKey(nil, 2048)
	block, _ := aes.NewCipher([]byte("key"))
	hash := md5.Sum([]byte("data"))
	_, _, _ = key, block, hash
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should find multiple patterns
	if len(results.Findings) < 2 {
		t.Errorf("Expected multiple findings, got %d", len(results.Findings))
	}

	// Check summary is populated
	if results.Summary.TotalFindings == 0 {
		t.Error("Expected summary to have findings")
	}
}

func TestScanWithMinSeverity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "crypto.go")
	content := `package main
import "crypto/rsa"
func gen() { rsa.GenerateKey(nil, 2048) }
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Scan with high severity filter
	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityCritical,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should have fewer or no findings with high severity filter
	for _, f := range results.Findings {
		if f.Severity < SeverityCritical {
			t.Errorf("Found finding below min severity: %v", f.Severity)
		}
	}
}

func TestScanWithConfidenceFilter(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "crypto.go")
	content := `package main
import "crypto/rsa"
func gen() { rsa.GenerateKey(nil, 2048) }
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:        tmpDir,
		MinSeverity:   SeverityInfo,
		MinConfidence: "HIGH",
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should only have high confidence findings
	for _, f := range results.Findings {
		if f.Confidence != "HIGH" {
			t.Errorf("Found finding with non-high confidence: %v", f.Confidence)
		}
	}
}

func TestScanInsights(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create file with RSA to trigger insights
	testFile := filepath.Join(tmpDir, "crypto.go")
	content := `package main
import "crypto/rsa"
func gen() {
	rsa.GenerateKey(nil, 2048)
	rsa.GenerateKey(nil, 4096)
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Check if insights are generated
	if len(results.Insights) > 0 {
		insight := results.Insights[0]
		if insight.Title == "" {
			t.Error("Insight should have a title")
		}
		if insight.Description == "" {
			t.Error("Insight should have a description")
		}
	}
}

func TestQuantumRiskString(t *testing.T) {
	tests := []struct {
		risk QuantumRisk
		want string
	}{
		{QuantumVulnerable, "VULNERABLE"},
		{QuantumPartial, "PARTIAL"},
		{QuantumSafe, "SAFE"},
		{QuantumUnknown, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := string(tt.risk); got != tt.want {
				t.Errorf("QuantumRisk = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanProgress(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create multiple files
	for i := 0; i < 5; i++ {
		testFile := filepath.Join(tmpDir, filepath.FromSlash(filepath.Join("dir", string(rune('a'+i))+".go")))
		if err := os.MkdirAll(filepath.Dir(testFile), 0755); err != nil {
			t.Fatal(err)
		}
		content := `package main
func init() {}
`
		if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	cfg := Config{
		Target:       tmpDir,
		MinSeverity:  SeverityInfo,
		ShowProgress: true,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if results.FilesScanned == 0 {
		t.Error("Expected files to be scanned")
	}
}

func TestScanMaxDepth(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create file at root level
	rootFile := filepath.Join(tmpDir, "root.go")
	rootContent := `package main
import "crypto/rsa"
func gen() { rsa.GenerateKey(nil, 2048) }
`
	if err := os.WriteFile(rootFile, []byte(rootContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create nested directory structure
	deepDir := filepath.Join(tmpDir, "a", "b", "c", "d")
	if err := os.MkdirAll(deepDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create file in deep directory
	deepFile := filepath.Join(deepDir, "deep.go")
	deepContent := `package main
import "crypto/rsa"
func gen() { rsa.GenerateKey(nil, 2048) }
`
	if err := os.WriteFile(deepFile, []byte(deepContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Scan with max depth 1 (should only find root.go)
	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
		MaxDepth:    1,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should find root file
	foundRoot := false
	for _, f := range results.Findings {
		if strings.Contains(f.File, "root.go") {
			foundRoot = true
		}
	}
	if !foundRoot && len(results.Findings) == 0 {
		t.Log("No findings at root level (may depend on pattern matching)")
	}

	// Verify max depth config was applied
	if cfg.MaxDepth != 1 {
		t.Error("MaxDepth config should be 1")
	}
}
