// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-cryptoscan/pkg/scanner"
)

func createTestResults() *scanner.Results {
	return &scanner.Results{
		ScanTarget:   "/test/path",
		ScanTime:     time.Now(),
		ScanDuration: time.Second * 5,
		FilesScanned: 10,
		LinesScanned: 1000,
		Findings: []scanner.Finding{
			{
				ID:          "RSA-001",
				Type:        "RSA Key Generation",
				Severity:    scanner.SeverityHigh,
				Category:    "Asymmetric Cryptography",
				Algorithm:   "RSA",
				KeySize:     2048,
				Quantum:     scanner.QuantumVulnerable,
				Confidence:  "HIGH",
				File:        "/test/crypto.go",
				Line:        42,
				Match:       "rsa.GenerateKey(rand.Reader, 2048)",
				Description: "RSA key generation detected",
				Remediation: "Consider migrating to ML-KEM for key exchange",
			},
			{
				ID:          "AES-001",
				Type:        "AES Cipher",
				Severity:    scanner.SeverityInfo,
				Category:    "Symmetric Cryptography",
				Algorithm:   "AES",
				KeySize:     256,
				Quantum:     scanner.QuantumPartial,
				Confidence:  "HIGH",
				File:        "/test/encrypt.go",
				Line:        15,
				Match:       "aes.NewCipher(key)",
				Description: "AES cipher usage",
				Remediation: "AES-256 provides adequate post-quantum security",
			},
		},
		Summary: scanner.Summary{
			TotalFindings: 2,
			BySeverity:    map[string]int{"HIGH": 1, "INFO": 1},
			ByCategory:    map[string]int{"Asymmetric Cryptography": 1, "Symmetric Cryptography": 1},
			ByQuantumRisk: map[string]int{"VULNERABLE": 1, "PARTIAL": 1},
		},
	}
}

func TestTextReporter(t *testing.T) {
	results := createTestResults()
	reporter := NewTextReporter(false)

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Check for key elements
	checks := []string{
		"CRYPTOGRAPHIC SCAN RESULTS",
		"RSA Key Generation",
		"AES Cipher",
		"QUANTUM VULNERABLE",
		"QRAMM",
		"CSNP",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Output missing expected text: %s", check)
		}
	}
}

func TestTextReporterWithColors(t *testing.T) {
	results := createTestResults()
	reporter := NewTextReporter(true)

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should contain ANSI color codes
	if !strings.Contains(output, "\033[") {
		t.Error("Expected ANSI color codes in output")
	}
}

func TestJSONReporter(t *testing.T) {
	results := createTestResults()
	reporter := NewJSONReporter(false)

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Check structure
	if _, ok := parsed["findings"]; !ok {
		t.Error("JSON missing 'findings' key")
	}
	if _, ok := parsed["summary"]; !ok {
		t.Error("JSON missing 'summary' key")
	}
}

func TestJSONReporterPretty(t *testing.T) {
	results := createTestResults()
	reporter := NewJSONReporter(true)

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Pretty printed JSON should have newlines
	if !strings.Contains(output, "\n") {
		t.Error("Expected pretty printed JSON with newlines")
	}
}

func TestCSVReporter(t *testing.T) {
	results := createTestResults()
	reporter := NewCSVReporter()

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		t.Error("Expected at least header and one data row")
	}

	// Check header
	header := lines[0]
	expectedCols := []string{"ID", "Severity", "Type", "Category", "Algorithm", "Quantum Risk"}
	for _, col := range expectedCols {
		if !strings.Contains(header, col) {
			t.Errorf("Header missing column: %s", col)
		}
	}

	// Should have 3 lines total (header + 2 findings)
	if len(lines) != 3 {
		t.Errorf("Expected 3 lines, got %d", len(lines))
	}
}

func TestSARIFReporter(t *testing.T) {
	results := createTestResults()
	reporter := NewSARIFReporter()

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should be valid JSON
	var sarif map[string]interface{}
	if err := json.Unmarshal([]byte(output), &sarif); err != nil {
		t.Fatalf("Invalid SARIF JSON: %v", err)
	}

	// Check SARIF schema
	if sarif["$schema"] == nil {
		t.Error("SARIF missing $schema")
	}
	if sarif["version"] != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %v", sarif["version"])
	}

	runs := sarif["runs"].([]interface{})
	if len(runs) == 0 {
		t.Error("SARIF missing runs")
	}
}

func TestCBOMReporter(t *testing.T) {
	results := createTestResults()
	reporter := NewCBOMReporter()

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should be valid JSON
	var cbom map[string]interface{}
	if err := json.Unmarshal([]byte(output), &cbom); err != nil {
		t.Fatalf("Invalid CBOM JSON: %v", err)
	}

	// Check CycloneDX structure
	if cbom["bomFormat"] != "CycloneDX" {
		t.Error("Expected bomFormat CycloneDX")
	}
	if cbom["specVersion"] == nil {
		t.Error("CBOM missing specVersion")
	}
}

func TestTextReporterGroupByFile(t *testing.T) {
	results := createTestResults()
	reporter := NewTextReporter(false)
	reporter.SetGroupBy("file")

	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should contain file grouping indicators
	checks := []string{
		"/test/crypto.go",
		"/test/encrypt.go",
		"findings",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Grouped output missing expected text: %s", check)
		}
	}
}

func TestSeverityColors(t *testing.T) {
	// Test all severity levels to ensure they produce different colored output
	results := &scanner.Results{
		ScanTarget:   "/test",
		ScanTime:     time.Now(),
		ScanDuration: time.Second,
		FilesScanned: 1,
		LinesScanned: 100,
		Findings: []scanner.Finding{
			{ID: "1", Type: "Critical Test", Severity: scanner.SeverityCritical, File: "/a.go", Line: 1},
			{ID: "2", Type: "High Test", Severity: scanner.SeverityHigh, File: "/b.go", Line: 2},
			{ID: "3", Type: "Medium Test", Severity: scanner.SeverityMedium, File: "/c.go", Line: 3},
			{ID: "4", Type: "Low Test", Severity: scanner.SeverityLow, File: "/d.go", Line: 4},
			{ID: "5", Type: "Info Test", Severity: scanner.SeverityInfo, File: "/e.go", Line: 5},
		},
		Summary: scanner.Summary{
			TotalFindings: 5,
			BySeverity:    map[string]int{"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1},
			ByCategory:    map[string]int{},
			ByQuantumRisk: map[string]int{},
		},
	}

	reporter := NewTextReporter(true)
	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// All severity levels should appear
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if !strings.Contains(output, sev) {
			t.Errorf("Output missing severity: %s", sev)
		}
	}
}

func TestQuantumRiskIcons(t *testing.T) {
	results := &scanner.Results{
		ScanTarget:   "/test",
		ScanTime:     time.Now(),
		ScanDuration: time.Second,
		FilesScanned: 1,
		LinesScanned: 100,
		Findings: []scanner.Finding{
			{ID: "1", Type: "Vulnerable", Quantum: scanner.QuantumVulnerable, File: "/a.go", Line: 1},
			{ID: "2", Type: "Partial", Quantum: scanner.QuantumPartial, File: "/b.go", Line: 2},
			{ID: "3", Type: "Safe", Quantum: scanner.QuantumSafe, File: "/c.go", Line: 3},
			{ID: "4", Type: "Unknown", Quantum: scanner.QuantumUnknown, File: "/d.go", Line: 4},
		},
		Summary: scanner.Summary{
			TotalFindings: 4,
			BySeverity:    map[string]int{},
			ByCategory:    map[string]int{},
			ByQuantumRisk: map[string]int{"VULNERABLE": 1, "PARTIAL": 1, "SAFE": 1, "UNKNOWN": 1},
		},
	}

	reporter := NewTextReporter(false)
	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	checks := []string{"QUANTUM VULNERABLE", "QUANTUM WEAKENED", "QUANTUM SAFE", "UNKNOWN"}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Output missing quantum icon: %s", check)
		}
	}
}

func TestCBOMCategoryToAssetType(t *testing.T) {
	tests := []struct {
		category string
		want     string
	}{
		{"asymmetric", "algorithm"},
		{"key-exchange", "algorithm"},
		{"symmetric", "algorithm"},
		{"hash", "algorithm"},
		{"tls", "protocol"},
		{"protocol", "protocol"},
		{"certificate", "certificate"},
		{"key", "certificate"},
		{"library", "related-crypto-material"},
		{"unknown", "algorithm"},
		{"", "algorithm"},
	}

	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			got := categoryToAssetType(tt.category)
			if got != tt.want {
				t.Errorf("categoryToAssetType(%q) = %q, want %q", tt.category, got, tt.want)
			}
		})
	}
}

func TestCBOMAlgorithmToPrimitive(t *testing.T) {
	tests := []struct {
		algo string
		want string
	}{
		{"RSA", "pke"},
		{"ECDSA", "signature"},
		{"DSA", "signature"},
		{"Ed25519", "signature"},
		{"DH", "kdf"},
		{"ECDH", "kdf"},
		{"X25519", "kdf"},
		{"AES", "block-cipher"},
		{"DES", "block-cipher"},
		{"3DES", "block-cipher"},
		{"Blowfish", "block-cipher"},
		{"ChaCha20", "block-cipher"},
		{"RC4", "block-cipher"},
		{"MD5", "hash"},
		{"SHA-1", "hash"},
		{"SHA-256", "hash"},
		{"SHA-384", "hash"},
		{"SHA-512", "hash"},
		{"SHA-3", "hash"},
		{"Unknown", "other"},
		{"", "other"},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			got := algorithmToPrimitive(tt.algo)
			if got != tt.want {
				t.Errorf("algorithmToPrimitive(%q) = %q, want %q", tt.algo, got, tt.want)
			}
		})
	}
}

func TestCBOMKeySizeToSecurityLevel(t *testing.T) {
	tests := []struct {
		keySize int
		algo    string
		want    int
	}{
		{4096, "RSA", 192},
		{3072, "RSA", 128},
		{2048, "RSA", 112},
		{1024, "RSA", 80},
		{256, "AES", 256},
		{128, "AES", 128},
		{256, "Unknown", 0},
		{0, "RSA", 80},
	}

	for _, tt := range tests {
		name := strings.ReplaceAll(tt.algo+"-"+string(rune(tt.keySize)), " ", "_")
		t.Run(name, func(t *testing.T) {
			got := keySizeToSecurityLevel(tt.keySize, tt.algo)
			if got != tt.want {
				t.Errorf("keySizeToSecurityLevel(%d, %q) = %d, want %d", tt.keySize, tt.algo, got, tt.want)
			}
		})
	}
}

func TestSARIFSeverityLevels(t *testing.T) {
	// Create results with all severity levels
	results := &scanner.Results{
		ScanTarget:   "/test",
		ScanTime:     time.Now(),
		ScanDuration: time.Second,
		FilesScanned: 1,
		LinesScanned: 100,
		Findings: []scanner.Finding{
			{ID: "1", Type: "Critical", Severity: scanner.SeverityCritical, File: "/a.go", Line: 1},
			{ID: "2", Type: "High", Severity: scanner.SeverityHigh, File: "/b.go", Line: 2},
			{ID: "3", Type: "Medium", Severity: scanner.SeverityMedium, File: "/c.go", Line: 3},
			{ID: "4", Type: "Low", Severity: scanner.SeverityLow, File: "/d.go", Line: 4},
			{ID: "5", Type: "Info", Severity: scanner.SeverityInfo, File: "/e.go", Line: 5},
		},
		Summary: scanner.Summary{TotalFindings: 5},
	}

	reporter := NewSARIFReporter()
	output, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal([]byte(output), &sarif); err != nil {
		t.Fatalf("Invalid SARIF: %v", err)
	}

	// Check that results exist
	runs := sarif["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results2 := run["results"].([]interface{})
	if len(results2) != 5 {
		t.Errorf("Expected 5 SARIF results, got %d", len(results2))
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.00 MB"},
		{1572864, "1.50 MB"},
		{1073741824, "1.00 GB"},
		{1610612736, "1.50 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatBytes(tt.bytes)
			if got != tt.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestTruncatePath(t *testing.T) {
	tests := []struct {
		path   string
		maxLen int
		want   string
	}{
		{"/short/path.go", 50, "/short/path.go"},
		{"/very/long/path/to/some/deeply/nested/file.go", 30, ".../deeply/nested/file.go"},
		{"/a.go", 10, "/a.go"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := truncatePath(tt.path, tt.maxLen)
			if len(got) > tt.maxLen && tt.maxLen > 10 {
				t.Errorf("truncatePath(%q, %d) = %q (len %d), exceeds max", tt.path, tt.maxLen, got, len(got))
			}
		})
	}
}

func TestEmptyResults(t *testing.T) {
	results := &scanner.Results{
		ScanTarget:   "/empty",
		ScanTime:     time.Now(),
		ScanDuration: time.Millisecond * 100,
		FilesScanned: 5,
		LinesScanned: 100,
		Findings:     []scanner.Finding{},
		Summary: scanner.Summary{
			TotalFindings: 0,
			BySeverity:    map[string]int{},
			ByCategory:    map[string]int{},
			ByQuantumRisk: map[string]int{},
		},
	}

	reporters := []struct {
		name string
		r    Reporter
	}{
		{"text", NewTextReporter(false)},
		{"json", NewJSONReporter(false)},
		{"csv", NewCSVReporter()},
		{"sarif", NewSARIFReporter()},
		{"cbom", NewCBOMReporter()},
	}

	for _, tc := range reporters {
		t.Run(tc.name, func(t *testing.T) {
			output, err := tc.r.Generate(results)
			if err != nil {
				t.Errorf("%s reporter failed on empty results: %v", tc.name, err)
			}
			if output == "" {
				t.Errorf("%s reporter returned empty output", tc.name)
			}
		})
	}
}
