// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/patterns"
	"github.com/csnp/cryptoscan/pkg/scanner"
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
		// A key is key material, not a certificate. CycloneDX models it as
		// related-crypto-material so the material's type and size survive.
		{"key", "related-crypto-material"},
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
		// CycloneDX 1.6 spells key agreement "key-agree". The previous
		// expectation of "key-agreement" is not a member of the spec enum, so
		// asserting it locked in output that failed schema validation.
		{"DH", "key-agree"},
		{"ECDH", "key-agree"},
		{"X25519", "key-agree"},
		{"AES", "block-cipher"},
		{"DES", "block-cipher"},
		{"3DES", "block-cipher"},
		{"Blowfish", "block-cipher"},
		{"ChaCha20", "stream-cipher"},
		{"RC4", "block-cipher"},
		{"MD5", "hash"},
		{"SHA-1", "hash"},
		{"SHA-256", "hash"},
		{"SHA-384", "hash"},
		{"SHA-512", "hash"},
		{"SHA-3", "hash"},
		// PQC algorithms
		{"ML-KEM-768", "kem"},
		{"Kyber768", "kem"},
		{"ML-DSA-65", "signature"},
		{"Dilithium3", "signature"},
		{"SLH-DSA-128f", "signature"},
		{"SPHINCS+", "signature"},
		// MACs and KDFs
		{"HMAC-SHA256", "mac"},
		{"KMAC256", "mac"},
		{"HKDF", "kdf"},
		{"PBKDF2", "kdf"},
		{"Argon2id", "kdf"},
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

// TestFindingsByContextAgreesWithJSON scans crypto-samples and checks the text
// report's "Findings by context" block against the JSON report of the same
// scan: one line per summary.byEvidence key in sorted order, the reported
// lines adding up to totalFindings, the withheld lines adding up to
// narrativeSuppressedCount, the rules stated once and no percentage.
func TestFindingsByContextAgreesWithJSON(t *testing.T) {
	for _, include := range []bool{false, true} {
		results, err := scanner.New(scanner.Config{
			Target:           "../../crypto-samples",
			MinSeverity:      scanner.SeverityInfo,
			IncludeNarrative: include,
		}).Scan()
		if err != nil {
			t.Fatalf("scan crypto-samples: %v", err)
		}

		jsonOut, err := NewJSONReporter(false).Generate(results)
		if err != nil {
			t.Fatalf("generate JSON: %v", err)
		}
		if !strings.Contains(jsonOut, `"byEvidence"`) {
			t.Fatalf("include-narrative=%v: JSON output has no \"byEvidence\"", include)
		}
		var parsed struct {
			Summary struct {
				TotalFindings       int            `json:"totalFindings"`
				NarrativeSuppressed int            `json:"narrativeSuppressedCount"`
				ByEvidence          map[string]int `json:"byEvidence"`
			} `json:"summary"`
		}
		if err := json.Unmarshal([]byte(jsonOut), &parsed); err != nil {
			t.Fatalf("parse JSON: %v", err)
		}
		if len(parsed.Summary.ByEvidence) == 0 {
			t.Fatalf("include-narrative=%v: summary.byEvidence is empty", include)
		}

		text, err := NewTextReporter(false).Generate(results)
		if err != nil {
			t.Fatalf("generate text: %v", err)
		}
		const heading = "  Findings by context:\n"
		const rules = "Context is decided by the scanner's rules, not by a model."
		start := strings.Index(text, heading)
		if start < 0 {
			t.Fatalf("include-narrative=%v: text output has no %q", include, strings.TrimSpace(heading))
		}
		if n := strings.Count(text, rules); n != 1 {
			t.Errorf("include-narrative=%v: the rules sentence appears %d times, want 1", include, n)
		}
		end := strings.Index(text[start:], rules)
		if end < 0 {
			t.Fatalf("include-narrative=%v: the rules sentence does not close the block", include)
		}
		block := text[start+len(heading) : start+end]
		if strings.Contains(block, "%") {
			t.Errorf("include-narrative=%v: the block prints a percentage:\n%s", include, block)
		}

		kinds := make([]string, 0, len(parsed.Summary.ByEvidence))
		for k := range parsed.Summary.ByEvidence {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)

		lines := strings.Split(strings.TrimRight(block, "\n "), "\n")
		if len(lines) != len(kinds) {
			t.Fatalf("include-narrative=%v: %d lines for %d kinds:\n%s", include, len(lines), len(kinds), block)
		}
		reported, withheld := 0, 0
		for i, kind := range kinds {
			fields := strings.Fields(lines[i])
			if len(fields) < 3 || fields[0] != kind {
				t.Fatalf("include-narrative=%v: line %d is %q, want kind %q", include, i, lines[i], kind)
			}
			n, err := strconv.Atoi(fields[1])
			if err != nil || n != parsed.Summary.ByEvidence[kind] {
				t.Errorf("include-narrative=%v: %s line says %q, JSON says %d", include, kind, fields[1], parsed.Summary.ByEvidence[kind])
			}
			rest := strings.Join(fields[2:], " ")
			switch rest {
			case "reported":
				reported += n
			case "withheld (--include-narrative shows them)":
				withheld += n
			default:
				t.Errorf("include-narrative=%v: %s line ends %q", include, kind, rest)
			}
		}
		if reported != parsed.Summary.TotalFindings {
			t.Errorf("include-narrative=%v: reported lines add up to %d, totalFindings is %d", include, reported, parsed.Summary.TotalFindings)
		}
		if withheld != parsed.Summary.NarrativeSuppressed {
			t.Errorf("include-narrative=%v: withheld lines add up to %d, narrativeSuppressedCount is %d", include, withheld, parsed.Summary.NarrativeSuppressed)
		}
		if !include && withheld == 0 {
			t.Error("the default scan of crypto-samples printed nothing as withheld")
		}
	}
}

// TestFooterLinksTheQuickAssessment pins the footer line that points a reader
// from one repository's scan to the organisation-level assessment.
func TestFooterLinksTheQuickAssessment(t *testing.T) {
	text, err := NewTextReporter(false).Generate(createTestResults())
	if err != nil {
		t.Fatalf("generate text: %v", err)
	}
	const toolkit = "  Part of the QRAMM Toolkit: https://qramm.org\n"
	const assess = "  Assess your organisation: https://qramm.org/quick-assessment.html\n"
	if !strings.Contains(text, toolkit+assess) {
		t.Errorf("footer does not carry %q directly after %q", strings.TrimSpace(assess), strings.TrimSpace(toolkit))
	}
}

// findingBlocks splits the detailed findings section of a text report into
// one string per "Finding #N" block.
func findingBlocks(text string) []string {
	parts := strings.Split(text, "┌── Finding #")
	if len(parts) < 2 {
		return nil
	}
	return parts[1:]
}

// lineWith returns the first line of block that contains marker.
func lineWith(block, marker string) string {
	for _, l := range strings.Split(block, "\n") {
		if strings.Contains(l, marker) {
			return l
		}
	}
	return ""
}

// An MD5 block names the classical break, prints a Java fix and a command
// that shows line 96; an RSA-1024 block keeps the harvest-now sentence.
func TestTextFindingBlockVerifyFixAndImpact(t *testing.T) {
	m := patterns.NewMatcher()
	engine := analyzer.NewRemediationEngine()
	ctx := &analyzer.FileContext{Language: analyzer.LangJava, FileType: analyzer.FileTypeCode}
	pick := func(line string, lineNum int, id string) scanner.Finding {
		t.Helper()
		for _, f := range m.MatchWithContext(line, "src/a.java", lineNum, ctx, nil) {
			if strings.HasPrefix(f.ID, id+"-") {
				engine.Apply(&f)
				return f
			}
		}
		t.Fatalf("no %s match in %q", id, line)
		return scanner.Finding{}
	}
	md5 := pick(`        MessageDigest md = MessageDigest.getInstance("MD5");`, 96, "MD5-001")
	rsa := pick(`        int keySize = 1024;`, 40, "RSA-1024")

	text, err := NewTextReporter(false).Generate(&scanner.Results{Findings: []scanner.Finding{md5, rsa}})
	if err != nil {
		t.Fatal(err)
	}
	blocks := findingBlocks(text)
	if len(blocks) != 2 {
		t.Fatalf("found %d finding blocks, want 2:\n%s", len(blocks), text)
	}
	md5Block, rsaBlock := blocks[0], blocks[1]

	for _, want := range []string{
		"│ Verify: sed -n '96p' src/a.java",
		`│ Fix: Replace MessageDigest.getInstance("MD5") with MessageDigest.getInstance("SHA-256")`,
		"│ Effort: Low",
		"│ Impact: Broken by classical attacks today",
	} {
		if !strings.Contains(md5Block, want) {
			t.Errorf("MD5 block lacks %q:\n%s", want, md5Block)
		}
	}
	if strings.Contains(text, "Assessment needed") {
		t.Errorf("report prints \"Assessment needed\":\n%s", text)
	}
	if impact := lineWith(md5Block, "│ Impact: "); strings.Contains(impact, "harvest") {
		t.Errorf("MD5 Impact uses quantum wording for a classical break: %q", impact)
	}

	if rsa.Severity != scanner.SeverityCritical {
		t.Fatalf("RSA-1024 severity = %s, want CRITICAL for this check", rsa.Severity)
	}
	for _, want := range []string{
		"│ Verify: sed -n '40p' src/a.java",
		"harvest-now-decrypt-later",
		"│ Fix: Migrate RSA",
		"│ Effort: Medium to High",
	} {
		if !strings.Contains(rsaBlock, want) {
			t.Errorf("RSA block lacks %q:\n%s", want, rsaBlock)
		}
	}
}

// A scanned finding carries a command that shows the matched line and one
// concrete change, in the text report and in JSON, and never ends in
// "Assessment needed".
func TestScannedFindingsCarryVerifyAndFix(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "src", "a.java")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	lines := make([]string, 100)
	lines[0] = "import java.security.MessageDigest;"
	lines[95] = `        MessageDigest md = MessageDigest.getInstance("MD5");`
	if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := scanner.New(scanner.Config{Target: dir}).Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(results.Findings) == 0 {
		t.Fatal("expected the MD5 use to be reported")
	}
	results.ScanTarget = dir

	text, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "Assessment needed") {
		t.Error("text report still prints \"Assessment needed\"")
	}

	blocks := findingBlocks(text)
	if len(blocks) != len(results.Findings) {
		t.Fatalf("found %d finding blocks, want %d", len(blocks), len(results.Findings))
	}
	md5Block := ""
	for i, b := range blocks {
		if n := strings.Count(b, "│ Verify: "); n != 1 {
			t.Errorf("finding #%d prints %d Verify lines, want 1", i+1, n)
		}
		if n := strings.Count(b, "│ Fix: "); n != 1 {
			t.Errorf("finding #%d prints %d Fix lines, want 1", i+1, n)
		}
		if _, fix, ok := strings.Cut(lineWith(b, "│ Fix: "), "│ Fix: "); ok && strings.Count(b, strings.TrimSpace(fix)) != 1 {
			t.Errorf("finding #%d prints its fix %q more than once", i+1, strings.TrimSpace(fix))
		}
		if strings.Contains(b, "│ Algorithm: MD5") {
			md5Block = b
		}
	}
	if md5Block == "" {
		t.Fatal("no MD5 finding block in the text report")
	}
	if want := "│ Verify: sed -n '96p' " + file; !strings.Contains(md5Block, want) {
		t.Errorf("MD5 block lacks %q:\n%s", want, md5Block)
	}
	if impact := lineWith(md5Block, "│ Impact: "); strings.Contains(impact, "harvest") {
		t.Errorf("MD5 Impact uses quantum wording for a classical break: %q", impact)
	}

	js, err := NewJSONReporter(false).Generate(results)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(js), &doc); err != nil {
		t.Fatal(err)
	}
	for i, f := range doc.Findings {
		for _, key := range []string{"verify", "fix"} {
			if s, _ := f[key].(string); s == "" {
				t.Errorf("JSON finding %d (%v) has no %q string", i, f["id"], key)
			}
		}
	}
}

// scanCryptoSamples runs the real scanner, with the default scan settings,
// over a temporary copy of crypto-samples. The copy keeps the scan away from
// any .cryptoscan.yaml in the repository, which the scanner would otherwise
// pick up from a parent directory.
func scanCryptoSamples(t *testing.T) *scanner.Results {
	t.Helper()

	// os.MkdirTemp rather than t.TempDir, whose path carries the test name.
	dir, err := os.MkdirTemp("", "cryptoscan-counts-")
	if err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	src := filepath.Join("..", "..", "crypto-samples")
	root := filepath.Join(dir, "crypto-samples")
	err = filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(root, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, body, 0o644)
	})
	if err != nil {
		t.Fatalf("copy crypto-samples: %v", err)
	}

	results, err := scanner.New(scanner.Config{
		Target:      root,
		MinSeverity: scanner.SeverityInfo,
	}).Scan()
	if err != nil {
		t.Fatalf("scan crypto-samples: %v", err)
	}
	if len(results.Findings) == 0 {
		t.Fatal("scan of crypto-samples produced no findings")
	}
	results.ScanTarget = root
	return results
}

// reportSection returns the text from the first line containing start up to,
// but not including, the next line containing end.
func reportSection(t *testing.T, text, start, end string) string {
	t.Helper()
	i := strings.Index(text, start)
	if i < 0 {
		t.Fatalf("report has no %q section:\n%s", start, text)
	}
	rest := text[i:]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("report has no %q after %q:\n%s", end, start, text)
	}
	return rest[:j]
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("not a number: %q", s)
	}
	return n
}

// quantumRows returns the per-risk rows and the printed total of the Quantum
// Risk Assessment block.
func quantumRows(t *testing.T, report string) (rows map[string]int, total int) {
	t.Helper()
	block := reportSection(t, report, "Quantum Risk Assessment", "Categories Found")
	rows = map[string]int{}
	for _, m := range regexp.MustCompile(`(?m)^\s+\S+\s+(VULNERABLE|PARTIAL|SAFE|UNKNOWN)\s+(\d+)\s*$`).FindAllStringSubmatch(block, -1) {
		rows[m[1]] += atoi(t, m[2])
	}
	m := regexp.MustCompile(`(?m)^\s+Total\s+(\d+)\s*$`).FindStringSubmatch(block)
	if m == nil {
		t.Fatalf("Quantum Risk Assessment prints no total row:\n%s", block)
	}
	return rows, atoi(t, m[1])
}

// TestTextReportCountsAgree checks that every breakdown in the text report
// adds up to the number it prints as Total Findings, and that each breakdown
// says which field of a finding it groups by. The readiness box groups by
// migration status and the Quantum Risk Assessment by quantum risk, so their
// rows differ (SAFE 35 against Safe (PQC) 32 on crypto-samples) and a reader
// could not tell why.
func TestTextReportCountsAgree(t *testing.T) {
	results := scanCryptoSamples(t)
	want := results.Summary.TotalFindings

	report, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("generate text report: %v", err)
	}

	m := regexp.MustCompile(`Total Findings: (\d+)`).FindStringSubmatch(report)
	if m == nil || atoi(t, m[1]) != want {
		t.Fatalf("Total Findings line = %v, want %d", m, want)
	}

	inventory := reportSection(t, report, "INVENTORY", "QRAMM DIMENSION")
	if !strings.Contains(inventory, "by migration status") {
		t.Errorf("INVENTORY does not say it counts by migration status:\n%s", inventory)
	}
	rowSum := 0
	for _, label := range []string{`Safe \(PQC\):`, `Hybrid:`, `Partial:`, `Vulnerable:`, `Critical:`} {
		m := regexp.MustCompile(label + `\s+(\d+)`).FindStringSubmatch(inventory)
		if m == nil {
			t.Fatalf("INVENTORY has no %s row:\n%s", label, inventory)
		}
		rowSum += atoi(t, m[1])
	}
	m = regexp.MustCompile(`Total:\s+(\d+)`).FindStringSubmatch(inventory)
	if m == nil {
		t.Fatalf("INVENTORY has no Total row:\n%s", inventory)
	}
	if got := atoi(t, m[1]); got != want {
		t.Errorf("INVENTORY Total: %d, Total Findings: %d", got, want)
	}
	if rowSum != want {
		t.Errorf("INVENTORY rows add up to %d, Total Findings: %d", rowSum, want)
	}

	if !strings.Contains(reportSection(t, report, "Quantum Risk Assessment", "\n"), "by quantum risk") {
		t.Errorf("Quantum Risk Assessment heading does not say it counts by quantum risk")
	}
	rows, total := quantumRows(t, report)
	quantumSum := 0
	for _, n := range rows {
		quantumSum += n
	}
	if total != want {
		t.Errorf("Quantum Risk Assessment total %d, Total Findings: %d", total, want)
	}
	if quantumSum != want {
		t.Errorf("Quantum Risk Assessment rows add up to %d, Total Findings: %d", quantumSum, want)
	}
}

// TestQuantumRowsCoverEveryFinding gives the text reporter a finding whose
// quantum risk is not one of the four printed rows. It has to be counted
// somewhere, or the rows stop adding up to Total Findings.
func TestQuantumRowsCoverEveryFinding(t *testing.T) {
	results := createTestResults()
	results.Findings[1].Quantum = ""
	results.Summary.ByQuantumRisk = map[string]int{"VULNERABLE": 1, "": 1}

	report, err := NewTextReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("generate text report: %v", err)
	}
	rows, total := quantumRows(t, report)
	sum := 0
	for _, n := range rows {
		sum += n
	}
	if sum != 2 || total != 2 {
		t.Errorf("Quantum Risk Assessment rows %v add up to %d with total %d, want 2", rows, sum, total)
	}
	if rows["UNKNOWN"] != 1 {
		t.Errorf("a finding with no quantum risk should be counted as UNKNOWN, rows %v", rows)
	}
}

// TestJSONReportCountsAgree checks that the three totals a JSON consumer can
// read for one scan are the same number.
func TestJSONReportCountsAgree(t *testing.T) {
	results := scanCryptoSamples(t)

	out, err := NewJSONReporter(false).Generate(results)
	if err != nil {
		t.Fatalf("generate JSON report: %v", err)
	}
	var doc struct {
		Summary struct {
			TotalFindings int `json:"totalFindings"`
		} `json:"summary"`
		Findings       []json.RawMessage `json:"findings"`
		MigrationScore *struct {
			TotalCount int `json:"totalCount"`
		} `json:"migrationScore"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("JSON report does not parse: %v", err)
	}
	if doc.MigrationScore == nil {
		t.Fatal("JSON report has no migrationScore")
	}
	n := len(doc.Findings)
	if n == 0 {
		t.Fatal("JSON report has no findings")
	}
	if doc.Summary.TotalFindings != n || doc.MigrationScore.TotalCount != n {
		t.Errorf("summary.totalFindings %d, len(findings) %d, migrationScore.totalCount %d: want all equal",
			doc.Summary.TotalFindings, n, doc.MigrationScore.TotalCount)
	}
}
