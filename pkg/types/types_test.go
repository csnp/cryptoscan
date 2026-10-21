// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"testing"
)

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
		{Severity(99), "INFO"}, // Unknown defaults to INFO
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.sev.String(); got != tt.want {
				t.Errorf("Severity.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverityOrder(t *testing.T) {
	// Verify severity ordering
	if SeverityInfo >= SeverityLow {
		t.Error("INFO should be less severe than LOW")
	}
	if SeverityLow >= SeverityMedium {
		t.Error("LOW should be less severe than MEDIUM")
	}
	if SeverityMedium >= SeverityHigh {
		t.Error("MEDIUM should be less severe than HIGH")
	}
	if SeverityHigh >= SeverityCritical {
		t.Error("HIGH should be less severe than CRITICAL")
	}
}

func TestQuantumRiskValues(t *testing.T) {
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
			if string(tt.risk) != tt.want {
				t.Errorf("QuantumRisk = %v, want %v", tt.risk, tt.want)
			}
		})
	}
}

func TestConfidenceValues(t *testing.T) {
	tests := []struct {
		conf Confidence
		want string
	}{
		{ConfidenceHigh, "HIGH"},
		{ConfidenceMedium, "MEDIUM"},
		{ConfidenceLow, "LOW"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if string(tt.conf) != tt.want {
				t.Errorf("Confidence = %v, want %v", tt.conf, tt.want)
			}
		})
	}
}

func TestFindingTypeValues(t *testing.T) {
	tests := []struct {
		ft   FindingType
		want string
	}{
		{FindingTypeAlgorithm, "algorithm"},
		{FindingTypeDependency, "dependency"},
		{FindingTypeConfig, "config"},
		{FindingTypeSecret, "secret"},
		{FindingTypeProtocol, "protocol"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if string(tt.ft) != tt.want {
				t.Errorf("FindingType = %v, want %v", tt.ft, tt.want)
			}
		})
	}
}

func TestFindingPriority(t *testing.T) {
	tests := []struct {
		name     string
		finding  Finding
		minScore int
		maxScore int
	}{
		{
			name: "Critical quantum-vulnerable secret",
			finding: Finding{
				Severity:    SeverityCritical,
				Quantum:     QuantumVulnerable,
				Confidence:  ConfidenceHigh,
				FindingType: FindingTypeSecret,
				FileType:    "code",
			},
			minScore: 200,
			maxScore: 300,
		},
		{
			name: "High severity algorithm in code",
			finding: Finding{
				Severity:    SeverityHigh,
				Quantum:     QuantumVulnerable,
				Confidence:  ConfidenceHigh,
				FindingType: FindingTypeAlgorithm,
				FileType:    "code",
			},
			minScore: 150,
			maxScore: 250,
		},
		{
			name: "Medium dependency finding",
			finding: Finding{
				Severity:    SeverityMedium,
				Quantum:     QuantumPartial,
				Confidence:  ConfidenceMedium,
				FindingType: FindingTypeDependency,
				FileType:    "config",
			},
			minScore: 80,
			maxScore: 150,
		},
		{
			name: "Low info in test file",
			finding: Finding{
				Severity:    SeverityInfo,
				Quantum:     QuantumSafe,
				Confidence:  ConfidenceLow,
				FindingType: FindingTypeConfig,
				FileType:    "test",
			},
			minScore: -20,
			maxScore: 50,
		},
		{
			name: "Documentation finding",
			finding: Finding{
				Severity:    SeverityInfo,
				Quantum:     QuantumUnknown,
				Confidence:  ConfidenceLow,
				FindingType: FindingTypeAlgorithm,
				FileType:    "documentation",
			},
			minScore: -30,
			maxScore: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := tt.finding.Priority()
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("Priority() = %d, want between %d and %d", score, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestFindingPriorityOrdering(t *testing.T) {
	// Critical should score higher than high
	critical := Finding{
		Severity:    SeverityCritical,
		Quantum:     QuantumVulnerable,
		Confidence:  ConfidenceHigh,
		FindingType: FindingTypeSecret,
		FileType:    "code",
	}
	high := Finding{
		Severity:    SeverityHigh,
		Quantum:     QuantumVulnerable,
		Confidence:  ConfidenceHigh,
		FindingType: FindingTypeSecret,
		FileType:    "code",
	}

	if critical.Priority() <= high.Priority() {
		t.Error("Critical findings should have higher priority than high")
	}

	// Quantum vulnerable should score higher than safe
	vulnQ := Finding{
		Severity:    SeverityHigh,
		Quantum:     QuantumVulnerable,
		Confidence:  ConfidenceHigh,
		FindingType: FindingTypeAlgorithm,
		FileType:    "code",
	}
	safeQ := Finding{
		Severity:    SeverityHigh,
		Quantum:     QuantumSafe,
		Confidence:  ConfidenceHigh,
		FindingType: FindingTypeAlgorithm,
		FileType:    "code",
	}

	if vulnQ.Priority() <= safeQ.Priority() {
		t.Error("Quantum vulnerable findings should have higher priority")
	}

	// Code files should score higher than test files
	codeFile := Finding{
		Severity:    SeverityMedium,
		Quantum:     QuantumPartial,
		Confidence:  ConfidenceMedium,
		FindingType: FindingTypeAlgorithm,
		FileType:    "code",
	}
	testFile := Finding{
		Severity:    SeverityMedium,
		Quantum:     QuantumPartial,
		Confidence:  ConfidenceMedium,
		FindingType: FindingTypeAlgorithm,
		FileType:    "test",
	}

	if codeFile.Priority() <= testFile.Priority() {
		t.Error("Code file findings should have higher priority than test files")
	}

	// Secrets should score higher than algorithms
	secret := Finding{
		Severity:    SeverityCritical,
		Quantum:     QuantumVulnerable,
		Confidence:  ConfidenceHigh,
		FindingType: FindingTypeSecret,
		FileType:    "code",
	}
	algo := Finding{
		Severity:    SeverityCritical,
		Quantum:     QuantumVulnerable,
		Confidence:  ConfidenceHigh,
		FindingType: FindingTypeAlgorithm,
		FileType:    "code",
	}

	if secret.Priority() <= algo.Priority() {
		t.Error("Secret findings should have higher priority than algorithm findings")
	}
}

func TestFindingFields(t *testing.T) {
	finding := Finding{
		ID:          "RSA-001",
		Type:        "RSA Key Generation",
		FindingType: FindingTypeAlgorithm,
		Category:    "Asymmetric Cryptography",
		Algorithm:   "RSA",
		KeySize:     2048,
		File:        "/src/crypto.go",
		Line:        42,
		Column:      10,
		Match:       "rsa.GenerateKey(rand.Reader, 2048)",
		Context:     "func generateKey() {",
		Severity:    SeverityHigh,
		Quantum:     QuantumVulnerable,
		Confidence:  ConfidenceHigh,
		Purpose:     "key-generation",
		Language:    "go",
		FileType:    "code",
		Description: "RSA key generation detected",
		Remediation: "Migrate to ML-KEM",
		Impact:      "High - exposed to quantum attacks",
		Effort:      "Medium - requires library changes",
		References:  []string{"https://nist.gov/pqc"},
		Tags:        []string{"asymmetric", "key-generation"},
		Metadata:    map[string]string{"nist_status": "deprecated"},
	}

	// Verify all fields are set
	if finding.ID == "" {
		t.Error("ID should be set")
	}
	if finding.Type == "" {
		t.Error("Type should be set")
	}
	if finding.Algorithm != "RSA" {
		t.Errorf("Algorithm = %s, want RSA", finding.Algorithm)
	}
	if finding.KeySize != 2048 {
		t.Errorf("KeySize = %d, want 2048", finding.KeySize)
	}
	if len(finding.References) != 1 {
		t.Errorf("References length = %d, want 1", len(finding.References))
	}
	if len(finding.Tags) != 2 {
		t.Errorf("Tags length = %d, want 2", len(finding.Tags))
	}
	if finding.Metadata["nist_status"] != "deprecated" {
		t.Error("Metadata nist_status should be deprecated")
	}
}

// A finding's severity is written by name, the form summary.bySeverity keys
// on, rather than as the number 0 to 4.
func TestFindingSeverityIsWrittenByName(t *testing.T) {
	for _, sev := range []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		data, err := json.Marshal(Finding{ID: "X-001", Severity: sev})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got := doc["severity"]; got != sev.String() {
			t.Errorf("severity %d is written as %#v, want %q", int(sev), got, sev.String())
		}
	}
}

// A severity is read by name in any case, and as the number an earlier
// release wrote, so that an older JSON report still loads as a baseline.
func TestSeverityReadsNameOrNumber(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Severity
	}{
		{`"HIGH"`, SeverityHigh},
		{`"critical"`, SeverityCritical},
		{`"Info"`, SeverityInfo},
		{`3`, SeverityHigh},
		{`0`, SeverityInfo},
		{`4`, SeverityCritical},
	} {
		var got Severity
		if err := json.Unmarshal([]byte(tc.in), &got); err != nil {
			t.Errorf("unmarshal %s: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("unmarshal %s = %s, want %s", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{`"SEVERE"`, `5`, `-1`, `true`} {
		var got Severity
		if err := json.Unmarshal([]byte(bad), &got); err == nil {
			t.Errorf("unmarshal %s = %s, want an error", bad, got)
		}
	}
}

// Every finding carries the algorithm and keySize keys: null when the pattern
// names no algorithm or records no key size, the value otherwise. A finding
// written this way reads back unchanged.
func TestFindingAlwaysHasAlgorithmAndKeySizeKeys(t *testing.T) {
	for _, f := range []Finding{
		{ID: "KEYSIZE-001", Type: "Hardcoded Key Size", Severity: SeverityLow},
		{ID: "RSA-001", Algorithm: "RSA", Severity: SeverityHigh},
		{ID: "RSA-1024", Algorithm: "RSA", KeySize: 1024, Severity: SeverityCritical},
	} {
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal %s: %v", f.ID, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("unmarshal %s: %v", f.ID, err)
		}
		algorithm, ok := doc["algorithm"]
		if !ok {
			t.Errorf("%s: no algorithm key in %s", f.ID, data)
		}
		keySize, ok := doc["keySize"]
		if !ok {
			t.Errorf("%s: no keySize key in %s", f.ID, data)
		}
		var wantAlgorithm, wantKeySize any
		if f.Algorithm != "" {
			wantAlgorithm = f.Algorithm
		}
		if f.KeySize != 0 {
			wantKeySize = float64(f.KeySize)
		}
		if algorithm != wantAlgorithm || keySize != wantKeySize {
			t.Errorf("%s: algorithm %#v, keySize %#v; want %#v and %#v", f.ID, algorithm, keySize, wantAlgorithm, wantKeySize)
		}

		var back Finding
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("read back %s: %v", f.ID, err)
		}
		if back.ID != f.ID || back.Algorithm != f.Algorithm || back.KeySize != f.KeySize || back.Severity != f.Severity {
			t.Errorf("%s read back as %+v", f.ID, back)
		}
	}
}
