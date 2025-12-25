// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package types contains shared type definitions
package types

// Severity levels for findings
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// QuantumRisk indicates quantum vulnerability status
type QuantumRisk string

const (
	QuantumVulnerable QuantumRisk = "VULNERABLE" // Broken by quantum computers
	QuantumPartial    QuantumRisk = "PARTIAL"    // Weakened but not fully broken
	QuantumSafe       QuantumRisk = "SAFE"       // Quantum-resistant
	QuantumUnknown    QuantumRisk = "UNKNOWN"    // Cannot determine
)

// Finding represents a single cryptographic finding
type Finding struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Category    string            `json:"category"`
	Algorithm   string            `json:"algorithm,omitempty"`
	KeySize     int               `json:"keySize,omitempty"`
	File        string            `json:"file"`
	Line        int               `json:"line"`
	Column      int               `json:"column,omitempty"`
	Match       string            `json:"match"`
	Context     string            `json:"context,omitempty"`
	Severity    Severity          `json:"severity"`
	Quantum     QuantumRisk       `json:"quantumRisk"`
	Description string            `json:"description"`
	Remediation string            `json:"remediation,omitempty"`
	References  []string          `json:"references,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}
