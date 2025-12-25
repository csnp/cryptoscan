// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"fmt"
	"strings"

	"github.com/csnp/qramm-cryptoscan/pkg/scanner"
)

// TextReporter generates human-readable text output
type TextReporter struct {
	colorEnabled bool
}

// NewTextReporter creates a new text reporter
func NewTextReporter(colorEnabled bool) *TextReporter {
	return &TextReporter{colorEnabled: colorEnabled}
}

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorBold    = "\033[1m"
)

func (r *TextReporter) color(code, text string) string {
	if !r.colorEnabled {
		return text
	}
	return code + text + colorReset
}

func (r *TextReporter) severityColor(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical:
		return colorRed + colorBold
	case scanner.SeverityHigh:
		return colorRed
	case scanner.SeverityMedium:
		return colorYellow
	case scanner.SeverityLow:
		return colorBlue
	default:
		return colorCyan
	}
}

func (r *TextReporter) quantumIcon(q scanner.QuantumRisk) string {
	switch q {
	case scanner.QuantumVulnerable:
		return "⚠️  QUANTUM VULNERABLE"
	case scanner.QuantumPartial:
		return "⚡ QUANTUM WEAKENED"
	case scanner.QuantumSafe:
		return "✓  QUANTUM SAFE"
	default:
		return "?  UNKNOWN"
	}
}

// Generate creates the text report
func (r *TextReporter) Generate(results *scanner.Results) (string, error) {
	var b strings.Builder

	// Header
	b.WriteString("\n")
	b.WriteString(r.color(colorBold, "═══════════════════════════════════════════════════════════════\n"))
	b.WriteString(r.color(colorBold, "                    CRYPTOGRAPHIC SCAN RESULTS\n"))
	b.WriteString(r.color(colorBold, "═══════════════════════════════════════════════════════════════\n"))
	b.WriteString("\n")

	// Scan metadata
	b.WriteString(r.color(colorBold, "Scan Target: "))
	b.WriteString(results.ScanTarget + "\n")
	b.WriteString(r.color(colorBold, "Scan Time:   "))
	b.WriteString(results.ScanTime.Format("2006-01-02 15:04:05") + "\n")
	b.WriteString(r.color(colorBold, "Duration:    "))
	b.WriteString(results.ScanDuration.String() + "\n")
	b.WriteString(r.color(colorBold, "Files:       "))
	b.WriteString(fmt.Sprintf("%d files, %d lines scanned\n", results.FilesScanned, results.LinesScanned))
	b.WriteString("\n")

	// Summary
	b.WriteString(r.color(colorBold, "─────────────────────────────────────────────────────────────────\n"))
	b.WriteString(r.color(colorBold, "                           SUMMARY\n"))
	b.WriteString(r.color(colorBold, "─────────────────────────────────────────────────────────────────\n"))
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("Total Findings: %d\n", results.Summary.TotalFindings))
	b.WriteString("\n")

	// By severity
	b.WriteString(r.color(colorBold, "By Severity:\n"))
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if count, ok := results.Summary.BySeverity[sev]; ok && count > 0 {
			b.WriteString(fmt.Sprintf("  %-10s %d\n", sev+":", count))
		}
	}
	b.WriteString("\n")

	// Quantum risk summary
	b.WriteString(r.color(colorBold, "Quantum Risk Assessment:\n"))
	if results.Summary.QuantumVulnCount > 0 {
		b.WriteString(r.color(colorRed+colorBold, fmt.Sprintf("  ⚠️  %d quantum-vulnerable findings require immediate attention\n", results.Summary.QuantumVulnCount)))
	}
	for _, risk := range []string{"VULNERABLE", "PARTIAL", "SAFE", "UNKNOWN"} {
		if count, ok := results.Summary.ByQuantumRisk[risk]; ok && count > 0 {
			b.WriteString(fmt.Sprintf("  %-12s %d\n", risk+":", count))
		}
	}
	b.WriteString("\n")

	// By category
	b.WriteString(r.color(colorBold, "By Category:\n"))
	for cat, count := range results.Summary.ByCategory {
		b.WriteString(fmt.Sprintf("  %-20s %d\n", cat+":", count))
	}
	b.WriteString("\n")

	if len(results.Findings) == 0 {
		b.WriteString(r.color(colorGreen, "✓ No cryptographic findings detected\n"))
		return b.String(), nil
	}

	// Detailed findings
	b.WriteString(r.color(colorBold, "─────────────────────────────────────────────────────────────────\n"))
	b.WriteString(r.color(colorBold, "                          FINDINGS\n"))
	b.WriteString(r.color(colorBold, "─────────────────────────────────────────────────────────────────\n"))
	b.WriteString("\n")

	for i, f := range results.Findings {
		// Finding header
		sevColor := r.severityColor(f.Severity)
		b.WriteString(r.color(sevColor, fmt.Sprintf("[%s] ", f.Severity.String())))
		b.WriteString(r.color(colorBold, f.Type))
		b.WriteString("\n")

		// Location
		b.WriteString(fmt.Sprintf("  File: %s:%d\n", f.File, f.Line))

		// Match
		b.WriteString(fmt.Sprintf("  Match: %s\n", f.Match))

		// Algorithm and key size if present
		if f.Algorithm != "" {
			b.WriteString(fmt.Sprintf("  Algorithm: %s", f.Algorithm))
			if f.KeySize > 0 {
				b.WriteString(fmt.Sprintf(" (%d-bit)", f.KeySize))
			}
			b.WriteString("\n")
		}

		// Quantum risk
		b.WriteString(fmt.Sprintf("  Quantum: %s\n", r.quantumIcon(f.Quantum)))

		// Description
		b.WriteString(fmt.Sprintf("  Description: %s\n", f.Description))

		// Remediation
		if f.Remediation != "" {
			b.WriteString(r.color(colorGreen, fmt.Sprintf("  Remediation: %s\n", f.Remediation)))
		}

		if i < len(results.Findings)-1 {
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(r.color(colorBold, "═══════════════════════════════════════════════════════════════\n"))

	return b.String(), nil
}
