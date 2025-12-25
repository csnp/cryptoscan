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
	b.WriteString(r.color(colorBold, "╔═══════════════════════════════════════════════════════════════╗\n"))
	b.WriteString(r.color(colorBold, "║              CRYPTOGRAPHIC SCAN RESULTS                       ║\n"))
	b.WriteString(r.color(colorBold, "╚═══════════════════════════════════════════════════════════════╝\n"))
	b.WriteString("\n")

	// Scan metadata in a box
	b.WriteString(r.color(colorCyan, "┌─ Scan Information ─────────────────────────────────────────────┐\n"))
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, " Target:   ") + fmt.Sprintf("%-52s", results.ScanTarget) + r.color(colorCyan, "│\n"))
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, " Time:     ") + fmt.Sprintf("%-52s", results.ScanTime.Format("2006-01-02 15:04:05")) + r.color(colorCyan, "│\n"))
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, " Duration: ") + fmt.Sprintf("%-52s", results.ScanDuration.String()) + r.color(colorCyan, "│\n"))
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, " Files:    ") + fmt.Sprintf("%-52s", fmt.Sprintf("%d files, %d lines scanned", results.FilesScanned, results.LinesScanned)) + r.color(colorCyan, "│\n"))
	b.WriteString(r.color(colorCyan, "└─────────────────────────────────────────────────────────────────┘\n"))
	b.WriteString("\n")

	// Summary section
	b.WriteString(r.color(colorBold, "┌─ Summary ───────────────────────────────────────────────────────┐\n"))
	b.WriteString(r.color(colorBold, fmt.Sprintf("│  Total Findings: %-46d │\n", results.Summary.TotalFindings)))
	b.WriteString(r.color(colorBold, "└─────────────────────────────────────────────────────────────────┘\n"))
	b.WriteString("\n")

	// Severity breakdown with visual indicators
	b.WriteString(r.color(colorBold, "  Severity Breakdown:\n"))
	severities := []struct {
		name  string
		color string
		icon  string
	}{
		{"CRITICAL", colorRed + colorBold, "●"},
		{"HIGH", colorRed, "●"},
		{"MEDIUM", colorYellow, "●"},
		{"LOW", colorBlue, "●"},
		{"INFO", colorCyan, "●"},
	}
	for _, sev := range severities {
		if count, ok := results.Summary.BySeverity[sev.name]; ok && count > 0 {
			bar := strings.Repeat("█", min(count, 30))
			b.WriteString(fmt.Sprintf("    %s %s%-10s%s %3d %s\n",
				r.color(sev.color, sev.icon),
				r.color(sev.color, ""),
				sev.name,
				r.color(colorReset, ""),
				count,
				r.color(sev.color, bar)))
		}
	}
	b.WriteString("\n")

	// Quantum Risk Assessment with visual emphasis
	b.WriteString(r.color(colorBold, "  Quantum Risk Assessment:\n"))
	if results.Summary.QuantumVulnCount > 0 {
		b.WriteString(r.color(colorRed+colorBold, fmt.Sprintf("    ⚠️  %d quantum-vulnerable findings require migration planning\n", results.Summary.QuantumVulnCount)))
	}
	quantumRisks := []struct {
		name  string
		color string
		icon  string
	}{
		{"VULNERABLE", colorRed, "◆"},
		{"PARTIAL", colorYellow, "◇"},
		{"SAFE", colorGreen, "✓"},
		{"UNKNOWN", colorCyan, "?"},
	}
	for _, risk := range quantumRisks {
		if count, ok := results.Summary.ByQuantumRisk[risk.name]; ok && count > 0 {
			b.WriteString(fmt.Sprintf("    %s %s%-12s%s %d\n",
				r.color(risk.color, risk.icon),
				r.color(risk.color, ""),
				risk.name,
				r.color(colorReset, ""),
				count))
		}
	}
	b.WriteString("\n")

	// Categories
	b.WriteString(r.color(colorBold, "  Categories Found:\n"))
	for cat, count := range results.Summary.ByCategory {
		b.WriteString(fmt.Sprintf("    ├─ %-24s %d\n", cat, count))
	}
	b.WriteString("\n")

	if len(results.Findings) == 0 {
		b.WriteString(r.color(colorGreen, "  ✓ No cryptographic findings detected\n"))
		b.WriteString("\n")
		r.writeFooter(&b)
		return b.String(), nil
	}

	// Findings section
	b.WriteString(r.color(colorBold, "╔═══════════════════════════════════════════════════════════════╗\n"))
	b.WriteString(r.color(colorBold, "║                      DETAILED FINDINGS                        ║\n"))
	b.WriteString(r.color(colorBold, "╚═══════════════════════════════════════════════════════════════╝\n"))
	b.WriteString("\n")

	for i, f := range results.Findings {
		// Finding number and severity badge
		sevColor := r.severityColor(f.Severity)
		b.WriteString(fmt.Sprintf("  %s Finding #%d %s\n",
			r.color(colorBold, "┌──"),
			i+1,
			r.color(sevColor, fmt.Sprintf("[%s]", f.Severity.String()))))

		// Type
		b.WriteString(fmt.Sprintf("  │ %s %s\n",
			r.color(colorBold, "Type:"),
			r.color(colorBold, f.Type)))

		// Location
		b.WriteString(fmt.Sprintf("  │ %s %s:%d\n",
			r.color(colorBold, "File:"),
			f.File, f.Line))

		// Match
		b.WriteString(fmt.Sprintf("  │ %s %s\n",
			r.color(colorBold, "Match:"),
			r.color(colorMagenta, f.Match)))

		// Algorithm and key size
		if f.Algorithm != "" {
			algoStr := f.Algorithm
			if f.KeySize > 0 {
				algoStr += fmt.Sprintf(" (%d-bit)", f.KeySize)
			}
			b.WriteString(fmt.Sprintf("  │ %s %s\n",
				r.color(colorBold, "Algorithm:"),
				algoStr))
		}

		// Quantum risk with icon
		b.WriteString(fmt.Sprintf("  │ %s %s\n",
			r.color(colorBold, "Quantum:"),
			r.quantumIcon(f.Quantum)))

		// Confidence
		if f.Confidence != "" {
			b.WriteString(fmt.Sprintf("  │ %s %s\n",
				r.color(colorBold, "Confidence:"),
				string(f.Confidence)))
		}

		// Description
		b.WriteString(fmt.Sprintf("  │ %s\n", r.color(colorBold, "Description:")))
		b.WriteString(fmt.Sprintf("  │   %s\n", f.Description))

		// Remediation
		if f.Remediation != "" {
			b.WriteString(fmt.Sprintf("  │ %s\n", r.color(colorGreen+colorBold, "Remediation:")))
			b.WriteString(fmt.Sprintf("  │   %s\n", r.color(colorGreen, f.Remediation)))
		}

		// Impact and Effort if present
		if f.Impact != "" {
			b.WriteString(fmt.Sprintf("  │ %s %s\n",
				r.color(colorBold, "Impact:"),
				f.Impact))
		}
		if f.Effort != "" {
			b.WriteString(fmt.Sprintf("  │ %s %s\n",
				r.color(colorBold, "Effort:"),
				f.Effort))
		}

		b.WriteString("  └────────────────────────────────────────────────────────────\n")

		if i < len(results.Findings)-1 {
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	r.writeFooter(&b)

	return b.String(), nil
}

func (r *TextReporter) writeFooter(b *strings.Builder) {
	b.WriteString(r.color(colorBold, "═══════════════════════════════════════════════════════════════\n"))
	b.WriteString(r.color(colorCyan, "  QRAMM Cryptographic Scanner") + " - Part of the QRAMM Toolkit\n")
	b.WriteString("  https://qramm.org  •  https://csnp.org\n")
	b.WriteString("\n")
	b.WriteString(r.color(colorGreen, "  CSNP Mission: ") + "Advancing cybersecurity through education,\n")
	b.WriteString("  research, and open-source tools that empower organizations.\n")
	b.WriteString(r.color(colorBold, "═══════════════════════════════════════════════════════════════\n"))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
