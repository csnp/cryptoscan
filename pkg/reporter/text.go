// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"fmt"
	"strings"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// TextReporter generates human-readable text output
type TextReporter struct {
	colorEnabled bool
	groupBy      string
}

// NewTextReporter creates a new text reporter
func NewTextReporter(colorEnabled bool) *TextReporter {
	return &TextReporter{colorEnabled: colorEnabled}
}

// SetGroupBy sets the grouping mode for output
func (r *TextReporter) SetGroupBy(groupBy string) {
	r.groupBy = groupBy
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
	b.WriteString(r.color(colorBold, "║                    QRAMM CryptoScan                           ║\n"))
	b.WriteString(r.color(colorBold, "╚═══════════════════════════════════════════════════════════════╝\n"))
	b.WriteString("\n")

	// Migration Readiness Score (the key feature)
	if results.MigrationScore != nil {
		r.writeMigrationScore(&b, results.MigrationScore)
	}

	// Scan metadata in a box
	b.WriteString(r.color(colorCyan, "┌─ Scan Information ─────────────────────────────────────────────┐\n"))
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, " Target:   ") + fmt.Sprintf("%-52s", truncatePath(results.ScanTarget, 52)) + r.color(colorCyan, "│\n"))
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, " Time:     ") + fmt.Sprintf("%-52s", results.ScanTime.Format("2006-01-02 15:04:05")) + r.color(colorCyan, "│\n"))
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, " Duration: ") + fmt.Sprintf("%-52s", results.ScanDuration.Round(1000000).String()) + r.color(colorCyan, "│\n"))
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, " Scanned:  ") + fmt.Sprintf("%-52s", fmt.Sprintf("%d files • %d lines • %s", results.FilesScanned, results.LinesScanned, formatBytes(results.BytesScanned))) + r.color(colorCyan, "│\n"))
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, " Speed:    ") + fmt.Sprintf("%-52s", formatScanSpeed(results)) + r.color(colorCyan, "│\n"))
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

	// Handle grouped output
	if r.groupBy == "file" {
		return r.generateGroupedByFile(results, &b)
	}

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

		// Source code context - the key feature for verification
		if f.SourceContext != nil && len(f.SourceContext.Lines) > 0 {
			b.WriteString("  │\n")
			b.WriteString(fmt.Sprintf("  │ %s\n", r.color(colorBold, "Source:")))
			b.WriteString(fmt.Sprintf("  │ %s\n", r.color(colorCyan, "┌────────────────────────────────────────────────────────")))
			for _, srcLine := range f.SourceContext.Lines {
				linePrefix := "  │ │"
				lineNumStr := fmt.Sprintf("%4d", srcLine.Number)
				if srcLine.IsMatch {
					// Highlight the matching line with arrow and color
					b.WriteString(fmt.Sprintf("%s %s %s %s\n",
						linePrefix,
						r.color(colorRed+colorBold, "→"),
						r.color(colorYellow, lineNumStr),
						r.color(colorRed+colorBold, srcLine.Content)))
				} else {
					b.WriteString(fmt.Sprintf("%s   %s %s\n",
						linePrefix,
						r.color(colorCyan, lineNumStr),
						r.color(colorReset, srcLine.Content)))
				}
			}
			b.WriteString(fmt.Sprintf("  │ %s\n", r.color(colorCyan, "└────────────────────────────────────────────────────────")))
			b.WriteString("  │\n")
		}

		// Match (what pattern was detected)
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

// generateGroupedByFile generates output grouped by file
func (r *TextReporter) generateGroupedByFile(results *scanner.Results, b *strings.Builder) (string, error) {
	// Group findings by file
	byFile := make(map[string][]scanner.Finding)
	for _, f := range results.Findings {
		byFile[f.File] = append(byFile[f.File], f)
	}

	// Sort files for consistent output
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	// Sort by number of findings (most first), then alphabetically
	for i := 0; i < len(files)-1; i++ {
		for j := i + 1; j < len(files); j++ {
			if len(byFile[files[i]]) < len(byFile[files[j]]) {
				files[i], files[j] = files[j], files[i]
			} else if len(byFile[files[i]]) == len(byFile[files[j]]) && files[i] > files[j] {
				files[i], files[j] = files[j], files[i]
			}
		}
	}

	findingNum := 0
	for _, file := range files {
		findings := byFile[file]

		// File header
		b.WriteString(r.color(colorBold+colorCyan, fmt.Sprintf("  ━━━ %s ", file)))
		b.WriteString(r.color(colorYellow, fmt.Sprintf("(%d findings)", len(findings))))
		b.WriteString(r.color(colorBold+colorCyan, " ━━━\n"))
		b.WriteString("\n")

		for _, f := range findings {
			findingNum++
			sevColor := r.severityColor(f.Severity)

			// Compact finding display
			b.WriteString(fmt.Sprintf("    %s #%d %s Line %d\n",
				r.color(sevColor, fmt.Sprintf("[%s]", f.Severity.String())),
				findingNum,
				r.color(colorBold, f.Type),
				f.Line))

			// Source code context
			if f.SourceContext != nil && len(f.SourceContext.Lines) > 0 {
				b.WriteString(r.color(colorCyan, "    ┌──────────────────────────────────────────────────\n"))
				for _, srcLine := range f.SourceContext.Lines {
					lineNumStr := fmt.Sprintf("%4d", srcLine.Number)
					if srcLine.IsMatch {
						b.WriteString(fmt.Sprintf("    │ %s %s %s\n",
							r.color(colorRed+colorBold, "→"),
							r.color(colorYellow, lineNumStr),
							r.color(colorRed+colorBold, srcLine.Content)))
					} else {
						b.WriteString(fmt.Sprintf("    │   %s %s\n",
							r.color(colorCyan, lineNumStr),
							srcLine.Content))
					}
				}
				b.WriteString(r.color(colorCyan, "    └──────────────────────────────────────────────────\n"))
			}

			// Match and quantum risk on one line
			b.WriteString(fmt.Sprintf("    %s %s  •  %s\n",
				r.color(colorBold, "Match:"),
				r.color(colorMagenta, f.Match),
				r.quantumIcon(f.Quantum)))

			// Remediation (compact)
			if f.Remediation != "" {
				b.WriteString(fmt.Sprintf("    %s %s\n",
					r.color(colorGreen+colorBold, "Fix:"),
					r.color(colorGreen, f.Remediation)))
			}

			b.WriteString("\n")
		}
	}

	r.writeFooter(b)
	return b.String(), nil
}

func (r *TextReporter) writeMigrationScore(b *strings.Builder, score *scanner.MigrationScore) {
	// Migration Readiness Score box
	b.WriteString(r.color(colorBold+colorCyan, "┌─ QUANTUM MIGRATION READINESS ──────────────────────────────────┐\n"))

	// Score visualization
	scoreInt := int(score.Score)
	filledBars := scoreInt / 4 // 25 bars = 100%
	emptyBars := 25 - filledBars

	scoreColor := colorRed
	if score.Score >= 75 {
		scoreColor = colorGreen
	} else if score.Score >= 50 {
		scoreColor = colorYellow
	} else if score.Score >= 25 {
		scoreColor = colorYellow
	}

	progressBar := r.color(scoreColor, strings.Repeat("█", filledBars)) + strings.Repeat("░", emptyBars)
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, fmt.Sprintf("  Score: %s %.1f%% ", progressBar, score.Score)))

	// Risk level badge
	levelColor := colorRed
	switch score.Level {
	case "LOW":
		levelColor = colorGreen
	case "MEDIUM":
		levelColor = colorYellow
	case "HIGH":
		levelColor = colorRed
	case "CRITICAL":
		levelColor = colorRed + colorBold
	}
	b.WriteString(r.color(levelColor, fmt.Sprintf("[%s]", score.Level)))
	b.WriteString(r.color(colorCyan, fmt.Sprintf("%s│\n", strings.Repeat(" ", 8-len(score.Level)))))

	b.WriteString(r.color(colorCyan, "│") + r.color(colorCyan, "─────────────────────────────────────────────────────────────────") + r.color(colorCyan, "│\n"))

	// Status breakdown
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, "  INVENTORY                                                     ") + r.color(colorCyan, "│\n"))
	b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    %s Safe (PQC):        %-5d", r.color(colorGreen, "✓"), score.SafeCount) + fmt.Sprintf("    %s Vulnerable:    %-5d", r.color(colorRed, "✗"), score.VulnerableCount) + r.color(colorCyan, "   │\n"))
	b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    %s Hybrid:            %-5d", r.color(colorGreen, "◐"), score.HybridCount) + fmt.Sprintf("    %s Critical:      %-5d", r.color(colorRed+colorBold, "⚠"), score.CriticalCount) + r.color(colorCyan, "   │\n"))
	b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    %s Partial:           %-5d", r.color(colorYellow, "◑"), score.PartialCount) + fmt.Sprintf("    Total:          %-5d", score.TotalCount) + r.color(colorCyan, "   │\n"))

	// QRAMM Readiness
	if score.QRAMMReadiness != nil {
		b.WriteString(r.color(colorCyan, "│") + r.color(colorCyan, "─────────────────────────────────────────────────────────────────") + r.color(colorCyan, "│\n"))
		b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, "  QRAMM DIMENSION 1: Cryptographic Visibility & Inventory (CVI) ") + r.color(colorCyan, "│\n"))

		// Practice levels
		b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    Practice 1.1 Discovery:   Level %d/5 %s", score.QRAMMReadiness.DiscoveryLevel, r.maturityIndicator(score.QRAMMReadiness.DiscoveryLevel)) + r.color(colorCyan, "                    │\n"))
		b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    Practice 1.2 Assessment:  Level %d/5 %s", score.QRAMMReadiness.AssessmentLevel, r.maturityIndicator(score.QRAMMReadiness.AssessmentLevel)) + r.color(colorCyan, "                    │\n"))
		b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    Practice 1.3 Mapping:     Level %d/5 %s", score.QRAMMReadiness.MappingLevel, r.maturityIndicator(score.QRAMMReadiness.MappingLevel)) + r.color(colorCyan, "                    │\n"))
	}

	// Top risk files
	if len(score.TopRiskFiles) > 0 {
		b.WriteString(r.color(colorCyan, "│") + r.color(colorCyan, "─────────────────────────────────────────────────────────────────") + r.color(colorCyan, "│\n"))
		b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, "  TOP PRIORITY FILES                                            ") + r.color(colorCyan, "│\n"))
		for i, f := range score.TopRiskFiles {
			if i >= 3 {
				break
			}
			truncFile := truncatePath(f.File, 40)
			b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    %d. %-42s (%d findings)", i+1, truncFile, f.TotalFindings) + r.color(colorCyan, "  │\n"))
		}
	}

	// Recommendations
	if score.QRAMMReadiness != nil && len(score.QRAMMReadiness.Recommendations) > 0 {
		b.WriteString(r.color(colorCyan, "│") + r.color(colorCyan, "─────────────────────────────────────────────────────────────────") + r.color(colorCyan, "│\n"))
		b.WriteString(r.color(colorCyan, "│") + r.color(colorBold+colorGreen, "  RECOMMENDATIONS                                               ") + r.color(colorCyan, "│\n"))
		for i, rec := range score.QRAMMReadiness.Recommendations {
			if i >= 3 {
				break
			}
			// Truncate recommendation to fit
			if len(rec) > 60 {
				rec = rec[:57] + "..."
			}
			b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    • %-59s", rec) + r.color(colorCyan, "│\n"))
		}
	}

	b.WriteString(r.color(colorBold+colorCyan, "└─────────────────────────────────────────────────────────────────┘\n"))
	b.WriteString("\n")
}

func (r *TextReporter) maturityIndicator(level int) string {
	filled := strings.Repeat("●", level)
	empty := strings.Repeat("○", 5-level)
	if level >= 4 {
		return r.color(colorGreen, filled) + empty
	} else if level >= 3 {
		return r.color(colorYellow, filled) + empty
	}
	return r.color(colorRed, filled) + empty
}

func (r *TextReporter) writeFooter(b *strings.Builder) {
	b.WriteString(r.color(colorBold, "═══════════════════════════════════════════════════════════════\n"))
	b.WriteString(r.color(colorCyan, "  QRAMM CryptoScan") + " - Quantum Readiness Assessment Tool\n")
	b.WriteString("  Part of the QRAMM Toolkit: https://qramm.org\n")
	b.WriteString("  Developed by CSNP: https://csnp.org\n")
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

// formatBytes converts bytes to human readable format
func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// formatScanSpeed calculates and formats scan speed metrics
func formatScanSpeed(results *scanner.Results) string {
	if results.ScanDuration.Seconds() == 0 {
		return "N/A"
	}
	secs := results.ScanDuration.Seconds()
	filesPerSec := float64(results.FilesScanned) / secs
	mbPerSec := float64(results.BytesScanned) / (1024 * 1024) / secs
	return fmt.Sprintf("%.0f files/sec • %.1f MB/sec", filesPerSec, mbPerSec)
}

// truncatePath shortens a path to fit within maxLen
func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}
	return "..." + path[len(path)-maxLen+3:]
}
