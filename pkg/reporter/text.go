// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/csnp/cryptoscan/pkg/analyzer"
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
		return "[!] QUANTUM VULNERABLE"
	case scanner.QuantumPartial:
		return "[~] QUANTUM WEAKENED"
	case scanner.QuantumSafe:
		return "✓  QUANTUM SAFE"
	default:
		return "?  UNKNOWN"
	}
}

// NothingScanned is the line printed in place of "No cryptographic findings
// detected" when a scan read no files, as for an empty directory or one whose
// every file was left out. Such a scan has no findings, but it checked
// nothing, so the line has no check mark. The scan command's stream footer
// prints the same line, and the pqc view prints it in place of its three
// lists. The target comes last so that a target written as "."
// does not end the line in "..".
func NothingScanned(target string) string {
	return "Nothing was checked: no files were scanned under " + target
}

// IncludeSkippedHint names the flag that scans the directories
// SkippedDirectoriesSummary counts.
const IncludeSkippedHint = "Scan them with --include-skipped."

// IncludeReportsHint names the flag that scans the files left out because
// they start like a CryptoScan report. The text report and the notice the
// scan command prints for the other formats add it to the list of files not
// scanned when one of them is such a file.
const IncludeReportsHint = "Pass --include-reports to scan as source the files listed as CryptoScan reports because of how they start."

// SkippedDirectoriesSummary says how many files the directories the default
// rules left out hold, and which rules those were, as in "3 files in 2
// directories were not scanned (default rules: examples, node_modules)." The
// text report, the pqc text view, the SARIF report and the notice the scan
// command prints for the other formats all use it, and all of them only when
// Files is not 0.
func SkippedDirectoriesSummary(s scanner.SkippedDirectories) string {
	verb := "were"
	if s.Files == 1 {
		verb = "was"
	}
	return fmt.Sprintf("%s in %s %s not scanned (default rules: %s).",
		countOf(s.Files, "file", "files"), countOf(s.Directories, "directory", "directories"),
		verb, strings.Join(s.Rules, ", "))
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

	// Report what was withheld. A scanner may reduce noise, but it must never
	// reduce it invisibly: the reader has to be able to tell the difference
	// between "nothing was found" and "something was found and not shown".
	if results.Summary.NarrativeSuppressed > 0 {
		b.WriteString(r.color(colorCyan, fmt.Sprintf(
			"\n  %d finding(s) withheld as documentation, log or comment text.\n"+
				"  Show them with: cryptoscan scan %s --include-narrative\n",
			results.Summary.NarrativeSuppressed, results.ScanTarget)))
	}

	// A file the scanner could not analyze is a gap in coverage. Say so, so
	// that a short report is not read as a clean one.
	if len(results.UnanalyzedFiles) > 0 {
		b.WriteString(r.color(colorYellow, fmt.Sprintf(
			"\n  %d file(s) could not be analyzed, so findings for them may be incomplete:\n",
			len(results.UnanalyzedFiles))))
		internal := false
		for _, u := range results.UnanalyzedFiles {
			location := u.File
			if u.Line > 0 {
				location = fmt.Sprintf("%s:%d", u.File, u.Line)
			}
			b.WriteString(fmt.Sprintf("    %s  %s\n", location, u.Reason))
			internal = internal || u.IsInternalError()
		}
		// An internal error is a scanner defect, worth reporting. For a
		// manifest that could not be decoded, the line and reason point at
		// the part of the file to check.
		if internal {
			b.WriteString("  Report this at https://github.com/csnp/cryptoscan/issues with the line shown.\n")
		}
	}
	// A file left out as minified or generated is a gap in coverage too: its
	// lines were not searched, so a count of 0 lines must not read as a clean
	// file.
	if len(results.SkippedFiles) > 0 {
		r.writeSkippedFiles(&b, results.SkippedFiles)
	}
	if len(results.SkippedDependencyDirs) > 0 {
		r.writeSkippedDependencyDirs(&b, results.SkippedDependencyDirs)
	}
	if results.Skipped.Files > 0 {
		b.WriteString(r.color(colorYellow, "\n  "+SkippedDirectoriesSummary(results.Skipped)+"\n"))
		b.WriteString("  " + IncludeSkippedHint + "\n")
	}
	if results.Config != nil {
		r.writeConfigSummary(&b, results)
	}
	b.WriteString("\n")

	r.writeFindingsByContext(&b, &results.Summary)

	// Quantum Risk Assessment with visual emphasis
	b.WriteString(r.color(colorBold, "  Quantum Risk Assessment (findings by quantum risk):\n"))
	if results.Summary.QuantumVulnCount > 0 {
		b.WriteString(r.color(colorRed+colorBold, fmt.Sprintf("    [!] %d quantum-vulnerable findings require migration planning\n", results.Summary.QuantumVulnCount)))
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
	// Every finding is counted in exactly one row, so the rows add up to
	// Total Findings. A quantum risk outside the three known values cannot be
	// determined, and is counted as UNKNOWN rather than left out.
	quantumCounts := make(map[string]int)
	for risk, count := range results.Summary.ByQuantumRisk {
		switch risk {
		case "VULNERABLE", "PARTIAL", "SAFE":
			quantumCounts[risk] += count
		default:
			quantumCounts["UNKNOWN"] += count
		}
	}
	quantumTotal := 0
	for _, risk := range quantumRisks {
		if count := quantumCounts[risk.name]; count > 0 {
			b.WriteString(fmt.Sprintf("    %s %s%-12s%s %d\n",
				r.color(risk.color, risk.icon),
				r.color(risk.color, ""),
				risk.name,
				r.color(colorReset, ""),
				count))
			quantumTotal += count
		}
	}
	b.WriteString(fmt.Sprintf("      %-12s %d\n", "Total", quantumTotal))
	if results.MigrationScore != nil && quantumTotal > 0 {
		if n := results.MigrationScore.TrustFindings; n > 0 {
			// The box leaves the trust findings out, so "the same findings"
			// would not be true without naming them.
			note := fmt.Sprintf("The migration readiness box above counts the same findings, except the %d Trust %s, by migration status, which also weighs hybrid use and algorithms that are already broken, so its rows differ from these.", n, pluralFindings(n))
			for _, row := range wrapPhrases("    ", strings.Fields(note), 71) {
				b.WriteString(r.color(colorCyan, row+"\n"))
			}
		} else {
			b.WriteString(r.color(colorCyan,
				"    The migration readiness box above counts the same findings by\n"+
					"    migration status, which also weighs hybrid use and algorithms that\n"+
					"    are already broken, so its rows differ from these.\n"))
		}
	}
	b.WriteString("\n")

	// Categories
	b.WriteString(r.color(colorBold, "  Categories Found:\n"))
	for _, cat := range categoriesByCount(results.Summary.ByCategory) {
		b.WriteString(fmt.Sprintf("    ├─ %-24s %d\n", cat, results.Summary.ByCategory[cat]))
	}
	b.WriteString("\n")

	if len(results.Findings) == 0 {
		switch {
		case results.FilesScanned == 0:
			b.WriteString(r.color(colorYellow, "  "+NothingScanned(results.ScanTarget)+"\n"))
		case results.Config.Any():
			b.WriteString(r.color(colorYellow, "  ! "+noFindingsHeadline(results.Config)+"\n"))
		default:
			b.WriteString(r.color(colorGreen, "  ✓ No cryptographic findings detected\n"))
		}
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

		// The matched value of a trust finding and the listed key, which
		// stand in place of the quantum verdict: the key is compromised or
		// distrusted already, whatever quantum computers do.
		if f.IsTrust() {
			for _, row := range trustValueRows(f) {
				fmt.Fprintf(&b, "  │ %s %s\n", r.color(colorBold, row[0]), row[1])
			}
		} else {
			// Quantum risk with icon
			b.WriteString(fmt.Sprintf("  │ %s %s\n",
				r.color(colorBold, "Quantum:"),
				r.quantumIcon(f.Quantum)))
		}

		// Confidence
		if f.Confidence != "" {
			b.WriteString(fmt.Sprintf("  │ %s %s\n",
				r.color(colorBold, "Confidence:"),
				string(f.Confidence)))
		}

		// Description
		b.WriteString(fmt.Sprintf("  │ %s\n", r.color(colorBold, "Description:")))
		b.WriteString(fmt.Sprintf("  │   %s\n", f.Description))

		// Remediation, unless the fix or guidance line below already says it
		if f.Remediation != "" && f.Remediation != f.Fix && f.Remediation != f.Guidance {
			b.WriteString(fmt.Sprintf("  │ %s\n", r.color(colorGreen+colorBold, "Remediation:")))
			b.WriteString(fmt.Sprintf("  │   %s\n", r.color(colorGreen, f.Remediation)))
		}

		// One concrete change, or advice when the finding needs no change,
		// and a command that shows the matched line
		if f.Fix != "" {
			b.WriteString(fmt.Sprintf("  │ %s %s\n",
				r.color(colorGreen+colorBold, "Fix:"),
				r.color(colorGreen, f.Fix)))
		}
		if f.Guidance != "" {
			fmt.Fprintf(&b, "  │ %s %s\n",
				r.color(colorCyan+colorBold, "Guidance:"),
				r.color(colorCyan, f.Guidance))
		}
		if f.Verify != "" {
			b.WriteString(fmt.Sprintf("  │ %s %s\n",
				r.color(colorBold, "Verify:"),
				f.Verify))
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
		b.WriteString(r.color(colorYellow, "("+findingCount(len(findings))+")"))
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

			// Match and quantum risk on one line; a trust finding shows its
			// matched value and the listed key instead of a quantum risk.
			if f.IsTrust() {
				fmt.Fprintf(b, "    %s %s\n", r.color(colorBold, "Match:"), r.color(colorMagenta, f.Match))
				for _, row := range trustValueRows(f) {
					fmt.Fprintf(b, "    %s %s\n", r.color(colorBold, row[0]), row[1])
				}
			} else {
				b.WriteString(fmt.Sprintf("    %s %s  •  %s\n",
					r.color(colorBold, "Match:"),
					r.color(colorMagenta, f.Match),
					r.quantumIcon(f.Quantum)))
			}

			// Fix or guidance, and verify command (compact)
			fix := f.Fix
			if fix == "" && f.Guidance == "" {
				fix = f.Remediation
			}
			if fix != "" {
				b.WriteString(fmt.Sprintf("    %s %s\n",
					r.color(colorGreen+colorBold, "Fix:"),
					r.color(colorGreen, fix)))
			} else if f.Guidance != "" {
				fmt.Fprintf(b, "    %s %s\n",
					r.color(colorCyan+colorBold, "Guidance:"),
					r.color(colorCyan, f.Guidance))
			}
			if f.Verify != "" {
				b.WriteString(fmt.Sprintf("    %s %s\n",
					r.color(colorBold, "Verify:"),
					f.Verify))
			}

			b.WriteString("\n")
		}
	}

	r.writeFooter(b)
	return b.String(), nil
}

// maxSkippedListed is the number of skipped files the text summary names. A
// tree can hold many minified bundles, and the JSON report lists them all.
const maxSkippedListed = 10

// writeSkippedFiles names the files the scan left out as minified or
// generated, as dependency manifests it has no reader for, or as reports
// CryptoScan wrote, and why.
func (r *TextReporter) writeSkippedFiles(b *strings.Builder, files []scanner.SkippedFile) {
	b.WriteString(r.color(colorYellow, fmt.Sprintf(
		"\n  %d file(s) were not scanned, so cryptography in them is not in this report:\n",
		len(files))))
	for i, sk := range files {
		if i == maxSkippedListed {
			fmt.Fprintf(b, "    and %d more, listed under skippedFiles in --format json\n", len(files)-maxSkippedListed)
			break
		}
		fmt.Fprintf(b, "    %s  %s\n", sk.File, sk.Reason)
	}
	minified, manifests, reports, recognized := false, false, false, false
	for _, sk := range files {
		switch {
		case sk.IsUnreadManifest():
			manifests = true
		case sk.IsCryptoScanReport():
			reports = true
			recognized = recognized || sk.IsRecognizedReport()
		default:
			minified = true
		}
	}
	if minified {
		b.WriteString("  Scan the source these files were built from, or search them for algorithm names.\n")
	}
	if manifests {
		b.WriteString("  Check the dependency manifests for cryptography libraries by hand.\n")
	}
	if reports {
		b.WriteString("  To leave CryptoScan reports off this list, write them outside the scanned folder or pass their names to --exclude.\n")
	}
	if recognized {
		b.WriteString("  " + IncludeReportsHint + "\n")
	}
}

// writeSkippedDependencyDirs names the node_modules directories the scan did
// not enter. The packages installed there are not in the report, and a report
// that did not say so read as one that had covered them.
func (r *TextReporter) writeSkippedDependencyDirs(b *strings.Builder, dirs []string) {
	head := fmt.Sprintf("%d dependency directories were", len(dirs))
	if len(dirs) == 1 {
		head = "1 dependency directory was"
	}
	b.WriteString(r.color(colorYellow, fmt.Sprintf(
		"\n  %s not scanned, so the packages installed there are not in this report:\n", head)))
	for i, d := range dirs {
		if i == maxSkippedListed {
			fmt.Fprintf(b, "    and %d more, listed under skippedDependencyDirs in --format json\n", len(dirs)-maxSkippedListed)
			break
		}
		fmt.Fprintf(b, "    %s\n", d)
	}
	b.WriteString("  Dependency manifests such as package.json are read for known crypto libraries.\n")
	b.WriteString("  To scan one installed package, pass its directory to cryptoscan scan.\n")
}

// writeConfigSummary names the config file the scan applied and what each of
// its settings removed. The file may sit in a directory above the scan target,
// where a reader of the report would not think to look.
func (r *TextReporter) writeConfigSummary(b *strings.Builder, results *scanner.Results) {
	c := results.Config
	b.WriteString(r.color(colorCyan, fmt.Sprintf("\n  Config file applied: %s\n", c.Path)))
	b.WriteString(r.color(colorCyan, fmt.Sprintf("    (%s)\n", configSourceText(c.Source))))
	effects := configEffects(c)
	if len(effects) == 0 {
		b.WriteString(r.color(colorCyan, "    It removed no findings and kept no files out of the scan.\n"))
	}
	for _, e := range effects {
		b.WriteString(r.color(colorCyan, "    "+e+"\n"))
	}
	if c.Source != scanner.ConfigSourceFlag && len(effects) > 0 {
		b.WriteString(r.color(colorCyan, fmt.Sprintf("  Scan without it: cryptoscan scan %s --no-config\n", results.ScanTarget)))
	}
}

func (r *TextReporter) writeMigrationScore(b *strings.Builder, score *scanner.MigrationScore) {
	// Migration Readiness Score box
	b.WriteString(r.color(colorBold+colorCyan, "┌─ QUANTUM MIGRATION READINESS ──────────────────────────────────┐\n"))
	r.writeScoreLine(b, score)

	// How the score was computed, with this scan's counts
	for _, row := range wrapPhrases("Method: ", analyzer.MethodPhrases(score), migrationTextWidth) {
		b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("  %-63s", row) + r.color(colorCyan, "│\n"))
	}
	if score.TestDirectoryFindings > 0 {
		line := fmt.Sprintf("%d of %d findings are in test directories.", score.TestDirectoryFindings, score.TotalCount)
		b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("  %-63s", line) + r.color(colorCyan, "│\n"))
	}

	b.WriteString(r.color(colorCyan, "│") + r.color(colorCyan, "─────────────────────────────────────────────────────────────────") + r.color(colorCyan, "│\n"))

	// Status breakdown
	b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, fmt.Sprintf("%-64s", "  INVENTORY (findings by migration status)")) + r.color(colorCyan, "│\n"))
	b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    %s Safe (PQC):        %-5d", r.color(colorGreen, "✓"), score.SafeCount) + fmt.Sprintf("    %s Vulnerable:    %-5d", r.color(colorRed, "✗"), score.VulnerableCount) + r.color(colorCyan, "   │\n"))
	b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    %s Hybrid:            %-5d", r.color(colorGreen, "◐"), score.HybridCount) + fmt.Sprintf("    %s Critical:      %-5d", r.color(colorRed+colorBold, "[!]"), score.CriticalCount) + r.color(colorCyan, "   │\n"))
	b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    %s Partial:           %-5d", r.color(colorYellow, "◑"), score.PartialCount) + fmt.Sprintf("    Total:          %-5d", score.TotalCount) + r.color(colorCyan, "   │\n"))

	r.writeQRAMMLevels(b, score)

	// Top risk files
	if len(score.TopRiskFiles) > 0 {
		b.WriteString(r.color(colorCyan, "│") + r.color(colorCyan, "─────────────────────────────────────────────────────────────────") + r.color(colorCyan, "│\n"))
		b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, "  TOP PRIORITY FILES                                            ") + r.color(colorCyan, "│\n"))
		for i, f := range score.TopRiskFiles {
			if i >= 3 {
				break
			}
			truncFile := truncatePath(f.File, 40)
			// "(1 finding)" is padded to the width "(1 findings)" had, so
			// the border stays where it was.
			count := fmt.Sprintf("%-*s", len(fmt.Sprintf("(%d findings)", f.TotalFindings)), "("+findingCount(f.TotalFindings)+")")
			b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    %d. %-42s %s", i+1, truncFile, count) + r.color(colorCyan, "  │\n"))
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

// writeScoreLine writes the migration score bar and risk level, one line of
// the readiness box.
func (r *TextReporter) writeScoreLine(b *strings.Builder, score *scanner.MigrationScore) {
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
}

// writeQRAMMLevels writes the QRAMM Dimension 1 practice levels of the
// readiness box, with the separator above them. It writes nothing when the
// score carries no QRAMM readiness.
func (r *TextReporter) writeQRAMMLevels(b *strings.Builder, score *scanner.MigrationScore) {
	// QRAMM Readiness
	if score.QRAMMReadiness != nil {
		b.WriteString(r.color(colorCyan, "│") + r.color(colorCyan, "─────────────────────────────────────────────────────────────────") + r.color(colorCyan, "│\n"))
		b.WriteString(r.color(colorCyan, "│") + r.color(colorBold, "  QRAMM DIMENSION 1: Cryptographic Visibility & Inventory (CVI) ") + r.color(colorCyan, "│\n"))

		// Practice levels
		b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    Practice 1.1 Discovery:   Level %d/5 %s", score.QRAMMReadiness.DiscoveryLevel, r.maturityIndicator(score.QRAMMReadiness.DiscoveryLevel)) + r.color(colorCyan, "                    │\n"))
		b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    Practice 1.2 Assessment:  Level %d/5 %s", score.QRAMMReadiness.AssessmentLevel, r.maturityIndicator(score.QRAMMReadiness.AssessmentLevel)) + r.color(colorCyan, "                    │\n"))
		b.WriteString(r.color(colorCyan, "│") + fmt.Sprintf("    Practice 1.3 Mapping:     Level %d/5 %s", score.QRAMMReadiness.MappingLevel, r.maturityIndicator(score.QRAMMReadiness.MappingLevel)) + r.color(colorCyan, "                    │\n"))
	}
}

// migrationTextWidth is the widest text a migration box row holds after its
// two-space indent, keeping a clear space before the closing border.
const migrationTextWidth = 61

// wrapPhrases joins phrases into rows no wider than width, breaking only
// between phrases. The first row starts with label; later rows are indented
// to line up under the first row's text.
// trustKeyLabels names the listed key a trust finding matched, by its use.
var trustKeyLabels = map[string]string{
	"tls":         "a listed TLS intermediate key",
	"codeSigning": "a listed code-signing intermediate key",
	"root":        "the key of a listed removed root",
}

// trustValueRows returns the label and text of each row that shows a trust
// finding's matched value, the value's type and the listed key, read from the
// finding's metadata: the block's SPKI hash for a key that is listed, or the
// block's certificate hash and the listed key its signature verifies under.
func trustValueRows(f scanner.Finding) [][2]string {
	md := f.Metadata
	key := trustKeyLabels[md["keyUse"]]
	switch md["valueType"] {
	case "spkiSha256":
		return [][2]string{{"SPKI SHA-256:", md["matchedValue"] + ", " + key}}
	case "certSha256":
		return [][2]string{
			{"Certificate SHA-256:", md["matchedValue"]},
			{"Signed by:", md["issuerSpkiSha256"] + " (SPKI SHA-256), " + key},
		}
	}
	return nil
}

func pluralFindings(n int) string {
	if n == 1 {
		return "finding"
	}
	return "findings"
}

func wrapPhrases(label string, phrases []string, width int) []string {
	indent := strings.Repeat(" ", len(label))
	var rows []string
	row, empty := label, true
	for _, p := range phrases {
		if !empty && len(row)+1+len(p) > width {
			rows = append(rows, row)
			row, empty = indent, true
		}
		if !empty {
			row += " "
		}
		row += p
		empty = false
	}
	return append(rows, row)
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

// writeFindingsByContext prints how the scan's findings divide by the rule that
// decided their context, including the findings the narrative rules withheld,
// so a reader can see how much of the raw scan was comment or documentation
// text. Kinds are sorted so the block is identical on every run.
func (r *TextReporter) writeFindingsByContext(b *strings.Builder, s *scanner.Summary) {
	if len(s.ByEvidence) == 0 {
		return
	}

	kinds := make([]string, 0, len(s.ByEvidence))
	for kind := range s.ByEvidence {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)

	b.WriteString(r.color(colorBold, "  Findings by context:\n"))
	for _, kind := range kinds {
		withheld := s.WithheldByEvidence[kind]
		reported := s.ByEvidence[kind] - withheld
		var status string
		switch {
		case withheld == 0:
			status = fmt.Sprintf("%4d reported", reported)
		case reported == 0:
			status = fmt.Sprintf("%4d withheld (--include-narrative shows them)", withheld)
		default:
			status = fmt.Sprintf("%4d reported, %d withheld (--include-narrative shows them)", reported, withheld)
		}
		b.WriteString(fmt.Sprintf("    %-12s %s\n", kind, status))
	}
	b.WriteString(r.color(colorCyan, "  Context is decided by the scanner's rules, not by a model.\n"))
	b.WriteString("\n")
}

// categoriesByCount returns the categories with the most findings first, and
// categories with the same count in name order, so the order of the
// "Categories Found" block does not depend on map iteration order.
func categoriesByCount(byCategory map[string]int) []string {
	cats := make([]string, 0, len(byCategory))
	for cat := range byCategory {
		cats = append(cats, cat)
	}
	sort.Slice(cats, func(i, j int) bool {
		if byCategory[cats[i]] != byCategory[cats[j]] {
			return byCategory[cats[i]] > byCategory[cats[j]]
		}
		return cats[i] < cats[j]
	})
	return cats
}

func (r *TextReporter) writeFooter(b *strings.Builder) {
	b.WriteString(r.color(colorBold, "═══════════════════════════════════════════════════════════════\n"))
	b.WriteString(r.color(colorCyan, "  QRAMM CryptoScan") + " - Quantum Readiness Assessment Tool\n")
	b.WriteString("  Part of the QRAMM Toolkit: https://qramm.org\n")
	b.WriteString("  Assess your organisation: https://qramm.org/quick-assessment.html\n")
	b.WriteString("  Developed by CSNP: https://csnp.org\n")
	b.WriteString(r.color(colorBold, "═══════════════════════════════════════════════════════════════\n"))
}

// findingCount returns "1 finding" for one finding and "N findings" for any
// other count.
func findingCount(n int) string {
	if n == 1 {
		return "1 finding"
	}
	return fmt.Sprintf("%d findings", n)
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
