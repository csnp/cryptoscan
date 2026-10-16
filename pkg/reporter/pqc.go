// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// maxPQCLocations is how many file:line locations the view lists for each
// algorithm or construction it found.
const maxPQCLocations = 3

// pqcAlgorithms are the post-quantum groups the view lists, in this order,
// matched on the pattern ID that starts each finding's ID.
var pqcAlgorithms = []struct{ prefix, label string }{
	{"PQC-MLKEM-", "ML-KEM"},
	{"PQC-MLDSA-", "ML-DSA"},
	{"PQC-SLHDSA-", "SLH-DSA"},
	{"PQC-FNDSA-", "FN-DSA"},
	{"PQC-XMSS-", "XMSS"},
	{"PQC-LMS-", "LMS"},
	{"PQC-LIB-", "PQC library imports"},
}

// PQCFindings returns the post-quantum and hybrid findings, those whose IDs
// start with PQC- or HYBRID-, in the order given. The result is never nil, so
// it encodes as an empty JSON array rather than null.
func PQCFindings(findings []scanner.Finding) []scanner.Finding {
	out := []scanner.Finding{}
	for _, f := range findings {
		if isPQCFinding(f) || isHybridFinding(f) {
			out = append(out, f)
		}
	}
	return out
}

func isPQCFinding(f scanner.Finding) bool    { return strings.HasPrefix(f.ID, "PQC-") }
func isHybridFinding(f scanner.Finding) bool { return strings.HasPrefix(f.ID, "HYBRID-") }

// PQCReporter writes the post-quantum readiness view that the pqc command
// prints: post-quantum algorithms, hybrid constructions and quantum-vulnerable
// algorithms found, then the readiness score and QRAMM Dimension 1 levels as
// the scan report prints them.
type PQCReporter struct {
	text *TextReporter
}

// NewPQCReporter creates a post-quantum readiness reporter
func NewPQCReporter(colorEnabled bool) *PQCReporter {
	return &PQCReporter{text: NewTextReporter(colorEnabled)}
}

// findingGroup is one algorithm or construction and the findings for it.
type findingGroup struct {
	label    string
	rank     int
	findings []scanner.Finding
}

// Generate creates the post-quantum readiness view
func (r *PQCReporter) Generate(results *scanner.Results) (string, error) {
	t := r.text
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(t.color(colorBold, "╔═══════════════════════════════════════════════════════════════╗\n"))
	b.WriteString(t.color(colorBold, "║                    POST-QUANTUM READINESS                     ║\n"))
	b.WriteString(t.color(colorBold, "║                    QRAMM CryptoScan                           ║\n"))
	b.WriteString(t.color(colorBold, "╚═══════════════════════════════════════════════════════════════╝\n"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s %s\n\n", t.color(colorBold, "Target:"), results.ScanTarget))

	// Post-quantum algorithms, in the fixed order above. A PQC pattern the
	// list does not know yet is still shown, after it, under its own name.
	pqc := groupFindings(results.Findings, isPQCFinding, func(f scanner.Finding) (string, int) {
		for i, alg := range pqcAlgorithms {
			if strings.HasPrefix(f.ID, alg.prefix) {
				return alg.label, i
			}
		}
		return findingName(f), len(pqcAlgorithms)
	})
	sort.SliceStable(pqc, func(i, j int) bool {
		if pqc[i].rank != pqc[j].rank {
			return pqc[i].rank < pqc[j].rank
		}
		return pqc[i].label < pqc[j].label
	})
	r.writeSection(&b, "Post-quantum algorithms found", pqc, true)

	hybrid := groupFindings(results.Findings, isHybridFinding, func(f scanner.Finding) (string, int) {
		if f.Type != "" {
			return f.Type, 0
		}
		return findingName(f), 0
	})
	sort.SliceStable(hybrid, func(i, j int) bool { return hybrid[i].label < hybrid[j].label })
	r.writeSection(&b, "Hybrid constructions found", hybrid, true)

	vulnerable := groupFindings(results.Findings, func(f scanner.Finding) bool {
		return f.Quantum == scanner.QuantumVulnerable
	}, func(f scanner.Finding) (string, int) { return findingName(f), 0 })
	sort.SliceStable(vulnerable, func(i, j int) bool {
		if len(vulnerable[i].findings) != len(vulnerable[j].findings) {
			return len(vulnerable[i].findings) > len(vulnerable[j].findings)
		}
		return vulnerable[i].label < vulnerable[j].label
	})
	r.writeSection(&b, "Quantum-vulnerable algorithms", vulnerable, false)

	// The readiness lines are the scan report's own, so the two never differ.
	if score := results.MigrationScore; score != nil {
		b.WriteString(t.color(colorBold+colorCyan, "┌─ QUANTUM MIGRATION READINESS ──────────────────────────────────┐\n"))
		t.writeScoreLine(&b, score)
		t.writeQRAMMLevels(&b, score)
		b.WriteString(t.color(colorBold+colorCyan, "└─────────────────────────────────────────────────────────────────┘\n"))
		b.WriteString("\n")
	}

	// As in the scan report, say what was withheld rather than hide it. The
	// command shown repeats this view's scan, quantum-safe findings included,
	// so it reproduces the count.
	if results.Summary.NarrativeSuppressed > 0 {
		b.WriteString(t.color(colorCyan, fmt.Sprintf(
			"  %d finding(s) withheld as documentation, log or comment text.\n"+
				"  Show them with: cryptoscan scan %s --include-quantum-safe --include-narrative\n\n",
			results.Summary.NarrativeSuppressed, results.ScanTarget)))
	}

	b.WriteString(fmt.Sprintf("  To see each finding with its source lines, run:\n    cryptoscan scan %s --include-quantum-safe\n\n", results.ScanTarget))
	t.writeFooter(&b)

	return b.String(), nil
}

// writeSection writes a heading and one line per group with its count, and
// with locations set, up to maxPQCLocations file:line locations under each.
func (r *PQCReporter) writeSection(b *strings.Builder, heading string, groups []findingGroup, locations bool) {
	b.WriteString(r.text.color(colorBold, "  "+heading+"\n"))
	if len(groups) == 0 {
		b.WriteString("    None found.\n\n")
		return
	}
	for _, g := range groups {
		b.WriteString(fmt.Sprintf("    %-28s %d\n", g.label, len(g.findings)))
		if !locations {
			continue
		}
		for i, f := range g.findings {
			if i == maxPQCLocations {
				b.WriteString(fmt.Sprintf("      and %d more\n", len(g.findings)-maxPQCLocations))
				break
			}
			b.WriteString(fmt.Sprintf("      %s:%d\n", f.File, f.Line))
		}
	}
	b.WriteString("\n")
}

// groupFindings collects the findings keep accepts under the label and rank
// that name gives them. Groups come in the order they are first seen, and
// each keeps its findings in the order given.
func groupFindings(findings []scanner.Finding, keep func(scanner.Finding) bool, name func(scanner.Finding) (string, int)) []findingGroup {
	index := make(map[string]int)
	var groups []findingGroup
	for _, f := range findings {
		if !keep(f) {
			continue
		}
		label, rank := name(f)
		i, ok := index[label]
		if !ok {
			i = len(groups)
			index[label] = i
			groups = append(groups, findingGroup{label: label, rank: rank})
		}
		groups[i].findings = append(groups[i].findings, f)
	}
	return groups
}

// findingName is the algorithm a finding names, or its type when it names
// none.
func findingName(f scanner.Finding) string {
	if f.Algorithm != "" {
		return f.Algorithm
	}
	if f.Type != "" {
		return f.Type
	}
	return f.ID
}
