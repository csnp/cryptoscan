// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns

import (
	"slices"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/types"
)

// wantTrustPatterns are the two Trust patterns as the product ruling sets them.
var wantTrustPatterns = []struct {
	id, name  string
	severity  types.Severity
	reference string
	tags      []string
}{
	{
		id:        "TRUST-COMPROMISED-KEY-001",
		name:      "Certificate with a publicly compromised CA key",
		severity:  types.SeverityCritical,
		reference: "https://github.com/csnp/cryptoscan/blob/main/docs/findings/trust-compromised-key.md",
		tags:      []string{"trust", "certificate", "ca", "compromised-key", "revoked", "emudhra"},
	},
	{
		id:        "TRUST-DISTRUSTED-ROOT-001",
		name:      "Certificate chain anchored on a root removed from browser trust stores",
		severity:  types.SeverityHigh,
		reference: "https://github.com/csnp/cryptoscan/blob/main/docs/findings/trust-distrusted-root.md",
		tags:      []string{"trust", "certificate", "root", "distrusted", "trust-store", "emudhra"},
	},
}

func trustPatternsByID(t *testing.T) map[string]Pattern {
	t.Helper()
	byID := map[string]Pattern{}
	for _, p := range NewMatcher().Patterns() {
		if strings.HasPrefix(p.ID, "TRUST-") {
			byID[p.ID] = p
		}
	}
	return byID
}

func TestTrustPatternsAreRegistered(t *testing.T) {
	byID := trustPatternsByID(t)
	if len(byID) != len(wantTrustPatterns) {
		t.Errorf("the matcher has %d TRUST- patterns, want %d", len(byID), len(wantTrustPatterns))
	}
	for _, w := range wantTrustPatterns {
		p, ok := byID[w.id]
		if !ok {
			t.Errorf("no pattern %s", w.id)
			continue
		}
		if p.Name != w.name {
			t.Errorf("%s name = %q, want %q", w.id, p.Name, w.name)
		}
		if p.Category != "Trust" {
			t.Errorf("%s category = %q, want Trust", w.id, p.Category)
		}
		if p.Severity != w.severity {
			t.Errorf("%s severity = %s, want %s", w.id, p.Severity, w.severity)
		}
		if p.Quantum != types.QuantumUnknown {
			t.Errorf("%s quantum risk = %s, want unknown", w.id, p.Quantum)
		}
		if !slices.Equal(p.References, []string{w.reference}) {
			t.Errorf("%s references = %q, want the one page link %q", w.id, p.References, w.reference)
		}
		if !slices.Equal(p.Tags, w.tags) {
			t.Errorf("%s tags = %q, want %q", w.id, p.Tags, w.tags)
		}
		if !p.Regex.MatchString("-----BEGIN CERTIFICATE-----") {
			t.Errorf("%s expression %q does not match the PEM certificate header", w.id, p.Regex)
		}
		// patterns search eMudhra finds a pattern by its description.
		if !strings.Contains(strings.ToLower(p.Description), "emudhra") {
			t.Errorf("%s description does not name eMudhra, so patterns search eMudhra misses it: %q", w.id, p.Description)
		}
	}
}

// The help offers --ignore "RSA-001,CERT-*" and --ignore-category
// "Certificate,Library Import" as examples; neither may hide a trust finding.
func TestTrustPatternsAreOutsideTheCertificateIgnoreExamples(t *testing.T) {
	byID := trustPatternsByID(t)
	if len(byID) == 0 {
		t.Fatal("no TRUST- patterns")
	}
	for id, p := range byID {
		if strings.HasPrefix(id, "CERT-") || strings.EqualFold(p.Category, "Certificate") || strings.EqualFold(p.Category, "Library Import") {
			t.Errorf("%s (category %q) is hidden by the help's own ignore examples", id, p.Category)
		}
	}
}

// A Trust finding on a header line comes before the certificate inventory
// finding on the same line, so the trust patterns are checked first.
func TestTrustPatternsComeBeforeTheCertificateInventoryPattern(t *testing.T) {
	ids := []string{}
	for _, p := range NewMatcher().Patterns() {
		ids = append(ids, p.ID)
	}
	cert := slices.Index(ids, "CERT-001")
	for _, w := range wantTrustPatterns {
		i := slices.Index(ids, w.id)
		if i < 0 || i > cert {
			t.Errorf("%s is at position %d, want before CERT-001 at %d", w.id, i, cert)
		}
	}
}

// The expression alone never raises a trust finding: a header line handed to
// the line matchers, without the lines after it, yields none.
func TestTrustExpressionAloneRaisesNoFinding(t *testing.T) {
	if len(trustPatternsByID(t)) == 0 {
		t.Fatal("no TRUST- patterns")
	}
	m := NewMatcher()
	header := "-----BEGIN CERTIFICATE-----"
	fileCtx := analyzer.Analyze("bundle.pem")
	lineCtx := analyzer.AnalyzeLine(header, fileCtx.Language, nil)
	for _, f := range append(m.Match(header, "bundle.pem", 1), m.MatchWithContext(header, "bundle.pem", 1, fileCtx, lineCtx)...) {
		if strings.HasPrefix(f.ID, "TRUST-") {
			t.Errorf("a header line alone raised %s", f.ID)
		}
	}
}
