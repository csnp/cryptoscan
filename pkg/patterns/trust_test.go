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

// wantTrustPatterns are the two Trust patterns: ID, name, severity, finding
// page and tags.
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

// wantTrustDescriptions are the four Description strings, by the rule that
// raises the finding.
var wantTrustDescriptions = map[int]string{
	1: "The certificate's public key is one of the eight eMudhra intermediate CA keys whose private keys were recovered by independent parties (Mozilla Bug 2083449). eMudhra revoked its certificates for these keys on 2026-10-18. Software that checks revocation rejects chains through this key; software that does not, and still trusts the key, accepts any certificate signed with it, including ones the CA never issued. Either way, the certificate and every chain through the key need replacing.",
	2: "The certificate is signed under one of the eight eMudhra intermediate CA keys whose private keys were recovered by independent parties (Mozilla Bug 2083449). The signature identifies the key, not who held it. Its issuer is revoked: software that checks revocation rejects this chain, and software that does not can still accept it. Either way, the certificate and every chain through the key need replacing.",
	3: "This certificate is emSign ECC Root CA - G3. After the eMudhra intermediate key compromise (Mozilla Bug 2083449), Mozilla removed this root from its root store on 2026-10-20, and Chrome's removal date for all devices is 2026-10-27. A client stops trusting chains that end here once its copy of Mozilla's or Chrome's root store drops the root.",
	4: "This certificate chains to emSign ECC Root CA - G3: its signature verifies under that root's key. Mozilla removed the root from its root store on 2026-10-20, and Chrome's removal date for all devices is 2026-10-27. A client stops trusting this chain once its copy of Mozilla's or Chrome's root store drops the root.",
}

// Each rule gives its finding its Description word for word, rule 4 included,
// which no certificate in the fixture raises.
func TestTrustDescriptionsByRule(t *testing.T) {
	if len(trustDescriptions) != len(wantTrustDescriptions) {
		t.Errorf("%d descriptions, want %d", len(trustDescriptions), len(wantTrustDescriptions))
	}
	for rule, want := range wantTrustDescriptions {
		if got := trustDescriptions[rule]; got != want {
			t.Errorf("rule %d description\n %q\nwant\n %q", rule, got, want)
		}
	}
}

// wantTrustImpacts are the two Impact strings, by the kind of the finding.
var wantTrustImpacts = map[string]string{
	"compromisedCaKey": "The listed CA key is already compromised, without a quantum computer: independent parties recovered its private key.",
	"distrustedRoot":   "A trust change, not a quantum risk: a client stops trusting chains that end at this root once its root store drops the root.",
}

// Each kind gives its finding its Impact word for word.
func TestTrustImpactsByKind(t *testing.T) {
	if len(trustImpacts) != len(wantTrustImpacts) {
		t.Errorf("%d impacts, want %d", len(trustImpacts), len(wantTrustImpacts))
	}
	for kind, want := range wantTrustImpacts {
		f := types.Finding{FindingType: types.FindingTypeTrust, Metadata: map[string]string{TrustMetaKind: kind}}
		if got := determineImpact(f); got != want {
			t.Errorf("%s impact\n %q\nwant\n %q", kind, got, want)
		}
	}
}
