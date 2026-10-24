// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"reflect"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

// trustScoringFinding is a finding of one of the two Trust patterns as the
// matcher raises it: category Trust, quantum risk unknown.
func trustScoringFinding(file string) types.Finding {
	return types.Finding{
		File:     file,
		Category: types.CategoryTrust,
		Quantum:  types.QuantumUnknown,
		Severity: types.SeverityCritical,
	}
}

// Trust findings enter no part of the readiness score: every field of the
// score is what it is with the trust findings left out, apart from the count
// of trust findings and the sentence of the method that states it, and the
// trust findings get no migration status and no QRAMM mapping.
func TestTrustFindingsAreLeftOutOfTheScore(t *testing.T) {
	quantum := []types.Finding{
		scoringFinding("src/pqc.go", types.QuantumSafe),
		scoringFinding("src/aes.go", types.QuantumPartial),
		scoringFinding("src/rsa.go", types.QuantumVulnerable),
		scoringFinding("test/rsa_test.go", types.QuantumVulnerable),
	}
	with := append(append([]types.Finding{}, quantum...),
		trustScoringFinding("certs/chain.pem"), trustScoringFinding("test/fixtures/root.pem"))
	without := append([]types.Finding{}, quantum...)

	got := *CalculateMigrationScore(with)
	want := *CalculateMigrationScore(without)
	if got.TrustFindings != 2 || want.TrustFindings != 0 {
		t.Errorf("TrustFindings = %d with and %d without, want 2 and 0", got.TrustFindings, want.TrustFindings)
	}
	if !strings.HasPrefix(got.Method, want.Method+" ") {
		t.Errorf("Method with trust findings %q does not start with the method without them %q", got.Method, want.Method)
	}
	got.TrustFindings, got.Method = 0, want.Method
	if !reflect.DeepEqual(got, want) {
		t.Errorf("score with trust findings = %+v, want the score without them %+v", got, want)
	}
	for _, f := range with[len(quantum):] {
		if f.MigrationStatus != "" || f.QRAMMMapping != nil {
			t.Errorf("%s: migration status %q, QRAMM mapping %v; want neither", f.File, f.MigrationStatus, f.QRAMMMapping)
		}
	}
}

// The method states how many trust findings it leaves out, in the singular
// for one, and says nothing about trust when there are none. A scan whose
// only findings are trust findings scores 0 and says why.
func TestMethodStatesTheTrustFindingsLeftOut(t *testing.T) {
	quantum := scoringFinding("src/rsa.go", types.QuantumVulnerable)
	trust := trustScoringFinding("certs/chain.pem")
	tests := []struct {
		name     string
		findings []types.Finding
		suffix   string
	}{
		{"one", []types.Finding{quantum, trust}, " 1 Trust finding is not counted: trust findings are not quantum findings."},
		{"two", []types.Finding{quantum, trust, trust}, " 2 Trust findings are not counted: trust findings are not quantum findings."},
		{"only trust findings", []types.Finding{trust, trust},
			"No findings to score, so the score is 0. 2 Trust findings are not counted: trust findings are not quantum findings."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := CalculateMigrationScore(append([]types.Finding{}, tt.findings...))
			if !strings.HasSuffix(score.Method, tt.suffix) {
				t.Errorf("Method = %q, want it to end with %q", score.Method, tt.suffix)
			}
			if joined := strings.Join(MethodPhrases(score), " "); joined != score.Method {
				t.Errorf("MethodPhrases joined = %q, Method = %q", joined, score.Method)
			}
		})
	}
	if m := CalculateMigrationScore([]types.Finding{quantum}).Method; strings.Contains(m, "Trust") {
		t.Errorf("Method with no trust findings mentions them: %q", m)
	}
	if s := CalculateMigrationScore([]types.Finding{trust}); s.Score != 0 || s.TotalCount != 0 {
		t.Errorf("score of trust findings alone = %v over %d findings, want 0 over 0", s.Score, s.TotalCount)
	}
}

// Apply keeps the Fix the trust check chose by the listed key's use, clears
// Guidance, and writes the Verify that recomputes the matched value from the
// certificate block at the finding's line, by value type. The path is quoted
// once, so a path holding a space, a leading dash or the placeholder words
// stays the path. A finding without a known value type, a file or a line gets
// no Verify.
func TestApplyWritesATrustFindingsVerifyAndKeepsItsFix(t *testing.T) {
	const fix = "Replace the chain with one issued by a CA none of whose keys is listed, and remove this certificate from any bundle or pin set you ship."
	const spki = " | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \\n'"
	const cert = " | openssl x509 -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \\n'"
	tests := []struct {
		name, file string
		line       int
		valueType  string
		want       string
	}{
		{"SPKI value", "certs/bundle.pem", 7, "spkiSha256", "awk 'NR>=7' certs/bundle.pem" + spki},
		{"certificate value", "certs/bundle.pem", 30, "certSha256", "awk 'NR>=30' certs/bundle.pem" + cert},
		{"path with a space and the placeholder words", "my certs/FILE LINE.pem", 1, "spkiSha256", "awk 'NR>=1' 'my certs/FILE LINE.pem'" + spki},
		{"path starting with a dash", "-chain.pem", 3, "certSha256", "awk 'NR>=3' ./-chain.pem" + cert},
		{"unknown value type", "certs/bundle.pem", 1, "", ""},
		{"no line", "certs/bundle.pem", 0, "spkiSha256", ""},
		{"no file", "", 1, "spkiSha256", ""},
	}
	engine := NewRemediationEngine()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := types.Finding{
				Category:    types.CategoryTrust,
				File:        tt.file,
				Line:        tt.line,
				Quantum:     types.QuantumUnknown,
				Remediation: fix,
				Fix:         fix,
				Guidance:    "left from an earlier step",
				Metadata:    map[string]string{"valueType": tt.valueType},
			}
			engine.Apply(&f)
			if f.Verify != tt.want {
				t.Errorf("Verify = %q, want %q", f.Verify, tt.want)
			}
			if f.Fix != fix || f.Guidance != "" {
				t.Errorf("Fix = %q, Guidance = %q; want the trust fix and no guidance", f.Fix, f.Guidance)
			}
		})
	}
}
