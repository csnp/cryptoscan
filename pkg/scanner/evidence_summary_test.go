// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"path/filepath"
	"reflect"
	"testing"
)

// samplesDir is the repository's own sample tree: real cryptographic calls in
// four languages, with comments and log lines that name algorithms beside them.
var samplesDir = filepath.Join("..", "..", "crypto-samples")

// TestByEvidenceDescribesTheRawScan pins what the "Findings by context" block
// stands on. The map counts every finding the scan produced, reported or
// withheld, so its values add up to TotalFindings plus NarrativeSuppressed, and
// --include-narrative, which changes what is reported, does not change the map.
func TestByEvidenceDescribesTheRawScan(t *testing.T) {
	filtered := scanDir(t, samplesDir, false)
	raw := scanDir(t, samplesDir, true)

	if len(filtered.Summary.ByEvidence) == 0 {
		t.Fatal("summary.byEvidence is empty for crypto-samples")
	}
	if filtered.Summary.NarrativeSuppressed == 0 {
		t.Fatal("nothing was withheld; crypto-samples no longer exercises the narrative rules")
	}

	sum := 0
	for _, n := range filtered.Summary.ByEvidence {
		sum += n
	}
	if want := filtered.Summary.TotalFindings + filtered.Summary.NarrativeSuppressed; sum != want {
		t.Errorf("byEvidence sums to %d, want totalFindings %d + narrativeSuppressedCount %d = %d",
			sum, filtered.Summary.TotalFindings, filtered.Summary.NarrativeSuppressed, want)
	}

	if !reflect.DeepEqual(filtered.Summary.ByEvidence, raw.Summary.ByEvidence) {
		t.Errorf("byEvidence depends on --include-narrative:\n  default: %v\n  include: %v",
			filtered.Summary.ByEvidence, raw.Summary.ByEvidence)
	}
	if raw.Summary.TotalFindings != sum {
		t.Errorf("--include-narrative reports %d findings, but byEvidence counts %d",
			raw.Summary.TotalFindings, sum)
	}
}

// TestWithheldByEvidenceMatchesTheWithheldCount checks the per-kind split the
// text report prints as "N reported" or "N withheld". The withheld counts add
// up to narrativeSuppressedCount, only narrative kinds are ever withheld, and
// nothing is withheld once --include-narrative is set.
func TestWithheldByEvidenceMatchesTheWithheldCount(t *testing.T) {
	filtered := scanDir(t, samplesDir, false)
	raw := scanDir(t, samplesDir, true)

	withheld := 0
	for kind, n := range filtered.Summary.WithheldByEvidence {
		if kind == EvidenceOperational {
			t.Errorf("%d operational findings were counted as withheld", n)
		}
		if n > filtered.Summary.ByEvidence[kind] {
			t.Errorf("%s: %d withheld but only %d in the scan", kind, n, filtered.Summary.ByEvidence[kind])
		}
		withheld += n
	}
	if withheld != filtered.Summary.NarrativeSuppressed {
		t.Errorf("withheld by kind sums to %d, want narrativeSuppressedCount %d",
			withheld, filtered.Summary.NarrativeSuppressed)
	}

	for kind, n := range raw.Summary.WithheldByEvidence {
		if n != 0 {
			t.Errorf("with --include-narrative, %d %s findings are still counted as withheld", n, kind)
		}
	}
}

// TestEvidenceKindsAreTheClassifierRules keeps the map's keys tied to rules
// the scanner applies. A key outside this set is a label nobody can trace to
// a line of code.
func TestEvidenceKindsAreTheClassifierRules(t *testing.T) {
	known := map[string]bool{
		EvidenceOperational: true,
		EvidenceKeyMaterial: true,
		EvidenceDependency:  true,
		"log-message":       true,
		"comment":           true,
		"url-or-path":       true,
	}

	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.py"), `import hashlib
d = 1  # md5 is kept only for legacy peers
log.info("falling back to sha1 for old clients")
see = "https://example.org/md5-deprecation.md"
h = hashlib.md5(b"x")
`)

	for _, include := range []bool{false, true} {
		results := scanDir(t, dir, include)
		for kind := range results.Summary.ByEvidence {
			if !known[kind] {
				t.Errorf("unknown evidence kind %q in byEvidence", kind)
			}
		}
		if results.Summary.ByEvidence[EvidenceOperational] == 0 {
			t.Errorf("include-narrative=%v: hashlib.md5(...) was not counted as operational: %v",
				include, results.Summary.ByEvidence)
		}
		if results.Summary.ByEvidence["comment"] == 0 {
			t.Errorf("include-narrative=%v: the comment line was not counted under \"comment\": %v",
				include, results.Summary.ByEvidence)
		}
	}
}
