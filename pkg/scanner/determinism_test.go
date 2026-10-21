// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

// TestFindingOrderIsDeterministic guards against the map-iteration ordering
// found by the v1.4.0 release test. deduplicateFindings built its result by
// ranging over a map, and Go randomises map iteration, so repeated scans of an
// unchanged tree produced the same findings in a different order every time.
//
// That breaks diffable CI output, golden-file tests and reproducible CBOMs.
// Several files with several findings each are needed to make the old
// behaviour fail reliably rather than by luck.
//
// The findings and the summary, byEvidence included, must also serialise to
// the same bytes on every run. The fixture carries a trailing comment so that
// byEvidence has more than one key and a map-ordered encoder would show up.
// A whole-line comment would not do: the scan loop skips those before
// matching.
func TestFindingOrderIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 6; i++ {
		write(t, filepath.Join(dir, fmt.Sprintf("f%d.py", i)), `import hashlib
a = hashlib.md5(b"x")
b = hashlib.sha1(b"y")
c = hashlib.new("md5")
d = 1  # sha1 stays until the legacy peers migrate
`)
	}

	var first []string
	var firstJSON []byte
	for run := 0; run < 5; run++ {
		results, err := New(Config{Target: dir, MinSeverity: types.SeverityInfo}).Scan()
		if err != nil {
			t.Fatalf("scan: %v", err)
		}

		order := make([]string, 0, len(results.Findings))
		for _, f := range results.Findings {
			order = append(order, fmt.Sprintf("%s:%d:%d:%s", f.File, f.Line, f.Column, f.ID))
		}

		// Scan time and duration differ on every run by design, so only the
		// content-determined parts of the report are compared.
		encoded, err := json.Marshal(struct {
			Findings []Finding `json:"findings"`
			Summary  Summary   `json:"summary"`
		}{results.Findings, results.Summary})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		if run == 0 {
			if len(order) < 6 {
				t.Fatalf("fixture produced only %d findings; too few to detect an ordering change", len(order))
			}
			if len(results.Summary.ByEvidence) < 2 {
				t.Fatalf("byEvidence has %d keys; the fixture no longer exercises its ordering: %v",
					len(results.Summary.ByEvidence), results.Summary.ByEvidence)
			}
			if !bytes.Contains(encoded, []byte(`"byEvidence"`)) {
				t.Fatalf("summary JSON carries no byEvidence: %s", encoded)
			}
			first = order
			firstJSON = encoded
			continue
		}
		if !bytes.Equal(encoded, firstJSON) {
			t.Fatalf("run %d JSON differs from run 0:\n%s\nvs\n%s", run, encoded, firstJSON)
		}
		if len(order) != len(first) {
			t.Fatalf("run %d returned %d findings, run 0 returned %d", run, len(order), len(first))
		}
		for i := range order {
			if order[i] != first[i] {
				t.Fatalf("run %d differs from run 0 at position %d: %q vs %q", run, i, order[i], first[i])
			}
		}
	}
}

// TestDependencyInsightListsLibrariesByName covers the "Libraries detected:"
// list of the dependency_update insight. The list was built by ranging over a
// map, and Go randomises map iteration order, so two scans of the same tree
// could list the libraries in different orders. It is sorted by name now.
func TestDependencyInsightListsLibrariesByName(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "package.json"), `{
  "name": "fixture",
  "version": "1.0.0",
  "dependencies": {
    "node-forge": "^1.3.1",
    "tweetnacl": "^1.0.3",
    "jose": "^5.2.0"
  }
}
`)
	write(t, filepath.Join(dir, "requirements.txt"), `pycryptodome==3.20.0
pynacl==1.5.0
cryptography==42.0.5
`)

	const want = "Libraries detected: cryptography, jose, node-forge, pycryptodome, pynacl, tweetnacl. " +
		"These provide quantum-vulnerable algorithms."
	for run := 0; run < 5; run++ {
		results, err := New(Config{Target: dir, MinSeverity: types.SeverityInfo}).Scan()
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		var got []string
		for _, insight := range results.Insights {
			if insight.Type == "dependency_update" {
				got = append(got, insight.Description)
			}
		}
		if len(got) != 1 {
			t.Fatalf("run %d: want one dependency_update insight, got %d: %q", run, len(got), got)
		}
		if got[0] != want {
			t.Fatalf("run %d: description = %q, want %q", run, got[0], want)
		}
	}
}
