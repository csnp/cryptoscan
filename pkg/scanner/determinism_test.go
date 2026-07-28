// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
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
func TestFindingOrderIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 6; i++ {
		write(t, filepath.Join(dir, fmt.Sprintf("f%d.py", i)), `import hashlib
a = hashlib.md5(b"x")
b = hashlib.sha1(b"y")
c = hashlib.new("md5")
`)
	}

	var first []string
	for run := 0; run < 5; run++ {
		results, err := New(Config{Target: dir, MinSeverity: types.SeverityInfo}).Scan()
		if err != nil {
			t.Fatalf("scan: %v", err)
		}

		order := make([]string, 0, len(results.Findings))
		for _, f := range results.Findings {
			order = append(order, fmt.Sprintf("%s:%d:%d:%s", f.File, f.Line, f.Column, f.ID))
		}

		if run == 0 {
			if len(order) < 6 {
				t.Fatalf("fixture produced only %d findings; too few to detect an ordering change", len(order))
			}
			first = order
			continue
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
