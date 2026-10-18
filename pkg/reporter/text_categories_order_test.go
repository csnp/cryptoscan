// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"regexp"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// TestTextCategoriesFollowCountThenName checks that the "Categories Found"
// block lists the category with the most findings first, categories with the
// same count in name order, and that repeated runs on the same results
// produce identical text output.
func TestTextCategoriesFollowCountThenName(t *testing.T) {
	// The categories and counts a default text scan of crypto-samples
	// reports, three pairs of them with the same count.
	byCategory := map[string]int{
		"Weak Key Size":               1,
		"Asymmetric Encryption":       37,
		"Deprecated Hash":             5,
		"Symmetric Encryption":        7,
		"Key Derivation Function":     12,
		"TLS/SSL":                     2,
		"Broken Hash":                 5,
		"Deprecated Algorithm":        4,
		"Message Authentication Code": 4,
		"Configuration":               1,
		"PQC Library Import":          11,
		"Post-Quantum Cryptography":   18,
		"Hybrid Cryptography":         3,
	}
	want := []string{
		"Asymmetric Encryption",
		"Post-Quantum Cryptography",
		"Key Derivation Function",
		"PQC Library Import",
		"Symmetric Encryption",
		"Broken Hash",
		"Deprecated Hash",
		"Deprecated Algorithm",
		"Message Authentication Code",
		"Hybrid Cryptography",
		"TLS/SSL",
		"Configuration",
		"Weak Key Size",
	}
	results := &scanner.Results{
		ScanTarget: "/",
		Summary:    scanner.Summary{ByCategory: byCategory},
	}

	reporter := NewTextReporter(false)
	first, err := reporter.Generate(results)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	block := reportSection(t, first, "Categories Found:", "\n\n")
	rows := regexp.MustCompile(`(?m)^    ├─ (.*\S)\s+(\d+)$`).FindAllStringSubmatch(block, -1)
	if len(rows) != len(want) {
		t.Fatalf("Categories Found has %d rows, want %d:\n%s", len(rows), len(want), block)
	}
	for i, row := range rows {
		if row[1] != want[i] {
			t.Fatalf("row %d is %q, want %q (most findings first, then by name):\n%s", i, row[1], want[i], block)
		}
		if n := atoi(t, row[2]); n != byCategory[want[i]] {
			t.Errorf("%s row says %d, want %d", want[i], n, byCategory[want[i]])
		}
	}

	for run := 0; run < 20; run++ {
		again, err := reporter.Generate(results)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		if again != first {
			t.Fatalf("run %d produced different text output for the same results", run+2)
		}
	}
}
