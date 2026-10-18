// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// patternCountClaims are the sentences in the documentation that state how
// many detection patterns the matcher defines. Each expression captures the
// number as written.
var patternCountClaims = []struct {
	file string
	re   *regexp.Regexp
}{
	{"../../PATTERNS.md", regexp.MustCompile(`CryptoScan uses (\S+) detection patterns`)},
	{"../../docs/how-it-works.md", regexp.MustCompile(`# Cryptographic pattern definitions \((\S+)\)`)},
}

// TestDocsStatePatternCount fails when a page states a number of patterns
// other than the number of pattern IDs the matcher defines.
func TestDocsStatePatternCount(t *testing.T) {
	ids := make(map[string]bool)
	for _, p := range NewMatcher().patterns {
		ids[p.ID] = true
	}
	want := strconv.Itoa(len(ids))

	for _, claim := range patternCountClaims {
		data, err := os.ReadFile(claim.file)
		if err != nil {
			t.Fatal(err)
		}
		m := claim.re.FindSubmatch(data)
		if m == nil {
			t.Errorf("%s has no line matching %q; point patternCountClaims at the sentence that states the pattern count", claim.file, claim.re)
			continue
		}
		if got := string(m[1]); got != want {
			t.Errorf("%s states %s patterns; the matcher defines %s pattern IDs", claim.file, got, want)
		}
	}
}
