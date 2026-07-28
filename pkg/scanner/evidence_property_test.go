// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math/rand"
	"testing"
)

// TestClassifyMatchNeverPanics is a property check over random lines and
// random match spans.
//
// classifyMatch does a lot of manual byte indexing (line[start-1],
// line[end+1], prefix[idx-1]) because it has to reason about the characters
// immediately around a match. A panic there is a denial of scan: one
// pathological source line would abort the whole run. The alphabet is weighted
// toward the characters the classifier actually branches on, plus multi-byte
// runes, since match offsets are byte offsets.
func TestClassifyMatchNeverPanics(t *testing.T) {
	alphabet := []rune{
		'a', 'M', 'D', '5', '.', '"', '\'', '`', '/', '(', ')', ' ', '\t',
		'#', '-', '=', ':', ',', '\\', '<', '>', '*', '{', '}', 'é', '中',
	}
	r := rand.New(rand.NewSource(1))

	for i := 0; i < 50000; i++ {
		buf := make([]rune, r.Intn(24))
		for j := range buf {
			buf[j] = alphabet[r.Intn(len(alphabet))]
		}
		line := string(buf)
		if line == "" {
			continue
		}

		// Deliberately includes spans that run past the end of the line and
		// spans with end before start.
		start := r.Intn(len(line) + 2)
		end := start + r.Intn(6)

		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("panic: line=%q start=%d end=%d: %v", line, start, end, p)
				}
			}()
			classifyMatch(matchContext{Line: line, Start: start, End: end})
		}()
	}
}

// TestUnclassifiableSpansAreReported pins the fail-open contract. A span the
// classifier cannot interpret must produce a finding, never a silent drop.
func TestUnclassifiableSpansAreReported(t *testing.T) {
	cases := []struct {
		line       string
		start, end int
	}{
		{"md5(b)", -1, 3},
		{"md5(b)", 0, 999},
		{"md5(b)", 5, 2},
		{"", 0, 1},
		{"md5(b)", 3, 3},
	}
	for _, tc := range cases {
		if class, reason := classifyMatch(matchContext{Line: tc.line, Start: tc.start, End: tc.end}); class != evidenceNarrative {
			continue
		} else {
			t.Errorf("classifyMatch(%q, %d, %d) suppressed the finding (reason %q); unclassifiable spans must be reported",
				tc.line, tc.start, tc.end, reason)
		}
	}
}
