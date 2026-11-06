// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/patterns"
	"github.com/csnp/cryptoscan/pkg/types"
)

// wordMatchTexts returns the paragraphs of the three texts that say how the
// patterns match words, keyed by where they are: the README,
// docs/how-it-works.md and scan --help. Each run of white space in a
// paragraph is read as one space, so a sentence the help text wraps reads as
// one line.
func wordMatchTexts(t *testing.T) map[string][]string {
	t.Helper()
	texts := map[string]string{"scan --help": scanCmd.Long}
	for _, path := range []string{"../../README.md", "../../docs/how-it-works.md"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		texts[path] = string(data)
	}
	paragraphs := map[string][]string{}
	for where, text := range texts {
		for _, paragraph := range strings.Split(text, "\n\n") {
			paragraphs[where] = append(paragraphs[where], strings.Join(strings.Fields(paragraph), " "))
		}
	}
	return paragraphs
}

// sentencesWith returns the sentences of paragraphs that contain phrase, in
// any case. A sentence ends at a full stop followed by a space, or at the end
// of its paragraph.
func sentencesWith(paragraphs []string, phrase string) []string {
	var found []string
	for _, paragraph := range paragraphs {
		for _, sentence := range strings.SplitAfter(paragraph, ". ") {
			if strings.Contains(strings.ToLower(sentence), phrase) {
				found = append(found, strings.TrimSpace(sentence))
			}
		}
	}
	return found
}

// patternIDWord matches a word shaped like a pattern ID, such as RSA-001 or
// CERT-VALIDATION-BYPASS-001.
var patternIDWord = regexp.MustCompile(`[A-Z0-9]+(?:-[A-Z0-9]+)+`)

// boundedByWordBoundaries reports whether every way through re begins with
// \b and ends with \b, so that no match starts or ends inside a word. It
// answers false for a construct it does not follow.
func boundedByWordBoundaries(re *regexp.Regexp) bool {
	tree, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return false
	}
	seq := []*syntax.Regexp{tree}
	return startsWithWordBoundary(seq, true) && startsWithWordBoundary(seq, false)
}

// startsWithWordBoundary reports whether every way through the sequence seq
// starts with \b, reading seq from its front, or from its back when front is
// false.
func startsWithWordBoundary(seq []*syntax.Regexp, front bool) bool {
	if len(seq) == 0 {
		return false
	}
	head, rest := seq[0], seq[1:]
	if !front {
		head, rest = seq[len(seq)-1], seq[:len(seq)-1]
	}
	// then returns seq with subs in the place of head.
	then := func(subs ...*syntax.Regexp) []*syntax.Regexp {
		out := make([]*syntax.Regexp, 0, len(subs)+len(rest))
		if front {
			return append(append(out, subs...), rest...)
		}
		return append(append(out, rest...), subs...)
	}
	switch head.Op {
	case syntax.OpWordBoundary:
		return true
	case syntax.OpEmptyMatch:
		return startsWithWordBoundary(rest, front)
	case syntax.OpConcat:
		return startsWithWordBoundary(then(head.Sub...), front)
	case syntax.OpCapture, syntax.OpPlus:
		return startsWithWordBoundary(then(head.Sub[0]), front)
	case syntax.OpRepeat:
		if head.Min > 0 {
			return startsWithWordBoundary(then(head.Sub[0]), front)
		}
		return startsWithWordBoundary(then(head.Sub[0]), front) && startsWithWordBoundary(rest, front)
	case syntax.OpQuest, syntax.OpStar:
		return startsWithWordBoundary(then(head.Sub[0]), front) && startsWithWordBoundary(rest, front)
	case syntax.OpAlternate:
		for _, alt := range head.Sub {
			if !startsWithWordBoundary(then(alt), front) {
				return false
			}
		}
		return true
	}
	return false
}

func TestBoundedByWordBoundaries(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{`\bRSA\b`, true},
		{`(?i)\b(RSA|rsa)[-_]?(1024|2048)?\b`, true},
		{`(\bfoo)?\bbar\b`, true},
		{`\bRSA\b|RSA_`, false},
		{`\bfoo|bar\b`, false},
		{`\bfoo\b(bar)?`, false},
		{`verify\s*[=:]\s*false`, false},
		{``, false},
	} {
		if got := boundedByWordBoundaries(regexp.MustCompile(tc.expr)); got != tc.want {
			t.Errorf("boundedByWordBoundaries(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

// A sentence about whole words in the README, docs/how-it-works.md or scan
// --help names the patterns it is about, and every way through the
// expression of each of them begins and ends with \b. The three texts said
// that detection matches whole words, and CERT-VALIDATION-BYPASS-001 reports
// ssl_verify=False by matching verify=False inside it.
func TestWholeWordSentencesNameWholeWordPatterns(t *testing.T) {
	byID := map[string]patterns.Pattern{}
	for _, p := range patterns.NewMatcher().Patterns() {
		byID[p.ID] = p
	}
	for where, paragraphs := range wordMatchTexts(t) {
		sentences := sentencesWith(paragraphs, "whole word")
		if len(sentences) == 0 {
			t.Errorf("%s has no sentence about whole words", where)
		}
		for _, sentence := range sentences {
			var named []string
			for _, word := range patternIDWord.FindAllString(sentence, -1) {
				if _, ok := byID[word]; ok {
					named = append(named, word)
				}
			}
			if len(named) == 0 {
				t.Errorf("%s: %q names no pattern ID, so it reads as true of every pattern", where, sentence)
			}
			for _, id := range named {
				if !boundedByWordBoundaries(byID[id].Regex) {
					t.Errorf("%s: %q names %s, whose expression %s can start or end inside a word", where, sentence, id, byID[id].Regex)
				}
			}
		}
	}
}

// matchesOf returns the text each finding of the pattern id matched in line.
func matchesOf(findings []types.Finding, id string) []string {
	var found []string
	for _, f := range findings {
		if f.PatternID == id {
			found = append(found, f.Match)
		}
	}
	return found
}

// The examples the README, docs/how-it-works.md and scan --help give hold for
// the matcher: no pattern matches the compound identifiers RSAPrivateKey and
// AESCipher, while RSA-001 and AES-001 match RSA and AES standing alone;
// CERT-VALIDATION-BYPASS-001 matches verify=False inside ssl_verify=False; and
// RNG-WEAK-001 matches key inside apiKey.
func TestWordMatchingExamplesHold(t *testing.T) {
	for where, paragraphs := range wordMatchTexts(t) {
		text := strings.Join(paragraphs, "\n")
		for _, example := range []string{"RSA-001", "AES-001", "RSAPrivateKey", "AESCipher", "CERT-VALIDATION-BYPASS-001", "ssl_verify=False", "RNG-WEAK-001", "apiKey", "cryptoscan patterns list --format json"} {
			if !strings.Contains(text, example) {
				t.Errorf("%s does not mention %s", where, example)
			}
		}
	}

	m := patterns.NewMatcher()
	for _, p := range m.Patterns() {
		if (p.ID == "CERT-VALIDATION-BYPASS-001" || p.ID == "RNG-WEAK-001") && boundedByWordBoundaries(p.Regex) {
			t.Errorf("every way through the expression of %s begins and ends with \\b, and the texts say it matches inside a longer word", p.ID)
		}
	}
	for _, line := range []string{"RSAPrivateKey", "AESCipher", "key = RSAPrivateKey.load(data)", "cipher = AESCipher(secret)"} {
		for _, f := range m.Match(line, "app.py", 1) {
			t.Errorf("%s matches %q in %q", f.PatternID, f.Match, line)
		}
	}
	for id, line := range map[string]string{
		"RSA-001": "key = RSA.generate(2048)",
		"AES-001": "cipher = AES.new(key, AES.MODE_GCM)",
	} {
		if len(matchesOf(m.Match(line, "app.py", 1), id)) == 0 {
			t.Errorf("%s does not match %q", id, line)
		}
	}

	bypass := "resp = client.get(url, ssl_verify=False)"
	var columns []int
	for _, f := range m.Match(bypass, "client.py", 1) {
		if f.PatternID == "CERT-VALIDATION-BYPASS-001" && f.Match == "verify=False" {
			columns = append(columns, f.Column)
		}
	}
	if want := strings.Index(bypass, "ssl_verify") + len("ssl_") + 1; len(columns) != 1 || columns[0] != want {
		t.Errorf("CERT-VALIDATION-BYPASS-001 matches verify=False in %q at columns %v, want column %d, inside ssl_verify", bypass, columns, want)
	}

	withName := "const id = Math.random().toString(36) + apiKey;"
	got := matchesOf(m.Match(withName, "app.js", 1), "RNG-WEAK-001")
	if len(got) != 1 || !strings.HasSuffix(got[0], "apiKey") {
		t.Errorf("RNG-WEAK-001 matches %q in %q, want one match that ends with apiKey", got, withName)
	}
	withoutKey := strings.Replace(withName, "apiKey", "api", 1)
	if got := matchesOf(m.Match(withoutKey, "app.js", 1), "RNG-WEAK-001"); len(got) != 0 {
		t.Errorf("RNG-WEAK-001 matches %q in %q, so the key in apiKey is not what it matched in %q", got, withoutKey, withName)
	}
}
