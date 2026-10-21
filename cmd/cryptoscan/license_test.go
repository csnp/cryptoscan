// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	// licenseFile is the repository's license: the terms of the Apache
	// License 2.0, then the project's copyright line and license notice.
	licenseFile = "../../LICENSE"

	// apacheLicenseURL is where the Apache Software Foundation publishes the
	// text of the Apache License 2.0.
	apacheLicenseURL = "https://www.apache.org/licenses/LICENSE-2.0.txt"

	// apacheLicenseFile is a byte-for-byte copy of the file at
	// apacheLicenseURL.
	apacheLicenseFile = "testdata/apache-2.0.txt"

	// apacheLicenseSHA256 is the SHA-256 of the file at apacheLicenseURL,
	// fetched on 2026-10-21.
	apacheLicenseSHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"

	// endOfTerms is the line that closes the terms of the license. The text
	// after it differs by design: the Apache text goes on with an appendix on
	// how to apply the license, and LICENSE with the project's copyright line
	// and license notice.
	endOfTerms = "END OF TERMS AND CONDITIONS"
)

// licenseWord is one whitespace-separated word of a license text and the
// 1-based line it is on.
type licenseWord struct {
	text string
	line int
}

// termsWords returns the words of text up to and including the line that
// reads endOfTerms, and whether text has such a line.
func termsWords(text string) ([]licenseWord, bool) {
	var words []licenseWord
	for i, line := range strings.Split(text, "\n") {
		for _, w := range strings.Fields(line) {
			words = append(words, licenseWord{text: w, line: i + 1})
		}
		if strings.TrimSpace(line) == endOfTerms {
			return words, true
		}
	}
	return nil, false
}

// wordsAround returns the words of words from two before index i to three
// after it, joined by single spaces. Indexes outside words are left out.
func wordsAround(words []licenseWord, i int) string {
	var parts []string
	for j := i - 2; j <= i+3; j++ {
		if j >= 0 && j < len(words) {
			parts = append(parts, words[j].text)
		}
	}
	return strings.Join(parts, " ")
}

// licenseTermsProblem compares the words of the terms in license with the
// words of the terms in apache, the text of the Apache License 2.0. The terms
// are the text up to and including the line that reads endOfTerms, and
// spacing and line breaks are not compared. It describes the first word that
// differs, with its line in license, or returns "" when the words are the
// same, along with the number of words it read from the terms in license.
func licenseTermsProblem(license, apache string) (problem string, words int) {
	got, ok := termsWords(license)
	if !ok {
		return fmt.Sprintf("LICENSE has no line that reads %q, so the end of its terms is not found", endOfTerms), 0
	}
	want, ok := termsWords(apache)
	if !ok {
		return fmt.Sprintf("the Apache License 2.0 text has no line that reads %q", endOfTerms), len(got)
	}
	for i := 0; i < len(got) || i < len(want); i++ {
		if i < len(got) && i < len(want) && got[i].text == want[i].text {
			continue
		}
		line := got[len(got)-1].line
		if i < len(got) {
			line = got[i].line
		}
		return fmt.Sprintf("LICENSE:%d: the terms read %q, where the Apache License 2.0 text reads %q",
			line, wordsAround(got, i), wordsAround(want, i)), len(got)
	}
	return "", len(got)
}

// TestLicenseTermsMatchTheApacheLicense fails when the terms in LICENSE, the
// text up to and including the line "END OF TERMS AND CONDITIONS", differ by
// a word from the Apache License 2.0 text that the Apache Software Foundation
// publishes. LICENSE read "submitted to the Licensor for inclusion" where
// that text reads "submitted to Licensor for inclusion".
func TestLicenseTermsMatchTheApacheLicense(t *testing.T) {
	apache, err := os.ReadFile(apacheLicenseFile)
	if err != nil {
		t.Fatal(err)
	}
	// The comparison holds LICENSE to the copy, so the copy has to be the
	// published file.
	if sum := fmt.Sprintf("%x", sha256.Sum256(apache)); sum != apacheLicenseSHA256 {
		t.Fatalf("%s has SHA-256 %s, want %s, the SHA-256 of %s; from cmd/cryptoscan, curl -sL %s -o %s writes the published file",
			apacheLicenseFile, sum, apacheLicenseSHA256, apacheLicenseURL, apacheLicenseURL, apacheLicenseFile)
	}

	license, err := os.ReadFile(licenseFile)
	if err != nil {
		t.Fatal(err)
	}
	problem, words := licenseTermsProblem(string(license), string(apache))
	t.Logf("compared %d words of the terms in LICENSE", words)
	if problem != "" {
		t.Errorf("%s; from the repository root, diff cmd/cryptoscan/%s LICENSE shows it, along with the blank first line of the copy and the lines after %q, which this test does not compare",
			problem, apacheLicenseFile, endOfTerms)
	}
}

func TestLicenseTermsProblem(t *testing.T) {
	const apache = "\n" +
		"                                 Apache License\n" +
		"\n" +
		"   1. Definitions.\n" +
		"\n" +
		"      submitted to Licensor for inclusion\n" +
		"      in the Work.\n" +
		"\n" +
		"   END OF TERMS AND CONDITIONS\n" +
		"\n" +
		"   APPENDIX: How to apply the Apache License to your work.\n"

	tests := []struct {
		name    string
		license string
		words   int    // words read from the terms in license
		problem string // the expected problem; empty when none is expected
	}{
		{
			name:    "same terms, with a copyright line in place of the appendix",
			license: "Apache License\n\n1. Definitions.\n\nsubmitted to Licensor for inclusion\nin the Work.\n\nEND OF TERMS AND CONDITIONS\n\nCopyright 2025-2026 Example\n",
			words:   17,
		},
		{
			name:    "same words with other line breaks and spacing",
			license: "Apache License\n1. Definitions.\nsubmitted to Licensor\nfor  inclusion in the Work.\r\nEND OF TERMS AND CONDITIONS\r\n",
			words:   17,
		},
		{
			name:    "word added",
			license: "Apache License\n\n1. Definitions.\n\nsubmitted to the Licensor for inclusion\nin the Work.\n\nEND OF TERMS AND CONDITIONS\n",
			words:   18,
			problem: `LICENSE:5: the terms read "submitted to the Licensor for inclusion", where the Apache License 2.0 text reads "submitted to Licensor for inclusion in"`,
		},
		{
			name:    "word changed",
			license: "Apache License\n\n1. Definitions.\n\nsubmitted to Licencor for inclusion\nin the Work.\n\nEND OF TERMS AND CONDITIONS\n",
			words:   17,
			problem: `LICENSE:5: the terms read "submitted to Licencor for inclusion in", where the Apache License 2.0 text reads "submitted to Licensor for inclusion in"`,
		},
		{
			name:    "word left out",
			license: "Apache License\n\n1. Definitions.\n\nsubmitted to Licensor inclusion\nin the Work.\n\nEND OF TERMS AND CONDITIONS\n",
			words:   16,
			problem: `LICENSE:5: the terms read "to Licensor inclusion in the Work.", where the Apache License 2.0 text reads "to Licensor for inclusion in the"`,
		},
		{
			name:    "no line that ends the terms",
			license: "Apache License\n\n1. Definitions.\n\nsubmitted to Licensor for inclusion\nin the Work.\n",
			problem: `LICENSE has no line that reads "END OF TERMS AND CONDITIONS", so the end of its terms is not found`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problem, words := licenseTermsProblem(tt.license, apache)
			if problem != tt.problem {
				t.Errorf("got problem %q, want %q", problem, tt.problem)
			}
			if words != tt.words {
				t.Errorf("read %d words, want %d", words, tt.words)
			}
		})
	}
}
