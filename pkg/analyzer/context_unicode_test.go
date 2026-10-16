// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"strings"
	"testing"
)

// Letters whose lowercase form has a different UTF-8 length than the letter.
// Built from code points so the test source stays ASCII.
const (
	capitalAWithStroke = string(rune(0x023A)) // two bytes, lowercases to three
	capitalTWithStroke = string(rune(0x023E)) // two bytes, lowercases to three
	capitalIWithDot    = string(rune(0x0130)) // two bytes, lowercases to one
	invalidUTF8Byte    = "\xff"               // strings.ToLower turns it into three bytes
	capitalEWithAcute  = string(rune(0x00C9)) // lowercases to a letter of the same length
	smallEWithAcute    = string(rune(0x00E9))
)

func TestLowerSameOffsets(t *testing.T) {
	// Each of these changes length under strings.ToLower, which is the
	// property that broke the context checks. Assert it so the test keeps
	// exercising the hazard.
	for _, s := range []string{capitalAWithStroke, capitalTWithStroke, capitalIWithDot, invalidUTF8Byte} {
		if len(strings.ToLower(s)) == len(s) {
			t.Fatalf("precondition: strings.ToLower(%q) keeps its length, so it does not test the fix", s)
		}
	}

	tests := []struct {
		in   string
		want string
	}{
		{"RSA.GenerateKey", "rsa.generatekey"},
		{"", ""},
		{strings.Repeat(capitalAWithStroke, 4) + " RSA", strings.Repeat(capitalAWithStroke, 4) + " rsa"},
		{capitalTWithStroke + "ECDSA", capitalTWithStroke + "ecdsa"},
		{capitalIWithDot + "DSA", capitalIWithDot + "dsa"},
		{invalidUTF8Byte + "RSA", invalidUTF8Byte + "rsa"},
		// Letters whose lowercase form is the same length are still lowered.
		{capitalEWithAcute + "CDSA", smallEWithAcute + "cdsa"},
	}
	for _, tt := range tests {
		got := LowerSameOffsets(tt.in)
		if got != tt.want {
			t.Errorf("LowerSameOffsets(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if len(got) != len(tt.in) {
			t.Errorf("LowerSameOffsets(%q) is %d bytes, want %d", tt.in, len(got), len(tt.in))
		}
	}
}

// A line with four U+023A letters before a match at the end of the line made
// IsURLOrPath slice past the end of the line and panic.
func TestContextChecksWithLettersThatGrowWhenLowercased(t *testing.T) {
	for _, letter := range []string{capitalAWithStroke, capitalTWithStroke} {
		line := `var s = "` + strings.Repeat(letter, 4) + `"; _ = rsa`

		if IsURLOrPath(line, "rsa") {
			t.Errorf("IsURLOrPath(%q) = true, want false", line)
		}
		if IsVariableOrFunctionName(line, "rsa") {
			t.Errorf("IsVariableOrFunctionName(%q) = true, want false", line)
		}

		// A path after the letters ran past the end of the line as well.
		pathLine := strings.Repeat(letter, 4) + " x/rsa"
		if !IsURLOrPath(pathLine, "rsa") {
			t.Errorf("IsURLOrPath(%q) = false, want true", pathLine)
		}
	}
}

// When the shifted position stayed inside the line, the checks read the
// wrong bytes and classified the match incorrectly instead of panicking.
func TestContextChecksReadTheMatchNotTheShiftedBytes(t *testing.T) {
	tests := []struct {
		name string
		got  func() bool
		want bool
	}{
		{
			// The byte before the shifted position is the "r" of the match.
			name: "standalone match is not an identifier",
			got:  func() bool { return IsVariableOrFunctionName(capitalAWithStroke+" = rsa", "rsa") },
			want: false,
		},
		{
			// The shifted position skips the "." of the file extension.
			name: "file extension after the match is a path",
			got:  func() bool { return IsURLOrPath(capitalAWithStroke+" rsa.pem", "rsa") },
			want: true,
		},
		{
			// A letter that shrinks when lowercased shifts the position the
			// other way, so the byte after the shifted match is its last "a".
			name: "standalone match after a shrinking letter is not an identifier",
			got:  func() bool { return IsVariableOrFunctionName(capitalIWithDot+" rsa", "rsa") },
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.got(); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
