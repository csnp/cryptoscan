// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// displayTarget removes the user information from a target URL in each form
// it can take: a user name with a password, a user name alone, an empty one,
// and one that url.Parse refuses.
func TestDisplayTargetRemovesUserInformation(t *testing.T) {
	user := strings.Join([]string{"scan", "user"}, "")
	password := strings.Join([]string{"fragment", "pass"}, "")
	join := func(parts ...string) string { return strings.Join(parts, "") }

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{"user and password", join("https://", user, ":", password, "@", "example.com/org/repo.git"), "https://example.com/org/repo.git"},
		{"user alone", join("https://", user, "@", "example.com/org/repo"), "https://example.com/org/repo"},
		{"empty user information", join("https://", "@", "example.com/org/repo"), "https://example.com/org/repo"},
		{"port, query and fragment", join("http://", user, ":", password, "@", "127.0.0.1:8080/repo.git?ref=main#readme"), "http://127.0.0.1:8080/repo.git?ref=main#readme"},
		{"scheme in capitals", join("HTTPS://", user, ":", password, "@", "example.com/repo"), "https://example.com/repo"},
		{"scheme the scanner does not clone", join("ssh://", user, ":", password, "@", "example.com/repo.git"), "ssh://example.com/repo.git"},
		// url.Parse refuses the next four, so the pattern removes the user
		// information.
		{"password holding a space", join("https://", user, ":", "frag", " ", "ment", "@", "example.com/repo"), "https://example.com/repo"},
		{"password holding @ and a space", join("https://", user, ":", "frag", "@", "ment", " ", "pass", "@", "example.com/repo"), "https://example.com/repo"},
		{"password holding #", join("https://", user, ":", "frag", "#", "ment", "@", "example.com/repo"), "https://example.com/repo"},
		{"refused, scheme in capitals", join("HTTPS://", user, ":", "frag", " ", "ment", "@", "example.com/repo"), "HTTPS://example.com/repo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := displayTarget(tt.target); got != tt.want {
				t.Errorf("displayTarget(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

// A target with no user information comes back from displayTarget byte for
// byte as it was given, including URLs that url.URL.String would write
// differently.
func TestDisplayTargetLeavesATargetWithoutUserInformationAsItIs(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"url", "https://github.com/csnp/cryptoscan"},
		{"url ending in .git", "https://github.com/csnp/cryptoscan.git"},
		{"url with a port", "http://127.0.0.1:1/repo.git"},
		{"url in capitals", "HTTPS://Example.com/Org/Repo"},
		{"url with a space in its path", "https://example.com/a b/repo"},
		{"url with @ in its query", "https://example.com/repo?ref=a@b"},
		{"url with @ in its fragment", "https://example.com/repo#a@b"},
		{"url with @ in its path", "https://example.com/repo/a@b"},
		{"file url", "file:///home/dev/repo"},
		{"relative path holding @", "./repo@v2"},
		{"bare name holding @", "build@2"},
		{"absolute path holding @", "/tmp/build@2/src"},
		{"windows path holding @", `C:\Users\dev\repo@2`},
		{"current directory", "."},
		{"empty", ""},
		{"user@host:path", "git@github.com:csnp/cryptoscan.git"},
		{"user@host:path with a relative path", "deploy@build-host:repos/app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := displayTarget(tt.target); got != tt.target {
				t.Errorf("displayTarget(%q) = %q, want it unchanged", tt.target, got)
			}
		})
	}
}
