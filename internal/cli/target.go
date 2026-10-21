// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/url"
	"regexp"
)

// userinfoPattern matches a URL's scheme and the user information after it,
// up to the last "@" before the path, so that a password holding "@" is
// matched whole. The scheme is matched in any case.
var userinfoPattern = regexp.MustCompile(`(?i)^([a-z][a-z0-9+.-]*://)[^/]*@`)

// displayTarget returns target as the program prints and saves it. A
// repository URL can carry a user name and password for the clone. They are
// removed here; the scanner, which clones the repository, is the only part of
// the program given the target as it was typed. A target with no user
// information, which includes a local path and the user@host:path form, is
// returned unchanged.
func displayTarget(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		// url.Parse refuses some user information, such as a password
		// holding a space or a "#".
		return userinfoPattern.ReplaceAllString(target, "$1")
	}
	if u.Scheme == "" || u.User == nil {
		return target
	}
	u.User = nil
	return u.String()
}
