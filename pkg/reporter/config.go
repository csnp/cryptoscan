// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"fmt"
	"strings"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// configSourceText describes where a config file was found, in the words the
// text and SARIF reports use.
func configSourceText(source string) string {
	switch source {
	case scanner.ConfigSourceFlag:
		return "passed with --config"
	case scanner.ConfigSourceScanTarget:
		return "found in the scan target"
	case scanner.ConfigSourceParentDirectory:
		return "found in a directory above the scan target, not in the target itself"
	case scanner.ConfigSourceWorkingDirectory:
		return "found from the working directory, not in the scanned repository"
	default:
		return "source unknown"
	}
}

// configEffects lists, one entry per setting, what a config file removed or
// skipped. Settings that removed nothing are left out; an empty list means
// the file changed nothing in this scan.
func configEffects(c *scanner.ConfigReport) []string {
	var effects []string
	removed := []struct {
		setting string
		count   int
	}{
		{"ignore.patterns", c.FindingsRemoved.IgnorePatterns},
		{"ignore.categories", c.FindingsRemoved.IgnoreCategories},
		{"minSeverity", c.FindingsRemoved.MinSeverity},
		{"baseline", c.FindingsRemoved.Baseline},
	}
	for _, r := range removed {
		if r.count > 0 {
			effects = append(effects, fmt.Sprintf("%s removed %s", r.setting, countOf(r.count, "finding", "findings")))
		}
	}

	if skipped := skippedPathsText(c); skipped != "" {
		effects = append(effects, fmt.Sprintf("ignore.files kept %s out of the scan", skipped))
	}
	return effects
}

// noFindingsHeadline replaces "No cryptographic findings detected" when the
// report is empty and the config file removed or skipped something, since the
// scan did not establish that nothing was there.
func noFindingsHeadline(c *scanner.ConfigReport) string {
	var parts []string
	if n := c.FindingsRemoved.Total; n > 0 {
		parts = append(parts, "removed "+countOf(n, "finding", "findings"))
	}
	if skipped := skippedPathsText(c); skipped != "" {
		parts = append(parts, "kept "+skipped+" out of the scan")
	}
	return "No findings reported: the config file " + strings.Join(parts, " and ")
}

func skippedPathsText(c *scanner.ConfigReport) string {
	var skipped []string
	if n := c.PathsSkipped.Files; n > 0 {
		skipped = append(skipped, countOf(n, "file", "files"))
	}
	if n := c.PathsSkipped.Directories; n > 0 {
		skipped = append(skipped, countOf(n, "directory", "directories"))
	}
	return strings.Join(skipped, " and ")
}

func countOf(n int, singular, pluralForm string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralForm)
}
