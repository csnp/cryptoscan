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
// skipped, with the severities of what each setting removed. Settings that
// removed nothing are left out; an empty list means the file changed nothing
// in this scan.
func configEffects(c *scanner.ConfigReport) []string {
	var effects []string
	removed := []struct {
		setting    string
		count      int
		bySeverity scanner.ConfigSeverityCounts
	}{
		{"ignore.patterns", c.FindingsRemoved.IgnorePatterns, c.FindingsRemoved.IgnorePatternsBySeverity},
		{"ignore.categories", c.FindingsRemoved.IgnoreCategories, c.FindingsRemoved.IgnoreCategoriesBySeverity},
		{"minSeverity", c.FindingsRemoved.MinSeverity, c.FindingsRemoved.MinSeverityBySeverity},
		{"baseline", c.FindingsRemoved.Baseline, c.FindingsRemoved.BaselineBySeverity},
	}
	for _, r := range removed {
		if r.count > 0 {
			effect := fmt.Sprintf("%s removed %s", r.setting, countOf(r.count, "finding", "findings"))
			if breakdown := severityBreakdown(r.bySeverity); breakdown != "" {
				effect += " (" + breakdown + ")"
			}
			effects = append(effects, effect)
		}
	}

	if skipped := skippedPathsText(c); skipped != "" {
		effects = append(effects, fmt.Sprintf("ignore.files kept %s out of the scan", skipped))
	}
	return effects
}

// severityBreakdown words counts as "2 high, 1 low": each severity with a
// count, highest first, in the names --fail-on takes. It is empty when
// nothing is counted.
func severityBreakdown(counts scanner.ConfigSeverityCounts) string {
	var parts []string
	for _, s := range []scanner.Severity{scanner.SeverityCritical, scanner.SeverityHigh, scanner.SeverityMedium, scanner.SeverityLow, scanner.SeverityInfo} {
		if n := counts.Of(s); n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(s.String())))
		}
	}
	return strings.Join(parts, ", ")
}

// failOnNotApplied says that a gate run did not take the failOn of a config
// file it found because the value would have raised the threshold, or is
// empty when that did not happen.
func failOnNotApplied(c *scanner.ConfigReport) string {
	f := c.FailOn
	if f == nil || f.Cap == "" {
		return ""
	}
	return fmt.Sprintf("failOn: %s in the file was not applied: a config file found without --config cannot raise the threshold above %s. Pass --config %s to apply it.",
		f.Value, f.Cap, c.Path)
}

// rerunWithoutConfig is the command that repeats the scan without its config
// file. A gate run, and a scan with --fail-on, keep their command and their
// threshold, so that the command's exit code follows the same threshold as
// the run's.
func rerunWithoutConfig(c *scanner.ConfigReport, target string) string {
	command := c.Rerun.Command
	if command == "" {
		command = "scan"
	}
	line := "cryptoscan " + command + " " + target
	if c.Rerun.FailOn != "" {
		line += " --fail-on " + c.Rerun.FailOn
	}
	return line + " --no-config"
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
