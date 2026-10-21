// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// baseline is a JSON report from an earlier scan whose findings were reviewed.
type baseline struct {
	ScanTarget string            `json:"scanTarget"`
	Metadata   map[string]string `json:"metadata"`
	Findings   []scanner.Finding `json:"findings"`
}

// baselineKey identifies a finding by what it is, not by where the repository
// is checked out or which line the finding is on. Keyed on the absolute path
// and the line, a baseline written on one machine read every finding as new on
// a CI runner, and so did a single line added above a reviewed finding.
type baselineKey struct {
	path    string // slash-separated, relative to the scan root
	pattern string // pattern ID, without the line and column the finding ID adds
	text    string // the matched line, with runs of whitespace collapsed
}

// loadBaseline loads a baseline JSON file containing previous scan results
func loadBaseline(path string) (*baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var b baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	// A report from an earlier release holds the target as it was typed,
	// which for a repository URL can include a user name and password. The
	// baseline keeps and compares the target without them.
	b.ScanTarget = displayTarget(b.ScanTarget)
	return &b, nil
}

// filterNewFindings removes findings that already exist in the baseline. root
// is the directory the current scan's file paths are under. Each baseline
// entry covers one finding, so a second copy of a reviewed line is new.
func filterNewFindings(findings []scanner.Finding, root string, b *baseline) []scanner.Finding {
	keys := make([]baselineKey, len(findings))
	paths := make(map[string]bool)
	for i, f := range findings {
		keys[i] = findingKey(f, root)
		paths[keys[i].path] = true
	}

	reviewed := make(map[baselineKey]int)
	baseRoot := b.root(paths)
	for _, f := range b.Findings {
		reviewed[findingKey(f, baseRoot)]++
	}

	// Not nil: a report with nothing new lists "findings": [], the same as a
	// scan that found nothing.
	newFindings := []scanner.Finding{}
	for i, f := range findings {
		if reviewed[keys[i]] > 0 {
			reviewed[keys[i]]--
			continue
		}
		newFindings = append(newFindings, f)
	}
	return newFindings
}

// root returns the directory the baseline's file paths are under. Reports
// from this release record it for a local target; a Git URL scan records
// none, and its paths, relative to the repository root, are kept as they
// are (inferBaselineRoot reads only absolute paths, so it returns "" for
// them). A report from 1.4.0 or earlier does not record a root either, and
// its scanTarget is the target as it was typed: an absolute path is used as
// it is, and anything else ("." in the README's CI recipe, or a repository
// URL that was cloned to a temporary directory) is inferred from the paths
// the current scan reports.
func (b *baseline) root(currentPaths map[string]bool) string {
	if root := b.Metadata[scanner.MetadataScanRoot]; root != "" {
		return root
	}
	if filepath.IsAbs(b.ScanTarget) {
		return b.ScanTarget
	}
	return inferBaselineRoot(b.Findings, currentPaths)
}

// inferBaselineRoot finds the directory an earlier scan ran from when its
// report does not say. Each distinct file in the baseline proposes the
// directory in front of any path from the current scan that its own path ends
// with. The directory proposed by the most files wins, and on a tie the
// shortest one, which matches the longest relative paths. When no file
// matches, the baseline covers nothing in the current scan and the root does
// not matter.
func inferBaselineRoot(entries []scanner.Finding, currentPaths map[string]bool) string {
	votes := make(map[string]int)
	seen := make(map[string]bool)
	for _, f := range entries {
		if !filepath.IsAbs(f.File) {
			continue
		}
		file := filepath.ToSlash(f.File)
		if seen[file] {
			continue
		}
		seen[file] = true
		for i := 0; i < len(file); i++ {
			if file[i] == '/' && currentPaths[file[i+1:]] {
				dir := file[:i]
				if dir == "" {
					dir = "/"
				}
				votes[dir]++
			}
		}
	}

	best := ""
	for dir, n := range votes {
		if best == "" || n > votes[best] ||
			(n == votes[best] && (len(dir) < len(best) || (len(dir) == len(best) && dir < best))) {
			best = dir
		}
	}
	return filepath.FromSlash(best)
}

func findingKey(f scanner.Finding, root string) baselineKey {
	return baselineKey{
		path:    relativeTo(root, f.File),
		pattern: patternID(f),
		text:    strings.Join(strings.Fields(matchedLine(f)), " "),
	}
}

// relativeTo returns file relative to root, slash-separated. A path that is
// already relative is kept, and one outside root stays absolute so that it
// cannot match a path inside another root.
func relativeTo(root, file string) string {
	if root == "" || !filepath.IsAbs(file) {
		return filepath.ToSlash(filepath.Clean(file))
	}
	rel, err := filepath.Rel(root, file)
	switch {
	case err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)):
		return filepath.ToSlash(file)
	case rel == ".":
		// An earlier release recorded a single-file target as the root.
		// This release records the file's directory, so key on its name.
		return filepath.Base(file)
	}
	return filepath.ToSlash(rel)
}

// matchedLine returns the source line a finding was reported on, from the
// context the scanner attaches. A finding without one, such as a dependency
// in a manifest, is identified by what it matched.
func matchedLine(f scanner.Finding) string {
	if f.SourceContext != nil {
		for _, l := range f.SourceContext.Lines {
			if l.IsMatch {
				return l.Content
			}
		}
	}
	return f.Match
}

// patternID returns the ID of the pattern that produced a finding. The
// matcher numbers each finding "<pattern>-<line>-<column>", and the line is
// exactly what the key must not depend on.
func patternID(f scanner.Finding) string {
	suffix := "-" + strconv.Itoa(f.Line) + "-"
	if i := strings.LastIndex(f.ID, suffix); i > 0 && isDigits(f.ID[i+len(suffix):]) {
		return f.ID[:i]
	}
	return extractPatternPrefix(f.ID)
}

// extractPatternPrefix extracts the pattern family prefix from a finding ID
// e.g., "RSA-001-a1b2c3d4" -> "RSA-001", "CERT-SELFSIGNED-001" -> "CERT-SELFSIGNED-001"
func extractPatternPrefix(id string) string {
	// If ID contains a hash suffix (pattern-NNN-HASH), remove it
	parts := strings.Split(id, "-")
	if len(parts) >= 3 {
		// Check if last part looks like a hash (lowercase hex)
		last := parts[len(parts)-1]
		if len(last) >= 6 && isHexString(last) {
			return strings.Join(parts[:len(parts)-1], "-")
		}
	}
	return id
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
