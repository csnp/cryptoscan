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
	"github.com/csnp/cryptoscan/pkg/types"
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
	newFindings, _ := applyBaseline(findings, nil, root, b)
	return newFindings
}

// applyBaseline is filterNewFindings, and also reports whether the baseline
// accepts each finding in withheld, the findings a config file removed. The
// findings in the report take their entries first, so a finding the file
// removed is accepted only by an entry no reported finding used. When the
// baseline's root is inferred (see root), it is inferred from the reported
// findings, as filterNewFindings infers it, so the withheld findings do not
// change which reported findings are new. Only when the reported paths give
// no root are the paths of the withheld findings used as well: when the file
// removed every finding in the baseline's files, the reported paths hold none
// of those files to infer the root from, and which entries the reported
// findings match does not then depend on the root.
//
// The withheld findings are set against the same root first. A root that a
// file the baseline lists is not under is not the one the earlier scan ran
// from, since that scan listed only files under its own root. The reported
// paths can give such a root, as when a new file's path is the end of a path
// the baseline lists in another directory, and so can the paths of the
// withheld findings when the reported paths give none, as when files the
// baseline lists in a subdirectory moved to the top of the tree and
// outnumber the listed files that did not move. The withheld findings the
// baseline does not accept under such a root are then set against the
// entries still left, under the root inferred from the paths of the reported
// and the withheld findings together, among the directories every file the
// baseline lists is under (see inferRootOfEveryFile). That root only adds to
// the withheld findings the baseline accepts, so a removed finding in a file
// that moved since, which the first root places at its entry, is still
// accepted. When no such directory is inferred, only the first root is used.
func applyBaseline(findings, withheld []scanner.Finding, root string, b *baseline) ([]scanner.Finding, []bool) {
	keys := make([]baselineKey, len(findings))
	paths := make(map[string]bool)
	for i, f := range findings {
		keys[i] = findingKey(f, root)
		paths[keys[i].path] = true
	}
	withheldKeys := make([]baselineKey, len(withheld))
	for i, f := range withheld {
		withheldKeys[i] = findingKey(f, root)
	}

	baseRoot := b.root(paths)
	withheldRoot := baseRoot
	if _, given := b.givenRoot(); !given && len(withheld) > 0 {
		allPaths := make(map[string]bool, len(paths)+len(withheldKeys))
		for path := range paths {
			allPaths[path] = true
		}
		for _, key := range withheldKeys {
			allPaths[key.path] = true
		}
		if baseRoot == "" {
			baseRoot = inferBaselineRoot(b.Findings, allPaths)
			withheldRoot = baseRoot
		}
		if baseRoot != "" && !holdsEveryFile(baseRoot, b.Findings) {
			if r := inferRootOfEveryFile(b.Findings, allPaths); r != "" {
				withheldRoot = r
			}
		}
	}

	// Each entry covers one finding. The reported findings take theirs by
	// their key under baseRoot, and the withheld findings then take the
	// entries left by their key under baseRoot and, when withheldRoot is
	// another root, the entries still left by their key under it.
	byKey := make(map[baselineKey][]int)
	for j, f := range b.Findings {
		key := findingKey(f, baseRoot)
		byKey[key] = append(byKey[key], j)
	}
	taken := make([]bool, len(b.Findings))

	// Not nil: a report with nothing new lists "findings": [], the same as a
	// scan that found nothing.
	newFindings := []scanner.Finding{}
	for i, f := range findings {
		if js := byKey[keys[i]]; len(js) > 0 {
			taken[js[0]] = true
			byKey[keys[i]] = js[1:]
			continue
		}
		newFindings = append(newFindings, f)
	}

	accepted := make([]bool, len(withheld))
	if len(withheld) == 0 {
		return newFindings, accepted
	}
	for i, key := range withheldKeys {
		if js := byKey[key]; len(js) > 0 {
			taken[js[0]] = true
			byKey[key] = js[1:]
			accepted[i] = true
		}
	}
	if withheldRoot == baseRoot {
		return newFindings, accepted
	}
	left := make(map[baselineKey]int)
	for j, f := range b.Findings {
		if !taken[j] {
			left[findingKey(f, withheldRoot)]++
		}
	}
	for i, key := range withheldKeys {
		if !accepted[i] && left[key] > 0 {
			left[key]--
			accepted[i] = true
		}
	}
	return newFindings, accepted
}

// root returns the directory the baseline's file paths are under. Reports
// from this release record it for a local target; a Git URL scan records
// none, and its paths, relative to the repository root, are kept as they
// are (inferBaselineRoot reads only absolute paths, so it returns "" for
// them). A report from 1.4.0 or earlier does not record a root either, and
// its scanTarget is the target as it was typed: an absolute path is used as
// it is, and anything else ("." in the README's CI recipe, or a repository
// URL that was cloned to a temporary directory) is inferred from the paths
// of the current scan's findings (see applyBaseline for which ones).
func (b *baseline) root(currentPaths map[string]bool) string {
	if root, ok := b.givenRoot(); ok {
		return root
	}
	return inferBaselineRoot(b.Findings, currentPaths)
}

// givenRoot returns the root a baseline gives itself: the root it records,
// or its scanTarget when that is an absolute path. ok is false when neither
// is there and the root is inferred.
func (b *baseline) givenRoot() (root string, ok bool) {
	if root := b.Metadata[scanner.MetadataScanRoot]; root != "" {
		return root, true
	}
	if filepath.IsAbs(b.ScanTarget) {
		return b.ScanTarget, true
	}
	return "", false
}

// inferBaselineRoot finds the directory an earlier scan ran from when its
// report does not say. Each distinct file in the baseline proposes the
// directory in front of any path from the current scan that its own path ends
// with. The directory proposed by the most files wins, and on a tie the
// shortest one, which matches the longest relative paths. When no file
// matches, the baseline covers nothing in the current scan and the root does
// not matter.
func inferBaselineRoot(entries []scanner.Finding, currentPaths map[string]bool) string {
	return mostProposed(proposedRoots(entries, currentPaths))
}

// inferRootOfEveryFile is inferBaselineRoot among the directories that every
// absolute file path in entries is under. The earlier scan read only the
// files under the directory it scanned, so a proposed directory that leaves
// out a file the baseline lists is not that directory.
func inferRootOfEveryFile(entries []scanner.Finding, currentPaths map[string]bool) string {
	votes := proposedRoots(entries, currentPaths)
	for dir := range votes {
		if !holdsEveryFile(filepath.FromSlash(dir), entries) {
			delete(votes, dir)
		}
	}
	return mostProposed(votes)
}

// holdsEveryFile reports whether every absolute file path in entries is in
// dir or below it, so that relativeTo keys each of them on a path relative
// to dir.
func holdsEveryFile(dir string, entries []scanner.Finding) bool {
	for _, f := range entries {
		if filepath.IsAbs(f.File) && outside(filepath.Rel(dir, f.File)) {
			return false
		}
	}
	return true
}

// proposedRoots counts, for each slash-separated directory, the distinct
// files in entries that propose it (see inferBaselineRoot).
func proposedRoots(entries []scanner.Finding, currentPaths map[string]bool) map[string]int {
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
	return votes
}

// mostProposed returns the directory with the most votes, on a tie the
// shortest one and then the first in byte order, in the form of the
// operating system, and "" when votes is empty.
func mostProposed(votes map[string]int) string {
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
	case outside(rel, err):
		return filepath.ToSlash(file)
	case rel == ".":
		// An earlier release recorded a single-file target as the root.
		// This release records the file's directory, so key on its name.
		return filepath.Base(file)
	}
	return filepath.ToSlash(rel)
}

// outside reports whether rel, as filepath.Rel returned it with err, leads
// out of the directory it is relative to.
func outside(rel string, err error) bool {
	return err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
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

// patternID returns the ID of the pattern that produced a finding. A report
// from this release records it as the finding's patternId. A report written
// before records only the finding's ID, which adds to the pattern ID what the
// key must not depend on: the matcher numbers each finding
// "<pattern>-<line>-<offset>", and a dependency manifest numbers each of its
// findings "DEP-<library>-<manifest file name>".
func patternID(f scanner.Finding) string {
	if f.PatternID != "" {
		return f.PatternID
	}
	if f.FindingType == types.FindingTypeDependency && strings.HasPrefix(f.ID, scanner.DependencyPatternPrefix) {
		manifest := "-" + filepath.Base(f.File)
		if id, ok := strings.CutSuffix(f.ID, manifest); ok && len(id) > len(scanner.DependencyPatternPrefix) {
			return id
		}
	}
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
