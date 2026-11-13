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
// A root that a file the baseline lists is not under is not the one the
// earlier scan ran from, since that scan listed only files under its own
// root. The reported paths can give such a root, as when a new file's path
// is the end of a path the baseline lists in another directory, or when
// files the baseline lists in a subdirectory moved to the top of the tree
// and outnumber the listed files that did not move. When that happens, a
// second root is found in the same way among the directories that hold
// every file the baseline lists (see inferRootOfEveryFile), and the
// reported findings are matched against the entries with the same
// three-step method the withheld findings use (see matchKeys), under that
// root first and the root the reported paths give second. A greedy pass
// under one root and then the other can give a finding's own entry away:
// tool.py and tools/tools/tool.py hold the same line; when tools/tool.py
// moves out to tool.py and tools/tools/tool.py moves into the path
// tools/tool.py left, tools/tool.py's entry matches tool.py's finding
// under the root the reported paths give, where it is keyed at tool.py,
// and tools/tools/tool.py's finding under the root that holds every
// listed file, where it is keyed at tools/tool.py, the path that finding
// now has (they hold the same line); a pass under the root that holds
// every listed file before the root the reported paths give, the order
// taken here, gives it to tools/tools/tool.py's finding, which also
// matches its own entry under the root the reported paths give, and
// leaves tool.py's finding, which matches only that entry and only under
// the root the reported paths give, with nothing. The method keeps
// what a first and a second greedy pass accept and, for a finding neither
// step accepts, moves another finding already holding an entry the first
// finding also matches to a different entry that finding matches, where
// one exists, so both keep an entry. When no second root is found, only
// the root the reported paths give is used.
//
// The withheld findings are then set against the entries left, under the
// root the reported paths give or, when they give none, the root inferred
// from the paths of the reported and the withheld findings together. That
// root can leave out a listed file too, as when files moved up as above and
// the config file removed every finding. The withheld findings the baseline
// does not accept under a root that leaves out a listed file are then set
// against the entries still left, under the root inferred from the paths of
// the reported and the withheld findings together, among the directories
// every file the baseline lists is under. That root only adds to the
// withheld findings the baseline accepts, so a removed finding in a file
// that moved since, which the first root places at its entry, is still
// accepted. A withheld finding can take, under the first root, the entry
// another one has under the second: helper.py and tools/helper.py hold the
// same line, and the first root places the baseline's tools/helper.py at
// helper.py. The entries are then given out again where that gives one to a
// withheld finding still not accepted (see matchKeys, through
// acceptWithheld). When no such directory is inferred, only the first root
// is used.
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

	_, given := b.givenRoot()
	baseRoot := b.root(paths)
	// everyRoot, when it is not empty, is the root the reported findings are
	// set against before baseRoot.
	everyRoot := ""
	if !given && baseRoot != "" && !holdsEveryFile(baseRoot, b.Findings) {
		everyRoot = inferRootOfEveryFile(b.Findings, paths)
	}
	withheldRoot := baseRoot
	if !given && len(withheld) > 0 {
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

	// Each entry covers one finding. The reported findings take theirs with
	// the same method as the withheld findings (see matchKeys), under
	// everyRoot's key, when there is one, and then baseRoot's; an entry that
	// gives a reported finding is then taken, so the withheld findings do
	// not take it too.
	taken := make([]bool, len(b.Findings))
	reportedFirst := make([]baselineKey, len(b.Findings))
	var reportedSecond []baselineKey
	if everyRoot != "" {
		reportedSecond = make([]baselineKey, len(b.Findings))
		for j, f := range b.Findings {
			reportedFirst[j] = findingKey(f, everyRoot)
			reportedSecond[j] = findingKey(f, baseRoot)
		}
	} else {
		for j, f := range b.Findings {
			reportedFirst[j] = findingKey(f, baseRoot)
		}
	}
	inBaseline, holder := matchKeys(keys, reportedFirst, reportedSecond, taken)
	for j, i := range holder {
		if i != -1 {
			taken[j] = true
		}
	}

	// Not nil: a report with nothing new lists "findings": [], the same as a
	// scan that found nothing.
	newFindings := []scanner.Finding{}
	for i, f := range findings {
		if !inBaseline[i] {
			newFindings = append(newFindings, f)
		}
	}

	first := make([]baselineKey, len(b.Findings))
	for j, f := range b.Findings {
		first[j] = findingKey(f, baseRoot)
	}
	var second []baselineKey
	if withheldRoot != baseRoot && len(withheld) > 0 {
		second = make([]baselineKey, len(b.Findings))
		for j, f := range b.Findings {
			second[j] = findingKey(f, withheldRoot)
		}
	}
	return newFindings, acceptWithheld(withheldKeys, first, second, taken)
}

// acceptWithheld reports, for each withheld finding with the key in keys,
// whether the baseline accepts it. Each entry j that no reported finding took
// (taken[j]) can be given to one withheld finding whose key is first[j], the
// entry's key under the root of the reported findings, or, when second is not
// nil, second[j], its key under the second root. See matchKeys for how.
func acceptWithheld(keys, first, second []baselineKey, taken []bool) []bool {
	accepted, _ := matchKeys(keys, first, second, taken)
	return accepted
}

// matchKeys matches each key in keys, in the order given, against the
// entries of taken (indexed the same as first and, when it is not nil,
// second) that taken does not mark, under first, and, when a key is not
// matched there, under second. It reports, for each key, whether it is
// matched, and, for each entry, the index in keys of the finding it is
// given to, or -1.
//
// The entries are given out in three steps. In the first, each key in turn
// takes the first entry left whose first key is its own. In the second, each
// one the first step did not match takes the first entry still left whose
// second key is its own. In the third, each one still not matched takes an
// entry whose first or second key is its own when the key that holds the
// entry can move to another entry matching its own key, whose holder can
// move in the same way, and so on until a key moves to an entry no key
// holds. For example, helper.py's key holds, by its first key, the entry for
// tools/helper.py that tools/helper.py's key matches by its second key, and
// moves to the entry for helper.py, which matches it by its second key. A
// key that holds an entry is only moved to another, so the third step adds
// to the keys the first two match and removes none of them.
func matchKeys(keys, first, second []baselineKey, taken []bool) (accepted []bool, holder []int) {
	accepted = make([]bool, len(keys))
	// holder[j] is the index in keys of the finding entry j is given to, or
	// -1.
	holder = make([]int, len(first))
	for j := range holder {
		holder[j] = -1
	}
	if len(keys) == 0 {
		return accepted, holder
	}
	give := func(entryKeys []baselineKey) {
		left := make(map[baselineKey][]int)
		for j, key := range entryKeys {
			if !taken[j] && holder[j] == -1 {
				left[key] = append(left[key], j)
			}
		}
		for i, key := range keys {
			if js := left[key]; !accepted[i] && len(js) > 0 {
				holder[js[0]] = i
				left[key] = js[1:]
				accepted[i] = true
			}
		}
	}
	give(first)
	if second == nil {
		return accepted, holder
	}
	give(second)

	// matching lists the entries a key can hold, under either root.
	matching := make(map[baselineKey][]int)
	for j := range first {
		if taken[j] {
			continue
		}
		matching[first[j]] = append(matching[first[j]], j)
		if second[j] != first[j] {
			matching[second[j]] = append(matching[second[j]], j)
		}
	}
	// Each key still not matched starts a search. seen[j] is the number of
	// the last search that reached entry j, and expanded[key] that of the
	// last search that went through the entries matching key: keys with the
	// same value match the same entries, so a search goes through them once.
	// A key value in failed, one a search could not give an entry to, is not
	// searched for again: the keys that hold an entry keep one, so the
	// search would fail again.
	seen := make([]int, len(first))
	expanded := make(map[baselineKey]int)
	failed := make(map[baselineKey]bool)
	search := 0
	// place gives key i an entry matching its value, one no key holds or one
	// whose holder can move to another entry, and reports whether it did.
	var place func(i int) bool
	place = func(i int) bool {
		key := keys[i]
		if expanded[key] == search {
			return false
		}
		expanded[key] = search
		for _, j := range matching[key] {
			if seen[j] == search {
				continue
			}
			seen[j] = search
			if holder[j] == -1 || place(holder[j]) {
				holder[j] = i
				return true
			}
		}
		return false
	}
	for i, key := range keys {
		if accepted[i] || failed[key] {
			continue
		}
		search++
		if place(i) {
			accepted[i] = true
		} else {
			failed[key] = true
		}
	}
	return accepted, holder
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
