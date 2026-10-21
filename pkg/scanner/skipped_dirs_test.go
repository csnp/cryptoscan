// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// findingFiles returns the slash-separated paths, relative to root, of the
// files results has findings in, in path order.
func findingFiles(t *testing.T, root string, results *Results) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, f := range results.Findings {
		rel, err := filepath.Rel(root, f.File)
		if err != nil {
			t.Fatal(err)
		}
		seen[filepath.ToSlash(rel)] = true
	}
	files := make([]string, 0, len(seen))
	for f := range seen {
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}

// The directories the default rules leave out used to be left out without a
// word: the results said how many files were scanned and nothing about the
// ones that were not. Each one is now listed with the rule that matched it
// and the number of files in it, and IncludeSkipped scans them.
func TestScanCountsTheDirectoriesTheDefaultRulesSkip(t *testing.T) {
	skipped := []string{
		".git/hooks/a.py",       // version control
		"examples/a.py",         // examples
		"fixtures/a.py",         // test data
		"testdata/a.py",         // test data
		"node_modules/pkg/a.py", // installed dependencies
		"vendor/mod/a.py",       // DefaultExcludeGlobs: vendor/*
		"web/dist/a.py",         // build output below the top level
	}
	root := writeRSATree(t, append([]string{"src/a.py"}, skipped...)...)

	results := scanWithConfig(t, Config{Target: root, DefaultExcludes: DefaultExcludeGlobs})
	want := SkippedDirectories{
		Files:       7,
		Directories: 7,
		Rules:       []string{".git", "dist", "examples", "fixtures", "node_modules", "testdata", "vendor"},
		Paths:       []string{".git", "examples", "fixtures", "node_modules", "testdata", "vendor", "web/dist"},
	}
	if !reflect.DeepEqual(results.Skipped, want) {
		t.Errorf("Skipped = %+v, want %+v", results.Skipped, want)
	}
	if results.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1 (src/a.py)", results.FilesScanned)
	}
	if got := findingFiles(t, root, results); !reflect.DeepEqual(got, []string{"src/a.py"}) {
		t.Errorf("findings in %q, want src/a.py only", got)
	}

	all := scanWithConfig(t, Config{Target: root, DefaultExcludes: DefaultExcludeGlobs, IncludeSkipped: true})
	none := SkippedDirectories{Rules: []string{}, Paths: []string{}}
	if !reflect.DeepEqual(all.Skipped, none) {
		t.Errorf("with IncludeSkipped, Skipped = %+v, want %+v", all.Skipped, none)
	}
	if all.FilesScanned != 1+len(skipped) {
		t.Errorf("with IncludeSkipped, FilesScanned = %d, want %d", all.FilesScanned, 1+len(skipped))
	}
	got := findingFiles(t, root, all)
	for _, rel := range []string{"src/a.py", "examples/a.py", "fixtures/a.py", "testdata/a.py"} {
		if !slices.Contains(got, rel) {
			t.Errorf("with IncludeSkipped, no finding in %s; findings in %q", rel, got)
		}
	}
}

// A default pattern that names files still applies with IncludeSkipped; only
// the ones that name a directory and everything in it are lifted.
func TestIncludeSkippedKeepsDefaultFilePatterns(t *testing.T) {
	root := writeRSATree(t, "src/a.py", "src/b_gen.py", "vendor/c.py")
	defaults := []string{"vendor/*", "*_gen.py"}

	results := scanWithConfig(t, Config{Target: root, DefaultExcludes: defaults})
	want := SkippedDirectories{Files: 1, Directories: 1, Rules: []string{"vendor"}, Paths: []string{"vendor"}}
	if !reflect.DeepEqual(results.Skipped, want) {
		t.Errorf("Skipped = %+v, want %+v", results.Skipped, want)
	}

	all := scanWithConfig(t, Config{Target: root, DefaultExcludes: defaults, IncludeSkipped: true})
	if got := findingFiles(t, root, all); !reflect.DeepEqual(got, []string{"src/a.py", "vendor/c.py"}) {
		t.Errorf("with IncludeSkipped, findings in %q, want src/a.py and vendor/c.py", got)
	}
}

// A directory is counted only when the default rules are what keeps it out.
// One that the user's exclude patterns or the config file name, or that the
// depth limit keeps out, would stay out with IncludeSkipped too, and files
// below the depth limit would not be read either.
func TestSkippedDirectoriesLeaveOutWhatOtherRulesKeepOut(t *testing.T) {
	root := writeRSATree(t,
		"src/d.py",
		"examples/a.py",         // the user's --exclude names it
		"testdata/a.py",         // the config file's ignore.files names it
		"fixtures/a.py",         // counted
		"fixtures/deep/b.py",    // below the depth limit
		"src/node_modules/c.py", // at the depth limit
	)

	results := scanWithConfig(t, Config{
		Target:       root,
		ExcludeGlobs: []string{"examples"},
		ConfigFile:   &ConfigFileRules{IgnoreFiles: []string{"testdata/*"}},
		MaxDepth:     2,
	})
	want := SkippedDirectories{Files: 1, Directories: 1, Rules: []string{"fixtures"}, Paths: []string{"fixtures"}}
	if !reflect.DeepEqual(results.Skipped, want) {
		t.Errorf("Skipped = %+v, want %+v", results.Skipped, want)
	}
}

// The scan root is never skipped by the default rules, whatever it is called,
// so scanning a directory named examples counts nothing as skipped.
func TestScanRootIsNotCountedAsSkipped(t *testing.T) {
	root := writeRSATree(t, "examples/a.py")

	results := scanWithConfig(t, Config{Target: filepath.Join(root, "examples"), DefaultExcludes: DefaultExcludeGlobs})
	if results.FilesScanned != 1 || results.Skipped.Directories != 0 || results.Skipped.Files != 0 {
		t.Errorf("FilesScanned = %d, Skipped = %+v, want 1 file scanned and nothing skipped",
			results.FilesScanned, results.Skipped)
	}
}

// JSON always carries the skipped object, with zeros and empty arrays when
// nothing was skipped, so that a reader can tell "nothing skipped" from an
// older report without the field.
func TestSkippedDirectoriesAreAlwaysWritten(t *testing.T) {
	clean := t.TempDir()
	writeTestFile(t, clean, "main.go", "package main\n")
	data, err := json.Marshal(scanWithConfig(t, Config{Target: clean, DefaultExcludes: DefaultExcludeGlobs}))
	if err != nil {
		t.Fatal(err)
	}
	if want := `"skipped":{"files":0,"directories":0,"rules":[],"paths":[]}`; !strings.Contains(string(data), want) {
		t.Errorf("expected %s in JSON, got %s", want, data)
	}
}
