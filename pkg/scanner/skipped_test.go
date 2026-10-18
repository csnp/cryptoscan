// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// bundledLine is one line of bundled JavaScript that calls MD5. It is longer
// than the 200-byte average above which a file counts as minified, and
// shorter than the 1000 bytes above which a line is passed over on its own.
func bundledLine() string {
	return `"use strict";var crypto=require("crypto");function digest(p){return crypto.createHash("md5").update(String(p)).digest("hex")}` +
		strings.Repeat(`function key(k){return "cache:"+k+":v1"}`, 10)
}

// The reproduction from the report: a file holding one long line with an MD5
// call was counted as scanned and gave no finding and no word that it had been
// skipped.
func TestScanListsMinifiedFileAsSkipped(t *testing.T) {
	dir := t.TempDir()
	line := bundledLine()
	path := writeTestFile(t, dir, "app.js", line+"\n")

	results := scanWithConfig(t, Config{Target: dir})

	if len(results.Findings) != 0 {
		t.Errorf("expected no findings from a skipped file, got %+v", results.Findings)
	}
	want := []SkippedFile{{
		File:   path,
		Reason: fmt.Sprintf("minified or generated: its lines average %d bytes", len(line)),
	}}
	if !reflect.DeepEqual(results.SkippedFiles, want) {
		t.Errorf("SkippedFiles = %+v, want %+v", results.SkippedFiles, want)
	}

	// The same call on a line of ordinary length is found, so the skip is
	// what kept it out of the report.
	writeTestFile(t, dir, "app.js", `const h = crypto.createHash("md5");`+"\n")
	if results := scanWithConfig(t, Config{Target: dir}); len(results.Findings) == 0 || len(results.SkippedFiles) != 0 {
		t.Errorf("expected the MD5 call to be found in an unminified file and nothing skipped, got %d findings and %+v",
			len(results.Findings), results.SkippedFiles)
	}
}

// A file whose name marks it as minified is left out before it is read, and
// is listed with the suffix that marked it, with the scan command's default
// excludes in place, and when the file is the scan target itself.
func TestScanListsMinifiedFileNameAsSkipped(t *testing.T) {
	for _, name := range []string{"app.min.js", "site.min.css", "app-min.js", "site-min.css", "APP.MIN.JS"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTestFile(t, dir, name, `const h = crypto.createHash("md5");`+"\n")
			suffix := name[strings.IndexAny(name, ".-"):]
			want := []SkippedFile{{File: path, Reason: "minified: the file name ends in " + strings.ToLower(suffix)}}

			for _, target := range []string{dir, path} {
				results := scanWithConfig(t, Config{Target: target, ExcludeGlobs: DefaultExcludeGlobs})
				if !reflect.DeepEqual(results.SkippedFiles, want) {
					t.Errorf("scan %s: SkippedFiles = %+v, want %+v", target, results.SkippedFiles, want)
				}
				if len(results.Findings) != 0 {
					t.Errorf("scan %s: expected no findings, got %+v", target, results.Findings)
				}
			}
		})
	}
}

// A minified file that another rule keeps out of the scan is not listed: the
// list names what the minified rule alone left out.
func TestSkippedFilesLeaveOutFilesOtherRulesExclude(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"docs", "node_modules"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, dir, filepath.Join("docs", "guide.min.js"), "var a = 1;\n")
	writeTestFile(t, dir, filepath.Join("docs", "bundle.js"), bundledLine()+"\n")
	writeTestFile(t, dir, filepath.Join("node_modules", "lib.min.js"), "var a = 1;\n")
	writeTestFile(t, dir, "main.go", "package main\n")
	writeTestFile(t, dir, "app.min.js", "var a = 1;\n")

	// --include *.go would not have scanned app.min.js either.
	results := scanWithConfig(t, Config{Target: dir, ExcludeGlobs: DefaultExcludeGlobs, IncludeGlobs: []string{"*.go"}})
	if len(results.SkippedFiles) != 0 {
		t.Errorf("with --include *.go, expected nothing listed as skipped, got %+v", results.SkippedFiles)
	}

	// Without it, only the file at the top is listed: documentation is not
	// scanned by default, and node_modules is never walked.
	results = scanWithConfig(t, Config{Target: dir, ExcludeGlobs: DefaultExcludeGlobs})
	want := []SkippedFile{{File: filepath.Join(dir, "app.min.js"), Reason: "minified: the file name ends in .min.js"}}
	if !reflect.DeepEqual(results.SkippedFiles, want) {
		t.Errorf("SkippedFiles = %+v, want %+v", results.SkippedFiles, want)
	}
}

// A line of 1 MB or more is longer than the scanner reads. The file used to be
// counted as scanned and dropped without a word, like a minified one.
func TestScanListsFileWithLineTooLongToReadAsSkipped(t *testing.T) {
	const limit = 1 << 20 // the scanner's line limit, 1 MB

	dir := t.TempDir()
	tooLong := writeTestFile(t, dir, "bundle.js", strings.Repeat("a", limit)+"\n")
	longest := writeTestFile(t, dir, "longest.js", strings.Repeat("a", limit-1)+"\n")

	results := scanWithConfig(t, Config{Target: dir})

	want := []SkippedFile{
		{File: tooLong, Reason: "minified or generated: a line is 1 MB or longer"},
		{File: longest, Reason: fmt.Sprintf("minified or generated: its lines average %d bytes", limit-1)},
	}
	if !reflect.DeepEqual(results.SkippedFiles, want) {
		t.Errorf("SkippedFiles = %+v, want %+v", results.SkippedFiles, want)
	}
}

// Files are scanned in parallel, so the list is sorted to keep the report the
// same from run to run, and JSON always carries it, as an empty array when
// nothing was skipped.
func TestSkippedFilesAreSortedAndAlwaysWritten(t *testing.T) {
	dir := t.TempDir()
	var want []SkippedFile
	for _, name := range []string{"e.js", "a.js", "d.js", "b.js", "c.js"} {
		writeTestFile(t, dir, name, bundledLine()+"\n")
	}
	for _, name := range []string{"a.js", "b.js", "c.js", "d.js", "e.js"} {
		want = append(want, SkippedFile{
			File:   filepath.Join(dir, name),
			Reason: fmt.Sprintf("minified or generated: its lines average %d bytes", len(bundledLine())),
		})
	}
	for run := 0; run < 5; run++ {
		results := scanWithConfig(t, Config{Target: dir})
		if !reflect.DeepEqual(results.SkippedFiles, want) {
			t.Fatalf("run %d: SkippedFiles = %+v, want %+v", run, results.SkippedFiles, want)
		}
	}

	clean := t.TempDir()
	writeTestFile(t, clean, "main.go", "package main\n")
	data, err := json.Marshal(scanWithConfig(t, Config{Target: clean}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"skippedFiles":[]`) {
		t.Errorf("expected an empty skippedFiles array in JSON, got %s", data)
	}
}
