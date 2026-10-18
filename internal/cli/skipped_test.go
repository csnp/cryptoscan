// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

func TestWriteSkippedNotice(t *testing.T) {
	files := []scanner.SkippedFile{
		{File: "/src/app.js", Reason: "minified or generated: its lines average 674 bytes"},
		{File: "/src/app.min.js", Reason: "minified: the file name ends in .min.js"},
	}

	for _, format := range []string{"json", "sarif", "csv", "cbom"} {
		var buf bytes.Buffer
		writeSkippedNotice(&buf, format, files)
		want := "cryptoscan: 2 file(s) were not scanned, so cryptography in them is not in this report:\n" +
			"  /src/app.js  minified or generated: its lines average 674 bytes\n" +
			"  /src/app.min.js  minified: the file name ends in .min.js\n"
		if got := buf.String(); got != want {
			t.Errorf("%s: notice = %q, want %q", format, got, want)
		}
	}

	// The text report lists the files itself, and a scan with none says nothing.
	var buf bytes.Buffer
	writeSkippedNotice(&buf, "text", files)
	writeSkippedNotice(&buf, "json", nil)
	if buf.Len() != 0 {
		t.Errorf("expected no notice, got %q", buf.String())
	}

	// Ten files are named, and the rest counted.
	var many []scanner.SkippedFile
	for i := 0; i < 11; i++ {
		many = append(many, scanner.SkippedFile{File: fmt.Sprintf("/src/f%02d.min.js", i), Reason: "minified: the file name ends in .min.js"})
	}
	buf.Reset()
	writeSkippedNotice(&buf, "sarif", many)
	got := buf.String()
	if n := strings.Count(got, "/src/f"); n != 10 {
		t.Errorf("notice names %d files, want 10:\n%s", n, got)
	}
	if !strings.HasSuffix(got, "  and 1 more, listed under skippedFiles in --format json\n") {
		t.Errorf("notice does not count the eleventh file:\n%s", got)
	}
}

// The reproduction from the report, through the scan command: one long line
// calling MD5 in app.js, and a minified app.min.js. Both are now named in the
// JSON report and on stderr, and, as before, they do not fail the scan.
func TestScanListsSkippedFilesWithoutChangingTheExitCode(t *testing.T) {
	saved := jsonPretty
	t.Cleanup(func() { jsonPretty = saved })

	dir := t.TempDir()
	line := `"use strict";var crypto=require("crypto");function digest(p){return crypto.createHash("md5").update(String(p)).digest("hex")}` +
		strings.Repeat(`function key(k){return "cache:"+k+":v1"}`, 10)
	for name, content := range map[string]string{"app.js": line + "\n", "app.min.js": line + "\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "report.json")

	resetPipelineFlags(t)
	outputFormat = "json"
	outputFile = out
	failOn = "low"
	jsonPretty = false

	var code int
	stderr := captureStderr(func() {
		var err error
		code, err = scanTarget(scanCmd, dir)
		if err != nil {
			t.Errorf("scan failed: %v", err)
		}
	})
	if code != 0 {
		t.Errorf("exit code = %d with --fail-on low, want 0: a skipped file does not fail the scan", code)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report written: %v", err)
	}
	var report scanner.Results
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}
	want := []scanner.SkippedFile{
		{File: filepath.Join(dir, "app.js"), Reason: fmt.Sprintf("minified or generated: its lines average %d bytes", len(line))},
		{File: filepath.Join(dir, "app.min.js"), Reason: "minified: the file name ends in .min.js"},
	}
	// The command resolves the target to an absolute path, as t.TempDir is.
	if !reflect.DeepEqual(report.SkippedFiles, want) {
		t.Errorf("skippedFiles = %+v, want %+v", report.SkippedFiles, want)
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(report.Findings))
	}
	for _, sk := range want {
		if !strings.Contains(stderr, "  "+sk.File+"  "+sk.Reason+"\n") {
			t.Errorf("stderr does not name %s:\n%s", sk.File, stderr)
		}
	}
}
