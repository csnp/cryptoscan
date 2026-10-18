// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// utf8BOM is the UTF-8 byte order mark, the bytes EF BB BF.
const utf8BOM = "\xef\xbb\xbf"

// A package.json saved with a byte order mark, which npm reads, failed to
// decode and gave no finding while the scan counted it as scanned. The first
// line of a requirements.txt saved with one did not match a package name.
func TestScanReadsDependencyManifestsThatStartWithAByteOrderMark(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantID  string
	}{
		{
			name:    "package.json",
			content: utf8BOM + `{"name": "fixture", "version": "1.0.0", "dependencies": {"crypto-js": "^4.2.0"}}` + "\n",
			wantID:  "DEP-crypto-js-package.json",
		},
		{
			name:    "requirements.txt",
			content: utf8BOM + "cryptography==41.0.0\n",
			wantID:  "DEP-cryptography-requirements.txt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTestFile(t, dir, tt.name, tt.content)

			results := scanWithConfig(t, Config{Target: dir})

			var ids []string
			for _, f := range results.Findings {
				if f.File == path {
					ids = append(ids, f.ID)
				}
			}
			if want := []string{tt.wantID}; !reflect.DeepEqual(ids, want) {
				t.Errorf("findings in %s = %q, want %q", tt.name, ids, want)
			}
			if results.FilesScanned != 1 || len(results.UnanalyzedFiles) != 0 {
				t.Errorf("filesScanned = %d, unanalyzedFiles = %+v; want 1 and none",
					results.FilesScanned, results.UnanalyzedFiles)
			}
		})
	}
}

// A package.json that could not be decoded gave no finding and no notice,
// and was counted as scanned. It is listed as not analyzed, with the line
// where decoding stopped, and left out of the scanned counts, while a
// manifest next to it that decodes is still reported.
func TestScanListsPackageJSONThatCannotBeDecoded(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"bad", "good"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The comma after the last dependency leaves the closing brace on line 4
	// where a key is expected.
	badPath := writeTestFile(t, dir, filepath.Join("bad", "package.json"),
		"{\n  \"dependencies\": {\n    \"crypto-js\": \"^4.2.0\",\n  }\n}\n")
	good := `{"dependencies": {"crypto-js": "^4.2.0"}}` + "\n"
	goodPath := writeTestFile(t, dir, filepath.Join("good", "package.json"), good)

	results := scanWithConfig(t, Config{Target: dir})

	if len(results.UnanalyzedFiles) != 1 {
		t.Fatalf("expected %s to be listed as not analyzed, got %+v", badPath, results.UnanalyzedFiles)
	}
	u := results.UnanalyzedFiles[0]
	if u.File != badPath || u.Line != 4 || !strings.HasPrefix(u.Reason, "not valid JSON: ") {
		t.Errorf("unanalyzed file = %+v, want %s at line 4 with a reason starting %q",
			u, badPath, "not valid JSON: ")
	}

	var ids []string
	for _, f := range results.Findings {
		ids = append(ids, f.ID+" "+f.File)
	}
	if want := []string{"DEP-crypto-js-package.json " + goodPath}; !reflect.DeepEqual(ids, want) {
		t.Errorf("findings = %q, want %q", ids, want)
	}

	if results.FilesScanned != 1 || results.BytesScanned != int64(len(good)) {
		t.Errorf("filesScanned = %d, bytesScanned = %d; want 1 and %d, the manifest that decoded",
			results.FilesScanned, results.BytesScanned, len(good))
	}
}

// The text report asks for an internal error to be reported as a scanner
// defect, and tells one from a manifest that could not be decoded with
// IsInternalError. Both entries here come from a real scan.
func TestIsInternalErrorTellsAScannerDefectFromAManifest(t *testing.T) {
	dir := t.TempDir()
	goPath := writeTestFile(t, dir, "bad.go", "package main\nkey, _ := rsa.GenerateKey(rand.Reader, 2048)\n")
	manifestPath := writeTestFile(t, dir, "package.json", `{"dependencies": {`+"\n")

	results := scanWithConfig(t, Config{
		Target: dir,
		OnFinding: func(f Finding) {
			if f.File == goPath {
				panic("simulated analyzer failure")
			}
		},
	})

	if len(results.UnanalyzedFiles) != 2 {
		t.Fatalf("expected %s and %s listed as not analyzed, got %+v", goPath, manifestPath, results.UnanalyzedFiles)
	}
	for _, u := range results.UnanalyzedFiles {
		if want := u.File == goPath; u.IsInternalError() != want {
			t.Errorf("IsInternalError() = %v for %+v, want %v", u.IsInternalError(), u, want)
		}
	}
}
