// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
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

// Every dependency finding is put on line 1 of its manifest, and findings were
// deduplicated on file, line and category alone, so a manifest that listed two
// known crypto libraries was reported with one of them. In a package.json, the
// library kept changed from run to run.
func TestScanReportsEveryCryptoLibraryAManifestLists(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantIDs []string
	}{
		{
			name:    "requirements.txt",
			content: "cryptography==41.0.0\npycryptodome==3.20.0\n",
			wantIDs: []string{"DEP-PyCryptodome-requirements.txt", "DEP-cryptography-requirements.txt"},
		},
		{
			name:    "package.json",
			content: `{"dependencies": {"crypto-js": "^4.2.0", "node-forge": "^1.3.1"}}` + "\n",
			wantIDs: []string{"DEP-crypto-js-package.json", "DEP-node-forge-package.json"},
		},
		{
			// Both libraries on one line, so a line number would not tell
			// them apart either.
			name:    "pyproject.toml",
			content: "[project]\ndependencies = [\"cryptography>=41.0.0\", \"pynacl>=1.5.0\"]\n",
			wantIDs: []string{"DEP-PyNaCl-pyproject.toml", "DEP-cryptography-pyproject.toml"},
		},
		{
			// circl is named on two lines and is still one finding.
			name: "go.mod",
			content: "module example.com/app\n\ngo 1.21\n\nrequire (\n" +
				"\tgithub.com/cloudflare/circl v1.3.7\n\tgithub.com/go-jose/go-jose/v4 v4.0.1\n)\n\n" +
				"replace github.com/cloudflare/circl => ../circl\n",
			wantIDs: []string{"DEP-circl-go.mod", "DEP-go-jose-go.mod"},
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
			sort.Strings(ids)
			if !reflect.DeepEqual(ids, tt.wantIDs) {
				t.Errorf("findings in %s = %q, want %q", tt.name, ids, tt.wantIDs)
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

// These files are named dependency manifests, so their lines are not
// searched, but the scanner has no reader for them. Each gave no finding and
// no notice, and was counted as scanned. They are listed as skipped and left
// out of the scanned counts, and a pom.xml and go.mod beside them are still
// read. Lock files such as Pipfile.lock are left out before this point and
// are not counted.
func TestScanListsDependencyManifestsItDoesNotRead(t *testing.T) {
	unread := map[string]string{
		"build.gradle":     "dependencies {\n    implementation 'org.bouncycastle:bcprov-jdk18on:1.77'\n}\n",
		"build.gradle.kts": "dependencies {\n    implementation(\"org.bouncycastle:bcprov-jdk18on:1.77\")\n}\n",
		"Pipfile":          "[packages]\ncryptography = \"==41.0.0\"\n",
		"go.sum":           "github.com/cloudflare/circl v1.3.7/go.mod h1:not-a-real-checksum=\n",
		"composer.json":    `{"require": {"phpseclib/phpseclib": "^3.0"}}` + "\n",
		"packages.config":  `<packages><package id="BouncyCastle.Cryptography" version="2.4.0" /></packages>` + "\n",
		"nuget.config":     "<configuration />\n",
	}
	dir := t.TempDir()
	var want []SkippedFile
	for name, content := range unread {
		want = append(want, SkippedFile{
			File:   writeTestFile(t, dir, name, content),
			Reason: "dependency manifest: the scanner does not read this format",
		})
	}
	sort.Slice(want, func(i, j int) bool { return want[i].File < want[j].File })

	results := scanWithConfig(t, Config{Target: dir})

	if !reflect.DeepEqual(results.SkippedFiles, want) {
		t.Errorf("SkippedFiles = %+v, want %+v", results.SkippedFiles, want)
	}
	if len(results.Findings) != 0 || len(results.UnanalyzedFiles) != 0 {
		t.Errorf("findings = %+v, unanalyzedFiles = %+v; want none", results.Findings, results.UnanalyzedFiles)
	}
	if results.FilesScanned != 0 || results.BytesScanned != 0 || len(results.LanguageStats) != 0 {
		t.Errorf("filesScanned = %d, bytesScanned = %d, languageStats = %v; want 0, 0 and none",
			results.FilesScanned, results.BytesScanned, results.LanguageStats)
	}
	for _, sk := range results.SkippedFiles {
		if !sk.IsUnreadManifest() {
			t.Errorf("IsUnreadManifest() = false for %+v", sk)
		}
	}

	pom := "<project><dependencies><dependency><groupId>org.bouncycastle</groupId></dependency></dependencies></project>\n"
	goMod := "module example.com/fixture\n\nrequire github.com/cloudflare/circl v1.3.7\n"
	writeTestFile(t, dir, "pom.xml", pom)
	writeTestFile(t, dir, "go.mod", goMod)

	results = scanWithConfig(t, Config{Target: dir})

	var ids []string
	for _, f := range results.Findings {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	if wantIDs := []string{"DEP-Bouncy Castle-pom.xml", "DEP-circl-go.mod"}; !reflect.DeepEqual(ids, wantIDs) {
		t.Errorf("findings = %q, want %q", ids, wantIDs)
	}
	if results.FilesScanned != 2 || results.BytesScanned != int64(len(pom)+len(goMod)) {
		t.Errorf("filesScanned = %d, bytesScanned = %d; want 2 and %d, the pom.xml and go.mod",
			results.FilesScanned, results.BytesScanned, len(pom)+len(goMod))
	}
	if !reflect.DeepEqual(results.SkippedFiles, want) {
		t.Errorf("SkippedFiles = %+v, want %+v", results.SkippedFiles, want)
	}
}

// A file skipped as minified is not a dependency manifest.
func TestIsUnreadManifestTellsAManifestFromAMinifiedFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.min.js", "var a = 1;\n")
	writeTestFile(t, dir, "build.gradle", "dependencies {\n}\n")

	results := scanWithConfig(t, Config{Target: dir})

	if len(results.SkippedFiles) != 2 {
		t.Fatalf("expected app.min.js and build.gradle listed as skipped, got %+v", results.SkippedFiles)
	}
	for _, sk := range results.SkippedFiles {
		if want := filepath.Base(sk.File) == "build.gradle"; sk.IsUnreadManifest() != want {
			t.Errorf("IsUnreadManifest() = %v for %+v, want %v", sk.IsUnreadManifest(), sk, want)
		}
	}
}

// A package.json key that matched "dependencies" or "devDependencies" only
// when case was ignored was read as that key, which npm does not do. A
// "DevDependencies" holding a string stopped the file from being decoded, so
// it was listed as not analyzed with no finding, and a list under
// "Dependencies" gave a finding for a package that `npm pkg get dependencies`
// does not list.
func TestScanReadsPackageJSONKeysAsWritten(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantIDs []string
	}{
		{
			name:    "DevDependencies holding a string",
			content: `{"name": "fixture", "version": "1.0.0", "dependencies": {"crypto-js": "^4.2.0"}, "DevDependencies": "none"}` + "\n",
			wantIDs: []string{"DEP-crypto-js-package.json"},
		},
		{
			name:    "Dependencies only",
			content: `{"name": "fixture", "version": "1.0.0", "Dependencies": {"crypto-js": "^4.2.0"}}` + "\n",
			wantIDs: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "package.json", tt.content)

			results := scanWithConfig(t, Config{Target: dir})

			var ids []string
			for _, f := range results.Findings {
				ids = append(ids, f.ID)
			}
			if !reflect.DeepEqual(ids, tt.wantIDs) {
				t.Errorf("findings = %q, want %q", ids, tt.wantIDs)
			}
			if results.FilesScanned != 1 || len(results.UnanalyzedFiles) != 0 {
				t.Errorf("filesScanned = %d, unanalyzedFiles = %+v; want 1 and none",
					results.FilesScanned, results.UnanalyzedFiles)
			}
		})
	}
}
