// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/patterns"
	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/types"
)

// cryptoJSManifest is a package.json that lists one library the dependency
// reader knows, crypto-js, whose finding is reported at medium severity.
const cryptoJSManifest = `{"name": "fixture", "dependencies": {"crypto-js": "^4.2.0"}}`

// Every JSON finding carries patternId, the ID of the pattern that raised it:
// for a match, an ID that patterns list prints, which the finding's id
// follows with its line and the match's offset; for a dependency, DEP- and
// the name of a library the dependency reader knows, which the finding's id
// follows with the manifest's file name. The trust fixture's certificates
// are matches too.
func TestJSONFindingsCarryPatternID(t *testing.T) {
	dir := t.TempDir()
	writeReviewedTree(t, dir, reviewedApp)
	writeFixtureFile(t, filepath.Join(dir, "package.json"), cryptoJSManifest)

	listed := map[string]bool{}
	for _, p := range patterns.NewMatcher().Patterns() {
		listed[p.ID] = true
	}
	libraries := map[string]bool{}
	for _, lib := range analyzer.KnownCryptoLibraries {
		libraries["DEP-"+lib.Name] = true
	}
	location := regexp.MustCompile(`^-[0-9]+-[0-9]+$`)

	for _, target := range []string{dir, trustFixture} {
		out := runScanWith(t, target, "--stream=false", "--no-config", "--format", "json")
		if out.err != "" {
			t.Fatalf("scan %s --format json: exit %d, error %q", target, out.code, out.err)
		}
		var report struct {
			Findings []map[string]any `json:"findings"`
		}
		if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
			t.Fatalf("scan %s printed output that is not JSON: %v", target, err)
		}
		if len(report.Findings) == 0 {
			t.Fatalf("scan %s reported no findings", target)
		}
		kinds := map[string]int{}
		for _, f := range report.Findings {
			id, _ := f["id"].(string)
			file, _ := f["file"].(string)
			patternID, ok := f["patternId"].(string)
			if !ok || patternID == "" {
				t.Errorf("%s: finding %s has patternId %#v, want the ID of its pattern", target, id, f["patternId"])
				continue
			}
			if f["findingType"] == "dependency" {
				kinds["dependency"]++
				if !libraries[patternID] {
					t.Errorf("%s: dependency finding %s has patternId %q, which names no known library", target, id, patternID)
				}
				if want := patternID + "-" + filepath.Base(file); id != want {
					t.Errorf("%s: dependency finding id %q, want %q", target, id, want)
				}
				continue
			}
			kinds["match"]++
			if !listed[patternID] {
				t.Errorf("%s: finding %s has patternId %q, which patterns list does not print", target, id, patternID)
			}
			if len(id) <= len(patternID) || id[:len(patternID)] != patternID || !location.MatchString(id[len(patternID):]) {
				t.Errorf("%s: finding id %q is not its patternId %q followed by a line and offset", target, id, patternID)
			}
		}
		if target == dir && (kinds["dependency"] == 0 || kinds["match"] == 0) {
			t.Errorf("%s gave %v; the check needs a match and a dependency finding", target, kinds)
		}
	}
}

// rewriteBaseline applies edit to each finding of the JSON baseline at path.
func rewriteBaseline(t *testing.T, path string, edit func(i int, finding map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("baseline is not JSON: %v", err)
	}
	findings, _ := report["findings"].([]any)
	for i, f := range findings {
		finding, ok := f.(map[string]any)
		if !ok {
			t.Fatalf("baseline finding %d is %T, want an object", i, f)
		}
		edit(i, finding)
	}
	if data, err = json.Marshal(report); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The baseline matches a finding by the patternId its report records, not by
// a pattern ID read back out of the finding's id: with every id in the
// baseline replaced by a value that names no pattern, the same tree reports
// nothing new.
func TestBaselineReadsPatternIDWhenPresent(t *testing.T) {
	dir := t.TempDir()
	writeReviewedTree(t, dir, reviewedApp)
	baseline := writeBaseline(t, dir)

	rewriteBaseline(t, baseline, func(i int, f map[string]any) {
		if id, _ := f["patternId"].(string); id == "" {
			t.Fatalf("baseline finding %v has patternId %#v, want the ID of its pattern", f["id"], f["patternId"])
		}
		f["id"] = fmt.Sprintf("reviewed-%d", i)
	})

	if got := scanTree(t, dir, baseline, filepath.Join(t.TempDir(), "out.json")); len(got) != 0 {
		t.Errorf("a baseline whose findings record their patternId should leave 0 new findings, got %d:\n  %s",
			len(got), describe(got))
	}
}

// A baseline written before findings carried patternId still matches: its
// pattern IDs are read from each finding's id, without the line and offset a
// match adds, and without the manifest file name a dependency finding adds,
// so the crypto-js finding in package.json is matched too.
func TestBaselineWithoutPatternIDStillFilters(t *testing.T) {
	dir := t.TempDir()
	writeReviewedTree(t, dir, reviewedApp)
	writeFixtureFile(t, filepath.Join(dir, "package.json"), cryptoJSManifest)
	baseline := writeBaseline(t, dir)

	dependencies := 0
	rewriteBaseline(t, baseline, func(_ int, f map[string]any) {
		delete(f, "patternId")
		if f["findingType"] == "dependency" {
			dependencies++
		}
	})
	if dependencies == 0 {
		t.Fatal("the baseline holds no dependency finding, so the check does not read a dependency finding's id")
	}

	if got := scanTree(t, dir, baseline, filepath.Join(t.TempDir(), "out.json")); len(got) != 0 {
		t.Errorf("a baseline without patternId should leave 0 new findings, got %d:\n  %s",
			len(got), describe(got))
	}
}

// The baseline key's pattern ID is the finding's patternId when its report
// records one. Otherwise it is read from the finding's ID as every earlier
// release built it: a match's ID without its line and offset, a dependency's
// ID without the manifest's file name, and an ID with a hash suffix without
// the hash. Only a dependency finding loses its file name.
func TestBaselinePatternIDOfEachFindingForm(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    scanner.Finding
		want string
	}{
		{"recorded", scanner.Finding{ID: "reviewed-1", PatternID: "SHA1-001", Line: 5, File: "/repo/src/app.py"}, "SHA1-001"},
		{"match", scanner.Finding{ID: "SHA1-001-5-11", Line: 5, File: "/repo/src/app.py"}, "SHA1-001"},
		{"dependency", scanner.Finding{ID: "DEP-crypto-js-package.json", FindingType: types.FindingTypeDependency, Line: 1, File: "/repo/package.json"}, "DEP-crypto-js"},
		{"dependency whose library name has a space", scanner.Finding{ID: "DEP-Bouncy Castle-pom.xml", FindingType: types.FindingTypeDependency, Line: 1, File: "/repo/pom.xml"}, "DEP-Bouncy Castle"},
		{"hash suffix", scanner.Finding{ID: "RSA-001-a1b2c3d4", Line: 7, File: "/repo/rsa.py"}, "RSA-001"},
		{"match whose ID ends in its file name", scanner.Finding{ID: "MD5-001-3-4", Line: 3, File: "/repo/4"}, "MD5-001"},
	} {
		if got := patternID(tc.f); got != tc.want {
			t.Errorf("%s: patternID(%q) = %q, want %q", tc.name, tc.f.ID, got, tc.want)
		}
	}
}
