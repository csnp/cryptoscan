// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

// configFixture writes a small tree with operational RSA, a key size, an MD5
// call and an MD5 mention in a log message, so that ignore patterns,
// categories, minSeverity and the narrative filter all have something to act
// on.
func configFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "app.py"), `from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
digest = hashlib.md5(b"data").hexdigest()
log.info("falling back to md5 for legacy peers")
`)
	return dir
}

func scanWith(t *testing.T, cfg Config) *Results {
	t.Helper()
	results, err := New(cfg).Scan()
	if err != nil {
		t.Fatalf("scan %s: %v", cfg.Target, err)
	}
	return results
}

func findingIDs(results *Results) []string {
	ids := make([]string, 0, len(results.Findings))
	for _, f := range results.Findings {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	return ids
}

// TestConfigFileRulesAreCountedAndChangeNothingElse pins two properties. A
// rule read from a config file removes exactly the findings the same rule
// removes when given on the command line, so counting them separately changes
// no verdict. And the count the report gives is exactly what scanning without
// the file adds back, so the number a reader sees can be reproduced with
// --no-config.
func TestConfigFileRulesAreCountedAndChangeNothingElse(t *testing.T) {
	dir := configFixture(t)
	base := scanWith(t, Config{Target: dir, MinSeverity: types.SeverityInfo})
	if len(base.Findings) < 3 {
		t.Fatalf("fixture produced %d findings, want at least 3: %v", len(base.Findings), findingIDs(base))
	}
	if base.Config != nil {
		t.Fatalf("a scan without a config file reported one: %+v", base.Config)
	}

	cases := []struct {
		name    string
		cli     Config
		rules   ConfigFileRules
		removed func(ConfigFindingsRemoved) int
	}{
		{
			name:    "every pattern",
			cli:     Config{IgnoreIDs: []string{"*"}},
			rules:   ConfigFileRules{IgnoreIDs: []string{"*"}},
			removed: func(r ConfigFindingsRemoved) int { return r.IgnorePatterns },
		},
		{
			name:    "one pattern family",
			cli:     Config{IgnoreIDs: []string{"RSA-*"}},
			rules:   ConfigFileRules{IgnoreIDs: []string{"RSA-*"}},
			removed: func(r ConfigFindingsRemoved) int { return r.IgnorePatterns },
		},
		{
			name:    "one category",
			cli:     Config{IgnoreCategories: []string{"Configuration"}},
			rules:   ConfigFileRules{IgnoreCategories: []string{"Configuration"}},
			removed: func(r ConfigFindingsRemoved) int { return r.IgnoreCategories },
		},
		{
			name:    "minimum severity",
			cli:     Config{MinSeverity: types.SeverityHigh},
			rules:   ConfigFileRules{MinSeverity: types.SeverityHigh, HasMinSeverity: true},
			removed: func(r ConfigFindingsRemoved) int { return r.MinSeverity },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli := tc.cli
			cli.Target = dir
			viaFlags := scanWith(t, cli)

			rules := tc.rules
			rules.Path = filepath.Join(dir, ".cryptoscan.yaml")
			rules.Source = ConfigSourceScanTarget
			viaFile := scanWith(t, Config{Target: dir, MinSeverity: types.SeverityInfo, ConfigFile: &rules})

			if got, want := findingIDs(viaFile), findingIDs(viaFlags); !reflect.DeepEqual(got, want) {
				t.Fatalf("config file reported %v, the same rule as a flag reported %v", got, want)
			}
			if got, want := viaFile.Summary.NarrativeSuppressed, viaFlags.Summary.NarrativeSuppressed; got != want {
				t.Errorf("narrative count %d with the config file, %d with the flag", got, want)
			}

			c := viaFile.Config
			if c == nil {
				t.Fatal("results carry no config report")
			}
			if c.Path != rules.Path || c.Source != ConfigSourceScanTarget {
				t.Errorf("config report names %q (%s), want %q (%s)", c.Path, c.Source, rules.Path, ConfigSourceScanTarget)
			}
			want := len(base.Findings) - len(viaFile.Findings)
			if want == 0 {
				t.Fatal("the rule removed nothing; the fixture no longer exercises it")
			}
			if got := tc.removed(c.FindingsRemoved); got != want {
				t.Errorf("setting counted %d removed, scanning without the file adds %d", got, want)
			}
			if c.FindingsRemoved.Total != want {
				t.Errorf("total removed %d, want %d", c.FindingsRemoved.Total, want)
			}
		})
	}
}

// TestConfigRemovalIsCountedOnceAgainstTheFirstSetting checks that a finding
// matched by both a pattern and a category is counted once, under
// ignore.patterns, so the per-setting counts add up to the total.
func TestConfigRemovalIsCountedOnceAgainstTheFirstSetting(t *testing.T) {
	dir := configFixture(t)
	base := scanWith(t, Config{Target: dir, MinSeverity: types.SeverityInfo})
	rules := ConfigFileRules{
		IgnoreIDs:        []string{"RSA-*"},
		IgnoreCategories: []string{"Asymmetric Encryption"},
	}
	results := scanWith(t, Config{Target: dir, MinSeverity: types.SeverityInfo, ConfigFile: &rules})

	r := results.Config.FindingsRemoved
	if r.IgnorePatterns == 0 {
		t.Fatalf("ignore.patterns removed nothing; the fixture no longer has RSA findings: %v", findingIDs(base))
	}
	if r.IgnoreCategories != 0 {
		t.Errorf("ignore.categories counted %d findings that ignore.patterns already removed", r.IgnoreCategories)
	}
	if got, want := r.Total, len(base.Findings)-len(results.Findings); got != want {
		t.Errorf("total removed %d, scanning without the file adds %d", got, want)
	}
}

// TestConfigIgnoreFilesCountsSkippedPaths checks that ignore.files reports the
// files and directories it kept out of the scan, and does not count a file
// that a command-line exclude had already removed.
func TestConfigIgnoreFilesCountsSkippedPaths(t *testing.T) {
	dir := t.TempDir()
	code := "import hashlib\ndigest = hashlib.md5(b\"data\").hexdigest()\n"
	write(t, filepath.Join(dir, "a.py"), code)
	write(t, filepath.Join(dir, "c.py"), code)
	if err := os.Mkdir(filepath.Join(dir, "gen"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "gen", "b.py"), code)

	rules := ConfigFileRules{IgnoreFiles: []string{"a.py", "c.py", "gen"}}
	results := scanWith(t, Config{
		Target:       dir,
		MinSeverity:  types.SeverityInfo,
		ExcludeGlobs: []string{"c.py"},
		ConfigFile:   &rules,
	})

	if len(results.Findings) != 0 {
		t.Errorf("skipped files still produced findings: %v", findingIDs(results))
	}
	want := ConfigPathsSkipped{Files: 1, Directories: 1}
	if got := results.Config.PathsSkipped; got != want {
		t.Errorf("paths skipped = %+v, want %+v", got, want)
	}
	if !results.Config.Any() {
		t.Error("Any() is false for a config file that kept paths out of the scan")
	}
}

// TestConfigReportInJSON checks the field names the JSON report carries, and
// that a scan without a config file has no config object at all.
func TestConfigReportInJSON(t *testing.T) {
	dir := configFixture(t)
	rules := ConfigFileRules{
		Path:      "/repo/.cryptoscan.yaml",
		Source:    ConfigSourceParentDirectory,
		IgnoreIDs: []string{"*"},
	}
	data, err := json.Marshal(scanWith(t, Config{Target: dir, MinSeverity: types.SeverityInfo, ConfigFile: &rules}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"config":{"path":"/repo/.cryptoscan.yaml","source":"parentDirectory"`,
		`"findingsRemoved":{"ignorePatterns":`,
		`"pathsSkipped":{"files":0,"directories":0}`,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("JSON report lacks %s", want)
		}
	}

	plain, err := json.Marshal(scanWith(t, Config{Target: dir, MinSeverity: types.SeverityInfo}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), `"config":{`) {
		t.Error("a scan without a config file has a config object in its JSON report")
	}
}
