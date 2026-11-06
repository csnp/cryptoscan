// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

// depFindingID is the ID of the finding a package.json that depends on
// crypto-js gives. Its pattern ID is DEP-crypto-js.
const depFindingID = "DEP-crypto-js-package.json"

// dependencyRuleFixture writes a package.json that depends on crypto-js, and
// checks that a scan with no rules reports it as the only finding, MEDIUM and
// in the dependency category, so each rule tested below has that finding to
// act on.
func dependencyRuleFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "package.json", `{"name": "fixture", "dependencies": {"crypto-js": "^4.2.0"}}`+"\n")

	results := scanWithConfig(t, Config{Target: dir})
	if got, want := findingIDs(results), []string{depFindingID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fixture findings = %q, want %q", got, want)
	}
	f := results.Findings[0]
	if f.PatternID != "DEP-crypto-js" || f.Severity != types.SeverityMedium || f.Category != dependencyCategory {
		t.Fatalf("fixture finding has pattern %q, severity %s, category %q; want DEP-crypto-js, MEDIUM, %q",
			f.PatternID, f.Severity, f.Category, dependencyCategory)
	}
	return dir
}

// dependencyRuleCase is a rule given once on the command line and once in a
// config file.
type dependencyRuleCase struct {
	name  string
	cli   Config
	rules ConfigFileRules
}

// scanStreaming scans with cfg and returns the results with the IDs of the
// findings passed to OnFinding while the scan ran.
func scanStreaming(t *testing.T, cfg Config) (*Results, []string) {
	t.Helper()
	var mu sync.Mutex
	var streamed []string
	cfg.OnFinding = func(f Finding) {
		mu.Lock()
		streamed = append(streamed, f.ID)
		mu.Unlock()
	}
	results := scanWithConfig(t, cfg)
	return results, streamed
}

// scanWithRuleInFile scans dir with the rules of tc as a config file found in
// the scan target, and no command-line rule.
func scanWithRuleInFile(t *testing.T, dir string, tc dependencyRuleCase) (*Results, []string) {
	t.Helper()
	rules := tc.rules
	rules.Path = filepath.Join(dir, ".cryptoscan.yaml")
	rules.Source = ConfigSourceScanTarget
	return scanStreaming(t, Config{Target: dir, ConfigFile: &rules})
}

// A crypto library found in a dependency manifest was reported whatever
// --min-severity, --ignore and --ignore-category said, and whatever minSeverity,
// ignore.patterns and ignore.categories in a config file said, although each
// of them removes a match in a source file. Each rule below now removes the
// dependency finding from the report and from the findings streamed while the
// scan runs, and the config file counts the finding it removed under the
// setting that removed it.
func TestRulesRemoveDependencyFindings(t *testing.T) {
	dir := dependencyRuleFixture(t)

	cases := []struct {
		dependencyRuleCase
		removed func(ConfigFindingsRemoved) int
	}{
		{
			dependencyRuleCase{
				name:  "minimum severity above the finding's",
				cli:   Config{MinSeverity: types.SeverityCritical},
				rules: ConfigFileRules{MinSeverity: types.SeverityCritical, HasMinSeverity: true},
			},
			func(r ConfigFindingsRemoved) int { return r.MinSeverity },
		},
		{
			dependencyRuleCase{
				name:  "pattern ID",
				cli:   Config{IgnoreIDs: []string{"DEP-crypto-js"}},
				rules: ConfigFileRules{IgnoreIDs: []string{"DEP-crypto-js"}},
			},
			func(r ConfigFindingsRemoved) int { return r.IgnorePatterns },
		},
		{
			dependencyRuleCase{
				name:  "pattern family",
				cli:   Config{IgnoreIDs: []string{"DEP-*"}},
				rules: ConfigFileRules{IgnoreIDs: []string{"DEP-*"}},
			},
			func(r ConfigFindingsRemoved) int { return r.IgnorePatterns },
		},
		{
			dependencyRuleCase{
				name:  "finding ID",
				cli:   Config{IgnoreIDs: []string{depFindingID}},
				rules: ConfigFileRules{IgnoreIDs: []string{depFindingID}},
			},
			func(r ConfigFindingsRemoved) int { return r.IgnorePatterns },
		},
		{
			dependencyRuleCase{
				name:  "category",
				cli:   Config{IgnoreCategories: []string{"dependency"}},
				rules: ConfigFileRules{IgnoreCategories: []string{"dependency"}},
			},
			func(r ConfigFindingsRemoved) int { return r.IgnoreCategories },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli := tc.cli
			cli.Target = dir
			viaFlags, streamed := scanStreaming(t, cli)
			if ids := findingIDs(viaFlags); len(ids) != 0 {
				t.Errorf("with the rule on the command line, the report holds %q", ids)
			}
			if len(streamed) != 0 {
				t.Errorf("with the rule on the command line, the scan streamed %q", streamed)
			}

			viaFile, streamed := scanWithRuleInFile(t, dir, tc.dependencyRuleCase)
			if ids := findingIDs(viaFile); len(ids) != 0 {
				t.Errorf("with the rule in a config file, the report holds %q", ids)
			}
			if len(streamed) != 0 {
				t.Errorf("with the rule in a config file, the scan streamed %q", streamed)
			}
			if viaFile.Config == nil {
				t.Fatal("results carry no config report")
			}
			if got := tc.removed(viaFile.Config.FindingsRemoved); got != 1 {
				t.Errorf("the setting counted %d findings removed, want 1", got)
			}
			if got := viaFile.Config.FindingsRemoved.Total; got != 1 {
				t.Errorf("the config file counted %d findings removed in total, want 1", got)
			}
		})
	}
}

// A rule that does not match the dependency finding leaves it in the report
// and in the streamed findings, and the config file counts nothing removed.
func TestRulesKeepDependencyFindingsTheyDoNotMatch(t *testing.T) {
	dir := dependencyRuleFixture(t)

	cases := []dependencyRuleCase{
		{
			name:  "minimum severity equal to the finding's",
			cli:   Config{MinSeverity: types.SeverityMedium},
			rules: ConfigFileRules{MinSeverity: types.SeverityMedium, HasMinSeverity: true},
		},
		{
			name:  "another library's pattern ID",
			cli:   Config{IgnoreIDs: []string{"DEP-node-forge"}},
			rules: ConfigFileRules{IgnoreIDs: []string{"DEP-node-forge"}},
		},
		{
			name:  "another category",
			cli:   Config{IgnoreCategories: []string{"Library Import"}},
			rules: ConfigFileRules{IgnoreCategories: []string{"Library Import"}},
		},
	}

	want := []string{depFindingID}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli := tc.cli
			cli.Target = dir
			viaFlags, streamed := scanStreaming(t, cli)
			if got := findingIDs(viaFlags); !reflect.DeepEqual(got, want) {
				t.Errorf("with the rule on the command line, the report holds %q, want %q", got, want)
			}
			if !reflect.DeepEqual(streamed, want) {
				t.Errorf("with the rule on the command line, the scan streamed %q, want %q", streamed, want)
			}

			viaFile, streamed := scanWithRuleInFile(t, dir, tc)
			if got := findingIDs(viaFile); !reflect.DeepEqual(got, want) {
				t.Errorf("with the rule in a config file, the report holds %q, want %q", got, want)
			}
			if !reflect.DeepEqual(streamed, want) {
				t.Errorf("with the rule in a config file, the scan streamed %q, want %q", streamed, want)
			}
			if viaFile.Config == nil {
				t.Fatal("results carry no config report")
			}
			if got := viaFile.Config.FindingsRemoved.Total; got != 0 {
				t.Errorf("the config file counted %d findings removed, want 0", got)
			}
		})
	}
}
