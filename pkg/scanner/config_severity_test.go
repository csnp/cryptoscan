// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

func TestConfigSeverityCountsArithmetic(t *testing.T) {
	c := CountSeverities([]Finding{
		{Severity: SeverityHigh}, {Severity: SeverityHigh}, {Severity: SeverityLow}, {Severity: SeverityInfo},
	})
	if want := (ConfigSeverityCounts{Info: 1, Low: 1, High: 2}); c != want {
		t.Fatalf("CountSeverities = %+v, want %+v", c, want)
	}
	for _, tt := range []struct {
		s    Severity
		want int
	}{
		{SeverityInfo, 4}, {SeverityLow, 3}, {SeverityMedium, 2}, {SeverityHigh, 2}, {SeverityCritical, 0},
	} {
		if got := c.AtOrAbove(tt.s); got != tt.want {
			t.Errorf("AtOrAbove(%s) = %d, want %d", tt.s, got, tt.want)
		}
	}
	if got := c.Of(SeverityHigh); got != 2 {
		t.Errorf("Of(HIGH) = %d, want 2", got)
	}
	other := ConfigSeverityCounts{Medium: 1, Critical: 1}
	if got := c.Plus(other).Minus(other); got != c {
		t.Errorf("Plus then Minus = %+v, want %+v", got, c)
	}
}

// TestConfigRemovalsAreCountedBySeverity checks that each setting's
// severities add up to its count, and that the severities are those of the
// findings scanning without the file adds back.
func TestConfigRemovalsAreCountedBySeverity(t *testing.T) {
	dir := configFixture(t)
	base := scanWith(t, Config{Target: dir, MinSeverity: types.SeverityInfo})

	rules := ConfigFileRules{
		Path:           filepath.Join(dir, ".cryptoscan.yaml"),
		Source:         ConfigSourceScanTarget,
		IgnoreIDs:      []string{"RSA-*"},
		MinSeverity:    types.SeverityMedium,
		HasMinSeverity: true,
	}
	results := scanWith(t, Config{Target: dir, MinSeverity: types.SeverityInfo, ConfigFile: &rules})
	r := results.Config.FindingsRemoved
	if r.IgnorePatterns == 0 || r.MinSeverity == 0 {
		t.Fatalf("the fixture no longer gives both settings something to remove: %+v; findings %v", r, findingIDs(base))
	}

	for _, tt := range []struct {
		setting string
		count   int
		counts  ConfigSeverityCounts
	}{
		{"ignore.patterns", r.IgnorePatterns, r.IgnorePatternsBySeverity},
		{"ignore.categories", r.IgnoreCategories, r.IgnoreCategoriesBySeverity},
		{"minSeverity", r.MinSeverity, r.MinSeverityBySeverity},
	} {
		if got := tt.counts.AtOrAbove(SeverityInfo); got != tt.count {
			t.Errorf("%s: severities add up to %d, count is %d", tt.setting, got, tt.count)
		}
	}
	if r.MinSeverityBySeverity.AtOrAbove(SeverityMedium) != 0 {
		t.Errorf("minSeverity medium removed findings at medium or above: %+v", r.MinSeverityBySeverity)
	}

	added := CountSeverities(base.Findings).Minus(CountSeverities(results.Findings))
	if r.BySeverity != added {
		t.Errorf("bySeverity = %+v; scanning without the file adds %+v", r.BySeverity, added)
	}
	if results.Config.Unbaselined != added {
		t.Errorf("unbaselined = %+v, want %+v before any baseline", results.Config.Unbaselined, added)
	}
	if len(results.ConfigWithheld) != r.Total {
		t.Errorf("%d findings held for the exit code, total removed %d", len(results.ConfigWithheld), r.Total)
	}
}

// TestConfigWithheldLeavesOutTheConfigFileItself covers a match in the
// config file: RSA-001 in its own ignore list. The setting's count includes
// it, as before, but it is not held as a finding the file kept out of the
// scanned code.
func TestConfigWithheldLeavesOutTheConfigFileItself(t *testing.T) {
	dir := configFixture(t)
	cfgPath := filepath.Join(dir, ".cryptoscan.yaml")
	write(t, cfgPath, "ignore:\n  patterns: [\"RSA-001\"]\n")

	base := scanWith(t, Config{Target: dir, MinSeverity: types.SeverityInfo})
	inFile := 0
	for _, f := range base.Findings {
		if f.File == cfgPath {
			inFile++
		}
	}
	if inFile == 0 {
		t.Fatalf("the config file no longer gives a match of its own: %v", findingIDs(base))
	}

	rules := ConfigFileRules{Path: cfgPath, Source: ConfigSourceScanTarget, IgnoreIDs: []string{"RSA-001"}}
	results := scanWith(t, Config{Target: dir, MinSeverity: types.SeverityInfo, ConfigFile: &rules})
	r := results.Config.FindingsRemoved
	if len(results.ConfigWithheld) != r.Total-inFile {
		t.Errorf("%d findings held for the exit code; removed %d, %d of them in the config file", len(results.ConfigWithheld), r.Total, inFile)
	}
	for _, f := range results.ConfigWithheld {
		if f.File == cfgPath {
			t.Errorf("held a match in the config file itself: %s", f.ID)
		}
	}
	if got, want := results.Config.Unbaselined.AtOrAbove(SeverityInfo), len(results.ConfigWithheld); got != want {
		t.Errorf("unbaselined counts %d findings, %d are held", got, want)
	}
}

// TestDependencyRemovalIsCountedBySeverity checks the second place a config
// setting holds a finding back, a dependency manifest: the MEDIUM crypto-js
// finding counts under the setting that removed it and is held for the exit
// code.
func TestDependencyRemovalIsCountedBySeverity(t *testing.T) {
	for _, tt := range []struct {
		name  string
		rules ConfigFileRules
		get   func(ConfigFindingsRemoved) ConfigSeverityCounts
	}{
		{"ignore.patterns", ConfigFileRules{IgnoreIDs: []string{"DEP-*"}},
			func(r ConfigFindingsRemoved) ConfigSeverityCounts { return r.IgnorePatternsBySeverity }},
		{"minSeverity", ConfigFileRules{MinSeverity: types.SeverityCritical, HasMinSeverity: true},
			func(r ConfigFindingsRemoved) ConfigSeverityCounts { return r.MinSeverityBySeverity }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, filepath.Join(dir, "package.json"), `{"name": "fixture", "dependencies": {"crypto-js": "^4.2.0"}}`)
			rules := tt.rules
			rules.Path = filepath.Join(dir, ".cryptoscan.yaml")
			rules.Source = ConfigSourceScanTarget
			results := scanWith(t, Config{Target: dir, MinSeverity: types.SeverityInfo, ConfigFile: &rules})
			want := ConfigSeverityCounts{Medium: 1}
			if got := tt.get(results.Config.FindingsRemoved); got != want {
				t.Errorf("%s severities = %+v, want %+v", tt.name, got, want)
			}
			if got := results.Config.FindingsRemoved.BySeverity; got != want {
				t.Errorf("bySeverity = %+v, want %+v", got, want)
			}
			if len(results.ConfigWithheld) != 1 || !strings.HasPrefix(results.ConfigWithheld[0].ID, "DEP-crypto-js") {
				t.Errorf("held %v, want the crypto-js dependency finding", results.ConfigWithheld)
			}
		})
	}
}

// TestConfigReportJSONCarriesSeveritiesAndFailOn checks the two fields the
// JSON config object gains, and that the counts kept for the text report and
// the exit code stay out of it.
func TestConfigReportJSONCarriesSeveritiesAndFailOn(t *testing.T) {
	report := ConfigReport{
		Path:   "/repo/.cryptoscan.yaml",
		Source: ConfigSourceScanTarget,
		FindingsRemoved: ConfigFindingsRemoved{
			IgnorePatterns: 3, Total: 3,
			BySeverity:               ConfigSeverityCounts{High: 2, Low: 1},
			IgnorePatternsBySeverity: ConfigSeverityCounts{High: 2, Low: 1},
		},
		Rerun:       ConfigRerun{Command: "gate"},
		Unbaselined: ConfigSeverityCounts{High: 2, Low: 1},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	want := `"findingsRemoved":{"ignorePatterns":3,"ignoreCategories":0,"minSeverity":0,"baseline":0,"total":3,` +
		`"bySeverity":{"info":0,"low":1,"medium":0,"high":2,"critical":0}}`
	if !strings.Contains(out, want) {
		t.Errorf("JSON = %s, want it to contain %s", out, want)
	}
	if strings.Contains(out, `"failOn"`) {
		t.Errorf("JSON = %s, which has failOn for a file that sets none", out)
	}
	for _, kept := range []string{"BySeverity\"", "Rerun", "rerun", "Unbaselined", "unbaselined", "Cap", "cap"} {
		if strings.Contains(out, kept) {
			t.Errorf("JSON = %s, which carries %s", out, kept)
		}
	}

	report.FailOn = &ConfigFailOn{Value: "critical", Applied: false, Cap: "high"}
	data, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if want := `"failOn":{"value":"critical","applied":false}`; !strings.Contains(string(data), want) {
		t.Errorf("JSON = %s, want it to contain %s", data, want)
	}
}
