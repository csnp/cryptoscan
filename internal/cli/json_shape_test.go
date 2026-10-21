// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// A JSON report names each finding's severity the way summary.bySeverity keys
// on it, and every finding has the algorithm and keySize keys, null when the
// pattern gives no value.
func TestJSONFindingsShareTheSummarySeverityNamesAndKeys(t *testing.T) {
	dir := t.TempDir()
	writeReviewedTree(t, dir, reviewedApp)
	writeFixtureFile(t, filepath.Join(dir, "src", "keys.py"), "key_size = 2048\n")

	out := runScanWith(t, dir, "--stream=false", "--format", "json")
	var report struct {
		Findings []map[string]any `json:"findings"`
		Summary  struct {
			BySeverity map[string]int `json:"bySeverity"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
		t.Fatalf("scan output is not JSON: %v\n%s", err, out.stdout)
	}
	if len(report.Findings) == 0 {
		t.Fatal("the fixture produced no findings")
	}

	counted := map[string]int{}
	withoutAlgorithm := 0
	for _, f := range report.Findings {
		name, ok := f["severity"].(string)
		if !ok {
			t.Errorf("finding %v has severity %#v, want a name", f["id"], f["severity"])
			continue
		}
		counted[name]++
		for _, key := range []string{"algorithm", "keySize"} {
			if _, ok := f[key]; !ok {
				t.Errorf("finding %v has no %s key", f["id"], key)
			}
		}
		if f["algorithm"] == nil {
			withoutAlgorithm++
		}
	}
	for name, n := range counted {
		if report.Summary.BySeverity[name] != n {
			t.Errorf("%d findings have severity %q, summary.bySeverity says %d", n, name, report.Summary.BySeverity[name])
		}
	}
	if withoutAlgorithm == 0 {
		t.Error("no finding in the fixture names no algorithm, so the null case is not checked")
	}
}

// A baseline written by an earlier release carries each severity as a number.
// It still loads, and its findings still match the scan.
func TestBaselineWithNumericSeveritiesStillLoads(t *testing.T) {
	a := t.TempDir()
	writeReviewedTree(t, a, reviewedApp)
	baseline := writeBaseline(t, a)

	data, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	named := regexp.MustCompile(`"severity":\s*"([A-Z]+)"`)
	if len(named.FindAll(data, -1)) == 0 {
		t.Fatalf("the baseline has no severity names to turn into numbers:\n%s", data)
	}
	numbers := named.ReplaceAllFunc(data, func(m []byte) []byte {
		name := string(named.FindSubmatch(m)[1])
		for level := scanner.SeverityInfo; level <= scanner.SeverityCritical; level++ {
			if level.String() == name {
				return []byte(`"severity": ` + strconv.Itoa(int(level)))
			}
		}
		t.Fatalf("unknown severity %q in the baseline", name)
		return m
	})
	if named.Match(numbers) || !regexp.MustCompile(`"severity": [0-4]`).Match(numbers) {
		t.Fatalf("the baseline still names its severities:\n%s", numbers)
	}
	if err := os.WriteFile(baseline, numbers, 0o644); err != nil {
		t.Fatal(err)
	}

	b := t.TempDir()
	writeReviewedTree(t, b, reviewedApp)
	if got := scanTree(t, b, baseline, filepath.Join(t.TempDir(), "out.json")); len(got) != 0 {
		t.Errorf("a baseline with numeric severities left %d findings new:\n  %s", len(got), describe(got))
	}
}
