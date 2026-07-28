// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/version"
)

// TestEveryEmitterReportsTheSameVersion guards the provenance defect found by
// the v1.4.0 release test: one binary reported four different versions. The
// version command said 1.4.0, SARIF said 1.0.0, CBOM said 1.1.0 and JSON
// carried no version at all.
//
// SARIF and CBOM are evidence artifacts. A CBOM claiming it was produced by
// CryptoScan 1.1.0 is a false provenance record, and a SARIF consumer cannot
// attribute a result to a scanner build. Every surface must read pkg/version.
func TestEveryEmitterReportsTheSameVersion(t *testing.T) {
	const want = "9.8.7-test"

	original := version.Get()
	version.Set(want)
	t.Cleanup(func() { version.Set(original) })

	results := &scanner.Results{
		Tool:       scanner.ToolInfo{Name: "CryptoScan", Version: version.Get()},
		ScanTarget: ".",
		Findings:   []scanner.Finding{},
		Summary:    scanner.Summary{},
	}

	t.Run("json", func(t *testing.T) {
		out := generate(t, NewJSONReporter(false), results)
		var doc struct {
			Tool struct {
				Version string `json:"version"`
			} `json:"tool"`
		}
		decode(t, out, &doc)
		if doc.Tool.Version != want {
			t.Errorf("JSON tool.version = %q, want %q", doc.Tool.Version, want)
		}
	})

	t.Run("sarif", func(t *testing.T) {
		out := generate(t, NewSARIFReporter(), results)
		var doc struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Version         string `json:"version"`
						SemanticVersion string `json:"semanticVersion"`
					} `json:"driver"`
				} `json:"tool"`
			} `json:"runs"`
		}
		decode(t, out, &doc)
		if len(doc.Runs) == 0 {
			t.Fatal("SARIF report has no runs")
		}
		d := doc.Runs[0].Tool.Driver
		if d.Version != want {
			t.Errorf("SARIF driver.version = %q, want %q", d.Version, want)
		}
		if d.SemanticVersion != want {
			t.Errorf("SARIF driver.semanticVersion = %q, want %q", d.SemanticVersion, want)
		}
	})

	t.Run("cbom", func(t *testing.T) {
		out := generate(t, NewCBOMReporter(), results)
		var doc struct {
			Metadata struct {
				Tools []struct {
					Version string `json:"version"`
				} `json:"tools"`
			} `json:"metadata"`
		}
		decode(t, out, &doc)
		if len(doc.Metadata.Tools) == 0 {
			t.Fatal("CBOM has no metadata.tools entry")
		}
		if got := doc.Metadata.Tools[0].Version; got != want {
			t.Errorf("CBOM metadata.tools[0].version = %q, want %q", got, want)
		}
	})

	// A literal left behind anywhere in the emitters would defeat the single
	// source of truth without failing the assertions above, so check that no
	// output still carries the old hardcoded values.
	t.Run("no stale literals", func(t *testing.T) {
		for name, out := range map[string]string{
			"json":  generate(t, NewJSONReporter(false), results),
			"sarif": generate(t, NewSARIFReporter(), results),
			"cbom":  generate(t, NewCBOMReporter(), results),
		} {
			for _, stale := range []string{`"1.0.0"`, `"1.1.0"`} {
				// SARIF's own spec version is legitimately 2.1.0; only the
				// tool version fields are checked here.
				if strings.Contains(out, `"version": `+stale) {
					t.Errorf("%s still emits a hardcoded tool version %s", name, stale)
				}
			}
		}
	})
}

type reportGenerator interface {
	Generate(*scanner.Results) (string, error)
}

func generate(t *testing.T, r reportGenerator, results *scanner.Results) string {
	t.Helper()
	out, err := r.Generate(results)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return out
}

func decode(t *testing.T, out string, into any) {
	t.Helper()
	if err := json.Unmarshal([]byte(out), into); err != nil {
		t.Fatalf("decode report: %v\n%s", err, out)
	}
}
