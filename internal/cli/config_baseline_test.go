// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/spf13/cobra"
)

// createBaselineHint is the second sentence of the next step printed when a
// baseline cannot be loaded, wherever its path came from.
const createBaselineHint = "To create a baseline: cryptoscan scan . --format json --output baseline.json"

// configBaselineTree writes a project and, in the directory above it, the
// project's baseline:
//
//	<root>/project/app.py  one rsa.generate_private_key call
//	<root>/baseline.json   the JSON report of a scan of <root>/project
//
// It returns root, the project directory and the number of findings in the
// baseline. The config file is left to the test.
func configBaselineTree(t *testing.T) (root, project string, baselined int) {
	t.Helper()
	root = t.TempDir()
	project = filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	code := "from cryptography.hazmat.primitives.asymmetric import rsa\n\n" +
		"key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
	if err := os.WriteFile(filepath.Join(project, "app.py"), []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}

	resetConfigScanFlags()
	defer resetConfigScanFlags()
	outputFormat = "json"
	noConfig = true
	report := captureStdout(func() {
		if _, err := scanTarget(&cobra.Command{}, project); err != nil {
			t.Errorf("scan for the baseline failed: %v", err)
		}
	})
	var prior struct {
		Findings []scanner.Finding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(report), &prior); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(prior.Findings) == 0 {
		t.Fatal("fixture produced no findings to put in a baseline")
	}
	if err := os.WriteFile(filepath.Join(root, "baseline.json"), []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, project, len(prior.Findings)
}

// writeBaselineConfigFile writes a .cryptoscan.yaml naming baseline into dir
// and returns its path.
func writeBaselineConfigFile(t *testing.T, dir, baseline string) string {
	t.Helper()
	path := filepath.Join(dir, ".cryptoscan.yaml")
	if err := os.WriteFile(path, []byte("baseline: "+baseline+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestConfigFileBaselineIsResolvedFromTheFileDirectory puts the config file
// in the directory above the scan target with the baseline beside it, and
// runs scan and gate from a working directory that holds no baseline.json.
// A relative baseline path in the file is read from the file's directory,
// whether the file was found above the target or given with --config, and an
// absolute path is read as written.
func TestConfigFileBaselineIsResolvedFromTheFileDirectory(t *testing.T) {
	tests := []struct {
		name string
		// absolute writes the baseline's full path into the file in place
		// of baseline.json.
		absolute bool
		// configFlag passes the file with --config in place of finding it
		// above the scan target.
		configFlag bool
	}{
		{name: "relative path, file found above the scan target"},
		{name: "relative path, file given with --config", configFlag: true},
		{name: "absolute path, file found above the scan target", absolute: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, project, baselined := configBaselineTree(t)
			value := "baseline.json"
			if tt.absolute {
				value = filepath.Join(root, "baseline.json")
			}
			cfg := writeBaselineConfigFile(t, root, value)
			chdirForTest(t, t.TempDir())

			resetConfigScanFlags()
			defer resetConfigScanFlags()
			outputFormat = "json"
			if tt.configFlag {
				configFile = cfg
			}

			var code int
			var err error
			output := captureStdout(func() {
				code, err = scanTarget(&cobra.Command{}, project)
			})
			if err != nil {
				t.Fatalf("scan from another directory failed: %v", err)
			}
			if code != 0 {
				t.Errorf("scan exit code = %d, want 0", code)
			}
			var report struct {
				Findings []scanner.Finding     `json:"findings"`
				Config   *scanner.ConfigReport `json:"config"`
			}
			if err := json.Unmarshal([]byte(output), &report); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if report.Config == nil {
				t.Fatal("JSON report has no config object")
			}
			if report.Config.Path != cfg {
				t.Errorf("config path = %q, want %q", report.Config.Path, cfg)
			}
			if len(report.Findings) != 0 {
				t.Errorf("baseline left %d findings, want 0", len(report.Findings))
			}
			if removed := report.Config.FindingsRemoved.Baseline; removed != baselined {
				t.Errorf("findingsRemoved.baseline = %d, want %d", removed, baselined)
			}

			captureStdout(func() {
				code, err = gateTarget(&cobra.Command{}, project)
			})
			if err != nil {
				t.Fatalf("gate from another directory failed: %v", err)
			}
			if code != 0 {
				t.Errorf("gate exit code = %d, want 0: the baseline removes every finding", code)
			}
		})
	}
}

// TestCommandLineBaselineIsResolvedFromTheWorkingDirectory gives --baseline
// baseline.json while the config file names a baseline.json beside it. The
// path on the command line is read from the working directory and takes the
// place of the file's.
func TestCommandLineBaselineIsResolvedFromTheWorkingDirectory(t *testing.T) {
	root, project, _ := configBaselineTree(t)
	writeBaselineConfigFile(t, root, "baseline.json")
	saved, err := os.ReadFile(filepath.Join(root, "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("working directory without baseline.json", func(t *testing.T) {
		chdirForTest(t, t.TempDir())
		resetConfigScanFlags()
		defer resetConfigScanFlags()
		outputFormat = "json"
		baselineFile = "baseline.json"

		var err error
		captureStdout(func() {
			_, err = scanTarget(&cobra.Command{}, project)
		})
		if err == nil {
			t.Fatal("scan read a baseline.json that is not in the working directory")
		}
		if want := "failed to load baseline: open baseline.json: "; !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
		var hinted *hintedError
		if !errors.As(err, &hinted) {
			t.Fatalf("error %q has no next step", err)
		}
		if want := "Check the --baseline path. " + createBaselineHint; hinted.hint != want {
			t.Errorf("hint = %q, want %q", hinted.hint, want)
		}
	})

	t.Run("working directory with baseline.json", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "baseline.json"), saved, 0o600); err != nil {
			t.Fatal(err)
		}
		chdirForTest(t, dir)
		resetConfigScanFlags()
		defer resetConfigScanFlags()
		outputFormat = "json"
		baselineFile = "baseline.json"

		var err error
		output := captureStdout(func() {
			_, err = scanTarget(&cobra.Command{}, project)
		})
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		var report struct {
			Findings []scanner.Finding     `json:"findings"`
			Config   *scanner.ConfigReport `json:"config"`
		}
		if err := json.Unmarshal([]byte(output), &report); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if len(report.Findings) != 0 {
			t.Errorf("baseline left %d findings, want 0", len(report.Findings))
		}
		if report.Config == nil {
			t.Fatal("JSON report has no config object")
		}
		if removed := report.Config.FindingsRemoved.Baseline; removed != 0 {
			t.Errorf("findingsRemoved.baseline = %d, want 0: the baseline came from the command line, not the file", removed)
		}
	})
}

// TestMissingConfigFileBaselineNamesTheFile checks the next step printed
// when the baseline a config file names cannot be read: it points at the
// file, not at a --baseline flag that was not given.
func TestMissingConfigFileBaselineNamesTheFile(t *testing.T) {
	root, project, _ := configBaselineTree(t)
	cfg := writeBaselineConfigFile(t, root, "missing.json")
	chdirForTest(t, t.TempDir())
	resetConfigScanFlags()
	defer resetConfigScanFlags()

	output, err := executeRoot(t, "scan", "--no-color", project)
	if err == nil {
		t.Fatal("expected an error")
	}
	if want := "Error: failed to load baseline: open " + filepath.Join(root, "missing.json") + ": "; !strings.Contains(output, want) {
		t.Errorf("output = %q, want an Error line containing %q", output, want)
	}
	if want := "Check the baseline path in " + cfg + ". " + createBaselineHint + "\n"; !strings.Contains(output, want) {
		t.Errorf("output = %q, want the next step %q", output, want)
	}
	if strings.Contains(output, "Check the --baseline path") {
		t.Errorf("output names --baseline, which was not given:\n%s", output)
	}
}
