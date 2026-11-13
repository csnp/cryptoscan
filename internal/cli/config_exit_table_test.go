// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The source files of the exit code table. rsaSource gives three findings:
// RSA-001 at HIGH twice and KEYSIZE-001 at LOW. bcryptSource gives two
// KDF-BCRYPT-001 findings at INFO. The package.json fixtures use
// cryptoJSManifest, which gives one MEDIUM dependency finding,
// DEP-crypto-js-package.json.
const (
	rsaSource = "from cryptography.hazmat.primitives.asymmetric import rsa\n" +
		"key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
	rsaSourceIgnoredInline = "from cryptography.hazmat.primitives.asymmetric import rsa  # cryptoscan:ignore\n" +
		"key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # cryptoscan:ignore\n"
	bcryptSource = "import bcrypt\nh = bcrypt.hashpw(b\"pw\", bcrypt.gensalt())\n"
	helloSource  = "print(\"hello\")\n"
)

// docsExampleConfig is the example file of docs/configuration.md as written
// there.
const docsExampleConfig = `# .cryptoscan.yaml - CryptoScan configuration
ignore:
  patterns:
    - CERT-SELFSIGNED-001   # Known dev certificates
    - RSA-001               # Legacy auth, migration tracked in JIRA-123
  categories:
    - Library Import        # Don't report import statements
  files:
    - "vendor/*"
    - "testdata/*"

failOn: high              # Exit non-zero on HIGH or CRITICAL findings
minSeverity: low          # Report LOW and above
baseline: baseline.json   # Only report new findings vs baseline
`

// configExitFixture is one tree of the exit code table.
type configExitFixture struct {
	name  string
	files map[string]string
	// config is the .cryptoscan.yaml written at the root of the tree, or
	// empty for none.
	config string
	// baselined writes baseline.json at the root, from a scan of the tree
	// with --no-config, before addedLater and the config file are written.
	baselined  bool
	addedLater map[string]string
	// target is the directory scanned, relative to the root of the tree.
	target string
	// inside runs each command from the scanned directory with target ".".
	inside bool
	// want maps a column to the expected result: the exit code, then
	// "line N <severity>" for the stderr line naming the config file,
	// "parse" for the stop on a file that does not parse, "warning" for the
	// warning, "load" for the error on a file passed with --config,
	// "not-applied" for the config block's failOn line, "removed-none" for a
	// config block that says the file removed nothing, and "no-baseline-error"
	// for a run whose baseline is found.
	want map[string]string
}

// configExitColumns are the commands of the table. CONFIG stands for the
// path of the fixture's config file.
var configExitColumns = []struct {
	name string
	cmd  *cobra.Command
	args []string
}{
	{"gate", gateCmd, nil},
	{"scan --fail-on high", scanCmd, []string{"--fail-on", "high"}},
	{"scan --fail-on low", scanCmd, []string{"--fail-on", "low"}},
	{"scan", scanCmd, nil},
	{"gate --config", gateCmd, []string{"--config", "CONFIG"}},
	{"gate --no-config", gateCmd, []string{"--no-config"}},
	{"scan --fail-on medium", scanCmd, []string{"--fail-on", "medium"}},
	{"scan --fail-on info", scanCmd, []string{"--fail-on", "info"}},
	{"scan --no-config --fail-on low", scanCmd, []string{"--no-config", "--fail-on", "low"}},
	{"gate --format json", gateCmd, []string{"--format", "json"}},
	{"gate --format sarif", gateCmd, []string{"--format", "sarif"}},
	{"gate --ignore *", gateCmd, []string{"--ignore", "*"}},
	{"gate --ignore RSA-001", gateCmd, []string{"--ignore", "RSA-001"}},
}

func configExitFixtures() []configExitFixture {
	everything := "ignore:\n  patterns: [\"*\"]\n"
	return []configExitFixture{
		{name: "fx0", files: map[string]string{"app.py": rsaSource},
			want: map[string]string{"gate": "1", "scan --fail-on high": "1", "scan --fail-on low": "1", "scan": "0", "gate --no-config": "1"}},
		{name: "fx1", files: map[string]string{"app.py": rsaSource}, config: everything,
			want: map[string]string{"gate": "1 line 2 high", "scan --fail-on high": "1 line 2 high", "scan --fail-on low": "1 line 3 low",
				"scan": "0", "gate --config": "0", "gate --no-config": "1",
				"gate --format json": "1 line 2 high", "gate --format sarif": "1 line 2 high", "gate --ignore *": "0 removed-none"}},
		{name: "fx7", files: map[string]string{"svc/app.py": rsaSource}, config: everything, target: "svc",
			want: map[string]string{"gate": "1 line 2 high", "scan --fail-on high": "1 line 2 high", "scan --fail-on low": "1 line 3 low",
				"scan": "0", "gate --config": "0", "gate --no-config": "1"}},
		{name: "fx2", files: map[string]string{"app.py": bcryptSource}, config: "minSeverity: low\n",
			want: map[string]string{"gate": "0", "scan --fail-on high": "0", "scan --fail-on low": "0",
				"scan": "0", "gate --config": "0", "gate --no-config": "0", "scan --fail-on info": "1 line 2 info"}},
		{name: "fx3", files: map[string]string{"app.py": bcryptSource}, config: "ignore:\n  categories: [\"Key Derivation Function\"]\n",
			want: map[string]string{"gate": "0", "scan --fail-on high": "0", "scan --fail-on low": "0",
				"scan": "0", "gate --config": "0", "gate --no-config": "0", "scan --fail-on info": "1 line 2 info"}},
		{name: "fx4", files: map[string]string{"app.py": rsaSource}, config: "baseline: baseline.json\n", baselined: true, inside: true,
			want: map[string]string{"gate": "0", "scan --fail-on high": "0", "scan --fail-on low": "0",
				"scan": "0", "gate --config": "0", "gate --no-config": "1"}},
		{name: "fx12", files: map[string]string{"app.py": rsaSource}, config: "baseline: baseline.json\n", baselined: true, inside: true,
			addedLater: map[string]string{"pw.py": bcryptSource},
			want: map[string]string{"gate": "0", "scan --fail-on high": "0", "scan --fail-on low": "0",
				"scan": "0", "gate --config": "0", "gate --no-config": "1"}},
		{name: "fx6", files: map[string]string{"app.py": rsaSource, "pw.py": bcryptSource}, config: "ignore:\n  patterns: [\"RSA-*\", \"KEYSIZE-*\"]\n",
			want: map[string]string{"gate": "1 line 2 high", "scan --fail-on high": "1 line 2 high", "scan --fail-on low": "1 line 3 low",
				"scan": "0", "gate --config": "0", "gate --no-config": "1"}},
		{name: "fx5", files: map[string]string{"app.py": rsaSource}, config: "ignore:\n  files: [\"*.py\"]\n",
			want: map[string]string{"gate": "0", "scan --fail-on high": "0", "scan --fail-on low": "0",
				"scan": "0", "gate --config": "0", "gate --no-config": "1"}},
		{name: "fx10", files: map[string]string{"app.py": rsaSourceIgnoredInline},
			want: map[string]string{"gate": "0", "scan --fail-on high": "0", "scan --fail-on low": "0", "scan": "0", "gate --no-config": "0"}},
		{name: "fx8", files: map[string]string{"app.py": helloSource}, config: "ignore: [unclosed\n",
			want: map[string]string{"gate": "1 parse", "scan --fail-on high": "1 parse", "scan --fail-on low": "1 parse",
				"scan": "0 warning", "gate --config": "1 load", "gate --no-config": "0"}},
		{name: "fx13", files: map[string]string{"app.py": bcryptSource}, config: "failOn: info\nignore: [unclosed\n",
			want: map[string]string{"gate": "1 parse"}},
		{name: "fx13c", files: map[string]string{"app.py": bcryptSource}, config: "failOn: info\n",
			want: map[string]string{"gate": "1"}},
		{name: "fx9", files: map[string]string{"app.py": rsaSource}, config: "ignores:\n  patterns: [\"*\"]\n",
			want: map[string]string{"gate": "1", "scan --fail-on high": "1", "scan --fail-on low": "1", "scan": "0"}},
		{name: "fx14", files: map[string]string{"app.py": rsaSource}, config: "failOn: critical\n",
			want: map[string]string{"gate": "1 not-applied", "scan --fail-on high": "1", "scan --fail-on low": "1",
				"scan": "0", "gate --config": "0", "gate --no-config": "1"}},
		{name: "fx16", files: map[string]string{"app.py": rsaSource}, config: "minSeverity: critical\n",
			want: map[string]string{"gate": "1 line 2 high", "scan --fail-on high": "1 line 2 high", "scan --fail-on low": "1 line 3 low",
				"scan": "0", "gate --config": "0", "gate --no-config": "1"}},
		{name: "fx17", files: map[string]string{"app.py": rsaSource}, config: "ignore:\n  patterns: [\"RSA-001\"]\n",
			want: map[string]string{"gate": "1 line 2 high", "scan --fail-on high": "1 line 2 high", "scan --fail-on low": "1",
				"scan": "0", "gate --config": "0", "gate --no-config": "1", "gate --ignore RSA-001": "0 removed-none"}},
		{name: "fx18", files: map[string]string{"app.py": rsaSource}, config: docsExampleConfig, baselined: true, inside: true,
			want: map[string]string{"gate": "0", "scan --fail-on high": "0", "scan --fail-on low": "0",
				"scan": "0", "gate --config": "0", "gate --no-config": "1"}},
		{name: "fxdep", files: map[string]string{"package.json": cryptoJSManifest}, config: "ignore: {patterns: [\"DEP-*\"]}\n",
			want: map[string]string{"gate": "0", "scan --fail-on high": "0", "scan --fail-on medium": "1 line 1 medium",
				"scan --fail-on low": "1 line 1 low", "scan": "0", "gate --config": "0", "gate --no-config": "0",
				"scan --no-config --fail-on low": "1"}},
		{name: "fxdep-minseverity", files: map[string]string{"package.json": cryptoJSManifest}, config: "minSeverity: critical\n",
			want: map[string]string{"gate": "0", "scan --fail-on high": "0", "scan --fail-on medium": "1 line 1 medium",
				"scan --fail-on low": "1 line 1 low", "scan": "0", "gate --config": "0", "gate --no-config": "0",
				"scan --no-config --fail-on low": "1"}},
	}
}

// buildConfigExitTree writes fx under a new temporary directory and returns
// its root.
func buildConfigExitTree(t *testing.T, fx configExitFixture) string {
	t.Helper()
	root := t.TempDir()
	write := func(files map[string]string) {
		for rel, content := range files {
			path := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(fx.files)
	if fx.baselined {
		out := runCommandWith(t, scanCmd, root, "--stream=false", "--no-config", "--format", "json",
			"--output", filepath.Join(root, "baseline.json"))
		if out.err != "" {
			t.Fatalf("baseline scan failed: %s", out.err)
		}
	}
	write(fx.addedLater)
	if fx.config != "" {
		write(map[string]string{".cryptoscan.yaml": fx.config})
	}
	return root
}

// configExitLine is the stderr line of a gated run that a config file found
// without --config failed.
func configExitLine(n int, severity, path string) string {
	findings := "findings"
	if n == 1 {
		findings = "finding"
	}
	return fmt.Sprintf("cryptoscan: exit code 1: a config file found without --config removed %d %s at or above %s: %s. "+
		"Pass --config %s to apply it and keep the normal exit code, or --no-config to use only command-line options.",
		n, findings, severity, path, path)
}

// TestConfigExitAcceptanceTable runs scan and gate over each tree of the exit
// code table. In a run whose pass or fail the command line asked for, a
// config file found without --config fails the run when it removed a finding
// at or above the threshold that no baseline accepts, and says so on stderr;
// a file whose removals are all below the threshold, a baseline workflow, a
// file passed with --config and plain scan keep the exit code of the
// findings that are left.
func TestConfigExitAcceptanceTable(t *testing.T) {
	for _, fx := range configExitFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			root := buildConfigExitTree(t, fx)
			dir := filepath.Join(root, filepath.FromSlash(fx.target))
			cfgPath := filepath.Join(root, ".cryptoscan.yaml")
			target := dir
			if fx.inside {
				wd, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chdir(dir); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chdir(wd); err != nil {
						t.Errorf("restore working directory: %v", err)
					}
				})
				target = "."
			}
			for _, col := range configExitColumns {
				want, ok := fx.want[col.name]
				if !ok {
					continue
				}
				t.Run(col.name, func(t *testing.T) {
					args := []string{}
					if col.cmd == scanCmd {
						args = append(args, "--stream=false")
					}
					for _, a := range col.args {
						if a == "CONFIG" {
							a = cfgPath
						}
						args = append(args, a)
					}
					out := runCommandWith(t, col.cmd, target, args...)
					checkConfigExitOutcome(t, out, want, cfgPath)
				})
			}
		})
	}
}

// TestConfigExitBaselineFromAnotherDirectory runs gate on the baseline tree
// from a working directory that is not the tree. The baseline the file names
// is found beside the file, and its removals do not fail the run.
func TestConfigExitBaselineFromAnotherDirectory(t *testing.T) {
	for _, fx := range configExitFixtures() {
		if fx.name != "fx4" && fx.name != "fx18" {
			continue
		}
		t.Run(fx.name, func(t *testing.T) {
			fx.inside = false
			root := buildConfigExitTree(t, fx)
			out := runCommandWith(t, gateCmd, root)
			checkConfigExitOutcome(t, out, "0 no-baseline-error", filepath.Join(root, ".cryptoscan.yaml"))
		})
	}
}

// checkConfigExitOutcome compares one run with want, in the form the want
// map of configExitFixture describes.
func checkConfigExitOutcome(t *testing.T, out commandOutcome, want, cfgPath string) {
	t.Helper()
	fields := strings.Fields(want)
	code := out.code
	if out.err != "" {
		code = 1
	}
	if wantCode := fields[0]; fmt.Sprint(code) != wantCode {
		t.Errorf("exit code = %d, want %s (error %q, stderr %q)", code, wantCode, out.err, out.stderr)
	}
	const linePrefix = "cryptoscan: exit code 1: a config file found without --config"
	mark := ""
	if len(fields) > 1 {
		mark = fields[1]
	}
	if mark == "line" {
		var n int
		if _, err := fmt.Sscan(fields[2], &n); err != nil {
			t.Fatalf("bad want %q", want)
		}
		if line := configExitLine(n, fields[3], cfgPath); !strings.Contains(out.stderr, line+"\n") {
			t.Errorf("stderr = %q, want the line %q", out.stderr, line)
		}
		if c := strings.Count(out.stderr, linePrefix); c != 1 {
			t.Errorf("stderr has %d lines naming the config file, want 1", c)
		}
	} else if strings.Contains(out.stderr, linePrefix) || strings.Contains(out.stderr, "auto-detected config file removed") {
		t.Errorf("stderr = %q, which names the config file as a reason for exit code 1", out.stderr)
	}
	switch mark {
	case "parse":
		if want := "config file " + cfgPath + " could not be parsed: "; !strings.HasPrefix(out.err, want) {
			t.Errorf("error = %q, want one starting %q", out.err, want)
		}
	case "warning":
		if !strings.Contains(out.stderr, "Warning: config file "+cfgPath+" could not be parsed and was not applied") {
			t.Errorf("stderr = %q, want the warning naming %s", out.stderr, cfgPath)
		}
	case "load":
		if !strings.Contains(out.err, "failed to load config file "+cfgPath) {
			t.Errorf("error = %q, want the load error naming %s", out.err, cfgPath)
		}
	case "not-applied":
		line := "failOn: critical in the file was not applied: a config file found without --config cannot raise the threshold above high. " +
			"Pass --config " + cfgPath + " to apply it."
		if !strings.Contains(out.stdout, line) {
			t.Errorf("report lacks %q:\n%s", line, out.stdout)
		}
	case "removed-none":
		if !strings.Contains(out.stdout, "It removed no findings and kept no files out of the scan.") {
			t.Errorf("config block does not say the file removed nothing:\n%s", out.stdout)
		}
	case "no-baseline-error":
		if strings.Contains(out.err+out.stderr, "failed to load baseline") {
			t.Errorf("error %q, stderr %q: the baseline beside the file was not found", out.err, out.stderr)
		}
	}
	if mark != "not-applied" && strings.Contains(out.stdout, "in the file was not applied") {
		t.Errorf("report says the file's failOn was not applied:\n%s", out.stdout)
	}
}
