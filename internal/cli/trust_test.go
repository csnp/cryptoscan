// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// trustFixture is the committed fixture of the two Trust patterns: the
// sixteen certificates of the eight listed intermediate keys (tls,
// codesigning), the removed root (root), a certificate issued under a listed
// TLS key (leaf) and a control bundle of three unlisted roots (control).
const trustFixture = "../../pkg/patterns/testdata/trust"

// trustFixtureFindings is how many trust findings the fixture holds: one per
// intermediate certificate, one for the root and one for the leaf.
const trustFixtureFindings = 18

const (
	compromisedKeyID   = "TRUST-COMPROMISED-KEY-001"
	distrustedRootID   = "TRUST-DISTRUSTED-ROOT-001"
	compromisedKeyName = "Certificate with a publicly compromised CA key"
	distrustedRootName = "Certificate chain anchored on a root removed from browser trust stores"
)

// trustPages is the one reference of each Trust pattern, its finding page.
var trustPages = map[string]string{
	compromisedKeyID: "https://github.com/csnp/cryptoscan/blob/main/docs/findings/trust-compromised-key.md",
	distrustedRootID: "https://github.com/csnp/cryptoscan/blob/main/docs/findings/trust-distrusted-root.md",
}

// trustFixStrings are the three Fix strings, by key use, as the finding pages
// word them.
var trustFixStrings = map[string]string{
	"tls":         "Replace the chain with one issued by a CA none of whose keys is listed, and remove this certificate from any bundle or pin set you ship.",
	"codeSigning": "Re-sign the artifacts with a certificate from a CA none of whose keys is listed and republish; a verifier that checks revocation rejects signatures under this key.",
	"root":        "Move the chain to a CA whose root stays trusted, and remove emSign ECC Root CA - G3 from any bundle you ship; Chrome removes it for all devices on 2026-10-27.",
}

// relativeTime matches a relative date or a countdown, which the trust texts
// never state: they give absolute dates.
var relativeTime = regexp.MustCompile(`(?i)\b(today|tomorrow|yesterday|tonight|now|ago|soon|recently|currently|this (week|month|year)|next (week|month|year)|last (week|month|year)|days?|weeks?|months?|years?|hours?)\b`)

// resetGateFlags puts every gate flag back to its default, value and
// "changed" state both, now and when the test ends, as resetScanFlags does
// for scan.
func resetGateFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		gateCmd.Flags().VisitAll(func(f *pflag.Flag) {
			if err := f.Value.Set(f.DefValue); err != nil {
				t.Errorf("reset --%s to %q: %v", f.Name, f.DefValue, err)
			}
			f.Changed = false
		})
	}
	reset()
	t.Cleanup(reset)
}

// runTrust runs scan or gate on target with args through the command's own
// code path, without exiting the process, and returns what it printed, the
// code it would exit with and the error it returned.
func runTrust(t *testing.T, cmd *cobra.Command, target string, args ...string) scanOutcome {
	t.Helper()
	resetScanFlags(t)
	resetGateFlags(t)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("%s %s: %v", cmd.Name(), strings.Join(args, " "), err)
	}
	run := scanTarget
	if cmd == gateCmd {
		run = gateTarget
	}
	var out scanOutcome
	var err error
	out.stdout = captureStdout(func() {
		out.code, err = run(cmd, target)
	})
	if err != nil {
		out.err = err.Error()
	}
	return out
}

// trustPatternID is the pattern ID of a finding or SARIF rule ID, which is
// the pattern ID followed by "-<line>-<column>".
func trustPatternID(id string) string {
	for pattern := range trustPages {
		if strings.HasPrefix(id, pattern+"-") {
			return pattern
		}
	}
	return ""
}

// The exit codes are the documented ones: the compromised keys are CRITICAL,
// which fails scan and gate; the removed root is HIGH, which fails gate and
// fails scan only under --fail-on high. The certificate ignore examples the
// help offers leave both kinds in place, ignoring one kind's ID leaves the
// other, and ignoring both IDs lets scan pass.
func TestTrustExitCodes(t *testing.T) {
	root := filepath.Join(trustFixture, "root")
	certificateIgnores := []string{"--ignore", "CERT-*", "--ignore-category", "Certificate"}
	cases := []struct {
		cmd    *cobra.Command
		target string
		args   []string
		want   int
	}{
		{scanCmd, trustFixture, nil, 1},
		{gateCmd, trustFixture, nil, 1},
		{gateCmd, trustFixture, certificateIgnores, 1},
		{scanCmd, trustFixture, []string{"--ignore", compromisedKeyID + "," + distrustedRootID}, 0},
		{gateCmd, trustFixture, []string{"--ignore", compromisedKeyID + "," + distrustedRootID}, 0},
		{gateCmd, trustFixture, []string{"--ignore", compromisedKeyID}, 1},
		{scanCmd, trustFixture, []string{"--ignore", compromisedKeyID}, 0},
		{scanCmd, trustFixture, []string{"--ignore", distrustedRootID}, 1},
		{gateCmd, root, nil, 1},
		{gateCmd, root, certificateIgnores, 1},
		{scanCmd, root, nil, 0},
		{scanCmd, root, []string{"--fail-on", "high"}, 1},
	}
	for _, tc := range cases {
		args := append([]string{"--no-color"}, tc.args...)
		out := runTrust(t, tc.cmd, tc.target, args...)
		if out.err != "" {
			t.Errorf("%s %s %s: %s", tc.cmd.Name(), tc.target, strings.Join(args, " "), out.err)
			continue
		}
		if out.code != tc.want {
			t.Errorf("%s %s %s: exit %d, want %d", tc.cmd.Name(), tc.target, strings.Join(args, " "), out.code, tc.want)
		}
	}
}

// trustJSONReport is the part of the JSON report the trust cells read.
type trustJSONReport struct {
	Findings []struct {
		ID          string            `json:"id"`
		Category    string            `json:"category"`
		Description string            `json:"description"`
		Fix         string            `json:"fix"`
		Guidance    string            `json:"guidance"`
		Verify      string            `json:"verify"`
		Impact      string            `json:"impact"`
		References  []string          `json:"references"`
		Metadata    map[string]string `json:"metadata"`
	} `json:"findings"`
}

func scanTrustJSON(t *testing.T, target string, args ...string) trustJSONReport {
	t.Helper()
	out := runTrust(t, scanCmd, target, append([]string{"--format", "json"}, args...)...)
	if out.err != "" {
		t.Fatalf("scan %s --format json: %s", target, out.err)
	}
	var report trustJSONReport
	if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
		t.Fatalf("scan %s --format json printed output that is not JSON: %v", target, err)
	}
	return report
}

// opensslBinaries returns the openssl programs to run the Verify commands
// under: the colon-separated paths in CRYPTOSCAN_TEST_OPENSSL, or the openssl
// on PATH.
func opensslBinaries(t *testing.T) []string {
	t.Helper()
	if list := os.Getenv("CRYPTOSCAN_TEST_OPENSSL"); list != "" {
		return filepath.SplitList(list)
	}
	path, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("no openssl on PATH; the Verify commands must run in CI")
		}
		t.Skip("no openssl on PATH")
	}
	return []string{path}
}

// runShell runs command with /bin/sh as printed, from the test's directory,
// with openssl resolving to bin, and returns what it wrote to standard
// output.
func runShell(t *testing.T, bin, command string) []byte {
	t.Helper()
	dir := t.TempDir()
	if err := os.Symlink(bin, filepath.Join(dir, "openssl")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+"/usr/bin"+string(os.PathListSeparator)+"/bin")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Errorf("%s: %v: %s", command, err, stderr.String())
	}
	return out
}

// The JSON report carries both pattern IDs on the fixture and neither on the
// control bundle. Each trust finding carries its kind, matched value, value
// type, key use and rule number (trustRule, a decimal string) as fields and
// no field named rule, the removed root its date too; its fix is
// one of the three ruled strings, its guidance is empty, its one reference is
// its page, and its verify, run as printed from where the scan was run,
// prints its matched value byte for byte under every openssl given.
func TestTrustJSONFindings(t *testing.T) {
	bins := opensslBinaries(t)
	report := scanTrustJSON(t, trustFixture)
	ids := map[string]int{}
	checked := 0
	for _, f := range report.Findings {
		if f.Category != "Trust" {
			continue
		}
		id := trustPatternID(f.ID)
		ids[id]++
		md := f.Metadata
		for _, field := range []string{"kind", "matchedValue", "valueType", "keyUse", "trustRule"} {
			if md[field] == "" {
				t.Errorf("%s: metadata has no %s: %v", f.ID, field, md)
			}
		}
		wantRules := []string{"1", "2"}
		if id == distrustedRootID {
			wantRules = []string{"3", "4"}
		}
		if !slices.Contains(wantRules, md["trustRule"]) {
			t.Errorf("%s: trustRule %q, want one of %q", f.ID, md["trustRule"], wantRules)
		}
		if _, has := md["rule"]; has {
			t.Errorf("%s: metadata carries rule; the rule number's key is trustRule", f.ID)
		}
		if id == distrustedRootID && md["distrustDate"] != "2026-10-27" {
			t.Errorf("%s: distrustDate %q, want 2026-10-27", f.ID, md["distrustDate"])
		}
		if f.Fix != trustFixStrings[md["keyUse"]] {
			t.Errorf("%s: fix %q is not the ruled string for key use %q", f.ID, f.Fix, md["keyUse"])
		}
		if f.Guidance != "" {
			t.Errorf("%s: guidance %q, want none", f.ID, f.Guidance)
		}
		if !slices.Equal(f.References, []string{trustPages[id]}) {
			t.Errorf("%s: references %v, want [%s]", f.ID, f.References, trustPages[id])
		}
		for _, bin := range bins {
			if got := runShell(t, bin, f.Verify); !bytes.Equal(got, []byte(md["matchedValue"])) {
				t.Errorf("%s under %s: verify printed %q, want %q\n %s", f.ID, bin, got, md["matchedValue"], f.Verify)
			}
			checked++
		}
	}
	if len(ids) != 2 || ids[compromisedKeyID]+ids[distrustedRootID] != trustFixtureFindings {
		t.Errorf("trust findings by pattern = %v, want both patterns and %d findings", ids, trustFixtureFindings)
	}
	if checked == 0 {
		t.Fatal("no verify command was run")
	}
}

// A scan that matches nothing says nothing about the listing: the control
// bundle's text, JSON and SARIF reports name neither pattern, its texts, the
// category or the incident, and print no all-clear line.
func TestTrustControlOutputSaysNothing(t *testing.T) {
	control := filepath.Join(trustFixture, "control")
	listing := regexp.MustCompile(`(?i)emudhra|emsign|` + compromisedKeyID + `|` + distrustedRootID + `|` +
		regexp.QuoteMeta(compromisedKeyName) + `|` + regexp.QuoteMeta(distrustedRootName) + `|trust findings?|─ Trust\b|"Trust"|compromised|distrusted`)
	for _, args := range [][]string{{"--no-color"}, {"--format", "json"}, {"--format", "sarif"}} {
		out := runTrust(t, scanCmd, control, args...)
		if out.err != "" || out.code != 0 {
			t.Errorf("scan control %s: exit %d, error %q", strings.Join(args, " "), out.code, out.err)
		}
		if m := listing.FindString(out.stdout); m != "" {
			t.Errorf("scan control %s printed %q", strings.Join(args, " "), m)
		}
	}
}

// trustSARIF is the part of the SARIF log the trust cells read.
type trustSARIF struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID      string `json:"id"`
					HelpURI string `json:"helpUri"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID     string         `json:"ruleId"`
			Properties map[string]any `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

// gate's SARIF report carries both patterns, each rule with its page as
// helpUri, and each result with the trust fields under the names the JSON
// report uses, the rule number (trustRule) as an integer.
func TestTrustSARIF(t *testing.T) {
	out := runTrust(t, gateCmd, trustFixture, "--format", "sarif")
	if out.err != "" || out.code != 1 {
		t.Fatalf("gate --format sarif: exit %d, error %q, want exit 1", out.code, out.err)
	}
	var log trustSARIF
	if err := json.Unmarshal([]byte(out.stdout), &log); err != nil {
		t.Fatalf("gate --format sarif printed output that is not JSON: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("%d runs, want 1", len(log.Runs))
	}
	rules := map[string]int{}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		id := trustPatternID(r.ID)
		if id == "" {
			continue
		}
		rules[id]++
		if r.HelpURI != trustPages[id] {
			t.Errorf("rule %s: helpUri %q, want %q", r.ID, r.HelpURI, trustPages[id])
		}
	}
	if len(rules) != 2 {
		t.Errorf("trust rules by pattern = %v, want both patterns", rules)
	}
	results := 0
	for _, r := range log.Runs[0].Results {
		id := trustPatternID(r.RuleID)
		if id == "" {
			continue
		}
		results++
		fields := []string{"kind", "matchedValue", "valueType", "keyUse"}
		if id == distrustedRootID {
			fields = append(fields, "distrustDate")
		}
		for _, field := range fields {
			if v, _ := r.Properties[field].(string); v == "" {
				t.Errorf("result %s: no %s property: %v", r.RuleID, field, r.Properties)
			}
		}
		// The rule number is a JSON number under trustRule: 1 or 2 for a
		// compromised key, 3 or 4 for the removed root.
		wantRules := []float64{1, 2}
		if id == distrustedRootID {
			wantRules = []float64{3, 4}
		}
		if rule, isNumber := r.Properties["trustRule"].(float64); !isNumber || !slices.Contains(wantRules, rule) {
			t.Errorf("result %s: trustRule %v (%T), want the number %v", r.RuleID, r.Properties["trustRule"], r.Properties["trustRule"], wantRules)
		}
		if _, has := r.Properties["rule"]; has {
			t.Errorf("result %s: carries rule; the rule number's key is trustRule", r.RuleID)
		}
	}
	if results != trustFixtureFindings {
		t.Errorf("%d trust results, want %d", results, trustFixtureFindings)
	}
}

// patterns search eMudhra lists the two patterns, and patterns list carries
// each with its severity and its page as its one reference.
func TestTrustPatternsListedAndSearchable(t *testing.T) {
	out, err := executePatterns(t, "patterns", "search", "eMudhra")
	if err != nil {
		t.Fatalf("patterns search eMudhra: %v\n%s", err, out)
	}
	got := textTableIDs(t, out)
	slices.Sort(got)
	if want := []string{compromisedKeyID, distrustedRootID}; !slices.Equal(got, want) {
		t.Errorf("patterns search eMudhra lists %v, want %v", got, want)
	}

	severities := map[string]string{compromisedKeyID: "CRITICAL", distrustedRootID: "HIGH"}
	listed := 0
	for _, p := range patternsJSON(t, "patterns", "list", "--format", "json").Patterns {
		if !strings.HasPrefix(p.ID, "TRUST-") {
			continue
		}
		listed++
		if p.Severity != severities[p.ID] || p.Category != "Trust" {
			t.Errorf("%s: severity %s, category %s; want %s, Trust", p.ID, p.Severity, p.Category, severities[p.ID])
		}
		if !slices.Equal(p.References, []string{trustPages[p.ID]}) {
			t.Errorf("%s: references %v, want [%s]", p.ID, p.References, trustPages[p.ID])
		}
	}
	if listed != 2 {
		t.Errorf("patterns list carries %d TRUST- patterns, want 2", listed)
	}
}

// reportBlocks returns the detailed finding blocks of a text report, each
// from its "┌── Finding #" line to its closing line.
func reportBlocks(report string) []string {
	var blocks, current []string
	in := false
	for _, line := range strings.Split(report, "\n") {
		switch {
		case strings.HasPrefix(line, "  ┌── Finding #"):
			in, current = true, []string{line}
		case in && strings.HasPrefix(line, "  └──"):
			blocks = append(blocks, strings.Join(append(current, line), "\n"))
			in = false
		case in:
			current = append(current, line)
		}
	}
	return blocks
}

// trustTextRows are the rows of a text block that hold words rather than
// the file's lines or path.
var trustTextRows = []string{"  │   ", "  │ Fix: ", "  │ Impact: ", "  │ SPKI SHA-256: ", "  │ Certificate SHA-256: ", "  │ Signed by: "}

// In the text report on the fixture, every trust block shows its matched
// value and the listed key, a Fix, a Verify and its page, and no quantum
// verdict, no Guidance and no relative date; and every trust block prints
// before the first certificate inventory block.
func TestTrustTextBlocks(t *testing.T) {
	out := runTrust(t, scanCmd, trustFixture, "--no-color")
	firstInventory, lastTrust, trust := -1, -1, 0
	for i, b := range reportBlocks(out.stdout) {
		var id string
		switch {
		case strings.Contains(b, "│ Type: "+compromisedKeyName+"\n"):
			id = compromisedKeyID
		case strings.Contains(b, "│ Type: "+distrustedRootName+"\n"):
			id = distrustedRootID
		case strings.Contains(b, "│ Type: X.509 Certificate\n"):
			if firstInventory < 0 {
				firstInventory = i
			}
			continue
		default:
			continue
		}
		trust++
		lastTrust = i
		for _, want := range []string{"\n  │ Fix: ", "\n  │ Verify: awk 'NR>=", "\n  │ Reference: " + trustPages[id] + "\n"} {
			if !strings.Contains(b, want) {
				t.Errorf("block %d (%s) has no %q:\n%s", i+1, id, strings.TrimSpace(want), b)
			}
		}
		bySPKI := strings.Contains(b, "\n  │ SPKI SHA-256: ")
		bySignature := strings.Contains(b, "\n  │ Certificate SHA-256: ") && strings.Contains(b, "\n  │ Signed by: ")
		if bySPKI == bySignature {
			t.Errorf("block %d (%s) shows neither or both value forms:\n%s", i+1, id, b)
		}
		for _, absent := range []string{"Quantum:", "Guidance:"} {
			if strings.Contains(b, absent) {
				t.Errorf("block %d (%s) shows %q:\n%s", i+1, id, absent, b)
			}
		}
		for _, line := range strings.Split(b, "\n") {
			for _, row := range trustTextRows {
				if strings.HasPrefix(line, row) {
					if m := relativeTime.FindString(line); m != "" {
						t.Errorf("block %d (%s): relative time %q in %q", i+1, id, m, line)
					}
				}
			}
		}
	}
	if trust != trustFixtureFindings {
		t.Errorf("%d trust blocks, want %d", trust, trustFixtureFindings)
	}
	if firstInventory < 0 || lastTrust > firstInventory {
		t.Errorf("last trust block is #%d, first certificate inventory block #%d: trust blocks print first", lastTrust+1, firstInventory+1)
	}
}

// streamOrder matches the number the text report's stream gives a match as
// it is found, which follows the order the parallel workers find matches in
// and so differs between any two runs.
var streamOrder = regexp.MustCompile(`(?m)^(  \[[A-Z]+\] )#[0-9]+ +`)

// The date a scan runs on changes no finding, no exit code and no output but
// the time fields the capture normalizers blank, and the stream's numbering
// of matches in the order they were found: scan and gate before and
// after 2026-10-27, the date the removed root's texts name, print the same
// reports. The clock does reach the report, in its time fields, so the two
// runs do differ before normalizing.
func TestTrustOutputDoesNotDependOnTheDate(t *testing.T) {
	saved := clock
	t.Cleanup(func() { clock = saved })
	dates := []time.Time{
		time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
	}
	runs := []struct {
		cmd  *cobra.Command
		args []string
		date string // the form the report prints the start time in, or "" for none
	}{
		{scanCmd, []string{"--no-color"}, "2006-01-02 15:04:05"},
		{scanCmd, []string{"--format", "json"}, time.RFC3339},
		{scanCmd, []string{"--format", "sarif"}, ""},
		{gateCmd, []string{"--no-color"}, "2006-01-02 15:04:05"},
		{gateCmd, []string{"--format", "json"}, time.RFC3339},
		{gateCmd, []string{"--format", "sarif"}, ""},
	}
	for _, r := range runs {
		var outs []scanOutcome
		for _, at := range dates {
			clock = func() time.Time { return at }
			out := runTrust(t, r.cmd, trustFixture, r.args...)
			if r.date != "" && !strings.Contains(out.stdout, at.Format(r.date)) {
				t.Errorf("%s %s at %s: the report does not show the clock's time %q", r.cmd.Name(), strings.Join(r.args, " "), at, at.Format(r.date))
			}
			outs = append(outs, out)
		}
		if outs[0].code != 1 || outs[1].code != 1 {
			t.Errorf("%s %s: exit %d before and %d after, want 1 both times", r.cmd.Name(), strings.Join(r.args, " "), outs[0].code, outs[1].code)
		}
		for i := range outs {
			outs[i].stdout = streamOrder.ReplaceAllString(outs[i].stdout, "$1#<n> ")
		}
		before, after := normalizeScanOutput(outs[0]), normalizeScanOutput(outs[1])
		if before != after {
			t.Errorf("%s %s: output before and after 2026-10-27 differs at %s", r.cmd.Name(), strings.Join(r.args, " "), firstDifference(before, after))
		}
		if !strings.Contains(outs[0].stdout, compromisedKeyName) || !strings.Contains(outs[0].stdout, distrustedRootName) {
			t.Errorf("%s %s: the report does not carry both kinds", r.cmd.Name(), strings.Join(r.args, " "))
		}
	}
}

// shellWord is one word of a command as a shell splits it, for the commands
// the finding pages cite: a double-quoted string or a run of other text.
var shellWord = regexp.MustCompile(`"[^"]*"|[^\s"]+`)

// Every cryptoscan command the two finding pages cite names a subcommand and
// flags the tool registers, so no command on a page is a dead end.
func TestTrustPagesCiteRegisteredCommands(t *testing.T) {
	commands := map[string]*cobra.Command{"scan": scanCmd, "gate": gateCmd}
	cited := regexp.MustCompile("`(cryptoscan [^`]+)`")
	checked := 0
	for _, page := range []string{"trust-compromised-key.md", "trust-distrusted-root.md"} {
		data, err := os.ReadFile(filepath.Join("../../docs/findings", page))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range cited.FindAllStringSubmatch(string(data), -1) {
			words := shellWord.FindAllString(m[1], -1)
			cmd, ok := commands[words[1]]
			if !ok {
				t.Errorf("%s cites %q, whose subcommand %q is not scan or gate", page, m[1], words[1])
				continue
			}
			args := make([]string, 0, len(words)-2)
			for _, w := range words[2:] {
				args = append(args, strings.Trim(w, `"`))
			}
			resetScanFlags(t)
			resetGateFlags(t)
			if err := cmd.ParseFlags(args); err != nil {
				t.Errorf("%s cites %q: %v", page, m[1], err)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("the pages cite no cryptoscan command, so this test checks nothing")
	}
}
