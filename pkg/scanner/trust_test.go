// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

// trustFixture is the committed fixture: the sixteen certificates of the
// eight listed intermediate keys (tls, codesigning), the removed root (root),
// a certificate issued under a listed TLS key (leaf), and a control bundle of
// three unlisted roots (control).
const trustFixture = "../patterns/testdata/trust"

const (
	compromisedKeyID = "TRUST-COMPROMISED-KEY-001"
	distrustedRootID = "TRUST-DISTRUSTED-ROOT-001"
)

// trustFixes are the three Fix strings, by key use, as the finding pages
// word them.
var trustFixes = map[string]string{
	"tls":         "Replace the chain with one issued by a CA none of whose keys is listed, and remove this certificate from any bundle or pin set you ship.",
	"codeSigning": "Re-sign the artifacts with a certificate from a CA none of whose keys is listed and republish; a verifier that checks revocation rejects signatures under this key.",
	"root":        "Move the chain to a CA whose root stays trusted, and remove emSign ECC Root CA - G3 from any bundle you ship; Chrome removes it for all devices on 2026-10-27.",
}

// trustVerify are the two Verify commands, by value type, with LINE and FILE
// to fill in.
var trustVerify = map[string]string{
	"spkiSha256": `awk 'NR>=LINE' FILE | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'`,
	"certSha256": `awk 'NR>=LINE' FILE | openssl x509 -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'`,
}

func scanTrust(t *testing.T, cfg Config) *Results {
	t.Helper()
	cfg.MinSeverity = types.SeverityInfo
	results, err := New(cfg).Scan()
	if err != nil {
		t.Fatalf("scan %s: %v", cfg.Target, err)
	}
	return results
}

func trustFindings(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Category == "Trust" {
			out = append(out, f)
		}
	}
	return out
}

// headerLines returns the line number of each PEM certificate header in file.
func headerLines(t *testing.T, file string) []int {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for i, l := range strings.Split(string(data), "\n") {
		if strings.TrimSuffix(l, "\r") == "-----BEGIN CERTIFICATE-----" {
			lines = append(lines, i+1)
		}
	}
	return lines
}

// Every fixture certificate yields exactly one finding, at its header line,
// with the ID, rule number and key use its directory calls for, and the
// control bundle yields none.
func TestTrustFixtureGivesOneFindingPerCertificate(t *testing.T) {
	results := scanTrust(t, Config{Target: trustFixture})
	byLocation := map[string][]Finding{}
	for _, f := range trustFindings(results.Findings) {
		key := filepath.ToSlash(f.File) + ":" + strconv.Itoa(f.Line)
		byLocation[key] = append(byLocation[key], f)
	}

	want := map[string]struct{ id, rule, use string }{
		"tls":         {compromisedKeyID, "1", "tls"},
		"codesigning": {compromisedKeyID, "1", "codeSigning"},
		"root":        {distrustedRootID, "3", "root"},
		"leaf":        {compromisedKeyID, "2", "tls"},
	}
	expected := 0
	for dir, w := range want {
		files, _ := filepath.Glob(filepath.Join(trustFixture, dir, "*.pem"))
		if len(files) == 0 {
			t.Fatalf("no fixture certificates in %s", dir)
		}
		for _, file := range files {
			for _, line := range headerLines(t, file) {
				expected++
				key := filepath.ToSlash(file) + ":" + strconv.Itoa(line)
				got := byLocation[key]
				if len(got) != 1 {
					t.Errorf("%s: %d trust findings, want 1", key, len(got))
					continue
				}
				f := got[0]
				if !strings.HasPrefix(f.ID, w.id+"-") || f.Metadata["rule"] != w.rule || f.Metadata["keyUse"] != w.use {
					t.Errorf("%s: %s rule %q key use %q, want %s rule %s key use %s", key, f.ID, f.Metadata["rule"], f.Metadata["keyUse"], w.id, w.rule, w.use)
				}
			}
		}
	}
	if n := len(trustFindings(results.Findings)); n != expected {
		t.Errorf("%d trust findings on the fixture, want %d, one per listed certificate", n, expected)
	}
	for key := range byLocation {
		if strings.Contains(key, "/control/") {
			t.Errorf("the control bundle raised a trust finding at %s", key)
		}
	}
}

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The slots of each trust finding are the ruled ones: the ID suffix the
// matcher gives, the header as the match, the ruled severity, a Fix by key
// use, an empty Guidance, one reference, the Verify form by value type, and
// metadata that carries the matched value and its type.
func TestTrustFindingSlots(t *testing.T) {
	results := scanTrust(t, Config{Target: trustFixture})
	trust := trustFindings(results.Findings)
	if len(trust) == 0 {
		t.Fatal("no trust findings on the fixture")
	}
	for _, f := range trust {
		md := f.Metadata
		kindA := strings.HasPrefix(f.ID, compromisedKeyID+"-")
		if !kindA && !strings.HasPrefix(f.ID, distrustedRootID+"-") {
			t.Errorf("%s: unknown trust ID", f.ID)
			continue
		}
		pattern := distrustedRootID
		severity, reference := types.SeverityHigh, "https://github.com/csnp/cryptoscan/blob/main/docs/findings/trust-distrusted-root.md"
		if kindA {
			pattern = compromisedKeyID
			severity, reference = types.SeverityCritical, "https://github.com/csnp/cryptoscan/blob/main/docs/findings/trust-compromised-key.md"
		}
		if want := pattern + "-" + strconv.Itoa(f.Line) + "-0"; f.ID != want {
			t.Errorf("%s: ID, want %s", f.ID, want)
		}
		if f.Match != "-----BEGIN CERTIFICATE-----" || f.Column != 1 {
			t.Errorf("%s: match %q at column %d, want the header at column 1", f.ID, f.Match, f.Column)
		}
		if f.Severity != severity || f.Quantum != types.QuantumUnknown || f.Confidence != types.ConfidenceHigh {
			t.Errorf("%s: severity %s, quantum %s, confidence %s", f.ID, f.Severity, f.Quantum, f.Confidence)
		}
		if f.Fix != trustFixes[md["keyUse"]] || f.Fix == "" {
			t.Errorf("%s: fix %q is not the %q string", f.ID, f.Fix, md["keyUse"])
		}
		if f.Guidance != "" {
			t.Errorf("%s: guidance %q, want empty", f.ID, f.Guidance)
		}
		if !slices.Equal(f.References, []string{reference}) {
			t.Errorf("%s: references %q, want %q", f.ID, f.References, reference)
		}
		if !lowerHex64.MatchString(md["matchedValue"]) {
			t.Errorf("%s: matchedValue %q is not lowercase hex", f.ID, md["matchedValue"])
		}
		rule := md["rule"]
		wantType := map[string]string{"1": "spkiSha256", "2": "certSha256", "3": "spkiSha256", "4": "certSha256"}[rule]
		if wantType == "" || md["valueType"] != wantType {
			t.Errorf("%s: rule %q, value type %q", f.ID, rule, md["valueType"])
		}
		if signed := rule == "2" || rule == "4"; signed != lowerHex64.MatchString(md["issuerSpkiSha256"]) {
			t.Errorf("%s: rule %s, issuerSpkiSha256 %q", f.ID, rule, md["issuerSpkiSha256"])
		}
		wantKind, dated := "compromisedCaKey", false
		if !kindA {
			wantKind, dated = "distrustedRoot", true
		}
		if md["kind"] != wantKind || (md["distrustDate"] == "2026-10-27") != dated {
			t.Errorf("%s: kind %q, distrustDate %q", f.ID, md["kind"], md["distrustDate"])
		}
		quoted := f.File
		if strings.ContainsAny(quoted, " '\"$`\\") {
			t.Fatalf("fixture path %q needs quoting; the test compares the plain form", quoted)
		}
		want := strings.NewReplacer("LINE", strconv.Itoa(f.Line), "FILE", quoted).Replace(trustVerify[md["valueType"]])
		if f.Verify != want {
			t.Errorf("%s: verify\n %q\nwant\n %q", f.ID, f.Verify, want)
		}
		if f.MigrationStatus != "" || f.QRAMMMapping != nil {
			t.Errorf("%s: carries quantum migration fields %q %v", f.ID, f.MigrationStatus, f.QRAMMMapping)
		}
		for _, text := range []string{f.Description, f.Fix, f.Impact} {
			if strings.Contains(strings.ToLower(text), "quantum-safe") || strings.Contains(text, "PQC") {
				t.Errorf("%s: quantum migration text %q", f.ID, text)
			}
		}
	}
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

// runVerify runs a Verify command as printed, with openssl resolving to bin,
// and returns what it wrote to standard output.
func runVerify(t *testing.T, bin, command string) []byte {
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

// Each printed Verify, run as printed, prints the finding's matched value
// byte for byte, under every openssl given. A copy of the fixture with CRLF
// line endings and a bundle holding several certificates are checked as well.
func TestTrustVerifyPrintsTheMatchedValue(t *testing.T) {
	bins := opensslBinaries(t)

	dir := t.TempDir()
	root, _ := filepath.Glob(filepath.Join(trustFixture, "root", "*.pem"))
	tls, _ := filepath.Glob(filepath.Join(trustFixture, "tls", "*.pem"))
	leaf, _ := filepath.Glob(filepath.Join(trustFixture, "leaf", "*.pem"))
	control, _ := filepath.Glob(filepath.Join(trustFixture, "control", "*.pem"))
	if len(root) == 0 || len(tls) == 0 || len(leaf) == 0 || len(control) == 0 {
		t.Fatal("fixture certificates missing")
	}
	var bundle, crlf []byte
	for _, f := range []string{control[0], tls[0], leaf[0], root[0]} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		bundle = append(bundle, data...)
	}
	crlf = bytes.ReplaceAll(bundle, []byte("\n"), []byte("\r\n"))
	if err := os.WriteFile(filepath.Join(dir, "bundle.pem"), bundle, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle-crlf.pem"), crlf, 0o644); err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, target := range []string{trustFixture, dir} {
		for _, f := range trustFindings(scanTrust(t, Config{Target: target}).Findings) {
			for _, bin := range bins {
				got := runVerify(t, bin, f.Verify)
				if !bytes.Equal(got, []byte(f.Metadata["matchedValue"])) {
					t.Errorf("%s under %s: Verify printed %q, want %q\n %s", f.ID, bin, got, f.Metadata["matchedValue"], f.Verify)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no Verify command was run")
	}
}

// The control bundle and the repository's own crypto samples raise no trust
// finding.
func TestTrustControlAndSamplesRaiseNone(t *testing.T) {
	for _, target := range []string{filepath.Join(trustFixture, "control"), "../../crypto-samples"} {
		results := scanTrust(t, Config{Target: target})
		if len(results.Findings) == 0 {
			t.Fatalf("%s gave no findings at all; the scan did not read it", target)
		}
		if n := len(trustFindings(results.Findings)); n != 0 {
			t.Errorf("%s: %d trust findings, want 0", target, n)
		}
	}
}

// Trust findings are not in the migration readiness score: the fixture's
// score is the score with both trust IDs ignored.
func TestTrustFindingsAreNotInTheReadinessScore(t *testing.T) {
	with := scanTrust(t, Config{Target: trustFixture})
	without := scanTrust(t, Config{Target: trustFixture, IgnoreIDs: []string{compromisedKeyID, distrustedRootID}})
	if len(trustFindings(with.Findings)) == 0 {
		t.Fatal("no trust findings on the fixture")
	}
	if len(trustFindings(without.Findings)) != 0 {
		t.Fatal("ignoring both IDs left trust findings")
	}
	a, b := with.MigrationScore, without.MigrationScore
	if a.Score != b.Score || a.Level != b.Level || a.TotalCount != b.TotalCount {
		t.Errorf("score %.4f %s over %d with trust findings, %.4f %s over %d with them ignored", a.Score, a.Level, a.TotalCount, b.Score, b.Level, b.TotalCount)
	}
	if !reflect.DeepEqual(a.QRAMMReadiness, b.QRAMMReadiness) {
		t.Errorf("QRAMM levels %+v with trust findings, %+v with them ignored", *a.QRAMMReadiness, *b.QRAMMReadiness)
	}
}

// A file holding a certificate of each kind gives two findings, one per block.
func TestTrustFileHoldingBothKindsGivesTwoFindings(t *testing.T) {
	root, _ := filepath.Glob(filepath.Join(trustFixture, "root", "*.pem"))
	tls, _ := filepath.Glob(filepath.Join(trustFixture, "tls", "*.pem"))
	if len(root) == 0 || len(tls) == 0 {
		t.Fatal("fixture certificates missing")
	}
	var chain []byte
	for _, f := range []string{tls[0], root[0]} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, data...)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "chain.pem"), chain, 0o644); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range trustFindings(scanTrust(t, Config{Target: dir}).Findings) {
		ids = append(ids, trustPatternOf(f.ID))
	}
	slices.Sort(ids)
	if want := []string{compromisedKeyID, distrustedRootID}; !slices.Equal(ids, want) {
		t.Errorf("chain.pem gave %q, want %q", ids, want)
	}
}

// Where a listed certificate sits does not lower its finding: in a test
// directory, under docs, in a test source file, and pasted into Markdown,
// which a scan reads when documentation is included, it keeps the ruled
// severity.
func TestTrustFindingKeepsItsSeverityInTestsAndDocs(t *testing.T) {
	leaf, _ := filepath.Glob(filepath.Join(trustFixture, "leaf", "*.pem"))
	if len(leaf) == 0 {
		t.Fatal("no leaf fixture")
	}
	data, err := os.ReadFile(leaf[0])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string][]byte{
		"pkg/test/ca.pem":     data,
		"site/docs/ca.pem":    data,
		"notes/setup.md":      append([]byte("Install this certificate:\n\n```\n"), append(data, []byte("```\n")...)...),
		"internal/ca_test.go": append([]byte("package internal\n\nconst caPEM = `\n"), append(data, []byte("`\n")...)...),
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]types.Severity{}
	for _, f := range trustFindings(scanTrust(t, Config{Target: dir, IncludeDocs: true}).Findings) {
		rel, _ := filepath.Rel(dir, f.File)
		got[filepath.ToSlash(rel)] = f.Severity
	}
	for name := range files {
		if sev, ok := got[name]; !ok || sev != types.SeverityCritical {
			t.Errorf("%s: trust finding severity %v (found %v), want CRITICAL", name, sev, ok)
		}
	}
}

// --ignore with one kind's own ID removes only that kind; the help's
// certificate examples remove neither.
func TestTrustIgnoreRemovesOnlyTheNamedKind(t *testing.T) {
	kinds := func(cfg Config) []string {
		set := map[string]bool{}
		for _, f := range trustFindings(scanTrust(t, cfg).Findings) {
			set[trustPatternOf(f.ID)] = true
		}
		var out []string
		for k := range set {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	both := []string{compromisedKeyID, distrustedRootID}
	cases := []struct {
		name string
		cfg  Config
		want []string
	}{
		{"no ignore", Config{Target: trustFixture}, both},
		{"CERT-* and Certificate", Config{Target: trustFixture, IgnoreIDs: []string{"RSA-001", "CERT-*"}, IgnoreCategories: []string{"Certificate", "Library Import"}}, both},
		{"kind A's ID", Config{Target: trustFixture, IgnoreIDs: []string{compromisedKeyID}}, []string{distrustedRootID}},
		{"kind B's ID", Config{Target: trustFixture, IgnoreIDs: []string{distrustedRootID}}, []string{compromisedKeyID}},
	}
	for _, c := range cases {
		if got := kinds(c.cfg); !slices.Equal(got, c.want) {
			t.Errorf("%s: trust kinds %q, want %q", c.name, got, c.want)
		}
	}
}

// The fixture holds the sixteen intermediate certificates, the removed root,
// one leaf, and three control roots.
func TestTrustFixtureInventory(t *testing.T) {
	want := map[string]int{"tls": 12, "codesigning": 4, "root": 1, "leaf": 1, "control": 3}
	for dir, n := range want {
		files, _ := filepath.Glob(filepath.Join(trustFixture, dir, "*.pem"))
		count := 0
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for rest := data; ; {
				var b *pem.Block
				if b, rest = pem.Decode(rest); b == nil {
					break
				}
				count++
			}
		}
		if count != n {
			t.Errorf("%s holds %d certificates, want %d", dir, count, n)
		}
	}
}

// trustPatternOf returns the pattern ID of a finding ID, which the matcher
// writes as <pattern>-<line>-<column>.
func trustPatternOf(id string) string {
	for n := 0; n < 2; n++ {
		if i := strings.LastIndex(id, "-"); i >= 0 {
			id = id[:i]
		}
	}
	return id
}
