// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"maps"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// trustKeyTableFile is the key table the build embeds in the patterns package.
const trustKeyTableFile = "../../pkg/patterns/trust_keys.json"

// trustRunReport is the part of a JSON report these cases read.
type trustRunReport struct {
	FilesScanned int `json:"filesScanned"`
	Findings     []struct {
		ID       string            `json:"id"`
		File     string            `json:"file"`
		Line     int               `json:"line"`
		Match    string            `json:"match"`
		Verify   string            `json:"verify"`
		Metadata map[string]string `json:"metadata"`
	} `json:"findings"`
}

// runTrustJSON runs scan or gate on target with --format json and args, and
// returns the report it printed and the code it would exit with.
func runTrustJSON(t *testing.T, cmd *cobra.Command, target string, args ...string) (trustRunReport, int) {
	t.Helper()
	args = append([]string{"--format", "json"}, args...)
	out := runTrust(t, cmd, target, args...)
	if out.err != "" {
		t.Fatalf("%s %s %s: %s", cmd.Name(), target, strings.Join(args, " "), out.err)
	}
	var report trustRunReport
	if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
		t.Fatalf("%s %s %s printed output that is not JSON: %v", cmd.Name(), target, strings.Join(args, " "), err)
	}
	return report, out.code
}

// findingsByPattern counts a report's findings by pattern ID, which is the
// finding ID without its "-<line>-<column>" suffix.
func findingsByPattern(report trustRunReport) map[string]int {
	counts := map[string]int{}
	for _, f := range report.Findings {
		id := f.ID
		for i := 0; i < 2; i++ {
			if j := strings.LastIndex(id, "-"); j > 0 {
				id = id[:j]
			}
		}
		counts[id]++
	}
	return counts
}

// trustKeyRow is the part of a key table row these cases read.
type trustKeyRow struct {
	SPKISHA256 string `json:"spkiSha256"`
	Use        string `json:"use"`
}

// trustKeyTable returns the rows of the key table file.
func trustKeyTable(t *testing.T) []trustKeyRow {
	t.Helper()
	data, err := os.ReadFile(trustKeyTableFile)
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Keys []trustKeyRow `json:"keys"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatalf("%s: %v", trustKeyTableFile, err)
	}
	if len(table.Keys) == 0 {
		t.Fatalf("%s has no rows", trustKeyTableFile)
	}
	return table.Keys
}

// An ignore that names one Trust pattern's ID removes that pattern's findings
// and no other: scan and gate on the fixture with --ignore naming one ID list
// every finding of the other Trust pattern, and of every other pattern, that
// the same command lists with no ignore. gate exits 1 either way, since its
// default threshold is high. scan exits 1 while the CRITICAL compromised-key
// findings stand, and 0 when only the HIGH removed-root finding is left, since
// scan fails on CRITICAL findings alone by default.
func TestTrustIgnoreOneIDLeavesTheOther(t *testing.T) {
	cases := []struct {
		cmd    *cobra.Command
		ignore string
		left   string
		code   int
	}{
		{scanCmd, compromisedKeyID, distrustedRootID, 0},
		{scanCmd, distrustedRootID, compromisedKeyID, 1},
		{gateCmd, compromisedKeyID, distrustedRootID, 1},
		{gateCmd, distrustedRootID, compromisedKeyID, 1},
	}
	// unfiltered holds each command's findings by pattern with no ignore.
	unfiltered := map[*cobra.Command]map[string]int{}
	for _, tc := range cases {
		all, ok := unfiltered[tc.cmd]
		if !ok {
			report, _ := runTrustJSON(t, tc.cmd, trustFixture)
			all = findingsByPattern(report)
			if all[compromisedKeyID] == 0 || all[distrustedRootID] == 0 || all[compromisedKeyID]+all[distrustedRootID] != trustFixtureFindings {
				t.Errorf("%s --format json: findings by pattern %v, want both Trust patterns and %d trust findings", tc.cmd.Name(), all, trustFixtureFindings)
			}
			unfiltered[tc.cmd] = all
		}
		want := maps.Clone(all)
		delete(want, tc.ignore)

		report, code := runTrustJSON(t, tc.cmd, trustFixture, "--ignore", tc.ignore)
		if got := findingsByPattern(report); !maps.Equal(got, want) || got[tc.left] == 0 {
			t.Errorf("%s --format json --ignore %s: findings by pattern %v, want %v, the %s findings among them", tc.cmd.Name(), tc.ignore, got, want, tc.left)
		}
		if code != tc.code {
			t.Errorf("%s --format json --ignore %s: exit %d, want %d", tc.cmd.Name(), tc.ignore, code, tc.code)
		}
	}
}

// Every finding the JSON report on the fixture prints carries a Verify, and
// each Verify, run as printed with sh -c from where the scan was run and with
// the openssl on PATH, prints what its finding states, byte for byte: a trust
// finding's matchedValue, and for any other finding the line it points at. The
// case needs openssl, so it fails rather than skips when there is none, and it
// logs openssl version once, so the test log names the openssl the commands
// ran under.
func TestTrustVerifyRunAsPrinted(t *testing.T) {
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatalf("no openssl on PATH, so the printed Verify commands cannot run: %v", err)
	}
	version, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatalf("%s version: %v", bin, err)
	}
	t.Logf("openssl version: %s (%s)", strings.TrimSpace(string(version)), bin)

	report, _ := runTrustJSON(t, scanCmd, trustFixture)
	verifies, values := 0, 0
	for _, f := range report.Findings {
		if f.Verify == "" {
			t.Errorf("finding %s in %s carries no verify", f.ID, filepath.Base(f.File))
			continue
		}
		verifies++
		verify, file, line, match := f.Verify, f.File, f.Line, f.Match
		value, stated := f.Metadata["matchedValue"]
		if stated {
			values++
		}
		t.Run(f.ID+" "+filepath.Base(file), func(t *testing.T) {
			want := []byte(value)
			if !stated {
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.SplitAfter(data, []byte("\n"))
				if line < 1 || line > len(lines) || !bytes.Contains(lines[line-1], []byte(match)) {
					t.Fatalf("%s has no line %d holding %q", file, line, match)
				}
				want = lines[line-1]
			}
			cmd := exec.Command("sh", "-c", verify)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			got, err := cmd.Output()
			if err != nil {
				t.Fatalf("%v: %s\n %s", err, stderr.String(), verify)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("verify printed %q, want %q\n %s", got, want, verify)
			}
		})
	}
	t.Logf("the JSON report prints %d findings; %d carry a verify, %d of those a matchedValue", len(report.Findings), verifies, values)
	if values != trustFixtureFindings {
		t.Errorf("%d findings carry a verify and a matchedValue, want the %d trust findings", values, trustFixtureFindings)
	}
}

// committedCertificates returns the certificates of every file under dir.
// Each PEM block a file holds must parse as a certificate.
func committedCertificates(t *testing.T, dir string) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rest, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for {
			var block *pem.Block
			if block, rest = pem.Decode(rest); block == nil {
				return nil
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("%s: %v", path, err)
			}
			certs = append(certs, cert)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return certs
}

// committedCertificate returns the fixture's certificate whose subject common
// name is cn. Each certificate the fixture holds for that name has the same
// subject and Subject Key Identifier.
func committedCertificate(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	var found []*x509.Certificate
	for _, cert := range committedCertificates(t, trustFixture) {
		if cert.Subject.CommonName == cn {
			found = append(found, cert)
		}
	}
	if len(found) == 0 {
		t.Fatalf("the fixture holds no certificate for %q", cn)
	}
	for _, c := range found[1:] {
		if !bytes.Equal(c.RawSubject, found[0].RawSubject) || !bytes.Equal(c.SubjectKeyId, found[0].SubjectKeyId) {
			t.Fatalf("the fixture's certificates for %q differ in subject or Subject Key Identifier", cn)
		}
	}
	return found[0]
}

// A certificate is matched by the key that signed it, never by the issuer
// name or the Authority Key Identifier it carries: a leaf that copies EM OV
// TLS CA - G3C's subject as its issuer and that CA's Subject Key Identifier as
// its Authority Key Identifier, but is signed by a key made for this test,
// gives no trust finding. The fixture's own leaf, which carries the same
// issuer name and Authority Key Identifier and whose signature verifies under
// the G3C key, gives its compromised-key finding when scanned the same way, so
// the copy's result comes from its signature and not from how the file is
// read.
func TestTrustIssuerAndAKICopySignedByAnotherKeyIsNotAFinding(t *testing.T) {
	g3c := committedCertificate(t, "EM OV TLS CA - G3C")
	listed := map[string]string{}
	for _, k := range trustKeyTable(t) {
		listed[k.SPKISHA256] = k.Use
	}
	if use := listed[sha256Hex(g3c.RawSubjectPublicKeyInfo)]; use != "tls" {
		t.Fatalf("the G3C certificate's key is listed with use %q, want tls", use)
	}

	signer, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "issuer-copy.example"},
		DNSNames:     []string{"issuer-copy.example"},
		NotBefore:    time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 10, 19, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// The parent carries G3C's name and key identifier and no public key, so
	// the leaf names G3C as its issuer and is signed by signer.
	parent := &x509.Certificate{RawSubject: g3c.RawSubject, SubjectKeyId: g3c.SubjectKeyId}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &leafKey.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf.RawIssuer, g3c.RawSubject) || !bytes.Equal(leaf.AuthorityKeyId, g3c.SubjectKeyId) {
		t.Fatal("the leaf does not carry G3C's subject as its issuer and its Subject Key Identifier as its Authority Key Identifier")
	}
	if g3c.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
		t.Fatal("the leaf's signature verifies under the G3C key")
	}
	if _, ok := listed[sha256Hex(leaf.RawSubjectPublicKeyInfo)]; ok {
		t.Fatal("the leaf's own key is a listed key")
	}
	signerSPKI, err := x509.MarshalPKIXPublicKey(&signer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := listed[sha256Hex(signerSPKI)]; ok {
		t.Fatal("the signing key is a listed key")
	}

	leaves := committedCertificates(t, filepath.Join(trustFixture, "leaf"))
	if len(leaves) != 1 {
		t.Fatalf("the fixture's leaf directory holds %d certificates, want 1", len(leaves))
	}
	signed := leaves[0]
	if !bytes.Equal(signed.RawIssuer, g3c.RawSubject) || !bytes.Equal(signed.AuthorityKeyId, g3c.SubjectKeyId) {
		t.Fatal("the fixture's leaf does not carry G3C's subject as its issuer and its Subject Key Identifier as its Authority Key Identifier")
	}
	if err := g3c.CheckSignature(signed.SignatureAlgorithm, signed.RawTBSCertificate, signed.Signature); err != nil {
		t.Fatalf("the fixture's leaf's signature does not verify under the G3C key: %v", err)
	}

	// scanAlone scans a directory that holds only the certificate in
	// cert.pem, and returns the pattern IDs of its trust findings.
	scanAlone := func(cert []byte) []string {
		dir := t.TempDir()
		writeFixtureFile(t, filepath.Join(dir, "cert.pem"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})))
		report, _ := runTrustJSON(t, scanCmd, dir)
		if report.FilesScanned != 1 {
			t.Fatalf("filesScanned = %d, want 1", report.FilesScanned)
		}
		var ids []string
		for _, f := range report.Findings {
			if id := trustPatternID(f.ID); id != "" {
				ids = append(ids, id)
			}
		}
		return ids
	}
	if got := scanAlone(signed.Raw); len(got) != 1 || got[0] != compromisedKeyID {
		t.Fatalf("the fixture's leaf alone gives trust findings %v, want one %s", got, compromisedKeyID)
	}
	if got := scanAlone(der); len(got) != 0 {
		t.Errorf("trust findings %v on a leaf that only copies G3C's issuer name and Authority Key Identifier", got)
	}
}

// writePinFiles writes, under dir, a script that holds each SHA-256 digest in
// hex and in base64 and a curl --pinnedpubkey line that pins each, and an
// Android network security config whose <pin-set> pins each.
func writePinFiles(t *testing.T, dir string, digests [][]byte) {
	t.Helper()
	var values, pins []string
	for _, d := range digests {
		pin := base64.StdEncoding.EncodeToString(d)
		values = append(values, hex.EncodeToString(d), pin)
		pins = append(pins, pin)
	}
	script := "#!/bin/sh\nlisted='\n" + strings.Join(values, "\n") + "\n'\n" +
		"curl --pinnedpubkey 'sha256//" + strings.Join(pins, ";sha256//") + "' https://example.com/\n"
	var config strings.Builder
	config.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<network-security-config>\n    <domain-config>\n" +
		"        <domain includeSubdomains=\"true\">example.com</domain>\n        <pin-set>\n")
	for _, pin := range pins {
		config.WriteString("            <pin digest=\"SHA-256\">" + pin + "</pin>\n")
	}
	config.WriteString("        </pin-set>\n    </domain-config>\n</network-security-config>\n")
	writeFixtureFile(t, filepath.Join(dir, "pins.sh"), script)
	writeFixtureFile(t, filepath.Join(dir, "res", "xml", "network_security_config.xml"), config.String())
}

// findingPlaces counts a report's findings by finding ID, which is the
// pattern ID, line and column, and by file under dir.
func findingPlaces(t *testing.T, report trustRunReport, dir string) map[string]int {
	t.Helper()
	places := map[string]int{}
	for _, f := range report.Findings {
		rel, err := filepath.Rel(dir, f.File)
		if err != nil {
			t.Fatal(err)
		}
		places[f.ID+" "+filepath.ToSlash(rel)]++
	}
	return places
}

// A listed key's hash written as text is not a finding input. The fourteen
// values (the SPKI SHA-256 of the six listed TLS keys and of the removed root,
// each in hex and in base64) in a script, with a curl --pinnedpubkey line that
// pins the seven, give no finding of any kind, and an Android network
// security config whose <pin-set> pins the seven gives the findings it gives
// when it pins seven unlisted digests: the <pin-set> element is reported as
// certificate pinning whatever it pins. No trust finding is raised. The
// values are computed here from the key table, so no file in the tree holds
// them for this test.
func TestTrustListedKeyHashAsTextIsNotAFindingInput(t *testing.T) {
	var listed [][]byte
	for _, use := range []string{"tls", "root"} {
		for _, k := range trustKeyTable(t) {
			if k.Use != use {
				continue
			}
			sum, err := hex.DecodeString(k.SPKISHA256)
			if err != nil || len(sum) != sha256.Size {
				t.Fatalf("%s: spkiSha256 %q is not a SHA-256 in hex", trustKeyTableFile, k.SPKISHA256)
			}
			listed = append(listed, sum)
		}
	}
	if len(listed) != 7 {
		t.Fatalf("the key table holds %d TLS and root keys, want 7, whose hashes in hex and base64 are the fourteen values", len(listed))
	}
	// The unlisted digests are fixed, so that the two scans differ in the
	// listing of the values and in nothing a run could vary.
	unlisted := make([][]byte, len(listed))
	for i := range unlisted {
		sum := sha256.Sum256([]byte("unlisted " + strconv.Itoa(i)))
		unlisted[i] = sum[:]
	}

	scanPins := func(digests [][]byte) map[string]int {
		dir := t.TempDir()
		writePinFiles(t, dir, digests)
		report, _ := runTrustJSON(t, scanCmd, dir)
		if report.FilesScanned != 2 {
			t.Fatalf("filesScanned = %d, want 2: both files must be read for the findings to mean anything", report.FilesScanned)
		}
		return findingPlaces(t, report, dir)
	}
	got, want := scanPins(listed), scanPins(unlisted)
	t.Logf("findings on the listed values: %v", got)
	if !maps.Equal(got, want) {
		t.Errorf("findings %v on the listed values, %v on unlisted ones: the values must add or change no finding", got, want)
	}
	for place := range got {
		if trustPatternID(place) != "" || strings.HasSuffix(place, " pins.sh") {
			t.Errorf("finding %s on listed-key hashes written as text", place)
		}
	}
}
