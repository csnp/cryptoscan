// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"go/parser"
	"go/token"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/cryptoscan/pkg/analyzer"
)

const (
	trustFixtureDir  = "testdata/trust"
	trustCapturedDir = "testdata/trust-captured"
	trustBugURL      = "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449"
	trustBlogURL     = "https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/"
)

// fixtureUse is the key use of the rows each fixture directory makes.
var fixtureUse = map[string]string{"tls": "tls", "codesigning": "codeSigning", "root": "root"}

// fixtureBlock is one certificate block of a fixture file.
type fixtureBlock struct {
	path  string
	dir   string // tls, codesigning, root, leaf or control
	index int    // index of the header line in lines
	lines []string
	der   []byte
	cert  *x509.Certificate
}

// readFixtureBlocks returns every certificate block in the fixture files of
// the given directories, reading lines as the scanner does.
func readFixtureBlocks(t *testing.T, dirs ...string) []fixtureBlock {
	t.Helper()
	var blocks []fixtureBlock
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(trustFixtureDir, dir, "*.crt"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no fixture certificates in %s (%v)", dir, err)
		}
		for _, file := range files {
			lines := readLines(t, file)
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			index := 0
			for rest := data; ; {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				for index < len(lines) && lines[index] != pemCertificateBegin {
					index++
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatalf("%s: %v", file, err)
				}
				blocks = append(blocks, fixtureBlock{path: file, dir: dir, index: index, lines: lines, der: block.Bytes, cert: cert})
				index++
			}
		}
	}
	return blocks
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

// Every row of the embedded key table is what the fixture certificates give:
// the certificate hashes, the SPKI hash and DER, the subject common name the
// certificates share, the use of the directory they sit in, and the listing.
func TestTrustKeyTableRecomputesFromFixtures(t *testing.T) {
	type group struct {
		dir   string
		spki  []byte
		name  string
		certs []string
	}
	groups := map[string]*group{}
	for _, b := range readFixtureBlocks(t, "tls", "codesigning", "root") {
		spki := sha256Hex(b.cert.RawSubjectPublicKeyInfo)
		g, ok := groups[spki]
		if !ok {
			g = &group{dir: b.dir, spki: b.cert.RawSubjectPublicKeyInfo, name: b.cert.Subject.CommonName}
			groups[spki] = g
		}
		if g.dir != b.dir {
			t.Errorf("key %s has certificates in %s and %s", spki, g.dir, b.dir)
		}
		if g.name != b.cert.Subject.CommonName {
			t.Errorf("key %s has certificates named %q and %q", spki, g.name, b.cert.Subject.CommonName)
		}
		if name := filepath.Base(b.path); name != sha256Hex(b.der)+".crt" {
			t.Errorf("%s is not named by its SHA-256 %s", b.path, sha256Hex(b.der))
		}
		g.certs = append(g.certs, sha256Hex(b.der))
	}

	table := trustKeys()
	if len(table.keys) != len(groups) {
		t.Errorf("the key table has %d rows; the fixture certificates have %d keys", len(table.keys), len(groups))
	}
	for i, k := range table.keys {
		g, ok := groups[k.SPKISHA256]
		if !ok {
			t.Errorf("row %d: no fixture certificate has SPKI SHA-256 %s", i, k.SPKISHA256)
			continue
		}
		slices.Sort(g.certs)
		if !slices.Equal(k.CertSHA256, g.certs) {
			t.Errorf("row %d: certSha256 = %q, the fixture certificates hash to %q", i, k.CertSHA256, g.certs)
		}
		if want := base64.StdEncoding.EncodeToString(g.spki); k.SPKIDER != want {
			t.Errorf("row %d: spkiDer is not the certificates' SubjectPublicKeyInfo", i)
		}
		if k.Name != g.name || k.Name == "" {
			t.Errorf("row %d: name %q, the certificates' subject common name is %q", i, k.Name, g.name)
		}
		if k.Use != fixtureUse[g.dir] {
			t.Errorf("row %d: use = %q, the certificates are in %s", i, k.Use, g.dir)
		}
		wantStatus, wantDate := "compromised", ""
		if g.dir == "root" {
			wantStatus, wantDate = "distrusted", "2026-10-27"
		}
		if k.Status != wantStatus || k.DistrustDate != wantDate {
			t.Errorf("row %d: status %q, distrustDate %q; want %q, %q", i, k.Status, k.DistrustDate, wantStatus, wantDate)
		}
		// The listing's two pages, sorted.
		if !slices.Equal(k.Source, []string{trustBlogURL, trustBugURL}) || k.Reported != "2026-10-17" {
			t.Errorf("row %d: source %q, reported %q", i, k.Source, k.Reported)
		}
	}

	// The rows are sorted by SPKI hash, and they are the eight keys, six TLS
	// and two code signing, and the removed root.
	uses := map[string]int{}
	for i, k := range table.keys {
		uses[k.Use]++
		if i > 0 && table.keys[i-1].SPKISHA256 >= k.SPKISHA256 {
			t.Errorf("row %d: spkiSha256 %s does not sort after row %d's %s", i, k.SPKISHA256, i-1, table.keys[i-1].SPKISHA256)
		}
	}
	if want := map[string]int{"tls": 6, "codeSigning": 2, "root": 1}; !maps.Equal(uses, want) {
		t.Errorf("rows by use = %v, want %v", uses, want)
	}
}

// keyTableFile and keyTableRow spell the key table file format field by
// field, in the format's order, apart from the reader's types, so that a
// field moved or dropped in the reader or in internal/trustgen does not move
// the format with it.
type keyTableFile struct {
	SchemaVersion int            `json:"schemaVersion"`
	Keys          []*keyTableRow `json:"keys"`
}

type keyTableRow struct {
	SPKISHA256   string   `json:"spkiSha256"`
	Name         string   `json:"name"`
	CertSHA256   []string `json:"certSha256"`
	SPKIDER      string   `json:"spkiDer"`
	Use          string   `json:"use"`
	Source       []string `json:"source"`
	Reported     string   `json:"reported"`
	Status       string   `json:"status"`
	DistrustDate string   `json:"distrustDate,omitempty"`
}

// The embedded key table is in the key table file format. Parsed, sorted
// (rows by spkiSha256, each row's certSha256 and source ascending) and
// written again in the format's field order by a json.Encoder with HTML
// escaping off and a two-space indent, it is the same bytes. Its
// schemaVersion is 1, and a row carries distrustDate exactly when its status
// is distrusted. A table edited by hand, written by another encoder or
// carrying a field the format does not have fails.
func TestTrustKeyTableIsInTheFileFormat(t *testing.T) {
	var file keyTableFile
	if err := json.Unmarshal(trustKeysJSON, &file); err != nil {
		t.Fatal(err)
	}
	if file.SchemaVersion != 1 {
		t.Errorf("schemaVersion %d, want 1", file.SchemaVersion)
	}
	for _, k := range file.Keys {
		if (k.DistrustDate != "") != (k.Status == trustStatusDistrusted) {
			t.Errorf("key %s: status %q with distrustDate %q; the date is there exactly when the status is distrusted", k.SPKISHA256, k.Status, k.DistrustDate)
		}
		slices.Sort(k.CertSHA256)
		slices.Sort(k.Source)
	}
	slices.SortFunc(file.Keys, func(a, b *keyTableRow) int { return strings.Compare(a.SPKISHA256, b.SPKISHA256) })

	var want bytes.Buffer
	enc := json.NewEncoder(&want)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(file); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(trustKeysJSON, want.Bytes()) {
		t.Errorf("trust_keys.json is not in the key table file format; regenerate it with go generate ./pkg/patterns. %s", firstDifference(trustKeysJSON, want.Bytes()))
	}
}

// firstDifference names the first line on which a file and the bytes the
// format writes differ.
func firstDifference(file, format []byte) string {
	f, w := strings.Split(string(file), "\n"), strings.Split(string(format), "\n")
	for i := 0; i < len(f) && i < len(w); i++ {
		if f[i] != w[i] {
			return fmt.Sprintf("Line %d is %q; the format writes %q.", i+1, f[i], w[i])
		}
	}
	return fmt.Sprintf("The file has %d lines; the format writes %d.", len(f), len(w))
}

// The reader refuses a key table it does not know, with an error, rather
// than reading it as fewer rows or none, which would read as nothing found:
// a schemaVersion other than 1, or none; a table with no rows; a row that is
// null, or whose use or status is outside the format's sets; a row that
// carries distrustDate when its status is not distrusted, or lacks it when it
// is; and a row whose spkiSha256 is not the hash of its spkiDer.
func TestTrustKeyTableReaderRefusesATableItDoesNotKnow(t *testing.T) {
	// edited returns the embedded table with one edit made to it.
	edited := func(edit func(file map[string]any, rows []map[string]any)) []byte {
		t.Helper()
		var file map[string]any
		if err := json.Unmarshal(trustKeysJSON, &file); err != nil {
			t.Fatal(err)
		}
		var rows []map[string]any
		for _, r := range file["keys"].([]any) {
			rows = append(rows, r.(map[string]any))
		}
		edit(file, rows)
		data, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	// rowOf returns the first row of a status.
	rowOf := func(rows []map[string]any, status string) map[string]any {
		t.Helper()
		for _, r := range rows {
			if r["status"] == status {
				return r
			}
		}
		t.Fatalf("the key table has no %s row", status)
		return nil
	}
	// parse reads a table and fails the test on a panic, so that a table the
	// reader cannot read is reported as one rather than ending the run.
	parse := func(t *testing.T, data []byte) (table *trustTable, err error) {
		t.Helper()
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("the reader panicked (%v); want an error", p)
				table, err = nil, fmt.Errorf("panic: %v", p)
			}
		}()
		return parseTrustTable(data)
	}

	// The table as embedded is read whole, so each refusal below is its
	// edit's doing.
	if table, err := parse(t, edited(func(map[string]any, []map[string]any) {})); err != nil || len(table.keys) != len(trustKeys().keys) {
		t.Fatalf("the embedded table, decoded and encoded again, is not read whole: %v", err)
	}
	cases := []struct {
		name string
		edit func(file map[string]any, rows []map[string]any)
	}{
		{"schemaVersion 2", func(file map[string]any, _ []map[string]any) { file["schemaVersion"] = 2 }},
		{"no schemaVersion", func(file map[string]any, _ []map[string]any) { delete(file, "schemaVersion") }},
		{"no rows", func(file map[string]any, _ []map[string]any) { file["keys"] = []any{} }},
		{"no keys list", func(file map[string]any, _ []map[string]any) { delete(file, "keys") }},
		{"a null row", func(file map[string]any, _ []map[string]any) { file["keys"] = append(file["keys"].([]any), nil) }},
		{"a row whose use is outside the set", func(_ map[string]any, rows []map[string]any) { rows[0]["use"] = "codesigning" }},
		{"a row whose status is outside the set", func(_ map[string]any, rows []map[string]any) { rows[0]["status"] = "revoked" }},
		{"a compromised row with a distrustDate", func(_ map[string]any, rows []map[string]any) {
			rowOf(rows, trustStatusCompromised)["distrustDate"] = "2026-10-27"
		}},
		{"a distrusted row without a distrustDate", func(_ map[string]any, rows []map[string]any) {
			delete(rowOf(rows, trustStatusDistrusted), "distrustDate")
		}},
		{"a row whose spkiSha256 is another row's", func(_ map[string]any, rows []map[string]any) { rows[0]["spkiSha256"] = rows[1]["spkiSha256"] }},
	}
	for _, c := range cases {
		data := edited(c.edit)
		t.Run(c.name, func(t *testing.T) {
			table, err := parse(t, data)
			switch {
			case err == nil:
				t.Errorf("read as a table of %d rows, want it refused", len(table.keys))
			case table != nil:
				t.Errorf("refused (%v) and still returned a table", err)
			default:
				t.Logf("refused: %v", err)
			}
		})
	}
}

// readCaptured returns the first column of each line of a captured-values
// file, keyed to the rest of the line.
func readCaptured(t *testing.T, name string) map[string]string {
	t.Helper()
	values := map[string]string{}
	for _, line := range readLines(t, filepath.Join(trustCapturedDir, name)) {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		value, rest, _ := strings.Cut(line, " ")
		values[value] = rest
	}
	return values
}

// The table's certificate hashes are the 16 values the Mozilla bug lists,
// each emSign-issued certificate is one key with its Sectigo cross-signed
// copy, and the six TLS keys' SPKI hashes are OneCRL's pubKeyHash values.
func TestTrustKeyTableMatchesCapturedValues(t *testing.T) {
	bug := readCaptured(t, "bugzilla-2083449-certificate-sha256.txt")
	if len(bug) != 16 {
		t.Fatalf("captured %d bug values, want 16", len(bug))
	}
	onecrl := readCaptured(t, "onecrl-pubkeyhash.txt")
	if len(onecrl) != 6 {
		t.Fatalf("captured %d OneCRL values, want 6", len(onecrl))
	}

	var tableCerts []string
	matchedOneCRL := map[string]bool{}
	for _, k := range trustKeys().keys {
		if k.Status != "compromised" {
			continue
		}
		tableCerts = append(tableCerts, k.CertSHA256...)
		// The two certificates of a key carry the same name in the bug's
		// comments, one in comment 0 and one in comment 2.
		var names, comments []string
		for _, c := range k.CertSHA256 {
			comment, name, _ := strings.Cut(bug[c], " ")
			names, comments = append(names, name), append(comments, comment)
		}
		slices.Sort(comments)
		if len(k.CertSHA256) != 2 || names[0] != names[1] || !slices.Equal(comments, []string{"0", "2"}) {
			t.Errorf("key %s: certificates %q are not one comment-0 and one comment-2 value of one name (%q, %q)", k.SPKISHA256, k.CertSHA256, names, comments)
		}
		spki, err := hex.DecodeString(k.SPKISHA256)
		if err != nil {
			t.Fatal(err)
		}
		b64 := base64.StdEncoding.EncodeToString(spki)
		if k.Use == "tls" {
			if _, ok := onecrl[b64]; !ok {
				t.Errorf("TLS key %s: base64 %s is not a OneCRL pubKeyHash", k.SPKISHA256, b64)
			}
			matchedOneCRL[b64] = true
		}
	}
	captured := make([]string, 0, len(bug))
	for v := range bug {
		captured = append(captured, v)
	}
	slices.Sort(captured)
	slices.Sort(tableCerts)
	if !slices.Equal(tableCerts, captured) {
		t.Errorf("the table's certificate values differ from the bug's:\n table %q\n bug   %q", tableCerts, captured)
	}
	if len(matchedOneCRL) != len(onecrl) {
		t.Errorf("%d of %d OneCRL values match a TLS key", len(matchedOneCRL), len(onecrl))
	}
}

// Every row has a fix for its use and a kind for its status.
func TestTrustTableRowsHaveAFixAndAKind(t *testing.T) {
	for _, k := range trustKeys().keys {
		if trustFixes[k.Use] == "" {
			t.Errorf("key %s: no fix for use %q", k.SPKISHA256, k.Use)
		}
		if trustKinds[k.Status] == "" || trustImpacts[trustKinds[k.Status]] == "" {
			t.Errorf("key %s: no kind or impact for status %q", k.SPKISHA256, k.Status)
		}
	}
}

// listedIssuer returns the row whose certificates issued c, found with the
// standard library's own chain check rather than the rule code.
func listedIssuer(t *testing.T, c *x509.Certificate) string {
	t.Helper()
	for _, b := range readFixtureBlocks(t, "tls", "codesigning") {
		if c.CheckSignatureFrom(b.cert) == nil {
			return sha256Hex(b.cert.RawSubjectPublicKeyInfo)
		}
	}
	return ""
}

// Each fixture certificate meets the rule its directory says: the eight keys'
// certificates rule 1, the removed root rule 3, the leaf rule 2 under the key
// that issued it, and no certificate of the control bundle any rule.
func TestTrustRulesOnEachFixtureCertificate(t *testing.T) {
	table := trustKeys()
	for _, b := range readFixtureBlocks(t, "tls", "codesigning", "root", "leaf", "control") {
		m, ok := matchTrustBlock(table, b.lines[b.index:])
		name := filepath.Join(b.dir, filepath.Base(b.path)) + ":" + strconv.Itoa(b.index+1)
		switch b.dir {
		case "control":
			if ok {
				t.Errorf("%s: control certificate met rule %d", name, m.rule)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: met no rule", name)
			continue
		}
		md := m.metadata()
		switch b.dir {
		case "tls", "codesigning":
			if m.rule != 1 || m.key.Use != fixtureUse[b.dir] || md["matchedValue"] != sha256Hex(b.cert.RawSubjectPublicKeyInfo) ||
				md["valueType"] != "spkiSha256" || md["kind"] != "compromisedCaKey" || md["issuerSpkiSha256"] != "" || md["distrustDate"] != "" {
				t.Errorf("%s: rule %d, metadata %v; want rule 1 by its own SPKI", name, m.rule, md)
			}
		case "root":
			if m.rule != 3 || m.key.Use != "root" || md["matchedValue"] != sha256Hex(b.cert.RawSubjectPublicKeyInfo) ||
				md["valueType"] != "spkiSha256" || md["kind"] != "distrustedRoot" || md["distrustDate"] != "2026-10-27" || md["issuerSpkiSha256"] != "" {
				t.Errorf("%s: rule %d, metadata %v; want rule 3 by its own SPKI", name, m.rule, md)
			}
		case "leaf":
			issuer := listedIssuer(t, b.cert)
			if issuer == "" {
				t.Fatalf("%s: no fixture intermediate issued the leaf", name)
			}
			if m.rule != 2 || m.key.Use != "tls" || md["matchedValue"] != sha256Hex(b.der) || md["valueType"] != "certSha256" ||
				md["issuerSpkiSha256"] != issuer || md["kind"] != "compromisedCaKey" {
				t.Errorf("%s: rule %d, metadata %v; want rule 2 under %s", name, m.rule, md, issuer)
			}
		}
	}
}

// generatedCert returns the DER of a certificate for pub signed by signer,
// with issuer standing in as the parent.
func generatedCert(t *testing.T, serial int64, pub any, signer *ecdsa.PrivateKey, isCA bool, issuer *x509.Certificate) ([]byte, *x509.Certificate) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "generated " + strconv.FormatInt(serial, 10)},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	parent := issuer
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, cert
}

func pemLines(der []byte) []string {
	text := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

func spkiOf(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Rules 2 and 4, and the order of the rules, on a table of generated keys:
// no certificate signed by one of the eight private keys is held here other
// than the fixture leaf, and none signed by the removed root other than the
// root itself.
func TestTrustRulesWithGeneratedKeys(t *testing.T) {
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	compromised, root, other := newKey(), newKey(), newKey()
	row := func(pub any, name, use, status, date string) map[string]any {
		spki := spkiOf(t, pub)
		r := map[string]any{"spkiSha256": sha256Hex(spki), "name": name, "certSha256": []string{}, "spkiDer": base64.StdEncoding.EncodeToString(spki),
			"use": use, "source": []string{trustBugURL}, "reported": "2026-10-17", "status": status}
		if date != "" {
			r["distrustDate"] = date
		}
		return r
	}
	// The names are the subjects of the certificates generated below for the
	// two keys, serials 2 and 1.
	data, err := json.Marshal(map[string]any{"schemaVersion": 1, "keys": []any{
		row(&compromised.PublicKey, "generated 2", "tls", "compromised", ""),
		row(&root.PublicKey, "generated 1", "root", "distrusted", "2026-10-27"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	table, err := parseTrustTable(data)
	if err != nil {
		t.Fatal(err)
	}
	compromisedSPKI := sha256Hex(spkiOf(t, &compromised.PublicKey))
	rootSPKI := sha256Hex(spkiOf(t, &root.PublicKey))

	_, rootCert := generatedCert(t, 1, &root.PublicKey, root, true, nil)
	_, compromisedCert := generatedCert(t, 2, &compromised.PublicKey, compromised, true, nil)
	_, otherCert := generatedCert(t, 3, &other.PublicKey, other, true, nil)

	cases := []struct {
		name      string
		der       []byte
		rule      int
		issuer    string
		kind      string
		valueType string
	}{}
	add := func(name string, der []byte, rule int, issuer, kind, valueType string) {
		cases = append(cases, struct {
			name      string
			der       []byte
			rule      int
			issuer    string
			kind      string
			valueType string
		}{name, der, rule, issuer, kind, valueType})
	}
	der, _ := generatedCert(t, 10, &other.PublicKey, compromised, false, compromisedCert)
	add("leaf signed by a compromised key", der, 2, compromisedSPKI, "compromisedCaKey", "certSha256")
	der, _ = generatedCert(t, 11, &other.PublicKey, root, true, rootCert)
	add("intermediate signed by a distrusted root", der, 4, rootSPKI, "distrustedRoot", "certSha256")
	der, _ = generatedCert(t, 12, &root.PublicKey, root, true, nil)
	add("the self-signed root meets rule 3, not 4", der, 3, "", "distrustedRoot", "spkiSha256")
	der, _ = generatedCert(t, 13, &compromised.PublicKey, root, true, rootCert)
	add("a compromised key signed by the root meets rule 1, not 4", der, 1, "", "compromisedCaKey", "spkiSha256")
	der, _ = generatedCert(t, 14, &root.PublicKey, compromised, true, compromisedCert)
	add("the root's key signed by a compromised key meets rule 2, not 3", der, 2, compromisedSPKI, "compromisedCaKey", "certSha256")
	der, _ = generatedCert(t, 15, &other.PublicKey, other, true, otherCert)
	add("an unlisted self-signed certificate", der, 0, "", "", "")

	for _, c := range cases {
		m, ok := matchTrustBlock(table, pemLines(c.der))
		if c.rule == 0 {
			if ok {
				t.Errorf("%s: met rule %d", c.name, m.rule)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: met no rule", c.name)
			continue
		}
		md := m.metadata()
		want := sha256Hex(c.der)
		if c.valueType == "spkiSha256" {
			cert, _ := x509.ParseCertificate(c.der)
			want = sha256Hex(cert.RawSubjectPublicKeyInfo)
		}
		if m.rule != c.rule || md["issuerSpkiSha256"] != c.issuer || md["kind"] != c.kind || md["valueType"] != c.valueType || md["matchedValue"] != want {
			t.Errorf("%s: rule %d, metadata %v; want rule %d, issuer %q, kind %q, %s %s", c.name, m.rule, md, c.rule, c.issuer, c.kind, c.valueType, want)
		}
		if _, dated := md["distrustDate"]; dated != (c.kind == "distrustedRoot") {
			t.Errorf("%s: distrustDate present = %v, want it on a distrusted-root finding only", c.name, dated)
		}
		if md["trustRule"] != strconv.Itoa(c.rule) {
			t.Errorf("%s: trustRule %q, want %q", c.name, md["trustRule"], strconv.Itoa(c.rule))
		}
		if _, has := md["rule"]; has {
			t.Errorf("%s: metadata carries rule; the rule number's key is trustRule", c.name)
		}
	}
}

// The block reader accepts what OpenSSL and LibreSSL read from the same lines
// and nothing looser, so a finding's Verify command always recomputes its
// value; anything else raises no finding.
func TestCertificateBlockReadsOnlyWhatOpenSSLReads(t *testing.T) {
	good := readFixtureBlocks(t, "root")[0]
	lines := good.lines[good.index:]
	end := slices.Index(lines, pemCertificateEnd)
	if end < 0 {
		t.Fatal("fixture root has no end line")
	}
	block := slices.Clone(lines[:end+1])
	edit := func(f func([]string) []string) []string { return f(slices.Clone(block)) }

	accept := map[string][]string{
		"as written": block,
		"CRLF line endings": edit(func(l []string) []string {
			for i := range l {
				l[i] += "\r"
			}
			return l
		}),
		"lines after it": append(slices.Clone(block), "trailing text", pemCertificateBegin),
	}
	tooLong := []string{pemCertificateBegin}
	for len(tooLong) <= maxCertificateLines {
		tooLong = append(tooLong, "AAAA")
	}
	tooLong = append(tooLong, pemCertificateEnd)
	reject := map[string][]string{
		"indented header":         edit(func(l []string) []string { l[0] = "  " + l[0]; return l }),
		"text before the header":  edit(func(l []string) []string { l[0] = "cert: " + l[0]; return l }),
		"space after the header":  edit(func(l []string) []string { l[0] += " "; return l }),
		"space in a body line":    edit(func(l []string) []string { l[1] = " " + l[1]; return l }),
		"empty body line":         edit(func(l []string) []string { return slices.Insert(l, 2, "") }),
		"no end line":             edit(func(l []string) []string { return l[:len(l)-1] }),
		"indented end line":       edit(func(l []string) []string { l[len(l)-1] = " " + l[len(l)-1]; return l }),
		"a non-base64 character":  edit(func(l []string) []string { l[1] = "!" + l[1][1:]; return l }),
		"another header inside":   edit(func(l []string) []string { return slices.Insert(l, 1, pemCertificateBegin) }),
		"a private key block":     edit(func(l []string) []string { l[0] = "-----BEGIN PRIVATE KEY-----"; return l }),
		"too many lines":          tooLong,
		"an empty block":          {pemCertificateBegin, pemCertificateEnd},
		"a truncated certificate": edit(func(l []string) []string { return append(l[:2], l[len(l)-1]) }),
	}
	for name, l := range accept {
		if _, ok := certificateBlock(l); !ok {
			t.Errorf("%s: block not read", name)
		}
		if _, ok := matchTrustBlock(trustKeys(), l); !ok {
			t.Errorf("%s: the removed root met no rule", name)
		}
	}
	for name, l := range reject {
		if _, ok := matchTrustBlock(trustKeys(), l); ok {
			t.Errorf("%s: a rule was met", name)
		}
	}

	// A broken block does not borrow the end line of the block after it: the
	// broken header raises nothing and the next header raises its own finding.
	broken := append(edit(func(l []string) []string { return l[:len(l)-1] }), block...)
	m := NewMatcher()
	fileCtx := analyzer.Analyze("bundle.pem")
	var lines2 []int
	for i := range broken {
		for _, f := range m.MatchInFile(broken, i, "bundle.pem", fileCtx, analyzer.AnalyzeLine(broken[i], fileCtx.Language, nil)) {
			if strings.HasPrefix(f.ID, "TRUST-") {
				lines2 = append(lines2, f.Line)
			}
		}
	}
	if want := []int{end + 1}; !slices.Equal(lines2, want) {
		t.Errorf("trust findings on lines %v, want %v", lines2, want)
	}
}

// Nothing the rules or their texts depend on reads the clock: the same tree
// gives the same findings before and after a date in the texts.
func TestTrustCodeReadsNoClock(t *testing.T) {
	for _, dir := range []string{".", "../analyzer"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				if imp.Path.Value == `"time"` {
					t.Errorf("%s imports time", file)
				}
			}
		}
	}
	src, err := os.ReadFile("trust.go")
	if err != nil {
		t.Fatal(err)
	}
	// x509's Verify checks validity against the clock; the rules use
	// CheckSignature, which does not.
	if strings.Contains(string(src), ".Verify(") {
		t.Error("trust.go calls Verify, which reads the clock")
	}
}

var relativeDate = regexp.MustCompile(`(?i)\b(today|tomorrow|yesterday|tonight|now|ago|soon|recently|currently|this (week|month|year)|next (week|month|year)|last (week|month|year)|days?|weeks?|months?|years?|hours?)\b`)

// The texts carry absolute dates only, no relative date or countdown, and no
// dash the writing standard leaves out.
func TestTrustTextsStateNoRelativeDate(t *testing.T) {
	var texts []string
	for _, s := range trustDescriptions {
		texts = append(texts, s)
	}
	for _, s := range trustFixes {
		texts = append(texts, s)
	}
	for _, s := range trustImpacts {
		texts = append(texts, s)
	}
	date := regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)
	for _, s := range texts {
		if m := relativeDate.FindString(s); m != "" {
			t.Errorf("relative time %q in %q", m, s)
		}
		if strings.ContainsAny(s, "\u2014\u2013") {
			t.Errorf("em or en dash in %q", s)
		}
		for _, d := range date.FindAllString(s, -1) {
			if _, err := time.Parse("2006-01-02", d); err != nil {
				t.Errorf("date %q in %q: %v", d, s, err)
			}
		}
	}
}
