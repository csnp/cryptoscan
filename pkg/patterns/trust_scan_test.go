// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns_test

import (
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
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/cryptoscan/pkg/patterns"
	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/types"
)

// The texts of the two kinds of match under TRUST-DISTRUSTED-ROOT-001.
const (
	// rootFileType and rootFileFix are the type and the Fix of a rule-3
	// match: the certificate is the root itself. The match cannot tell a
	// file that software loads as a trust store from one that holds the root
	// on purpose, so the Fix gives the action for each, trust store first,
	// and each opens with the kind of file it is for.
	rootFileType = "File holds emSign ECC Root CA - G3"
	rootFileFix  = "For a file that software loads as a trust store or CA bundle: remove emSign ECC Root CA - G3 from it, because software that loads this file still accepts chains that end at this root. For a file that holds the certificate on purpose without trusting it, such as a list of distrusted certificates or a test fixture: no change."

	// removedRootType and removedRootFix are the type and the Fix of a
	// rule-4 match: the root's key signed the certificate.
	removedRootType = "Certificate chain anchored on a root removed from browser trust stores"
	removedRootFix  = "Move the chain to a CA whose root stays trusted, and remove emSign ECC Root CA - G3 from any bundle you ship; Chrome's removal date for all devices is 2026-10-27."
)

// signedCertificate returns the DER of a CA certificate for pub, signed by
// signer, with parent as its issuer, or self-signed when parent is nil.
func signedCertificate(t *testing.T, serial int64, pub any, signer *ecdsa.PrivateKey, parent *x509.Certificate) ([]byte, *x509.Certificate) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "generated " + strconv.FormatInt(serial, 10)},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
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

// The scanner reports a generated root that a test key table lists as
// distrusted, and a certificate that root signed, under
// TRUST-DISTRUSTED-ROOT-001 at HIGH. The root, rule 3, leads with what the
// file holds and gives one action for each kind of file; the certificate the
// root signed, rule 4, keeps the pattern's name and the removed-root Fix.
func TestScanReportsADistrustedRootAndACertificateItSigned(t *testing.T) {
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	root, other := newKey(), newKey()
	spki, err := x509.MarshalPKIXPublicKey(&root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	table, err := json.Marshal(map[string]any{"schemaVersion": 1, "keys": []any{map[string]any{
		"spkiSha256": hex.EncodeToString(sum[:]), "certSha256": []string{}, "spkiDer": base64.StdEncoding.EncodeToString(spki),
		"use": "root", "source": []string{"https://bugzilla.mozilla.org/show_bug.cgi?id=2083449"}, "reported": "2026-10-17",
		"status": "distrusted", "distrustDate": "2026-10-27",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	patterns.UseTrustTable(t, table)

	rootDER, rootCert := signedCertificate(t, 1, &root.PublicKey, root, nil)
	signedDER, _ := signedCertificate(t, 2, &other.PublicKey, root, rootCert)
	dir := t.TempDir()
	for name, der := range map[string][]byte{"root.pem": rootDER, "signed.pem": signedDER} {
		data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	results, err := scanner.New(scanner.Config{Target: dir, MinSeverity: types.SeverityInfo}).Scan()
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string]types.Finding{}
	for _, f := range results.Findings {
		if f.IsTrust() {
			byRule[f.Metadata[patterns.TrustMetaRule]] = f
		}
	}
	if len(byRule) != 2 {
		t.Fatalf("trust findings by rule: %v, want rules 3 and 4", byRule)
	}
	for _, c := range []struct {
		rule, file, typ, fix string
	}{
		{"3", "root.pem", rootFileType, rootFileFix},
		{"4", "signed.pem", removedRootType, removedRootFix},
	} {
		f, ok := byRule[c.rule]
		if !ok {
			t.Errorf("no rule-%s finding", c.rule)
			continue
		}
		if !strings.HasPrefix(f.ID, patterns.TrustDistrustedRootID+"-") || f.Severity != types.SeverityHigh {
			t.Errorf("rule %s: id %q, severity %s; want an id starting %s- and HIGH", c.rule, f.ID, f.Severity, patterns.TrustDistrustedRootID)
		}
		if filepath.Base(f.File) != c.file {
			t.Errorf("rule %s: reported on %s, want %s", c.rule, f.File, c.file)
		}
		if f.Type != c.typ {
			t.Errorf("rule %s: type %q, want %q", c.rule, f.Type, c.typ)
		}
		if f.Fix != c.fix || f.Remediation != c.fix {
			t.Errorf("rule %s: fix %q and remediation %q, want both\n %q", c.rule, f.Fix, f.Remediation, c.fix)
		}
	}
	if byRule["3"].Type == byRule["4"].Type {
		t.Errorf("rule 3 and rule 4 share the lead %q", byRule["3"].Type)
	}
	checkRootFileFix(t, byRule["3"].Fix)
}

// checkRootFileFix reads a rule-3 Fix as a person or an agent carrying it out
// would: each action opens with the kind of file it is for, the trust-store
// action comes first and says what software that loads the file accepts, no
// action tells the reader to move a chain or names an action before its
// condition, and the reasons stay on the finding page.
func checkRootFileFix(t *testing.T, fix string) {
	t.Helper()
	sentences := strings.SplitAfter(fix, ". ")
	if len(sentences) != 2 {
		t.Errorf("the rule-3 Fix has %d sentences, want one for each kind of file: %q", len(sentences), fix)
		return
	}
	for i, prefix := range []string{
		"For a file that software loads as a trust store or CA bundle: ",
		"For a file that holds the certificate on purpose without trusting it, ",
	} {
		if !strings.HasPrefix(sentences[i], prefix) {
			t.Errorf("sentence %d %q does not open with %q", i+1, sentences[i], prefix)
		}
		condition, _, ok := strings.Cut(sentences[i], ": ")
		if !ok || strings.Contains(strings.ToLower(condition), "remove") {
			t.Errorf("sentence %d %q gives an action before its condition", i+1, sentences[i])
		}
	}
	if !strings.Contains(sentences[0], "software that loads this file still accepts chains that end at this root") {
		t.Errorf("the trust-store action does not say what software that loads the file accepts: %q", sentences[0])
	}
	if !strings.HasSuffix(sentences[1], ": no change.") {
		t.Errorf("the on-purpose action is not %q: %q", "no change", sentences[1])
	}
	lower := strings.ToLower(fix)
	for _, absent := range []string{"move the chain", "move a chain", "revocation", "cross-signed", "spki"} {
		if strings.Contains(lower, absent) {
			t.Errorf("the rule-3 Fix holds %q, which belongs to the rule-4 Fix or to the page: %q", absent, fix)
		}
	}
}
