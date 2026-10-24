// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/csnp/cryptoscan/pkg/types"
)

//go:generate go run ./internal/trustgen -fixtures testdata/trust -keys trust_keys.json -pages ../../docs/findings

// The two Trust patterns. Their regular expression only finds a PEM
// certificate header; a finding is raised when the block that starts there
// decodes and one of the four key rules below holds. No subject or issuer
// name is read.
const (
	TrustCompromisedKeyID  = "TRUST-COMPROMISED-KEY-001"
	TrustDistrustedRootID  = "TRUST-DISTRUSTED-ROOT-001"
	trustCompromisedKeyURL = "https://github.com/csnp/cryptoscan/blob/main/docs/findings/trust-compromised-key.md"
	trustDistrustedRootURL = "https://github.com/csnp/cryptoscan/blob/main/docs/findings/trust-distrusted-root.md"
)

// Key table statuses. A compromised key raises TRUST-COMPROMISED-KEY-001 and
// a distrusted root TRUST-DISTRUSTED-ROOT-001.
const (
	trustStatusCompromised = "compromised"
	trustStatusDistrusted  = "distrusted"
)

// Metadata keys and values of a trust finding. The values are lowercase hex
// without colons.
const (
	TrustMetaKind         = "kind"
	TrustMetaMatchedValue = "matchedValue"
	TrustMetaValueType    = "valueType"
	TrustMetaIssuerSPKI   = "issuerSpkiSha256"
	TrustMetaKeyUse       = "keyUse"
	TrustMetaRule         = "rule"
	TrustMetaDistrustDate = "distrustDate"

	TrustValueSPKI = "spkiSha256"
	TrustValueCert = "certSha256"
)

// trustKinds names the kind of finding each status raises, as the kind
// metadata value.
var trustKinds = map[string]string{
	trustStatusCompromised: "compromisedCaKey",
	trustStatusDistrusted:  "distrustedRoot",
}

// trustDescriptions is the description of a finding by the rule that raised it.
var trustDescriptions = map[int]string{
	1: "The certificate's public key is one of the eight eMudhra intermediate CA keys whose private keys were recovered by independent parties (Mozilla Bug 2083449, reported 2026-10-17). eMudhra revoked these certificates on 2026-10-18 and the browser root programs block the keys: a bundle that still trusts this key accepts certificates anyone can mint, and a chain through it no longer validates.",
	2: "The certificate is signed by one of the eight eMudhra intermediate CA keys whose private keys were recovered by independent parties (Mozilla Bug 2083449, reported 2026-10-17). Its issuer is revoked, so this chain no longer validates.",
	3: "This certificate is emSign ECC Root CA - G3. After the eMudhra intermediate key compromise (Mozilla Bug 2083449), Mozilla removed this root in an emergency change and Chrome removes it for all devices on 2026-10-27, so chains that end here stop validating in browsers.",
	4: "This certificate chains to emSign ECC Root CA - G3: its signature verifies under that root's key. Mozilla removed the root in an emergency change and Chrome removes it for all devices on 2026-10-27, so this chain stops validating in browsers.",
}

// trustFixes is the fix of a finding by the use of the listed key it matched.
var trustFixes = map[string]string{
	"tls":         "Replace the chain with one issued by a CA none of whose keys is listed, and remove this certificate from any bundle or pin set you ship.",
	"codeSigning": "Re-sign the artifacts with a certificate from a CA none of whose keys is listed and republish; a verifier that checks revocation rejects signatures under this key.",
	"root":        "Move the chain to a CA whose root stays trusted, and remove emSign ECC Root CA - G3 from any bundle you ship; Chrome removes it for all devices on 2026-10-27.",
}

// The PEM lines of a certificate block, and how far past its header a block
// is read for its end line. A certificate of 64 KB is about 1,100 lines of
// base64.
const (
	pemCertificateBegin = "-----BEGIN CERTIFICATE-----"
	pemCertificateEnd   = "-----END CERTIFICATE-----"
	maxCertificateLines = 2000
)

//go:embed trust_keys.json
var trustKeysJSON []byte

// trustKey is one row of the key table: a public key a published advisory
// lists, the certificates known for it and the listing. The table is
// generated from the certificates in testdata/trust by internal/trustgen, and
// a test recomputes every row from them.
type trustKey struct {
	SPKISHA256   string   `json:"spkiSha256"`             // SHA-256 of the DER SubjectPublicKeyInfo
	CertSHA256   []string `json:"certSha256"`             // SHA-256 of the DER of each known certificate
	SPKIDER      string   `json:"spkiDer"`                // the DER SubjectPublicKeyInfo, base64
	Use          string   `json:"use"`                    // tls, codeSigning or root
	Source       []string `json:"source"`                 // public pages that list the key
	Reported     string   `json:"reported"`               // date the listing was reported
	Status       string   `json:"status"`                 // compromised or distrusted
	DistrustDate string   `json:"distrustDate,omitempty"` // for a distrusted root, the date browsers remove it

	publicKey any
}

// trustTable holds the key table and an index of it by SPKI hash.
type trustTable struct {
	keys   []*trustKey
	bySPKI map[string]*trustKey
}

var (
	defaultTrustTable     *trustTable
	defaultTrustTableOnce sync.Once
)

// trustKeys returns the embedded key table. The file is part of the build and
// a test checks every row, so a row that does not parse is a defect in the
// build, not an input error.
func trustKeys() *trustTable {
	defaultTrustTableOnce.Do(func() {
		t, err := parseTrustTable(trustKeysJSON)
		if err != nil {
			panic("trust_keys.json: " + err.Error())
		}
		defaultTrustTable = t
	})
	return defaultTrustTable
}

// parseTrustTable reads a key table and checks that each row's SPKI hash is
// the hash of its SPKI DER.
func parseTrustTable(data []byte) (*trustTable, error) {
	var file struct {
		Keys []*trustKey `json:"keys"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	t := &trustTable{bySPKI: make(map[string]*trustKey, len(file.Keys))}
	for i, k := range file.Keys {
		der, err := base64.StdEncoding.DecodeString(k.SPKIDER)
		if err != nil {
			return nil, fmt.Errorf("row %d: spkiDer: %w", i, err)
		}
		if got := sha256Hex(der); got != k.SPKISHA256 {
			return nil, fmt.Errorf("row %d: spkiDer hashes to %s, not %s", i, got, k.SPKISHA256)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("row %d: spkiDer: %w", i, err)
		}
		if _, ok := trustKinds[k.Status]; !ok {
			return nil, fmt.Errorf("row %d: unknown status %q", i, k.Status)
		}
		k.publicKey = pub
		t.keys = append(t.keys, k)
		t.bySPKI[k.SPKISHA256] = k
	}
	return t, nil
}

// trustMatch is the rule a certificate block meets and the listed key it
// meets it with.
type trustMatch struct {
	rule  int
	key   *trustKey
	value string // the block's SPKI hash for rules 1 and 3, its certificate hash for rules 2 and 4
}

// valueType names what value holds.
func (m *trustMatch) valueType() string {
	if m.rule == 1 || m.rule == 3 {
		return TrustValueSPKI
	}
	return TrustValueCert
}

// metadata returns the fields of the finding the match raises.
func (m *trustMatch) metadata() map[string]string {
	md := map[string]string{
		TrustMetaKind:         trustKinds[m.key.Status],
		TrustMetaMatchedValue: m.value,
		TrustMetaValueType:    m.valueType(),
		TrustMetaKeyUse:       m.key.Use,
		TrustMetaRule:         strconv.Itoa(m.rule),
	}
	if m.rule == 2 || m.rule == 4 {
		md[TrustMetaIssuerSPKI] = m.key.SPKISHA256
	}
	if m.key.DistrustDate != "" {
		md[TrustMetaDistrustDate] = m.key.DistrustDate
	}
	return md
}

// match returns the first of the four rules the certificate meets:
//
//  1. its SPKI hash is a compromised key's;
//  2. its signature verifies under a compromised key;
//  3. its SPKI hash is a distrusted root's;
//  4. its signature verifies under a distrusted root's key.
//
// A block meets at most one rule in the report, so a self-signed root meets
// rule 3 and not rule 4, and a listed intermediate meets rule 1 even when it
// is also signed by a listed root.
func (t *trustTable) match(der []byte, cert *x509.Certificate) (*trustMatch, bool) {
	spki := sha256Hex(cert.RawSubjectPublicKeyInfo)
	for _, status := range []string{trustStatusCompromised, trustStatusDistrusted} {
		if k, ok := t.bySPKI[spki]; ok && k.Status == status {
			return &trustMatch{rule: ruleBySPKI(status), key: k, value: spki}, true
		}
		for _, k := range t.keys {
			if k.Status != status {
				continue
			}
			issuer := &x509.Certificate{PublicKey: k.publicKey}
			if issuer.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil {
				return &trustMatch{rule: ruleBySPKI(status) + 1, key: k, value: sha256Hex(der)}, true
			}
		}
	}
	return nil, false
}

// ruleBySPKI is the SPKI rule for a status; the signature rule follows it.
func ruleBySPKI(status string) int {
	if status == trustStatusCompromised {
		return 1
	}
	return 3
}

// certificateBlock returns the DER of the PEM certificate block whose header
// is lines[0], or false. The block is read the way OpenSSL and LibreSSL read
// it, so that the Verify command, which gives the same lines to openssl,
// recomputes the same value: the header and the end line stand alone on their
// lines, and every line between them holds base64 only.
func certificateBlock(lines []string) ([]byte, bool) {
	if len(lines) == 0 || strings.TrimSuffix(lines[0], "\r") != pemCertificateBegin {
		return nil, false
	}
	var body strings.Builder
	for i := 1; i < len(lines) && i <= maxCertificateLines; i++ {
		line := strings.TrimSuffix(lines[i], "\r")
		if line == pemCertificateEnd {
			der, err := base64.StdEncoding.DecodeString(body.String())
			if err != nil || len(der) == 0 {
				return nil, false
			}
			return der, true
		}
		if !isBase64Line(line) {
			return nil, false
		}
		body.WriteString(line)
	}
	return nil, false
}

// isBase64Line reports whether line is a non-empty run of standard base64
// characters.
func isBase64Line(line string) bool {
	if line == "" {
		return false
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// matchTrustBlock decodes the certificate block whose header is lines[0] and
// returns the rule it meets in table.
func matchTrustBlock(table *trustTable, lines []string) (*trustMatch, bool) {
	der, ok := certificateBlock(lines)
	if !ok {
		return nil, false
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false
	}
	return table.match(der, cert)
}

// trustFinding fills a finding the matcher built from a header match with
// what the rule decided.
func trustFinding(f *types.Finding, m *trustMatch) {
	fix := trustFixes[m.key.Use]
	f.FindingType = types.FindingTypeTrust
	f.Confidence = types.ConfidenceHigh
	f.Description = trustDescriptions[m.rule]
	f.Remediation = fix
	f.Fix = fix
	f.Guidance = ""
	f.Metadata = m.metadata()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
