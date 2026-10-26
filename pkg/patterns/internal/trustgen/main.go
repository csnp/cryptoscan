// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Command trustgen writes the trust key table, pkg/patterns/trust_keys.json,
// from the certificates in pkg/patterns/testdata/trust, and the key table of
// each finding page under docs/findings. Run it with
//
//	go generate ./pkg/patterns
//
// after adding or changing a certificate there. No value in the table is
// typed: every hash and key is computed from a certificate file.
//
// A certificate's key use is the directory it sits in: tls, codesigning or
// root. The command refuses a TLS certificate without the serverAuth extended
// key usage, a code-signing certificate without codeSigning, and a root that
// is not a self-signed CA, so a certificate filed in the wrong directory is
// caught. Certificates with the same SubjectPublicKeyInfo are one key. Each
// file holds one certificate and is named by its SHA-256.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The listing every row of the current table comes from: the Mozilla bug
// that reported the eight keys, and the Chrome root program's announcement.
var sources = []string{
	"https://bugzilla.mozilla.org/show_bug.cgi?id=2083449",
	"https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/",
}

const reported = "2026-10-17"

// useDirs maps each fixture directory to the key use, status and date of the
// rows its certificates make, in the order the rows are written.
var useDirs = []struct {
	dir, use, status, distrustDate string
}{
	{"tls", "tls", "compromised", ""},
	{"codesigning", "codeSigning", "compromised", ""},
	{"root", "root", "distrusted", "2026-10-27"},
}

// Key is one row of trust_keys.json.
type Key struct {
	SPKISHA256   string   `json:"spkiSha256"`
	CertSHA256   []string `json:"certSha256"`
	SPKIDER      string   `json:"spkiDer"`
	Use          string   `json:"use"`
	Source       []string `json:"source"`
	Reported     string   `json:"reported"`
	Status       string   `json:"status"`
	DistrustDate string   `json:"distrustDate,omitempty"`

	label string // the subject common name, shown on the page only
}

// The markers between which a finding page holds its key table.
const (
	tableStart = "<!-- trust-key-table:start (written by go generate ./pkg/patterns) -->"
	tableEnd   = "<!-- trust-key-table:end -->"
)

// pages maps each finding page to the status of the rows it lists.
var pages = map[string]string{
	"trust-compromised-key.md": "compromised",
	"trust-distrusted-root.md": "distrusted",
}

func main() {
	fixtures := flag.String("fixtures", "testdata/trust", "directory holding tls, codesigning and root")
	keysPath := flag.String("keys", "trust_keys.json", "key table to write")
	pagesDir := flag.String("pages", "", "directory of the finding pages whose tables to rewrite")
	flag.Parse()

	keys, err := buildKeys(*fixtures)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trustgen:", err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(struct {
		Keys []*Key `json:"keys"`
	}{keys}, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "trustgen:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*keysPath, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "trustgen:", err)
		os.Exit(1)
	}
	if *pagesDir != "" {
		for name, status := range pages {
			if err := writeTable(filepath.Join(*pagesDir, name), keys, status); err != nil {
				fmt.Fprintln(os.Stderr, "trustgen:", err)
				os.Exit(1)
			}
		}
	}
}

// buildKeys reads every certificate under fixtures and returns one row per
// SubjectPublicKeyInfo.
func buildKeys(fixtures string) ([]*Key, error) {
	var keys []*Key
	for _, d := range useDirs {
		files, err := filepath.Glob(filepath.Join(fixtures, d.dir, "*.crt"))
		if err != nil {
			return nil, err
		}
		bySPKI := map[string]*Key{}
		for _, file := range files {
			cert, der, err := readCertificate(file)
			if err != nil {
				return nil, err
			}
			if err := checkUse(cert, d.use); err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
			certHash := hexSHA256(der)
			if filepath.Base(file) != certHash+".crt" {
				return nil, fmt.Errorf("%s: name the file %s.crt, its SHA-256", file, certHash)
			}
			spki := hexSHA256(cert.RawSubjectPublicKeyInfo)
			k, ok := bySPKI[spki]
			if !ok {
				k = &Key{
					SPKISHA256:   spki,
					SPKIDER:      base64.StdEncoding.EncodeToString(cert.RawSubjectPublicKeyInfo),
					Use:          d.use,
					Source:       sources,
					Reported:     reported,
					Status:       d.status,
					DistrustDate: d.distrustDate,
					label:        cert.Subject.CommonName,
				}
				bySPKI[spki] = k
			}
			k.CertSHA256 = append(k.CertSHA256, certHash)
		}
		var rows []*Key
		for _, k := range bySPKI {
			slices.Sort(k.CertSHA256)
			rows = append(rows, k)
		}
		slices.SortFunc(rows, func(a, b *Key) int { return strings.Compare(a.SPKISHA256, b.SPKISHA256) })
		keys = append(keys, rows...)
	}
	for _, k := range keys {
		for _, other := range keys {
			if k != other && k.SPKISHA256 == other.SPKISHA256 {
				return nil, fmt.Errorf("key %s is in two directories", k.SPKISHA256)
			}
		}
	}
	return keys, nil
}

// readCertificate returns the one certificate a PEM file holds.
func readCertificate(file string) (*x509.Certificate, []byte, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("%s: no PEM certificate", file)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, fmt.Errorf("%s: holds more than one PEM block", file)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	return cert, block.Bytes, nil
}

// checkUse refuses a certificate whose contents do not fit the directory it
// was filed in.
func checkUse(cert *x509.Certificate, use string) error {
	switch use {
	case "tls":
		if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
			return errors.New("filed as TLS but has no serverAuth extended key usage")
		}
	case "codeSigning":
		if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
			return errors.New("filed as code signing but has no codeSigning extended key usage")
		}
	case "root":
		if !cert.IsCA || cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil {
			return errors.New("filed as a root but is not a self-signed CA")
		}
	}
	return nil
}

// writeTable replaces the table between the markers of a finding page with
// the rows of one status: for each key its SPKI hash, then the hash of each
// certificate known for it, in hex and in base64.
func writeTable(page string, keys []*Key, status string) error {
	data, err := os.ReadFile(page)
	if err != nil {
		return err
	}
	text := string(data)
	start := strings.Index(text, tableStart)
	end := strings.Index(text, tableEnd)
	if start < 0 || end < start {
		return fmt.Errorf("%s: no %q ... %q markers", page, tableStart, tableEnd)
	}
	var b strings.Builder
	b.WriteString(tableStart + "\n\n")
	b.WriteString("| Key | Use | Value | SHA-256 (hex) | SHA-256 (base64) |\n")
	b.WriteString("|-----|-----|-------|---------------|------------------|\n")
	for _, k := range keys {
		if k.Status != status {
			continue
		}
		fmt.Fprintf(&b, "| %s | %s | SPKI | `%s` | `%s` |\n", k.label, k.Use, k.SPKISHA256, hexToBase64(k.SPKISHA256))
		for _, c := range k.CertSHA256 {
			fmt.Fprintf(&b, "| %s | %s | Certificate | `%s` | `%s` |\n", k.label, k.Use, c, hexToBase64(c))
		}
	}
	b.WriteString("\n" + tableEnd)
	out := text[:start] + b.String() + text[end+len(tableEnd):]
	return os.WriteFile(page, []byte(out), 0o644)
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hexToBase64(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
