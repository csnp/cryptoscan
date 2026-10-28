// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Command trustgen writes the trust key table, pkg/patterns/trust_keys.json,
// from the certificates in pkg/patterns/testdata/trust and the records in
// pkg/patterns/testdata/trust-captured/source-records.txt, and the key table
// of each finding page under docs/findings. Run it with
//
//	go generate ./pkg/patterns
//
// after adding or changing a certificate or a record there. No hash, key,
// name, source or reported date in the table is typed: each hash, key and
// name is read from a certificate file, and each source and reported date
// from the records file.
//
// A certificate's key use is the directory it sits in: tls, codesigning or
// root. The command refuses a TLS certificate without the serverAuth extended
// key usage, a code-signing certificate without codeSigning, and a root that
// is not a self-signed CA, so a certificate filed in the wrong directory is
// caught. Certificates with the same SubjectPublicKeyInfo are one key, named
// by the subject common name they carry; a certificate with no common name,
// and a key whose certificates carry two names, are refused. Each file holds
// one certificate and is named by its SHA-256.
//
// The records file holds one line per public record the table cites: its
// URL, the UTC time it states for itself, its role and the keys it lists, in
// columns separated by single spaces; its header states the rules. A row's
// source is the sorted URLs of the records that list it, and its reported
// date is the UTC date of the earliest of those whose role is status. The
// command refuses a record that lists no row, a row that no status record
// lists, and a row with a record dated before the earliest that reports its
// status, so that reported is also the earliest date among the row's sources.
//
// The table is written in the key table file format: schemaVersion 1, then
// the rows sorted by SPKI hash, each row's certificate hashes and sources
// sorted, in the bytes a json.Encoder writes with SetEscapeHTML(false) and
// SetIndent("", "  "). The same certificates and records always give the same
// bytes.
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
	"time"
)

// schemaVersion is the version of the key table file format written.
const schemaVersion = 1

// useDirs maps each fixture directory to the key use, status and date of the
// rows its certificates make, in the order a finding page lists them.
var useDirs = []struct {
	dir, use, status, distrustDate string
}{
	{"tls", "tls", "compromised", ""},
	{"codesigning", "codeSigning", "compromised", ""},
	{"root", "root", "distrusted", "2026-10-27"},
}

// Key is one row of trust_keys.json, its fields in the file format's order.
// Its source is the https URL of each public record that reports the key's
// status (for the root, its removal from a trust store), and its reported is
// the earliest UTC date those records state for themselves.
type Key struct {
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
	records := flag.String("records", "testdata/trust-captured/source-records.txt", "the public records the table cites")
	keysPath := flag.String("keys", "trust_keys.json", "key table to write")
	pagesDir := flag.String("pages", "", "directory of the finding pages whose tables to rewrite")
	flag.Parse()

	keys, err := buildKeys(*fixtures, *records)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trustgen:", err)
		os.Exit(1)
	}
	data, err := encodeTable(keys)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trustgen:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*keysPath, data, 0o644); err != nil {
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

// encodeTable returns the bytes of the key table file. They are written by a
// json.Encoder with HTML escaping off and a two-space indent, which ends them
// with a newline; json.MarshalIndent and the encoder's default escape &, <
// and >, which the format's other writers do not.
func encodeTable(keys []*Key) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(struct {
		SchemaVersion int    `json:"schemaVersion"`
		Keys          []*Key `json:"keys"`
	}{schemaVersion, keys})
	return b.Bytes(), err
}

// buildKeys reads every certificate under fixtures and returns one row per
// SubjectPublicKeyInfo, sorted by SPKI hash, each citing the records of the
// records file that list it.
func buildKeys(fixtures, recordsPath string) ([]*Key, error) {
	records, err := readRecords(recordsPath)
	if err != nil {
		return nil, err
	}
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
			if cert.Subject.CommonName == "" {
				return nil, fmt.Errorf("%s: its subject has no common name to name the key by", file)
			}
			spki := hexSHA256(cert.RawSubjectPublicKeyInfo)
			k, ok := bySPKI[spki]
			if !ok {
				k = &Key{
					SPKISHA256:   spki,
					Name:         cert.Subject.CommonName,
					SPKIDER:      base64.StdEncoding.EncodeToString(cert.RawSubjectPublicKeyInfo),
					Use:          d.use,
					Status:       d.status,
					DistrustDate: d.distrustDate,
				}
				bySPKI[spki] = k
			}
			if cert.Subject.CommonName != k.Name {
				return nil, fmt.Errorf("%s: names key %s %q; another of its certificates names it %q", file, spki, cert.Subject.CommonName, k.Name)
			}
			k.CertSHA256 = append(k.CertSHA256, certHash)
		}
		for _, k := range bySPKI {
			slices.Sort(k.CertSHA256)
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		for _, other := range keys {
			if k != other && k.SPKISHA256 == other.SPKISHA256 {
				return nil, fmt.Errorf("key %s is in two directories", k.SPKISHA256)
			}
		}
	}
	slices.SortFunc(keys, func(a, b *Key) int { return strings.Compare(a.SPKISHA256, b.SPKISHA256) })
	if err := cite(keys, records, filepath.Dir(recordsPath)); err != nil {
		return nil, fmt.Errorf("%s: %w", recordsPath, err)
	}
	return keys, nil
}

// record is one line of the records file.
type record struct {
	url   string
	date  string // the UTC date of the time the record states for itself
	role  string // status when it reports the key's status, lists when it only lists the key
	lists string // certs:<file>, pkh:<pubKeyHash> or root:<subject common name>
}

// readRecords returns the records of the records file in file order. A line
// that starts with # is a comment; any other is a record, whose four columns
// are separated by single spaces, the last, lists, holding any spaces.
func readRecords(path string) ([]record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []record
	seen := map[string]bool{}
	for i, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.SplitN(line, " ", 4)
		if len(f) != 4 {
			return nil, fmt.Errorf("%s:%d: want url, published, role and lists", path, i+1)
		}
		url, published, role, lists := f[0], f[1], f[2], f[3]
		if !strings.HasPrefix(url, "https://") {
			return nil, fmt.Errorf("%s:%d: %q is not an https URL", path, i+1, url)
		}
		if seen[url] {
			return nil, fmt.Errorf("%s:%d: %s is listed twice", path, i+1, url)
		}
		seen[url] = true
		at, err := time.Parse(time.RFC3339, published)
		if err != nil || !strings.HasSuffix(published, "Z") {
			return nil, fmt.Errorf("%s:%d: published %q is not a UTC time", path, i+1, published)
		}
		if role != "status" && role != "lists" {
			return nil, fmt.Errorf("%s:%d: role %q is not status or lists", path, i+1, role)
		}
		records = append(records, record{url: url, date: at.Format("2006-01-02"), role: role, lists: lists})
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%s: holds no record", path)
	}
	return records, nil
}

// cite sets each row's source to the sorted URLs of the records that list
// it, and its reported to the date of the earliest of those whose role is
// status. A certs: file is read from dir.
func cite(keys []*Key, records []record, dir string) error {
	earliest := map[*Key]string{}
	for _, r := range records {
		lists, err := lister(r.lists, dir)
		if err != nil {
			return fmt.Errorf("%s: %w", r.url, err)
		}
		listed := false
		for _, k := range keys {
			if !lists(k) {
				continue
			}
			listed = true
			k.Source = append(k.Source, r.url)
			if e, ok := earliest[k]; !ok || r.date < e {
				earliest[k] = r.date
			}
			if r.role == "status" && (k.Reported == "" || r.date < k.Reported) {
				k.Reported = r.date
			}
		}
		if !listed {
			return fmt.Errorf("%s lists no row of the table", r.url)
		}
	}
	for _, k := range keys {
		if k.Reported == "" {
			return fmt.Errorf("key %s: no record that reports its status lists it", k.SPKISHA256)
		}
		if earliest[k] != k.Reported {
			return fmt.Errorf("key %s: a record of %s lists it before the earliest that reports its status, of %s", k.SPKISHA256, earliest[k], k.Reported)
		}
		slices.Sort(k.Source)
	}
	return nil
}

// lister returns whether a record's lists column lists a row: certs:<file>
// lists every row with a certificate in that captured file, pkh:<value> the
// row whose SPKI digest that is, and root:<name> the root row of that
// subject name.
func lister(lists, dir string) (func(*Key) bool, error) {
	kind, value, _ := strings.Cut(lists, ":")
	switch kind {
	case "certs":
		if value == "" || value != filepath.Base(value) {
			return nil, fmt.Errorf("certs:%s is not a file name", value)
		}
		certs, err := readFirstColumn(filepath.Join(dir, value))
		if err != nil {
			return nil, err
		}
		return func(k *Key) bool {
			return slices.ContainsFunc(k.CertSHA256, func(c string) bool { return certs[c] })
		}, nil
	case "pkh":
		digest, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("pkh:%s is not a base64 SHA-256", value)
		}
		spki := hex.EncodeToString(digest)
		return func(k *Key) bool { return k.SPKISHA256 == spki }, nil
	case "root":
		return func(k *Key) bool { return k.Use == "root" && k.Name == value }, nil
	}
	return nil, fmt.Errorf("lists %q is not certs:, pkh: or root:", lists)
}

// readFirstColumn returns the first column of each line of a captured-values
// file that is neither empty nor a comment.
func readFirstColumn(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		value, _, _ := strings.Cut(line, " ")
		values[value] = true
	}
	return values, nil
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
// the rows of one status, grouped by use in the order of useDirs and in the
// key table's order within a use: for each key its SPKI hash, then the hash
// of each certificate known for it, in hex and in base64.
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
	for _, d := range useDirs {
		for _, k := range keys {
			if k.Status != status || k.Use != d.use {
				continue
			}
			fmt.Fprintf(&b, "| %s | %s | SPKI | `%s` | `%s` |\n", k.Name, k.Use, k.SPKISHA256, hexToBase64(k.SPKISHA256))
			for _, c := range k.CertSHA256 {
				fmt.Fprintf(&b, "| %s | %s | Certificate | `%s` | `%s` |\n", k.Name, k.Use, c, hexToBase64(c))
			}
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
