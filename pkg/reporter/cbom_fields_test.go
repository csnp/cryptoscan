// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// cbomFieldsDoc documents every field the CBOM reporter writes. The tests in
// this file hold that page to the reporter's real output, so the page cannot
// claim a field that a scan does not produce.
const cbomFieldsDoc = "../../docs/cbom-fields.md"

// documentedFieldStatuses is the closed set of values the Status column may
// hold. Anything else, such as "yes" or "compliant", is rejected.
var documentedFieldStatuses = map[string]bool{
	"emitted":     true,
	"partial":     true,
	"not emitted": true,
}

type documentedField struct {
	path   string
	status string
	line   int
}

// parseDocumentedFields collects the rows of every Markdown table that has a
// "JSON path" column and a "Status" column. Other tables are left alone.
func parseDocumentedFields(markdown string) ([]documentedField, error) {
	lines := strings.Split(markdown, "\n")
	var fields []documentedField

	for i := 0; i+1 < len(lines); i++ {
		if !isTableRow(lines[i]) || !isTableSeparator(lines[i+1]) {
			continue
		}

		pathCol, statusCol := -1, -1
		for col, cell := range tableCells(lines[i]) {
			switch strings.ToLower(cell) {
			case "json path":
				pathCol = col
			case "status":
				statusCol = col
			}
		}

		j := i + 2
		for ; j < len(lines) && isTableRow(lines[j]); j++ {
			if pathCol < 0 || statusCol < 0 {
				continue
			}
			cells := tableCells(lines[j])
			if pathCol >= len(cells) || statusCol >= len(cells) {
				return nil, fmt.Errorf("line %d: row has fewer cells than its header", j+1)
			}

			path := cells[pathCol]
			if strings.Count(path, "`") != 2 || !strings.HasPrefix(path, "`") || !strings.HasSuffix(path, "`") {
				return nil, fmt.Errorf("line %d: JSON path %q must be a single code span", j+1, path)
			}
			path = strings.Trim(path, "`")

			status := strings.ToLower(strings.Trim(cells[statusCol], "` "))
			if !documentedFieldStatuses[status] {
				return nil, fmt.Errorf("line %d: status %q for %s is not one of emitted, partial, not emitted",
					j+1, cells[statusCol], path)
			}

			fields = append(fields, documentedField{path: path, status: status, line: j + 1})
		}
		i = j - 1
	}

	return fields, nil
}

func isTableRow(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "|")
}

func isTableSeparator(line string) bool {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "|") {
		return false
	}
	return strings.Trim(trimmed, "|-: ") == ""
}

func tableCells(line string) []string {
	trimmed := strings.Trim(strings.TrimSpace(line), "|")
	cells := strings.Split(trimmed, "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells
}

// valuesAt returns every value found at a documented path. A segment ending in
// [] descends into each element of that array, so components[].name yields the
// name of every component, and a trailing dependencies[] yields nothing for an
// empty or missing array.
func valuesAt(node any, path string) []any {
	current := []any{node}
	for _, segment := range strings.Split(path, ".") {
		key := strings.TrimSuffix(segment, "[]")
		eachElement := key != segment

		var next []any
		for _, n := range current {
			obj, ok := n.(map[string]any)
			if !ok {
				continue
			}
			value, ok := obj[key]
			if !ok {
				continue
			}
			if !eachElement {
				next = append(next, value)
				continue
			}
			if elements, ok := value.([]any); ok {
				next = append(next, elements...)
			}
		}
		current = next
	}
	return current
}

func isNonEmpty(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return v != ""
	case float64:
		return v != 0
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	default:
		return true
	}
}

// checkDocumentedFields compares each documented row with a generated CBOM.
// A row marked emitted or partial must have a non-empty value at its path in
// at least one place; a row marked not emitted must have none, so a later
// change that starts writing the field also has to update the page.
func checkDocumentedFields(fields []documentedField, bom map[string]any) []string {
	var problems []string
	for _, f := range fields {
		present := false
		for _, v := range valuesAt(bom, f.path) {
			if isNonEmpty(v) {
				present = true
				break
			}
		}

		switch {
		case f.status != "not emitted" && !present:
			problems = append(problems, fmt.Sprintf(
				"docs/cbom-fields.md:%d marks %s as %s, but the generated CBOM has no non-empty value there",
				f.line, f.path, f.status))
		case f.status == "not emitted" && present:
			problems = append(problems, fmt.Sprintf(
				"docs/cbom-fields.md:%d marks %s as not emitted, but the generated CBOM now writes it; update the row",
				f.line, f.path))
		}
	}
	return problems
}

// fieldsFixture is a small project whose findings cover each kind of asset the
// reporter handles: algorithms, key material, a certificate, TLS and a hybrid
// key exchange. PEM headers are assembled from pieces so that this source file
// does not itself look like key material to a secret scanner.
var fieldsFixture = map[string]string{
	"service/server.go": `package service

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"

	"golang.org/x/crypto/chacha20poly1305"
)

func signingKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func sessionCipher(key []byte) error {
	_, err := aes.NewCipher(key)
	return err
}

func recordCipher(key []byte) error {
	_, err := chacha20poly1305.New(key)
	return err
}

func serverTLS() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}
}
`,
	"service/settings.py": `import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2

SERVICE_KEY = """` + "-----BEGIN " + "RSA PRIVATE KEY-----" + `
"""

SERVICE_CERT = """` + "-----BEGIN " + "CERTIFICATE-----" + `
"""
`,
}

// scanFieldsFixture runs the real scanner over fieldsFixture with the default
// scan settings and returns the CBOM the reporter writes for it. Hand-built
// findings are not used here: one could carry a category or an algorithm name
// that no detection pattern produces, and the page would then describe a field
// that no real scan writes.
func scanFieldsFixture(t *testing.T) map[string]any {
	t.Helper()

	// os.MkdirTemp rather than t.TempDir, whose path carries the test name.
	root, err := os.MkdirTemp("", "cbom-fields-")
	if err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	for name, body := range fieldsFixture {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	results, err := scanner.New(scanner.Config{
		Target:      root,
		MinSeverity: scanner.SeverityInfo,
	}).Scan()
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	results.ScanTarget = root

	out, err := NewCBOMReporter().Generate(results)
	if err != nil {
		t.Fatalf("generate CBOM: %v", err)
	}
	var bom map[string]any
	if err := json.Unmarshal([]byte(out), &bom); err != nil {
		t.Fatalf("CBOM is not valid JSON: %v", err)
	}
	requireFixtureCoverage(t, bom)
	return bom
}

// requireFixtureCoverage fails when the fixture no longer produces one of the
// asset kinds it exists to cover. Without it, a row marked not emitted, such as
// protocolProperties, would pass simply because the fixture had stopped
// producing a TLS finding.
func requireFixtureCoverage(t *testing.T, bom map[string]any) {
	t.Helper()

	has := func(path, want string) bool {
		for _, v := range valuesAt(bom, path) {
			if v == want {
				return true
			}
		}
		return false
	}

	checks := []struct {
		kind, path, want string
	}{
		{"an algorithm", "components[].cryptoProperties.assetType", "algorithm"},
		{"key material", "components[].cryptoProperties.assetType", "related-crypto-material"},
		{"a certificate", "components[].cryptoProperties.assetType", "certificate"},
		{"a TLS finding", "components[].name", "TLS"},
		{"a hybrid construction", "components[].cryptoProperties.algorithmProperties.primitive", primitiveCombiner},
	}
	for _, c := range checks {
		if !has(c.path, c.want) {
			t.Fatalf("the fixture no longer produces %s (no %s equal to %q)", c.kind, c.path, c.want)
		}
	}
}

func readDocumentedFields(t *testing.T) []documentedField {
	t.Helper()

	raw, err := os.ReadFile(cbomFieldsDoc)
	if err != nil {
		t.Fatalf("read %s: %v", cbomFieldsDoc, err)
	}
	fields, err := parseDocumentedFields(string(raw))
	if err != nil {
		t.Fatalf("%s: %v", cbomFieldsDoc, err)
	}
	return fields
}

// TestDocumentedCBOMFieldsAreEmitted makes the field page unable to overclaim:
// every row marked emitted or partial must be present, with a value, in a CBOM
// generated by a real scan.
func TestDocumentedCBOMFieldsAreEmitted(t *testing.T) {
	fields := readDocumentedFields(t)

	emitted := 0
	for _, f := range fields {
		if f.status == "emitted" {
			emitted++
		}
	}
	if emitted == 0 {
		t.Fatalf("%s has no rows marked emitted", cbomFieldsDoc)
	}

	bom := scanFieldsFixture(t)
	var claimed []documentedField
	for _, f := range fields {
		if f.status != "not emitted" {
			claimed = append(claimed, f)
		}
	}
	for _, problem := range checkDocumentedFields(claimed, bom) {
		t.Error(problem)
	}
}

// TestFieldsDocumentedAsNotEmittedAreAbsent keeps the page from going stale in
// the other direction: once the reporter starts writing a field, the row that
// says it does not must be updated.
func TestFieldsDocumentedAsNotEmittedAreAbsent(t *testing.T) {
	fields := readDocumentedFields(t)

	var absent []documentedField
	for _, f := range fields {
		if f.status == "not emitted" {
			absent = append(absent, f)
		}
	}
	if len(absent) == 0 {
		t.Fatalf("%s has no rows marked not emitted", cbomFieldsDoc)
	}

	for _, problem := range checkDocumentedFields(absent, scanFieldsFixture(t)) {
		t.Error(problem)
	}
}

// TestOverclaimedFieldIsReported checks the check itself. The reporter writes
// no supplier, so a row claiming one must be reported, and an unknown status
// must be refused when the page is parsed.
func TestOverclaimedFieldIsReported(t *testing.T) {
	page := strings.Join([]string{
		"| JSON path | Status |",
		"|---|---|",
		"| `components[].supplier` | emitted |",
	}, "\n")

	fields, err := parseDocumentedFields(page)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("parsed %d rows, want 1", len(fields))
	}
	if problems := checkDocumentedFields(fields, scanFieldsFixture(t)); len(problems) != 1 {
		t.Errorf("a row claiming components[].supplier as emitted produced %d problems, want 1: %v",
			len(problems), problems)
	}

	if _, err := parseDocumentedFields(strings.Replace(page, "| emitted |", "| compliant |", 1)); err == nil {
		t.Error("a status outside emitted, partial, not emitted was accepted")
	}
}

// TestCBOMFieldsPageClaimsNoCompliance holds the page to what it can support.
// No CBOM minimum-elements list from CISA and NIST is published yet, so the
// page maps fields and makes no claim of compliance with any list.
func TestCBOMFieldsPageClaimsNoCompliance(t *testing.T) {
	raw, err := os.ReadFile(cbomFieldsDoc)
	if err != nil {
		t.Fatalf("read %s: %v", cbomFieldsDoc, err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "complian") {
		t.Errorf("%s uses the word compliant or compliance", cbomFieldsDoc)
	}
}
