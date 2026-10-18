// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/patterns"
	"github.com/csnp/cryptoscan/pkg/types"
)

// patternsJSONView is the JSON the patterns commands print.
type patternsJSONView struct {
	Tool struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tool"`
	Patterns []struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Category    string   `json:"category"`
		Severity    string   `json:"severity"`
		QuantumRisk string   `json:"quantumRisk"`
		Algorithm   string   `json:"algorithm"`
		KeySize     int      `json:"keySize"`
		Description string   `json:"description"`
		Remediation string   `json:"remediation"`
		References  []string `json:"references"`
		Tags        []string `json:"tags"`
		Regex       string   `json:"regex"`
	} `json:"patterns"`
}

func (v patternsJSONView) ids() []string {
	ids := make([]string, 0, len(v.Patterns))
	for _, p := range v.Patterns {
		ids = append(ids, p.ID)
	}
	return ids
}

// resetPatternsFlags puts the patterns flags back to their defaults. Cobra
// keeps a flag's value between runs in one test binary.
func resetPatternsFlags() {
	patternsCategory = ""
	patternsQuantum = ""
	patternsFormat = "text"
	patternsListCmd.SilenceUsage = false
	patternsSearchCmd.SilenceUsage = false
}

// executePatterns runs cryptoscan with args, starting from the default
// patterns flags, and returns everything it printed.
func executePatterns(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetPatternsFlags()
	t.Cleanup(resetPatternsFlags)
	return executeRoot(t, args...)
}

// patternsJSON runs a patterns command that prints JSON and decodes what it
// printed.
func patternsJSON(t *testing.T, args ...string) patternsJSONView {
	t.Helper()
	out, err := executePatterns(t, args...)
	if err != nil {
		t.Fatalf("cryptoscan %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	var view patternsJSONView
	if err := json.Unmarshal([]byte(out), &view); err != nil {
		t.Fatalf("cryptoscan %s printed output that is not JSON: %v\n%s", strings.Join(args, " "), err, out)
	}
	return view
}

// textTableIDs returns the first column of the table the text output prints:
// the rows after the header line, up to the first blank line.
func textTableIDs(t *testing.T, out string) []string {
	t.Helper()
	lines := strings.Split(out, "\n")
	header := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "ID ") })
	if header < 0 {
		t.Fatalf("output has no table header starting with \"ID \":\n%s", out)
	}
	var ids []string
	for _, line := range lines[header+1:] {
		if strings.TrimSpace(line) == "" {
			break
		}
		ids = append(ids, strings.Fields(line)[0])
	}
	return ids
}

// scannerPatterns returns the patterns the scanner runs, from the matcher it
// builds, in the order it checks them.
func scannerPatterns(t *testing.T) []patterns.Pattern {
	t.Helper()
	all := patterns.NewMatcher().Patterns()
	if len(all) == 0 {
		t.Fatal("the matcher has no patterns, so this test checks nothing")
	}
	return all
}

func idsOf(ps []patterns.Pattern, keep func(patterns.Pattern) bool) []string {
	var ids []string
	for _, p := range ps {
		if keep(p) {
			ids = append(ids, p.ID)
		}
	}
	return ids
}

func everyPattern(patterns.Pattern) bool { return true }

// searchSelects is what search promises: the term appears, ignoring case, in
// the pattern's ID, name, category, algorithm or description, or the
// pattern's expression matches the term.
func searchSelects(p patterns.Pattern, term string) bool {
	lower := strings.ToLower(term)
	for _, field := range []string{p.ID, p.Name, p.Category, p.Algorithm, p.Description} {
		if strings.Contains(strings.ToLower(field), lower) {
			return true
		}
	}
	return p.Regex.MatchString(term)
}

func TestPatternsCmdIsRegistered(t *testing.T) {
	if !isRegistered("patterns") {
		t.Fatal("patterns is not registered on the root command")
	}
	for _, sub := range []string{"list", "search"} {
		found := false
		for _, c := range patternsCmd.Commands() {
			found = found || c.Name() == sub
		}
		if !found {
			t.Errorf("patterns has no %s subcommand", sub)
		}
	}
}

// The catalogue is read from the matcher the scanner builds: every entry it
// prints is a pattern the scanner runs, and every pattern the scanner runs is
// printed once, in the order the scanner checks them.
func TestPatternsListTextPrintsEveryPatternTheScannerRuns(t *testing.T) {
	all := scannerPatterns(t)
	want := idsOf(all, everyPattern)

	out, err := executePatterns(t, "patterns", "list")
	if err != nil {
		t.Fatalf("patterns list failed: %v\n%s", err, out)
	}
	if got := textTableIDs(t, out); !slices.Equal(got, want) {
		t.Errorf("patterns list printed the IDs\n\t%v\nthe scanner runs\n\t%v", got, want)
	}
	if count := fmt.Sprintf("\n%d patterns.", len(all)); !strings.Contains(out, count) {
		t.Errorf("patterns list output does not contain %q:\n%s", count, out)
	}

	// Each row carries the pattern's severity, quantum risk, category and
	// name as the scanner defines them.
	rows := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			rows[f[0]] = line
		}
	}
	for _, p := range all {
		line, ok := rows[p.ID]
		if !ok {
			continue // reported above
		}
		for _, want := range []string{p.Severity.String(), string(p.Quantum), p.Category, p.Name} {
			if !strings.Contains(line, want) {
				t.Errorf("the row for %s does not contain %q: %q", p.ID, want, line)
			}
		}
	}
}

func TestPatternsListJSONCarriesEachPatternAsTheScannerDefinesIt(t *testing.T) {
	all := scannerPatterns(t)
	view := patternsJSON(t, "patterns", "list", "--format", "json")

	if got, want := view.ids(), idsOf(all, everyPattern); !slices.Equal(got, want) {
		t.Fatalf("patterns list --format json printed the IDs\n\t%v\nthe scanner runs\n\t%v", got, want)
	}
	if view.Tool.Name != "CryptoScan" || view.Tool.Version == "" {
		t.Errorf("tool = %+v, want the name CryptoScan and a version", view.Tool)
	}
	for i, got := range view.Patterns {
		p := all[i]
		for _, c := range []struct{ field, got, want string }{
			{"name", got.Name, p.Name},
			{"category", got.Category, p.Category},
			{"severity", got.Severity, p.Severity.String()},
			{"quantumRisk", got.QuantumRisk, string(p.Quantum)},
			{"algorithm", got.Algorithm, p.Algorithm},
			{"description", got.Description, p.Description},
			{"remediation", got.Remediation, p.Remediation},
			{"regex", got.Regex, p.Regex.String()},
		} {
			if c.got != c.want {
				t.Errorf("%s: %s = %q, the scanner's pattern has %q", p.ID, c.field, c.got, c.want)
			}
		}
		if got.KeySize != p.KeySize {
			t.Errorf("%s: keySize = %d, the scanner's pattern has %d", p.ID, got.KeySize, p.KeySize)
		}
		if !slices.Equal(got.References, p.References) || !slices.Equal(got.Tags, p.Tags) {
			t.Errorf("%s: references %q and tags %q, the scanner's pattern has %q and %q",
				p.ID, got.References, got.Tags, p.References, p.Tags)
		}
	}
}

func TestPatternsSearchMatchesNamesAndExpressions(t *testing.T) {
	all := scannerPatterns(t)
	tests := []struct {
		term string
		// mustList are patterns the result has to contain, chosen from the
		// patterns as they are defined today.
		mustList []string
	}{
		{"rsa", []string{"RSA-001", "RSA-1024", "RSA-2048"}},
		{"Certificate", []string{"CERT-001"}},
		// The ML-KEM pattern's expression matches the name Kyber.
		{"Kyber768", []string{"PQC-MLKEM-001"}},
		{"ssh-dss", []string{"DSA-001"}},
	}
	for _, tt := range tests {
		t.Run(tt.term, func(t *testing.T) {
			want := idsOf(all, func(p patterns.Pattern) bool { return searchSelects(p, tt.term) })
			got := patternsJSON(t, "patterns", "search", tt.term, "--format", "json").ids()
			if !slices.Equal(got, want) {
				t.Errorf("patterns search %q printed\n\t%v\nwant\n\t%v", tt.term, got, want)
			}
			for _, id := range tt.mustList {
				if !slices.Contains(got, id) {
					t.Errorf("patterns search %q does not list %s", tt.term, id)
				}
			}

			out, err := executePatterns(t, "patterns", "search", tt.term)
			if err != nil {
				t.Fatalf("patterns search %q failed: %v\n%s", tt.term, err, out)
			}
			if got := textTableIDs(t, out); !slices.Equal(got, want) {
				t.Errorf("patterns search %q text table lists\n\t%v\nwant\n\t%v", tt.term, got, want)
			}
			if count := fmt.Sprintf("\n%d of %d patterns.", len(want), len(all)); !strings.Contains(out, count) {
				t.Errorf("patterns search %q output does not contain %q:\n%s", tt.term, count, out)
			}
		})
	}
}

// selects is checked on a pattern made up for the test, so each case keeps
// testing the rule it names whatever the scanner's patterns say. Each term
// below appears in one field only.
func TestPatternFilterSelects(t *testing.T) {
	p := patterns.Pattern{
		ID:          "EXAMPLE-001",
		Name:        "Sample Widget",
		Category:    "Symmetric Encryption",
		Algorithm:   "ZQX",
		Description: "Detected an obsolete construction.",
		Remediation: "Move to AES-256.",
		Quantum:     types.QuantumPartial,
		Regex:       regexp.MustCompile(`(?i)\bexcipher[-_]?(128|256)\b`),
	}
	tests := []struct {
		name   string
		filter patternFilter
		want   bool
	}{
		{"no filter", patternFilter{}, true},
		{"term in the ID, another case", patternFilter{term: "example-0"}, true},
		{"term in the name", patternFilter{term: "WIDGET"}, true},
		{"term in the category", patternFilter{term: "symmetric"}, true},
		{"term in the algorithm", patternFilter{term: "zqx"}, true},
		{"term in the description", patternFilter{term: "obsolete"}, true},
		{"term only in the remediation", patternFilter{term: "aes-256"}, false},
		{"term the expression matches", patternFilter{term: "EXCIPHER_256"}, true},
		{"term the expression does not match", patternFilter{term: "excipher-512"}, false},
		{"category compared as --ignore-category compares it", patternFilter{category: " symmetric encryption "}, true},
		{"another category", patternFilter{category: "Hash Function"}, false},
		{"quantum level in another case", patternFilter{quantum: "partial"}, true},
		{"another quantum level", patternFilter{quantum: "safe"}, false},
		{"every filter has to select the pattern", patternFilter{term: "widget", quantum: "vulnerable"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.selects(p); got != tt.want {
				t.Errorf("%+v selects the pattern = %v, want %v", tt.filter, got, tt.want)
			}
		})
	}
}

func TestPatternsFilterByCategoryAndQuantumRisk(t *testing.T) {
	all := scannerPatterns(t)
	tests := []struct {
		name string
		args []string
		keep func(patterns.Pattern) bool
	}{
		{
			name: "quantum vulnerable",
			args: []string{"patterns", "list", "--quantum", "vulnerable"},
			keep: func(p patterns.Pattern) bool { return p.Quantum == types.QuantumVulnerable },
		},
		{
			name: "quantum level in capitals",
			args: []string{"patterns", "list", "--quantum", "SAFE"},
			keep: func(p patterns.Pattern) bool { return p.Quantum == types.QuantumSafe },
		},
		{
			name: "category in another case",
			args: []string{"patterns", "list", "--category", "certificate"},
			keep: func(p patterns.Pattern) bool { return p.Category == "Certificate" },
		},
		{
			name: "search term with both filters",
			args: []string{"patterns", "search", "ml", "--category", "Post-Quantum Cryptography", "--quantum", "safe"},
			keep: func(p patterns.Pattern) bool {
				return searchSelects(p, "ml") && p.Category == "Post-Quantum Cryptography" && p.Quantum == types.QuantumSafe
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := idsOf(all, tt.keep)
			if len(want) == 0 {
				t.Fatal("no pattern passes this filter, so this case checks nothing")
			}
			got := patternsJSON(t, append(tt.args, "--format", "json")...).ids()
			if !slices.Equal(got, want) {
				t.Errorf("cryptoscan %s printed\n\t%v\nwant\n\t%v", strings.Join(tt.args, " "), got, want)
			}
		})
	}
}

func TestPatternsRejectsValuesItDoesNotKnow(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"quantum level", []string{"patterns", "list", "--quantum", "high"}, `unknown --quantum "high" (valid: vulnerable, partial, safe, unknown)`},
		{"category", []string{"patterns", "list", "--category", "Certificates"}, `unknown --category "Certificates" (valid: `},
		{"format", []string{"patterns", "search", "rsa", "--format", "sarif"}, `unknown --format "sarif" (valid: text, json)`},
		{"blank search term", []string{"patterns", "search", " "}, `search needs a term`},
		{"unknown subcommand", []string{"patterns", "show"}, `unknown command "show" for "cryptoscan patterns"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := executePatterns(t, tt.args...)
			if err == nil {
				t.Fatalf("cryptoscan %s succeeded, want an error:\n%s", strings.Join(tt.args, " "), out)
			}
			if !strings.Contains(out, tt.want) {
				t.Errorf("output = %q, want it to contain %q", out, tt.want)
			}
		})
	}

	// The category error names every category the patterns carry.
	out, _ := executePatterns(t, "patterns", "list", "--category", "Certificates")
	for _, p := range scannerPatterns(t) {
		if !strings.Contains(out, p.Category) {
			t.Errorf("the --category error does not name the category %q:\n%s", p.Category, out)
		}
	}
}

func TestPatternsSearchWithNoMatchSaysSoAndSucceeds(t *testing.T) {
	const term = "no-pattern-has-this-term"
	all := scannerPatterns(t)
	if ids := idsOf(all, func(p patterns.Pattern) bool { return searchSelects(p, term) }); len(ids) > 0 {
		t.Fatalf("%v match %q; pick a term that no pattern matches", ids, term)
	}

	out, err := executePatterns(t, "patterns", "search", term)
	if err != nil {
		t.Fatalf("a search with no match failed: %v\n%s", err, out)
	}
	if want := fmt.Sprintf("0 of %d patterns match.", len(all)); !strings.Contains(out, want) {
		t.Errorf("output = %q, want it to contain %q", out, want)
	}
	if !strings.Contains(out, "cryptoscan patterns list") {
		t.Errorf("output = %q, want it to name cryptoscan patterns list", out)
	}
	if strings.Contains(out, "QUANTUM RISK") {
		t.Errorf("output prints a table header with no rows:\n%s", out)
	}

	out, err = executePatterns(t, "patterns", "search", term, "--format", "json")
	if err != nil {
		t.Fatalf("a JSON search with no match failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"patterns":[]`) {
		t.Errorf("JSON output = %q, want an empty patterns array", out)
	}
}

func TestPatternsWithoutSubcommandPrintsHelp(t *testing.T) {
	out, err := executePatterns(t, "patterns")
	if err != nil {
		t.Fatalf("cryptoscan patterns failed: %v\n%s", err, out)
	}
	for _, want := range []string{"list", "search", "Available Commands:"} {
		if !strings.Contains(out, want) {
			t.Errorf("cryptoscan patterns output does not contain %q:\n%s", want, out)
		}
	}
}
