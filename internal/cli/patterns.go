// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/csnp/cryptoscan/pkg/config"
	"github.com/csnp/cryptoscan/pkg/patterns"
	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/types"
	"github.com/csnp/cryptoscan/pkg/version"
)

// patternsFormats are the outputs the patterns commands print.
var patternsFormats = []string{"text", "json"}

// quantumRisks are the quantum risk levels a pattern can carry, in the order
// --quantum lists them.
var quantumRisks = []types.QuantumRisk{
	types.QuantumVulnerable, types.QuantumPartial, types.QuantumSafe, types.QuantumUnknown,
}

var (
	patternsCategory string
	patternsQuantum  string
	patternsFormat   string
)

var patternsCmd = &cobra.Command{
	Use:   "patterns",
	Short: "List and search the detection patterns a scan checks for",
	Long: `List and search the detection patterns a scan matches against the lines
of the files it reads, without scanning anything.

The list comes from the scanner's own pattern definitions, so it holds the
patterns a scan runs. Each pattern has an ID, which --ignore accepts, a
category, which --ignore-category accepts, a severity, a quantum risk
(vulnerable, partial, safe or unknown) and a name.

What a scan reports can differ from the list: it can lower a finding's
severity, for example in a test file, and some findings appear only when a
flag such as --include-imports asks for them. Dependency manifests such as
go.mod and package.json are checked against a separate list of crypto
libraries, so their findings (IDs starting with DEP-) are not in this list.

Examples:
  cryptoscan patterns list
  cryptoscan patterns list --quantum vulnerable
  cryptoscan patterns list --category Certificate
  cryptoscan patterns search kyber
  cryptoscan patterns search rsa --format json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var patternsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List every detection pattern, or those in one category or at one quantum risk",
	Long: `List the detection patterns, one per line, in the order the scanner checks
them: ID, severity, quantum risk, category and name. --category keeps the
patterns in one category, ignoring case, as --ignore-category compares it.
--quantum keeps the patterns at one quantum risk. --format json adds each
pattern's description, remediation, references, tags and regular expression.

Examples:
  cryptoscan patterns list
  cryptoscan patterns list --quantum vulnerable
  cryptoscan patterns list --category "Secret Detection"
  cryptoscan patterns list --format json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return printPatterns(cmd, "")
	},
}

var patternsSearchCmd = &cobra.Command{
	Use:   "search <term>",
	Short: "List the detection patterns that mention a term or whose expression matches it",
	Long: `List the detection patterns whose ID, name, category, algorithm or
description contains the term, ignoring case, and those whose regular
expression matches the term itself. "search kyber" lists the ML-KEM pattern,
whose expression matches the name Kyber. --category, --quantum and --format
work as they do for list.

Examples:
  cryptoscan patterns search rsa
  cryptoscan patterns search kyber
  cryptoscan patterns search md5 --format json
  cryptoscan patterns search key --quantum vulnerable`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		term := strings.TrimSpace(args[0])
		if term == "" {
			cmd.SilenceUsage = true
			return errors.New(`search needs a term; to see every pattern, run "cryptoscan patterns list"`)
		}
		return printPatterns(cmd, term)
	},
}

func init() {
	for _, cmd := range []*cobra.Command{patternsListCmd, patternsSearchCmd} {
		cmd.Flags().StringVar(&patternsCategory, "category", "", "Show only patterns in this category (e.g., \"Certificate\")")
		cmd.Flags().StringVar(&patternsQuantum, "quantum", "", "Show only patterns at this quantum risk: "+strings.Join(quantumRiskNames(), ", "))
		cmd.Flags().StringVarP(&patternsFormat, "format", "f", "text", "Output format: "+strings.Join(patternsFormats, ", "))
		patternsCmd.AddCommand(cmd)
	}
}

// quantumRiskNames are the values --quantum accepts.
func quantumRiskNames() []string {
	names := make([]string, len(quantumRisks))
	for i, q := range quantumRisks {
		names[i] = strings.ToLower(string(q))
	}
	return names
}

// patternCategories returns the categories the patterns carry, sorted, each
// once.
func patternCategories(all []patterns.Pattern) []string {
	var categories []string
	for _, p := range all {
		if !slices.Contains(categories, p.Category) {
			categories = append(categories, p.Category)
		}
	}
	slices.Sort(categories)
	return categories
}

// patternFilter selects the patterns a patterns command prints. An empty
// field selects every pattern.
type patternFilter struct {
	term     string
	category string
	quantum  string
}

// selects reports whether f keeps p. The term is found when it appears,
// ignoring case, in the pattern's ID, name, category, algorithm or
// description, or when the pattern's expression matches the term, as it
// would match a scanned line holding only the term. The category is compared
// as --ignore-category compares it.
func (f patternFilter) selects(p patterns.Pattern) bool {
	if f.category != "" && !config.MatchesCategory(p.Category, f.category) {
		return false
	}
	if f.quantum != "" && !strings.EqualFold(string(p.Quantum), f.quantum) {
		return false
	}
	if f.term == "" {
		return true
	}
	term := strings.ToLower(f.term)
	for _, field := range []string{p.ID, p.Name, p.Category, p.Algorithm, p.Description} {
		if strings.Contains(strings.ToLower(field), term) {
			return true
		}
	}
	return p.Regex.MatchString(f.term)
}

// checkPatternsOptions returns an error for the first --format, --quantum or
// --category value the patterns commands do not accept. The categories
// accepted are the ones in all.
func checkPatternsOptions(all []patterns.Pattern) error {
	if !containsFold(patternsFormats, patternsFormat) {
		return fmt.Errorf("unknown --format %q (valid: %s)", patternsFormat, strings.Join(patternsFormats, ", "))
	}
	if patternsQuantum != "" && !containsFold(quantumRiskNames(), patternsQuantum) {
		return fmt.Errorf("unknown --quantum %q (valid: %s)", patternsQuantum, strings.Join(quantumRiskNames(), ", "))
	}
	if patternsCategory != "" {
		categories := patternCategories(all)
		known := slices.ContainsFunc(categories, func(c string) bool {
			return config.MatchesCategory(c, patternsCategory)
		})
		if !known {
			return fmt.Errorf("unknown --category %q (valid: %s)", patternsCategory, strings.Join(categories, ", "))
		}
	}
	return nil
}

// printPatterns prints the patterns that term, --category and --quantum
// select, in the order the scanner checks them.
func printPatterns(cmd *cobra.Command, term string) error {
	// Cobra has parsed the arguments by now. An error from here on names the
	// values that are accepted, which the usage block would bury.
	cmd.SilenceUsage = true

	all := patterns.NewMatcher().Patterns()
	if err := checkPatternsOptions(all); err != nil {
		return err
	}
	filter := patternFilter{term: term, category: patternsCategory, quantum: patternsQuantum}
	var selected []patterns.Pattern
	for _, p := range all {
		if filter.selects(p) {
			selected = append(selected, p)
		}
	}

	if strings.EqualFold(patternsFormat, "json") {
		return writePatternsJSON(cmd.OutOrStdout(), selected)
	}
	return writePatternsText(cmd.OutOrStdout(), selected, len(all), filter != patternFilter{})
}

// writePatternsText prints one line per pattern under a header, then how many
// of the total patterns it printed.
func writePatternsText(w io.Writer, selected []patterns.Pattern, total int, filtered bool) error {
	if len(selected) == 0 {
		_, err := fmt.Fprintf(w, "0 of %d patterns match. Run \"cryptoscan patterns list\" to see them all.\n", total)
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tQUANTUM RISK\tCATEGORY\tNAME")
	for _, p := range selected {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.ID, p.Severity, p.Quantum, p.Category, p.Name)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	count := fmt.Sprintf("%d patterns.", total)
	if filtered {
		count = fmt.Sprintf("%d of %d patterns.", len(selected), total)
	}
	_, err := fmt.Fprintf(w, "\n%s For each pattern's description, remediation and regular expression, add --format json.\n", count)
	return err
}

// patternEntry is one pattern in the JSON the patterns commands print.
type patternEntry struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	QuantumRisk string   `json:"quantumRisk"`
	Algorithm   string   `json:"algorithm,omitempty"`
	KeySize     int      `json:"keySize,omitempty"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Regex       string   `json:"regex"`
}

// writePatternsJSON writes the tool and the selected patterns as one JSON
// object. No match gives an empty patterns array.
func writePatternsJSON(w io.Writer, selected []patterns.Pattern) error {
	entries := make([]patternEntry, 0, len(selected))
	for _, p := range selected {
		entries = append(entries, patternEntry{
			ID:          p.ID,
			Name:        p.Name,
			Category:    p.Category,
			Severity:    p.Severity.String(),
			QuantumRisk: string(p.Quantum),
			Algorithm:   p.Algorithm,
			KeySize:     p.KeySize,
			Description: p.Description,
			Remediation: p.Remediation,
			References:  p.References,
			Tags:        p.Tags,
			Regex:       p.Regex.String(),
		})
	}
	data, err := json.Marshal(struct {
		Tool     scanner.ToolInfo `json:"tool"`
		Patterns []patternEntry   `json:"patterns"`
	}{
		Tool:     scanner.ToolInfo{Name: "CryptoScan", Version: version.Get()},
		Patterns: entries,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
