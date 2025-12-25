// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/csv"
	"strconv"
	"strings"

	"github.com/csnp/qramm-cryptoscan/pkg/scanner"
)

// CSVReporter generates CSV output for easy import into spreadsheets
type CSVReporter struct{}

// NewCSVReporter creates a new CSV reporter
func NewCSVReporter() *CSVReporter {
	return &CSVReporter{}
}

// Generate creates the CSV report
func (r *CSVReporter) Generate(results *scanner.Results) (string, error) {
	var b strings.Builder
	w := csv.NewWriter(&b)

	// Write header row
	header := []string{
		"ID",
		"Severity",
		"Type",
		"Category",
		"Algorithm",
		"Key Size",
		"Quantum Risk",
		"Confidence",
		"File",
		"Line",
		"Column",
		"Match",
		"Language",
		"File Type",
		"Purpose",
		"Description",
		"Remediation",
		"Impact",
		"Effort",
		"Tags",
		"Priority Score",
	}
	if err := w.Write(header); err != nil {
		return "", err
	}

	// Write findings
	for _, f := range results.Findings {
		row := []string{
			f.ID,
			f.Severity.String(),
			f.Type,
			f.Category,
			f.Algorithm,
			intToStr(f.KeySize),
			string(f.Quantum),
			string(f.Confidence),
			f.File,
			strconv.Itoa(f.Line),
			intToStr(f.Column),
			f.Match,
			f.Language,
			f.FileType,
			f.Purpose,
			f.Description,
			f.Remediation,
			f.Impact,
			f.Effort,
			strings.Join(f.Tags, "; "),
			strconv.Itoa(f.Priority()),
		}
		if err := w.Write(row); err != nil {
			return "", err
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}

	return b.String(), nil
}

// intToStr converts int to string, returning empty string for zero
func intToStr(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}
