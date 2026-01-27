// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"

	"github.com/csnp/cryptoscan/pkg/scanner"
)

// JSONReporter generates JSON output
type JSONReporter struct {
	pretty bool
}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter(pretty bool) *JSONReporter {
	return &JSONReporter{pretty: pretty}
}

// Generate creates the JSON report
func (r *JSONReporter) Generate(results *scanner.Results) (string, error) {
	var data []byte
	var err error

	if r.pretty {
		data, err = json.MarshalIndent(results, "", "  ")
	} else {
		data, err = json.Marshal(results)
	}

	if err != nil {
		return "", err
	}

	return string(data), nil
}
