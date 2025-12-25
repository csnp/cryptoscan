// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import "github.com/csnp/qramm-cryptoscan/pkg/scanner"

// Reporter interface for generating output in various formats
type Reporter interface {
	Generate(results *scanner.Results) (string, error)
}
