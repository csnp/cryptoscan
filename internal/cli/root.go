// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/csnp/cryptoscan/pkg/version"
)

var (
	commit    = "none"
	buildDate = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "cryptoscan",
	Short: "Scan codebases for cryptographic usage and quantum vulnerabilities",
	Long: `CryptoScan - QRAMM Cryptographic Discovery Scanner

A powerful tool for discovering cryptographic algorithms, key sizes, and
quantum-vulnerable patterns in your codebase. Part of the QRAMM (Quantum
Readiness Assurance Maturity Model) toolkit by CSNP.

CryptoScan helps organizations prepare for post-quantum cryptography by:
  - Discovering hardcoded cryptographic algorithms (RSA, ECC, AES, etc.)
  - Identifying key sizes and configurations
  - Detecting crypto library usage patterns
  - Generating CBOM (Cryptographic Bill of Materials)
  - Flagging quantum-vulnerable cryptography

Examples:
  # Scan current directory
  cryptoscan scan .

  # Scan a Git repository
  cryptoscan scan https://github.com/org/repo

  # Scan with JSON output
  cryptoscan scan . --format json --output report.json

  # Scan specific file types only
  cryptoscan scan . --include "*.go,*.py,*.java"

Learn more at https://qramm.org`,
}

// SetVersionInfo records the build metadata injected by GoReleaser. The version
// string is stored in pkg/version so that every output surface reports the same
// value; commit and build date are only shown by the version command.
func SetVersionInfo(v, c, d string) {
	version.Set(v)
	commit = c
	buildDate = d
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("cryptoscan %s\n", version.Get())
		if commit != "none" {
			fmt.Printf("  commit: %s\n", commit)
		}
		if buildDate != "unknown" {
			fmt.Printf("  built:  %s\n", buildDate)
		}
		fmt.Printf("\nPart of QRAMM - https://qramm.org\n")
		fmt.Printf("Copyright 2025-2026 CSNP - https://csnp.org\n")
	},
}
