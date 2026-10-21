// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/csnp/cryptoscan/pkg/version"
)

var (
	commit    = "none"
	buildDate = "unknown"
)

var rootCmd = &cobra.Command{
	Use:     "cryptoscan",
	Short:   "Scan codebases for cryptographic usage and quantum vulnerabilities",
	Version: version.Get(),
	Long: `CryptoScan - QRAMM Cryptographic Discovery Scanner

CryptoScan finds the cryptographic algorithms, key sizes and quantum-vulnerable
patterns in source code and configuration files. It is part of the QRAMM
(Quantum Readiness Assurance Maturity Model) toolkit by CSNP.

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
// value; commit and build date are only shown by the version command and the
// --version flag.
func SetVersionInfo(v, c, d string) {
	version.Set(v)
	rootCmd.Version = version.Get()
	commit = c
	buildDate = d
}

// hintedError is a runtime failure that carries one line telling the user what
// to try next. Execute prints the hint under cobra's "Error:" line.
type hintedError struct {
	err  error
	hint string
}

func (e *hintedError) Error() string { return e.err.Error() }
func (e *hintedError) Unwrap() error { return e.err }

// withHint attaches a next step to err. An empty hint leaves err unchanged.
func withHint(err error, hint string) error {
	if hint == "" {
		return err
	}
	return &hintedError{err: err, hint: hint}
}

func Execute() error {
	err := rootCmd.Execute()
	var hinted *hintedError
	if errors.As(err, &hinted) {
		fmt.Fprintln(rootCmd.ErrOrStderr(), hinted.hint)
	}
	return err
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(cbomCmd)
	rootCmd.AddCommand(gateCmd)
	rootCmd.AddCommand(pqcCmd)
	rootCmd.AddCommand(patternsCmd)
	rootCmd.AddCommand(versionCmd)

	// --version prints the same text as the version command. Declaring the
	// flag here, rather than letting cobra add it, sets its help text.
	rootCmd.Flags().BoolP("version", "v", false, "Print version information")
	cobra.AddTemplateFunc("versionText", versionText)
	rootCmd.SetVersionTemplate("{{versionText}}")
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprint(cmd.OutOrStdout(), versionText())
	},
}

// versionText is the output of both `cryptoscan version` and
// `cryptoscan --version`.
func versionText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "cryptoscan %s\n", version.Get())
	if commit != "none" {
		fmt.Fprintf(&b, "  commit: %s\n", commit)
	}
	if buildDate != "unknown" {
		fmt.Fprintf(&b, "  built:  %s\n", buildDate)
	}
	b.WriteString("\nPart of QRAMM - https://qramm.org\n")
	b.WriteString("Copyright 2025-2026 CSNP - https://csnp.org\n")
	return b.String()
}
