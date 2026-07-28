// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package version holds the single source of truth for the CryptoScan version
// string. The release build injects the value into main.version via GoReleaser
// ldflags; cmd/cryptoscan calls Set exactly once at startup, and every surface
// that reports a version (the version command, SARIF, CBOM, JSON) reads it from
// here.
//
// Emitting a version literal anywhere else produces a false provenance record:
// SARIF and CBOM are consumed as evidence of which scanner produced a result.
package version

// value is the process-wide version string. It is written once from
// cmd/cryptoscan before any command runs and read-only afterwards.
var value = "dev"

// Set records the version string for the running binary. It is called once from
// cmd/cryptoscan/main.go with the value injected at build time.
func Set(v string) {
	if v != "" {
		value = v
	}
}

// Get returns the version string reported by every CryptoScan output surface.
func Get() string {
	return value
}
