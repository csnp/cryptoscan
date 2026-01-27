// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/csnp/cryptoscan/internal/cli"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetVersionInfo(version, commit, date)
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
