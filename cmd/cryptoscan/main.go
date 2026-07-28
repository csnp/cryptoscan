// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"runtime/debug"
	"time"

	"github.com/csnp/cryptoscan/internal/cli"
)

var (
	// These can be overridden with ldflags:
	// go build -ldflags "-X main.version=v1.1.1 -X main.commit=abc123 -X main.date=2025-01-27"
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func init() {
	// Try to get version info from Go module (works with go install)
	if info, ok := debug.ReadBuildInfo(); ok {
		if version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if commit == "none" && len(setting.Value) >= 7 {
					commit = setting.Value[:7]
				}
			case "vcs.time":
				if date == "unknown" && setting.Value != "" {
					if t, err := time.Parse(time.RFC3339, setting.Value); err == nil {
						date = t.Format("2006-01-02")
					}
				}
			}
		}
	}
}

func main() {
	cli.SetVersionInfo(version, commit, date)
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
