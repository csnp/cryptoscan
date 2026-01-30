// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package config handles configuration file loading for cryptoscan
package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the .cryptoscan.yaml configuration file
type Config struct {
	Ignore struct {
		Patterns   []string `yaml:"patterns"`   // Pattern IDs to ignore (e.g., "RSA-001", "CERT-SELFSIGNED-001")
		Categories []string `yaml:"categories"` // Categories to ignore (e.g., "Certificate", "Library Import")
		Files      []string `yaml:"files"`      // File patterns to ignore (e.g., "vendor/*", "test/*")
	} `yaml:"ignore"`

	FailOn      string `yaml:"failOn"`      // Exit non-zero if findings at this severity or higher (info, low, medium, high, critical)
	MinSeverity string `yaml:"minSeverity"` // Minimum severity to report (info, low, medium, high, critical)
	Format      string `yaml:"format"`      // Output format (text, json, sarif, cbom)

	// CI/CD specific
	Baseline string `yaml:"baseline"` // Path to baseline JSON file for comparison
}

// Load reads and parses a config file from the given path
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// FindConfigFile searches for a config file in the given directory and its parents
// Returns the path to the config file if found, empty string otherwise
func FindConfigFile(startDir string) string {
	// Config file names to search for (in order of preference)
	configNames := []string{".cryptoscan.yaml", ".cryptoscan.yml", "cryptoscan.yaml", "cryptoscan.yml"}

	dir := startDir
	for {
		for _, name := range configNames {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}

		// Move to parent directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root, no config found
			break
		}
		dir = parent
	}

	return ""
}

// MatchesPattern checks if a pattern ID matches an ignore pattern
// Supports exact matches and prefix wildcards (e.g., "RSA-*" matches "RSA-001")
func MatchesPattern(patternID, ignorePattern string) bool {
	ignorePattern = strings.TrimSpace(ignorePattern)
	patternID = strings.TrimSpace(patternID)

	// Exact match (case-insensitive)
	if strings.EqualFold(patternID, ignorePattern) {
		return true
	}

	// Wildcard match (e.g., "RSA-*" matches "RSA-001")
	if strings.HasSuffix(ignorePattern, "*") {
		prefix := strings.TrimSuffix(ignorePattern, "*")
		if strings.HasPrefix(strings.ToUpper(patternID), strings.ToUpper(prefix)) {
			return true
		}
	}

	// Prefix match (e.g., "RSA" matches "RSA-001")
	if strings.HasPrefix(strings.ToUpper(patternID), strings.ToUpper(ignorePattern)+"-") {
		return true
	}

	return false
}

// MatchesCategory checks if a category matches an ignore category (case-insensitive)
func MatchesCategory(category, ignoreCategory string) bool {
	return strings.EqualFold(strings.TrimSpace(category), strings.TrimSpace(ignoreCategory))
}
