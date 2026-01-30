// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		patternID     string
		ignorePattern string
		want          bool
	}{
		// Exact matches
		{"RSA-001", "RSA-001", true},
		{"RSA-001", "rsa-001", true}, // case insensitive
		{"RSA-001", "RSA-002", false},

		// Wildcard matches
		{"RSA-001", "RSA-*", true},
		{"RSA-002", "RSA-*", true},
		{"CERT-SELFSIGNED-001", "CERT-*", true},
		{"CERT-SELFSIGNED-001", "CERT-SELFSIGNED-*", true},
		{"DES-001", "RSA-*", false},

		// Prefix matches (no wildcard)
		{"RSA-001", "RSA", true},
		{"RSA-002", "RSA", true},
		{"ECDSA-001", "ECD", false}, // partial prefix doesn't match without wildcard

		// No match
		{"RSA-001", "DES-001", false},
		{"RSA-001", "ECDSA-*", false},
	}

	for _, tt := range tests {
		t.Run(tt.patternID+"/"+tt.ignorePattern, func(t *testing.T) {
			got := MatchesPattern(tt.patternID, tt.ignorePattern)
			if got != tt.want {
				t.Errorf("MatchesPattern(%q, %q) = %v, want %v", tt.patternID, tt.ignorePattern, got, tt.want)
			}
		})
	}
}

func TestMatchesCategory(t *testing.T) {
	tests := []struct {
		category       string
		ignoreCategory string
		want           bool
	}{
		{"Certificate", "Certificate", true},
		{"Certificate", "certificate", true}, // case insensitive
		{"Certificate", "CERTIFICATE", true},
		{"Library Import", "Library Import", true},
		{"Library Import", "library import", true},
		{"Certificate", "Library Import", false},
		{"Hash", "Certificate", false},
	}

	for _, tt := range tests {
		t.Run(tt.category+"/"+tt.ignoreCategory, func(t *testing.T) {
			got := MatchesCategory(tt.category, tt.ignoreCategory)
			if got != tt.want {
				t.Errorf("MatchesCategory(%q, %q) = %v, want %v", tt.category, tt.ignoreCategory, got, tt.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".cryptoscan.yaml")

	content := `
ignore:
  patterns:
    - RSA-001
    - CERT-SELFSIGNED-001
  categories:
    - Library Import
  files:
    - "vendor/*"
    - "test/*"

failOn: high
minSeverity: low
format: json
baseline: baseline.json
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Check patterns
	if len(cfg.Ignore.Patterns) != 2 {
		t.Errorf("Expected 2 patterns, got %d", len(cfg.Ignore.Patterns))
	}
	if cfg.Ignore.Patterns[0] != "RSA-001" {
		t.Errorf("Expected first pattern 'RSA-001', got %q", cfg.Ignore.Patterns[0])
	}

	// Check categories
	if len(cfg.Ignore.Categories) != 1 {
		t.Errorf("Expected 1 category, got %d", len(cfg.Ignore.Categories))
	}
	if cfg.Ignore.Categories[0] != "Library Import" {
		t.Errorf("Expected category 'Library Import', got %q", cfg.Ignore.Categories[0])
	}

	// Check files
	if len(cfg.Ignore.Files) != 2 {
		t.Errorf("Expected 2 file patterns, got %d", len(cfg.Ignore.Files))
	}

	// Check other settings
	if cfg.FailOn != "high" {
		t.Errorf("Expected failOn 'high', got %q", cfg.FailOn)
	}
	if cfg.MinSeverity != "low" {
		t.Errorf("Expected minSeverity 'low', got %q", cfg.MinSeverity)
	}
	if cfg.Format != "json" {
		t.Errorf("Expected format 'json', got %q", cfg.Format)
	}
	if cfg.Baseline != "baseline.json" {
		t.Errorf("Expected baseline 'baseline.json', got %q", cfg.Baseline)
	}
}

func TestLoadNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/.cryptoscan.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

func TestFindConfigFile(t *testing.T) {
	// Create a temp directory structure
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir", "nested")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdirs: %v", err)
	}

	// Create config in root
	configPath := filepath.Join(tmpDir, ".cryptoscan.yaml")
	if err := os.WriteFile(configPath, []byte("failOn: high\n"), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Find from nested directory should find parent config
	found := FindConfigFile(subDir)
	if found != configPath {
		t.Errorf("FindConfigFile(%q) = %q, want %q", subDir, found, configPath)
	}

	// Find from root directory
	found = FindConfigFile(tmpDir)
	if found != configPath {
		t.Errorf("FindConfigFile(%q) = %q, want %q", tmpDir, found, configPath)
	}
}

func TestFindConfigFileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	found := FindConfigFile(tmpDir)
	if found != "" {
		t.Errorf("Expected empty string for no config, got %q", found)
	}
}

func TestFindConfigFileYml(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .yml variant
	configPath := filepath.Join(tmpDir, ".cryptoscan.yml")
	if err := os.WriteFile(configPath, []byte("failOn: high\n"), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	found := FindConfigFile(tmpDir)
	if found != configPath {
		t.Errorf("FindConfigFile(%q) = %q, want %q", tmpDir, found, configPath)
	}
}
