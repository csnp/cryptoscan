// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/csnp/qramm-cryptoscan/pkg/patterns"
	"github.com/csnp/qramm-cryptoscan/pkg/types"
)

// Re-export types for convenience
type Severity = types.Severity
type QuantumRisk = types.QuantumRisk
type Finding = types.Finding

const (
	SeverityInfo     = types.SeverityInfo
	SeverityLow      = types.SeverityLow
	SeverityMedium   = types.SeverityMedium
	SeverityHigh     = types.SeverityHigh
	SeverityCritical = types.SeverityCritical
)

const (
	QuantumVulnerable = types.QuantumVulnerable
	QuantumPartial    = types.QuantumPartial
	QuantumSafe       = types.QuantumSafe
	QuantumUnknown    = types.QuantumUnknown
)

// Config holds scanner configuration
type Config struct {
	Target         string
	IncludeGlobs   []string
	ExcludeGlobs   []string
	MaxDepth       int
	ShowProgress   bool
	ScanGitHistory bool
	MinSeverity    Severity
}

// Results contains all scan results
type Results struct {
	Findings     []Finding         `json:"findings"`
	Summary      Summary           `json:"summary"`
	ScanTarget   string            `json:"scanTarget"`
	ScanTime     time.Time         `json:"scanTime"`
	ScanDuration time.Duration     `json:"scanDuration"`
	FilesScanned int               `json:"filesScanned"`
	LinesScanned int               `json:"linesScanned"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// Summary provides aggregate statistics
type Summary struct {
	TotalFindings    int            `json:"totalFindings"`
	BySeverity       map[string]int `json:"bySeverity"`
	ByCategory       map[string]int `json:"byCategory"`
	ByQuantumRisk    map[string]int `json:"byQuantumRisk"`
	QuantumVulnCount int            `json:"quantumVulnerableCount"`
}

// HasCritical returns true if any critical findings exist
func (r *Results) HasCritical() bool {
	return r.Summary.BySeverity["CRITICAL"] > 0
}

// Scanner performs cryptographic scanning
type Scanner struct {
	config   Config
	patterns *patterns.Matcher
	mu       sync.Mutex
	findings []Finding
	stats    struct {
		filesScanned int
		linesScanned int
	}
}

// New creates a new Scanner instance
func New(cfg Config) *Scanner {
	return &Scanner{
		config:   cfg,
		patterns: patterns.NewMatcher(),
		findings: make([]Finding, 0),
	}
}

// Scan performs the scan and returns results
func (s *Scanner) Scan() (*Results, error) {
	// Check if target is URL (git clone) or local path
	target := s.config.Target
	if isGitURL(target) {
		return nil, fmt.Errorf("git URL scanning not yet implemented - clone locally first")
	}

	// Verify path exists
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot access target: %w", err)
	}

	if info.IsDir() {
		err = s.scanDirectory(target)
	} else {
		err = s.scanFile(target)
	}

	if err != nil {
		return nil, err
	}

	// Build results
	results := &Results{
		Findings:     s.findings,
		FilesScanned: s.stats.filesScanned,
		LinesScanned: s.stats.linesScanned,
		Metadata:     make(map[string]string),
	}

	// Calculate summary
	results.Summary = s.calculateSummary()

	return results, nil
}

func (s *Scanner) scanDirectory(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors, continue scanning
		}

		// Skip directories we should exclude
		if d.IsDir() {
			relPath, _ := filepath.Rel(root, path)
			for _, pattern := range s.config.ExcludeGlobs {
				if matched, _ := filepath.Match(pattern, relPath); matched {
					return filepath.SkipDir
				}
				if matched, _ := filepath.Match(pattern, d.Name()); matched {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check if file should be scanned
		if !s.shouldScanFile(path) {
			return nil
		}

		return s.scanFile(path)
	})
}

func (s *Scanner) shouldScanFile(path string) bool {
	name := filepath.Base(path)
	ext := filepath.Ext(path)

	// Skip binary and non-text files
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
		".pdf": true, ".zip": true, ".tar": true, ".gz": true,
		".bin": true, ".dat": true, ".db": true, ".sqlite": true,
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
		".mp3": true, ".mp4": true, ".wav": true, ".avi": true,
		".class": true, ".jar": true, ".war": true,
	}
	if binaryExts[ext] {
		return false
	}

	// Check exclude patterns
	for _, pattern := range s.config.ExcludeGlobs {
		if matched, _ := filepath.Match(pattern, name); matched {
			return false
		}
		if matched, _ := filepath.Match(pattern, path); matched {
			return false
		}
	}

	// Check include patterns (if specified)
	if len(s.config.IncludeGlobs) > 0 {
		included := false
		for _, pattern := range s.config.IncludeGlobs {
			if matched, _ := filepath.Match(pattern, name); matched {
				included = true
				break
			}
		}
		if !included {
			return false
		}
	}

	return true
}

func (s *Scanner) scanFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return nil // Skip files we can't open
	}
	defer file.Close()

	s.mu.Lock()
	s.stats.filesScanned++
	s.mu.Unlock()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		s.mu.Lock()
		s.stats.linesScanned++
		s.mu.Unlock()

		// Run pattern matching
		matches := s.patterns.Match(line, path, lineNum)
		for _, m := range matches {
			if m.Severity >= s.config.MinSeverity {
				s.mu.Lock()
				s.findings = append(s.findings, m)
				s.mu.Unlock()
			}
		}
	}

	return scanner.Err()
}

func (s *Scanner) calculateSummary() Summary {
	summary := Summary{
		TotalFindings: len(s.findings),
		BySeverity:    make(map[string]int),
		ByCategory:    make(map[string]int),
		ByQuantumRisk: make(map[string]int),
	}

	for _, f := range s.findings {
		summary.BySeverity[f.Severity.String()]++
		summary.ByCategory[f.Category]++
		summary.ByQuantumRisk[string(f.Quantum)]++
		if f.Quantum == QuantumVulnerable {
			summary.QuantumVulnCount++
		}
	}

	return summary
}

func isGitURL(s string) bool {
	return strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "git@")
}
