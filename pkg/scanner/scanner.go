// Copyright 2025 Cyber Security Non-Profit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/csnp/qramm-cryptoscan/pkg/analyzer"
	"github.com/csnp/qramm-cryptoscan/pkg/patterns"
	"github.com/csnp/qramm-cryptoscan/pkg/types"
)

// Re-export types for convenience
type Severity = types.Severity
type QuantumRisk = types.QuantumRisk
type Confidence = types.Confidence
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
	Target           string
	IncludeGlobs     []string
	ExcludeGlobs     []string
	MaxDepth         int
	ShowProgress     bool
	ScanGitHistory   bool
	ScanDependencies bool
	MinSeverity      Severity
	MinConfidence    Confidence
	IncludeDocs      bool // Whether to include documentation files
}

// Results contains all scan results
type Results struct {
	Findings       []Finding            `json:"findings"`
	Summary        Summary              `json:"summary"`
	Insights       []Insight            `json:"insights"`
	ScanTarget     string               `json:"scanTarget"`
	ScanTime       time.Time            `json:"scanTime"`
	ScanDuration   time.Duration        `json:"scanDuration"`
	FilesScanned   int                  `json:"filesScanned"`
	LinesScanned   int                  `json:"linesScanned"`
	LanguageStats  map[string]int       `json:"languageStats"`
	Metadata       map[string]string    `json:"metadata,omitempty"`
}

// Insight provides actionable intelligence derived from findings
type Insight struct {
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`    // high, medium, low
	Effort      string   `json:"effort"`      // Migration effort
	Findings    []string `json:"findingIds"`  // Related finding IDs
	Action      string   `json:"action"`      // Recommended action
}

// Summary provides aggregate statistics
type Summary struct {
	TotalFindings    int            `json:"totalFindings"`
	BySeverity       map[string]int `json:"bySeverity"`
	ByCategory       map[string]int `json:"byCategory"`
	ByQuantumRisk    map[string]int `json:"byQuantumRisk"`
	ByConfidence     map[string]int `json:"byConfidence"`
	ByFileType       map[string]int `json:"byFileType"`
	ByLanguage       map[string]int `json:"byLanguage"`
	QuantumVulnCount int            `json:"quantumVulnerableCount"`
	HighConfidence   int            `json:"highConfidenceCount"`
	ActionableCount  int            `json:"actionableCount"` // High confidence + code files
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
		filesScanned  int
		linesScanned  int
		languageStats map[string]int
	}
}

// New creates a new Scanner instance
func New(cfg Config) *Scanner {
	// Set defaults
	if cfg.MinConfidence == "" {
		cfg.MinConfidence = types.ConfidenceLow
	}

	return &Scanner{
		config:   cfg,
		patterns: patterns.NewMatcher(),
		findings: make([]Finding, 0),
		stats: struct {
			filesScanned  int
			linesScanned  int
			languageStats map[string]int
		}{
			languageStats: make(map[string]int),
		},
	}
}

// Scan performs the scan and returns results
func (s *Scanner) Scan() (*Results, error) {
	target := s.config.Target
	if isGitURL(target) {
		return nil, fmt.Errorf("git URL scanning not yet implemented - clone locally first")
	}

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

	// Sort findings by priority
	sort.Slice(s.findings, func(i, j int) bool {
		return s.findings[i].Priority() > s.findings[j].Priority()
	})

	// Build results
	results := &Results{
		Findings:      s.findings,
		FilesScanned:  s.stats.filesScanned,
		LinesScanned:  s.stats.linesScanned,
		LanguageStats: s.stats.languageStats,
		Metadata:      make(map[string]string),
	}

	results.Summary = s.calculateSummary()
	results.Insights = s.generateInsights()

	return results, nil
}

func (s *Scanner) scanDirectory(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			return s.shouldSkipDir(root, path, d.Name())
		}

		if !s.shouldScanFile(path) {
			return nil
		}

		return s.scanFile(path)
	})
}

func (s *Scanner) shouldSkipDir(root, path, name string) error {
	relPath, _ := filepath.Rel(root, path)

	// Always skip these
	skipDirs := map[string]bool{
		".git": true, ".svn": true, ".hg": true,
		"node_modules": true, "__pycache__": true,
		".idea": true, ".vscode": true,
	}
	if skipDirs[name] {
		return filepath.SkipDir
	}

	for _, pattern := range s.config.ExcludeGlobs {
		if matched, _ := filepath.Match(pattern, relPath); matched {
			return filepath.SkipDir
		}
		if matched, _ := filepath.Match(pattern, name); matched {
			return filepath.SkipDir
		}
	}

	return nil
}

func (s *Scanner) shouldScanFile(path string) bool {
	name := filepath.Base(path)
	ext := filepath.Ext(path)

	// Skip binary files
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
		".pdf": true, ".zip": true, ".tar": true, ".gz": true, ".7z": true,
		".bin": true, ".dat": true, ".db": true, ".sqlite": true,
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
		".mp3": true, ".mp4": true, ".wav": true, ".avi": true, ".mkv": true,
		".class": true, ".jar": true, ".war": true, ".pyc": true,
		// Office formats (ZIP archives containing XML - scanning raw causes false positives)
		".xlsx": true, ".xls": true, ".docx": true, ".doc": true,
		".pptx": true, ".ppt": true, ".odt": true, ".ods": true, ".odp": true,
	}
	if binaryExts[ext] {
		return false
	}

	// Get file context
	ctx := analyzer.Analyze(path)

	// Skip documentation if not explicitly included
	if !s.config.IncludeDocs && ctx.FileType == analyzer.FileTypeDocumentation {
		return false
	}

	// Check exclude patterns
	for _, pattern := range s.config.ExcludeGlobs {
		if matched, _ := filepath.Match(pattern, name); matched {
			return false
		}
	}

	// Check include patterns
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
		return nil
	}
	defer file.Close()

	// Analyze file context
	fileCtx := analyzer.Analyze(path)

	s.mu.Lock()
	s.stats.filesScanned++
	s.stats.languageStats[string(fileCtx.Language)]++
	s.mu.Unlock()

	// Check if this is a dependency file
	if fileCtx.FileType == analyzer.FileTypeDependency {
		return s.scanDependencyFile(path, fileCtx)
	}

	scanner := bufio.NewScanner(file)
	// Increase buffer size for long lines (e.g., minified files, go.sum)
	const maxScanTokenSize = 1024 * 1024 // 1MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	lineNum := 0
	var prevLines []string

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		s.mu.Lock()
		s.stats.linesScanned++
		s.mu.Unlock()

		// Get line context
		lineCtx := analyzer.AnalyzeLine(line, fileCtx.Language, prevLines)

		// Skip comments in code files (but still scan for keys/secrets)
		if lineCtx.IsComment && !strings.Contains(strings.ToLower(line), "key") &&
			!strings.Contains(strings.ToLower(line), "secret") {
			prevLines = append(prevLines, line)
			if len(prevLines) > 5 {
				prevLines = prevLines[1:]
			}
			continue
		}

		// Run pattern matching with context
		matches := s.patterns.MatchWithContext(line, path, lineNum, fileCtx, lineCtx)

		for _, m := range matches {
			// Apply confidence filter
			if !s.meetsConfidenceThreshold(m.Confidence) {
				continue
			}

			// Apply severity filter
			if m.Severity >= s.config.MinSeverity {
				s.mu.Lock()
				s.findings = append(s.findings, m)
				s.mu.Unlock()
			}
		}

		// Keep last 5 lines for context
		prevLines = append(prevLines, line)
		if len(prevLines) > 5 {
			prevLines = prevLines[1:]
		}
	}

	return scanner.Err()
}

func (s *Scanner) scanDependencyFile(path string, fileCtx *analyzer.FileContext) error {
	deps, err := analyzer.ScanDependencies(path)
	if err != nil {
		return nil // Don't fail on dependency scanning errors
	}

	for _, dep := range deps {
		finding := Finding{
			ID:          fmt.Sprintf("DEP-%s-%s", dep.Library.Name, filepath.Base(path)),
			Type:        "Crypto Library Dependency",
			FindingType: types.FindingTypeDependency,
			Category:    "dependency",
			Algorithm:   strings.Join(dep.Library.Algorithms, ", "),
			File:        path,
			Line:        1,
			Match:       dep.Library.Package,
			Context:     fmt.Sprintf("Version: %s", dep.Version),
			Severity:    dep.Severity,
			Quantum:     dep.Quantum,
			Confidence:  types.ConfidenceHigh,
			Language:    string(dep.Library.Language),
			FileType:    "dependency",
			Description: dep.Description,
			Remediation: dep.Remediation,
			Tags:        []string{"dependency", string(dep.Library.Language)},
		}

		if dep.Library.QuantumSafe {
			finding.Tags = append(finding.Tags, "pqc-ready")
		}

		s.mu.Lock()
		s.findings = append(s.findings, finding)
		s.mu.Unlock()
	}

	return nil
}

func (s *Scanner) meetsConfidenceThreshold(conf types.Confidence) bool {
	switch s.config.MinConfidence {
	case types.ConfidenceHigh:
		return conf == types.ConfidenceHigh
	case types.ConfidenceMedium:
		return conf == types.ConfidenceHigh || conf == types.ConfidenceMedium
	default:
		return true
	}
}

func (s *Scanner) calculateSummary() Summary {
	summary := Summary{
		TotalFindings: len(s.findings),
		BySeverity:    make(map[string]int),
		ByCategory:    make(map[string]int),
		ByQuantumRisk: make(map[string]int),
		ByConfidence:  make(map[string]int),
		ByFileType:    make(map[string]int),
		ByLanguage:    make(map[string]int),
	}

	for _, f := range s.findings {
		summary.BySeverity[f.Severity.String()]++
		summary.ByCategory[f.Category]++
		summary.ByQuantumRisk[string(f.Quantum)]++
		summary.ByConfidence[string(f.Confidence)]++
		if f.FileType != "" {
			summary.ByFileType[f.FileType]++
		}
		if f.Language != "" {
			summary.ByLanguage[f.Language]++
		}

		if f.Quantum == QuantumVulnerable {
			summary.QuantumVulnCount++
		}
		if f.Confidence == types.ConfidenceHigh {
			summary.HighConfidence++
		}
		if f.Confidence == types.ConfidenceHigh && f.FileType == "code" {
			summary.ActionableCount++
		}
	}

	return summary
}

func (s *Scanner) generateInsights() []Insight {
	var insights []Insight

	// Group findings by algorithm
	algoFindings := make(map[string][]Finding)
	for _, f := range s.findings {
		if f.Algorithm != "" {
			algoFindings[f.Algorithm] = append(algoFindings[f.Algorithm], f)
		}
	}

	// RSA Usage Insight
	if rsaFindings, ok := algoFindings["RSA"]; ok && len(rsaFindings) > 0 {
		var ids []string
		for _, f := range rsaFindings {
			ids = append(ids, f.ID)
		}
		insights = append(insights, Insight{
			Type:        "migration_required",
			Title:       fmt.Sprintf("RSA Migration Required (%d instances)", len(rsaFindings)),
			Description: "RSA is quantum-vulnerable and will be broken by Shor's algorithm. All RSA usage must migrate to ML-KEM (FIPS 203) for key encapsulation.",
			Priority:    "high",
			Effort:      "medium",
			Findings:    ids,
			Action:      "1. Inventory all RSA usage\n2. Implement hybrid RSA+ML-KEM during transition\n3. Complete migration to pure ML-KEM by 2030",
		})
	}

	// ECC Usage Insight
	if eccFindings, ok := algoFindings["ECC"]; ok && len(eccFindings) > 0 {
		var ids []string
		for _, f := range eccFindings {
			ids = append(ids, f.ID)
		}
		insights = append(insights, Insight{
			Type:        "migration_required",
			Title:       fmt.Sprintf("ECC/ECDSA Migration Required (%d instances)", len(eccFindings)),
			Description: "Elliptic curve cryptography is quantum-vulnerable. Signatures must migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
			Priority:    "high",
			Effort:      "medium",
			Findings:    ids,
			Action:      "1. Identify ECC usage (signatures vs key exchange)\n2. For signatures: migrate to ML-DSA\n3. For key exchange: migrate to ML-KEM",
		})
	}

	// Dependency vulnerabilities
	var depFindings []Finding
	for _, f := range s.findings {
		if f.FindingType == types.FindingTypeDependency && f.Quantum == QuantumVulnerable {
			depFindings = append(depFindings, f)
		}
	}
	if len(depFindings) > 0 {
		var ids []string
		libs := make(map[string]bool)
		for _, f := range depFindings {
			ids = append(ids, f.ID)
			libs[f.Match] = true
		}
		var libList []string
		for lib := range libs {
			libList = append(libList, lib)
		}
		insights = append(insights, Insight{
			Type:        "dependency_update",
			Title:       fmt.Sprintf("Crypto Libraries Need PQC Upgrade (%d libraries)", len(libs)),
			Description: fmt.Sprintf("Libraries detected: %s. These provide quantum-vulnerable algorithms.", strings.Join(libList, ", ")),
			Priority:    "medium",
			Effort:      "low",
			Findings:    ids,
			Action:      "Check for PQC-ready versions of these libraries or add PQC-capable alternatives",
		})
	}

	// Critical secrets
	var secretFindings []Finding
	for _, f := range s.findings {
		if f.FindingType == types.FindingTypeSecret {
			secretFindings = append(secretFindings, f)
		}
	}
	if len(secretFindings) > 0 {
		var ids []string
		for _, f := range secretFindings {
			ids = append(ids, f.ID)
		}
		insights = append(insights, Insight{
			Type:        "security_critical",
			Title:       fmt.Sprintf("Private Keys/Secrets Exposed (%d instances)", len(secretFindings)),
			Description: "Private keys or secrets found in source code. This is a critical security issue requiring immediate action.",
			Priority:    "critical",
			Effort:      "low",
			Findings:    ids,
			Action:      "1. Immediately rotate all exposed credentials\n2. Remove secrets from source code\n3. Use secrets management (Vault, AWS Secrets Manager, etc.)",
		})
	}

	return insights
}

func isGitURL(s string) bool {
	return strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "git@")
}
