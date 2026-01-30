// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/patterns"
	"github.com/csnp/cryptoscan/pkg/types"
)

// Re-export types for convenience
type Severity = types.Severity
type QuantumRisk = types.QuantumRisk
type Confidence = types.Confidence
type Finding = types.Finding
type MigrationScore = types.MigrationScore
type QRAMMReadiness = types.QRAMMReadiness
type FileRiskScore = types.FileRiskScore

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
	Target             string
	IncludeGlobs       []string
	ExcludeGlobs       []string
	MaxDepth           int
	ShowProgress       bool
	ScanGitHistory     bool
	ScanDependencies   bool
	MinSeverity        Severity
	MinConfidence      Confidence
	IncludeDocs        bool              // Whether to include documentation files
	IncludeImports     bool              // Whether to include library import findings (low-value, default false)
	IncludeQuantumSafe bool              // Whether to include quantum-safe findings like SHA-256, AES-256 (default false)
	OnFinding          func(Finding)     // Callback when a finding is discovered (for streaming output)
	OnFileScanned      func(path string) // Callback when a file is scanned (for progress)
}

// Results contains all scan results
type Results struct {
	Findings       []Finding             `json:"findings"`
	Summary        Summary               `json:"summary"`
	MigrationScore *types.MigrationScore `json:"migrationScore,omitempty"`
	Insights       []Insight             `json:"insights"`
	ScanTarget     string                `json:"scanTarget"`
	ScanTime       time.Time             `json:"scanTime"`
	ScanDuration   time.Duration         `json:"scanDuration"`
	FilesScanned   int                   `json:"filesScanned"`
	LinesScanned   int                   `json:"linesScanned"`
	BytesScanned   int64                 `json:"bytesScanned"`
	LanguageStats  map[string]int        `json:"languageStats"`
	Metadata       map[string]string     `json:"metadata,omitempty"`
}

// Insight provides actionable intelligence derived from findings
type Insight struct {
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`   // high, medium, low
	Effort      string   `json:"effort"`     // Migration effort
	Findings    []string `json:"findingIds"` // Related finding IDs
	Action      string   `json:"action"`     // Recommended action
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
	tempDir  string // Temporary directory for cloned repos
	stats    struct {
		filesScanned  int
		linesScanned  int
		bytesScanned  int64
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
			bytesScanned  int64
			languageStats map[string]int
		}{
			languageStats: make(map[string]int),
		},
	}
}

// Scan performs the scan and returns results
func (s *Scanner) Scan() (*Results, error) {
	target := s.config.Target

	// Handle Git URL - clone to temp directory
	if isGitURL(target) {
		clonePath, err := s.cloneRepository(target)
		if err != nil {
			return nil, fmt.Errorf("failed to clone repository: %w", err)
		}
		// Clean up temp directory when done
		defer s.Cleanup()
		target = clonePath
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot access target: %w", err)
	}

	if info.IsDir() {
		err = s.scanDirectory(target)
	} else {
		// Check if single file should be scanned (apply same filters as directory scan)
		if s.shouldScanFile(target) {
			err = s.scanFile(target)
		}
	}

	if err != nil {
		return nil, err
	}

	// Deduplicate findings (same file+line+category = keep highest priority)
	s.findings = s.deduplicateFindings(s.findings)

	// Sort findings by priority
	sort.Slice(s.findings, func(i, j int) bool {
		return s.findings[i].Priority() > s.findings[j].Priority()
	})

	// Calculate migration score and enhance findings with QRAMM mapping
	migrationScore := analyzer.CalculateMigrationScore(s.findings)

	// Build results
	results := &Results{
		Findings:       s.findings,
		MigrationScore: migrationScore,
		FilesScanned:   s.stats.filesScanned,
		LinesScanned:   s.stats.linesScanned,
		BytesScanned:   s.stats.bytesScanned,
		LanguageStats:  s.stats.languageStats,
		Metadata:       make(map[string]string),
	}

	results.Summary = s.calculateSummary()
	results.Insights = s.generateInsights()

	return results, nil
}

// cloneRepository clones a Git repository to a temporary directory
func (s *Scanner) cloneRepository(url string) (string, error) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "cryptoscan-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	s.tempDir = tempDir

	// Clone with shallow depth for speed, quiet mode
	cmd := exec.Command("git", "clone", "--depth", "1", "--single-branch", "--quiet", url, tempDir)

	if err := cmd.Run(); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("git clone failed: %w", err)
	}

	return tempDir, nil
}

// Cleanup removes temporary files created during scanning
func (s *Scanner) Cleanup() {
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
		s.tempDir = ""
	}
}

func (s *Scanner) scanDirectory(root string) error {
	// Collect files to scan (fast walk, no I/O)
	var filesToScan []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return s.shouldSkipDir(root, path, d.Name())
		}
		if s.shouldScanFile(path) {
			filesToScan = append(filesToScan, path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Use worker pool for parallel scanning
	numWorkers := runtime.NumCPU()
	if numWorkers > 16 {
		numWorkers = 16 // Cap at 16 to avoid too many open files
	}

	fileChan := make(chan string, 100)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				_ = s.scanFile(path) // Error logged internally
			}
		}()
	}

	// Send files to workers
	for _, path := range filesToScan {
		fileChan <- path
	}
	close(fileChan)

	// Wait for all workers to finish
	wg.Wait()
	return nil
}

func (s *Scanner) shouldSkipDir(root, path, name string) error {
	relPath, _ := filepath.Rel(root, path)
	pathLower := strings.ToLower(path)

	// Always skip these directory names
	skipDirs := map[string]bool{
		// Version control
		".git": true, ".svn": true, ".hg": true,
		// Dependencies
		"node_modules": true, "__pycache__": true,
		// IDE
		".idea": true, ".vscode": true,
		// Build outputs (these contain compiled/bundled code with false positives)
		".next": true, "dist": true, "build": true, "out": true,
		".output": true, ".nuxt": true, ".cache": true,
		// Coverage and test artifacts
		"coverage": true, ".nyc_output": true,
		// Compiled binaries
		"bin": true,
		// Example/demo directories (often contain non-production code)
		"examples": true, "example": true, "samples": true, "sample": true,
		"demo": true, "demos": true, "mock": true, "mocks": true,
		"fixtures": true, "testdata": true, "test-fixtures": true,
		// Terraform/infrastructure state
		".terraform": true,
	}
	if skipDirs[name] {
		return filepath.SkipDir
	}

	// Also check if ANY path component is a skip directory
	// This catches nested cases like .next/standalone/.next/ or sdk/typescript/dist/
	skipPathPatterns := []string{
		"/.next/", "/dist/", "/build/", "/out/", "/.output/",
		"/.nuxt/", "/.cache/", "/node_modules/", "/__pycache__/",
		"/coverage/", "/.nyc_output/", "/bin/",
		"/standalone/",    // Next.js standalone builds
		"/target/apidocs", // Java generated API docs
		"/target/site/",   // Maven site docs
		"/.egg-info/",     // Python build artifacts
	}
	for _, pattern := range skipPathPatterns {
		if strings.Contains(pathLower, pattern) {
			return filepath.SkipDir
		}
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
	nameLower := strings.ToLower(name)
	ext := filepath.Ext(path)

	// Skip binary files by extension
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
		// Source maps (generated, not real source)
		".map": true,
	}
	if binaryExts[ext] {
		return false
	}

	// Skip source map files (e.g., foo.js.map, foo.css.map)
	if strings.HasSuffix(nameLower, ".js.map") || strings.HasSuffix(nameLower, ".css.map") {
		return false
	}

	// Skip minified files (contain bundled code with coincidental matches)
	if strings.HasSuffix(nameLower, ".min.js") || strings.HasSuffix(nameLower, ".min.css") ||
		strings.HasSuffix(nameLower, "-min.js") || strings.HasSuffix(nameLower, "-min.css") {
		return false
	}

	// Skip lock files (contain package metadata with algorithm names, not actionable)
	lockFiles := map[string]bool{
		"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
		"poetry.lock": true, "pipfile.lock": true, "composer.lock": true,
		"gemfile.lock": true, "cargo.lock": true, "pubspec.lock": true,
		"packages.lock.json": true, "paket.lock": true,
	}
	if lockFiles[nameLower] {
		return false
	}

	// Skip backup and disabled test files
	if strings.HasSuffix(nameLower, ".bak") || strings.HasSuffix(nameLower, ".disabled") ||
		strings.HasSuffix(nameLower, ".orig") || strings.HasSuffix(nameLower, ".old") {
		return false
	}

	// Skip package metadata files (contain descriptions mentioning algorithms)
	metadataFiles := map[string]bool{
		"pkg-info": true, "metadata": true,
	}
	if metadataFiles[nameLower] {
		return false
	}

	// Skip compiled binaries without extensions (ELF, Mach-O, PE)
	if ext == "" && isBinaryFile(path) {
		return false
	}

	// Also check files that may be binaries with odd extensions
	if isBinaryFile(path) {
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

	// Get file size for stats
	fileInfo, err := file.Stat()
	if err != nil {
		return nil
	}
	fileSize := fileInfo.Size()

	// Analyze file context
	fileCtx := analyzer.Analyze(path)

	s.mu.Lock()
	s.stats.filesScanned++
	s.stats.bytesScanned += fileSize
	s.stats.languageStats[string(fileCtx.Language)]++
	s.mu.Unlock()

	// Progress callback
	if s.config.OnFileScanned != nil {
		s.config.OnFileScanned(path)
	}

	// Check if this is a dependency file
	if fileCtx.FileType == analyzer.FileTypeDependency {
		return s.scanDependencyFile(path, fileCtx)
	}

	// Read all lines first for context extraction
	allLines, err := s.readFileLines(path)
	if err != nil {
		return nil
	}

	// Skip minified files (detected by average line length)
	if isMinifiedFile(allLines) {
		return nil
	}

	var prevLines []string

	for lineNum, line := range allLines {
		lineNum++ // Convert to 1-based

		s.mu.Lock()
		s.stats.linesScanned++
		s.mu.Unlock()

		// Check for ignore comment on this line or previous line
		if s.hasIgnoreComment(line, allLines, lineNum) {
			continue
		}

		// Skip extremely long lines (minified/bundled code)
		// These produce false positives from coincidental string matches
		if len(line) > 1000 {
			continue
		}

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

			// Apply noise reduction filters
			if !s.shouldIncludeFinding(m) {
				continue
			}

			// Add source context (3 lines before and after)
			m.SourceContext = s.extractSourceContext(allLines, lineNum, 3)

			// Apply severity filter
			if m.Severity >= s.config.MinSeverity {
				s.mu.Lock()
				s.findings = append(s.findings, m)
				s.mu.Unlock()

				// Stream finding via callback
				if s.config.OnFinding != nil {
					s.config.OnFinding(m)
				}
			}
		}

		// Keep last 5 lines for context
		prevLines = append(prevLines, line)
		if len(prevLines) > 5 {
			prevLines = prevLines[1:]
		}
	}

	return nil
}

// readFileLines reads all lines from a file
func (s *Scanner) readFileLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	const maxScanTokenSize = 1024 * 1024 // 1MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// hasIgnoreComment checks if this line should be ignored via cryptoscan:ignore
func (s *Scanner) hasIgnoreComment(line string, allLines []string, lineNum int) bool {
	lowerLine := strings.ToLower(line)

	// Check inline comment on same line
	if strings.Contains(lowerLine, "cryptoscan:ignore") ||
		strings.Contains(lowerLine, "crypto-scan:ignore") ||
		strings.Contains(lowerLine, "noscan") {
		return true
	}

	// Check previous line for ignore directive
	if lineNum >= 2 && lineNum-2 < len(allLines) {
		prevLine := strings.ToLower(allLines[lineNum-2])
		if strings.Contains(prevLine, "cryptoscan:ignore") ||
			strings.Contains(prevLine, "crypto-scan:ignore") ||
			strings.Contains(prevLine, "cryptoscan:ignore-next-line") {
			return true
		}
	}

	return false
}

// extractSourceContext extracts lines around a finding for display
func (s *Scanner) extractSourceContext(allLines []string, lineNum int, contextLines int) *types.SourceContext {
	startLine := lineNum - contextLines
	if startLine < 1 {
		startLine = 1
	}
	endLine := lineNum + contextLines
	if endLine > len(allLines) {
		endLine = len(allLines)
	}

	ctx := &types.SourceContext{
		StartLine: startLine,
		EndLine:   endLine,
		MatchLine: lineNum,
		Lines:     make([]types.SourceLine, 0, endLine-startLine+1),
	}

	for i := startLine; i <= endLine; i++ {
		if i-1 < len(allLines) {
			content := allLines[i-1]
			// Truncate very long lines for display
			if len(content) > 200 {
				content = content[:200] + "..."
			}
			ctx.Lines = append(ctx.Lines, types.SourceLine{
				Number:  i,
				Content: content,
				IsMatch: i == lineNum,
			})
		}
	}

	return ctx
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

		// Stream finding via callback
		if s.config.OnFinding != nil {
			s.config.OnFinding(finding)
		}
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

// shouldIncludeFinding applies noise reduction filters
// Returns false if the finding should be suppressed based on config
func (s *Scanner) shouldIncludeFinding(f types.Finding) bool {
	// Skip library import findings unless explicitly included
	// These are low-value (just import statements, not actual crypto usage)
	if !s.config.IncludeImports && f.Category == "Library Import" {
		return false
	}

	// Skip quantum-safe/acceptable algorithms unless explicitly included
	// SHA-256, SHA-384, SHA-512, AES-256 are acceptable and create noise
	if !s.config.IncludeQuantumSafe {
		// Skip SHA-2 family (quantum partial, acceptable)
		if f.Algorithm == "SHA-2" && f.Quantum == types.QuantumPartial {
			return false
		}
		// Skip AES (quantum partial, acceptable especially AES-256)
		if f.Algorithm == "AES" && f.Quantum == types.QuantumPartial && f.Severity <= types.SeverityInfo {
			return false
		}
	}

	// Skip findings in low-value contexts (logs, labels, error messages, docstrings)
	// These mention algorithms but aren't actual cryptographic operations
	if isLowValueContext(f.Context) {
		return false
	}

	// Skip findings in files whose names indicate API docs or documentation
	fileLower := strings.ToLower(f.File)
	if strings.Contains(fileLower, "-documentation") || strings.Contains(fileLower, "-docs") ||
		strings.Contains(fileLower, "_documentation") || strings.Contains(fileLower, "_docs") ||
		strings.Contains(fileLower, "/docs/") || strings.Contains(fileLower, "/documentation/") {
		return false
	}

	return true
}

// isLowValueContext checks if a line contains algorithm mentions in contexts
// that are not actual cryptographic operations (logs, labels, error messages, docstrings)
func isLowValueContext(line string) bool {
	lineLower := strings.ToLower(line)

	// Log/print statements - algorithm mentioned in output, not usage
	logPatterns := []string{
		"fmt.print", "fmt.sprint", "fmt.fprint",
		"log.", "logger.", "logging.",
		"console.log", "console.error", "console.warn",
		"print(", "println(",
		"debug(", "info(", "warn(", "error(",
	}
	for _, pattern := range logPatterns {
		if strings.Contains(lineLower, pattern) {
			return true
		}
	}

	// String labels/metadata - algorithm name as a value, not usage
	// e.g., "auth_method": "ed25519", c.Locals("authenticated_via", "ed25519")
	labelPatterns := []string{
		"auth_method",
		"authenticated_via",
		"authentication_type",
		"signing_algorithm",
		"encryption_algorithm",
		"key_type",
		"algorithm_name",
		"crypto_type",
		`"type":`,
		`"method":`,
	}
	for _, pattern := range labelPatterns {
		if strings.Contains(lineLower, pattern) {
			return true
		}
	}

	// Error message strings - validation messages mentioning algorithms
	// e.g., "publicKey must be a valid Ed25519 public key"
	errorPatterns := []string{
		"must be a valid",
		"invalid.*key",
		"failed to",
		"error:",
		"expected.*got",
		"cannot be empty",
	}
	for _, pattern := range errorPatterns {
		if strings.Contains(lineLower, pattern) {
			return true
		}
	}

	// Docstrings - documentation inside code
	// e.g., """Sign a message using Ed25519""", // Sign using Ed25519
	docstringPatterns := []string{
		`"""`, // Python docstring
		"'''", // Python docstring
		"sign a message using",
		"verify a message using",
		"encrypt using",
		"decrypt using",
		"generated.*key",
	}
	for _, pattern := range docstringPatterns {
		if strings.Contains(lineLower, pattern) {
			return true
		}
	}

	// Common documentation patterns
	docPatterns := []string{
		"description:",
		"description\":",
		"summary:",
		"summary\":",
		" - ",           // Markdown list item
		"* ",            // Markdown list item
		"fingerprint",   // UI label like "Public Key Fingerprint (SHA-256)"
		"hashed before", // API doc like "SHA-256 hashed before storage"
		"uses sha",      // Description like "Uses SHA-256 for..."
		"uses aes",
		"encrypted with",
		"algorithm:",
		// API documentation object patterns
		"auth:",              // API auth method description
		"auth\":",            // JSON style
		"authentication:",    // Auth description
		"verification using", // API doc like "verification using Ed25519"
		"signing using",      // API doc about signing
		"cryptographic",      // Description of cryptographic features
		"zero-effort",        // Feature description
		"attestation",        // Security attestation descriptions
		"capabilities",       // Capability descriptions
	}
	for _, pattern := range docPatterns {
		if strings.Contains(lineLower, pattern) {
			return true
		}
	}

	return false
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

// deduplicateFindings removes near-duplicate findings
// Keeps the highest priority finding for each file+line+category combination
func (s *Scanner) deduplicateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	// Key: file:line:category -> best finding
	seen := make(map[string]Finding)

	for _, f := range findings {
		// Create a key for grouping similar findings
		key := fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.Category)

		existing, exists := seen[key]
		if !exists {
			seen[key] = f
		} else {
			// Keep the higher priority finding
			if f.Priority() > existing.Priority() {
				seen[key] = f
			}
		}
	}

	// Convert map back to slice
	deduped := make([]Finding, 0, len(seen))
	for _, f := range seen {
		deduped = append(deduped, f)
	}

	return deduped
}

// isMinifiedFile detects minified code by checking line characteristics
func isMinifiedFile(lines []string) bool {
	if len(lines) == 0 {
		return false
	}

	// Calculate average line length
	totalLen := 0
	longLines := 0
	for _, line := range lines {
		totalLen += len(line)
		if len(line) > 500 {
			longLines++
		}
	}

	avgLen := totalLen / len(lines)

	// Minified files typically have:
	// - Very high average line length (>200 chars)
	// - Or mostly very long lines (>50% lines over 500 chars)
	if avgLen > 200 {
		return true
	}
	if len(lines) > 0 && float64(longLines)/float64(len(lines)) > 0.5 {
		return true
	}

	return false
}

// isBinaryFile checks if a file is a compiled binary by reading magic bytes
func isBinaryFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	// Read first 4 bytes for magic number detection
	magic := make([]byte, 4)
	n, err := f.Read(magic)
	if err != nil || n < 4 {
		return false
	}

	// ELF binary (Linux): \x7fELF
	if magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' {
		return true
	}

	// Mach-O binary (macOS): various magic numbers
	// 32-bit: 0xfeedface, 64-bit: 0xfeedfacf, universal: 0xcafebabe
	if (magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa && (magic[3] == 0xce || magic[3] == 0xcf)) ||
		(magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe) ||
		(magic[0] == 0xce && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe) ||
		(magic[0] == 0xca && magic[1] == 0xfe && magic[2] == 0xba && magic[3] == 0xbe) {
		return true
	}

	// PE binary (Windows): MZ
	if magic[0] == 'M' && magic[1] == 'Z' {
		return true
	}

	return false
}
