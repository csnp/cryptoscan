// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/config"
	"github.com/csnp/cryptoscan/pkg/patterns"
	"github.com/csnp/cryptoscan/pkg/types"
	"github.com/csnp/cryptoscan/pkg/version"
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
	MaxDepth           int // Directory depth limit: 1 scans only the files directly in the target, 2 adds the files in its subdirectories, and so on; 0 means no limit
	ShowProgress       bool
	ScanDependencies   bool
	MinSeverity        Severity
	MinConfidence      Confidence
	ContextLines       int               // Source lines kept before and after each matched line in a finding's SourceContext; 0 keeps the matched line alone
	IncludeDocs        bool              // Whether to include documentation files
	IncludeImports     bool              // Whether to include library import findings (low-value, default false)
	IncludeQuantumSafe bool              // Whether to include quantum-safe findings like SHA-256, AES-256 (default false)
	IncludeNarrative   bool              // Whether to include algorithms named in prose, logs, docs and config keys (default false)
	OnFinding          func(Finding)     // Callback when a finding is discovered (for streaming output)
	OnFileScanned      func(path string) // Callback when a file is scanned (for progress)

	// CI/CD flexibility options
	IgnoreIDs        []string // Pattern IDs to ignore (e.g., "RSA-001", "CERT-SELFSIGNED-001")
	IgnoreCategories []string // Categories to ignore (e.g., "Certificate", "Library Import")
	IgnoreFiles      []string // File patterns to ignore (e.g., "vendor/*", "test/*")

	// ConfigFile carries the rules read from a .cryptoscan.yaml file. They are
	// kept apart from the command-line rules above and checked after them, so
	// that what each setting removes can be counted and reported. Checking
	// them separately does not change which findings are reported.
	ConfigFile *ConfigFileRules

	// ReportFile is the file the scan's report is written to, if any. A file
	// already at that path, which the scan would otherwise read, is left out
	// and listed as skipped, whatever it holds, since the report replaces it.
	ReportFile string

	// DefaultExcludes are exclude patterns applied as default rules rather
	// than as the user's own; the scan command passes DefaultExcludeGlobs.
	// They are matched like ExcludeGlobs, after them. A directory one of them
	// keeps out of the scan is counted in Results.Skipped.
	DefaultExcludes []string

	// IncludeSkipped walks the directories the default rules leave out: those
	// the built-in directory rules name and those a DefaultExcludes pattern
	// matches. DefaultExcludes patterns still apply to files, except the ones
	// that name a directory and everything in it, such as "vendor/*". The
	// .git directory of a URL scan's clone is not walked: the clone made it,
	// and it is not part of the repository.
	IncludeSkipped bool
}

// Where a configuration file was found, as recorded in ConfigReport.Source.
const (
	ConfigSourceFlag             = "flag"             // passed with --config
	ConfigSourceScanTarget       = "scanTarget"       // found in the scanned directory
	ConfigSourceParentDirectory  = "parentDirectory"  // found in a directory above the scan target
	ConfigSourceWorkingDirectory = "workingDirectory" // found from the working directory, for a repository URL target
)

// ConfigFileRules are the suppression settings read from a configuration
// file, with the path and source that the report names.
type ConfigFileRules struct {
	Path             string
	Source           string
	IgnoreIDs        []string
	IgnoreCategories []string
	IgnoreFiles      []string
	MinSeverity      Severity // applied only when HasMinSeverity is true
	HasMinSeverity   bool
}

// ConfigReport records the configuration file a scan applied and what each of
// its suppression settings removed. A configuration file in the scanned tree,
// or in any directory above it, can remove every finding, and without this
// record a report cannot tell "nothing was found" from "everything found was
// removed by a file the reader never saw".
type ConfigReport struct {
	Path            string                `json:"path"`
	Source          string                `json:"source"`
	FindingsRemoved ConfigFindingsRemoved `json:"findingsRemoved"`
	PathsSkipped    ConfigPathsSkipped    `json:"pathsSkipped"`
}

// ConfigFindingsRemoved counts the findings each setting removed from the
// report. A finding matched by more than one setting is counted once, against
// the first of ignore.patterns, ignore.categories, minSeverity and baseline
// that matched it.
type ConfigFindingsRemoved struct {
	IgnorePatterns   int `json:"ignorePatterns"`
	IgnoreCategories int `json:"ignoreCategories"`
	MinSeverity      int `json:"minSeverity"`
	Baseline         int `json:"baseline"`
	Total            int `json:"total"`
}

// ConfigPathsSkipped counts what ignore.files kept out of the scan. Skipped
// files are not read, so the findings they would have produced are unknown.
type ConfigPathsSkipped struct {
	Files       int `json:"files"`
	Directories int `json:"directories"`
}

// Any reports whether the configuration file removed or skipped anything.
func (c *ConfigReport) Any() bool {
	return c != nil && (c.FindingsRemoved.Total > 0 || c.PathsSkipped.Files > 0 || c.PathsSkipped.Directories > 0)
}

// Indexes into Scanner.configWithheld, in the order the rules are checked.
const (
	configRulePatterns = iota
	configRuleCategories
	configRuleMinSeverity
	configRuleCount
)

// DefaultExcludeGlobs are the exclude patterns the scan command applies to
// every scan as Config.DefaultExcludes: version control metadata, dependency
// and virtual environment trees, build output, and generated or minified
// files.
var DefaultExcludeGlobs = []string{
	".git/*", ".svn/*", ".hg/*",
	"node_modules/*", "vendor/*", "venv/*", ".venv/*",
	"__pycache__/*", "*.pyc",
	"dist/*", "build/*", "target/*",
	"*.min.js", "*.min.css",
	"*.lock", "package-lock.json", "yarn.lock",
}

// ToolInfo identifies the scanner build that produced a set of results.
//
// JSON reports previously carried no tool identity at all, so a stored report
// could not be attributed to a scanner version. The value comes from
// pkg/version, the same source the version command, SARIF and CBOM read.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Results contains all scan results
type Results struct {
	Tool           ToolInfo              `json:"tool"`
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
	Config         *ConfigReport         `json:"config,omitempty"`

	// UnanalyzedFiles lists files whose analysis stopped on an internal
	// error, and dependency manifests that could not be decoded. The rest of
	// the scan still runs, but findings for these files may be incomplete, so
	// the gap is reported rather than hidden.
	UnanalyzedFiles []UnanalyzedFile `json:"unanalyzedFiles"`

	// SkippedFiles lists files left out of the scan because they look
	// minified or generated, because they are dependency manifests the
	// scanner has no reader for, or because they are reports CryptoScan
	// wrote. Cryptography in them is not in the report, so they are named
	// rather than dropped without a word.
	SkippedFiles []SkippedFile `json:"skippedFiles"`

	// SkippedDependencyDirs lists the node_modules directories the scan did
	// not enter, relative to the scan root and slash-separated. Installed
	// packages are left out of every scan; this list says where they were,
	// so that a report without their findings is not read as a full one.
	SkippedDependencyDirs []string `json:"skippedDependencyDirs"`

	// Skipped counts the directories the default rules kept out of the scan
	// and the files in them, so that a report without their findings is not
	// read as one that covered them. JSON always carries it.
	Skipped SkippedDirectories `json:"skipped"`

	// ScanRoot is the directory finding paths were walked from, or empty for
	// a Git URL, whose finding paths are relative to the repository root. It
	// is used to recompute the migration score and is not written to any
	// report.
	ScanRoot string `json:"-"`
}

// UnanalyzedFile is a file the scanner could not analyze to the end.
type UnanalyzedFile struct {
	File string `json:"file"`
	// Line is the 1-based line being analyzed when the error occurred, or 0
	// when it occurred before line-by-line analysis began. Findings the file
	// produced before the error are kept in the report. For a dependency
	// manifest that could not be decoded, it is the line where decoding
	// stopped, and the manifest gives no findings.
	Line   int    `json:"line,omitempty"`
	Reason string `json:"reason"`
}

// internalErrorReason starts the Reason of a file whose analysis stopped on
// an internal error.
const internalErrorReason = "internal error: "

// IsInternalError reports whether the file's analysis stopped on an internal
// error, which is a defect in the scanner, rather than on a dependency
// manifest that could not be decoded.
func (u UnanalyzedFile) IsInternalError() bool {
	return strings.HasPrefix(u.Reason, internalErrorReason)
}

// SkippedFile is a file the scanner did not search for cryptography because
// its name or its line lengths mark it as minified or generated code, because
// it is a dependency manifest the scanner has no reader for, or because it is
// a report CryptoScan wrote.
type SkippedFile struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// SkippedDirectories describes the directories the default rules kept out of
// the scan, such as version control metadata, installed dependencies, editor
// state, build output, and example, sample, demo, mock and test data
// directories. Files is the number of files in them, counted without being
// read, down to the depth limit. Rules names the rules that matched, such as
// ".git", "node_modules" or "vendor", in name order, and Paths the
// directories, relative to the scan root and slash-separated, in path order.
//
// A directory that the user's exclude patterns or the config file's
// ignore.files also name, or that the depth limit keeps out, is not counted,
// since Config.IncludeSkipped would not scan it either. Nor is the .git
// directory of a URL scan's clone, which the clone made.
type SkippedDirectories struct {
	Files       int      `json:"files"`
	Directories int      `json:"directories"`
	Rules       []string `json:"rules"`
	Paths       []string `json:"paths"`
}

// skippedDir is one directory a default rule kept out of the walk.
type skippedDir struct {
	path  string // relative to the scan root, slash-separated
	rule  string
	files int
}

// unreadManifestReason is the Reason of a dependency manifest the scanner has
// no reader for, such as build.gradle or Pipfile.
const unreadManifestReason = "dependency manifest: the scanner does not read this format"

// IsUnreadManifest reports whether the file was skipped because it is a
// dependency manifest the scanner does not read, rather than because it looks
// minified or generated.
func (sk SkippedFile) IsUnreadManifest() bool {
	return sk.Reason == unreadManifestReason
}

// IsCryptoScanReport reports whether the file was skipped because it is a
// report CryptoScan wrote, or the file the scan's own report replaces.
func (sk SkippedFile) IsCryptoScanReport() bool {
	return strings.HasPrefix(sk.Reason, reportReasonPrefix)
}

// MetadataScanRoot is the Results.Metadata entry holding the directory the
// scan's file paths are under. ScanTarget is the target as it was given, such
// as "." or a repository URL, so a saved report needs this to turn each
// finding's path back into a path relative to the scanned tree. A Git URL
// scan has no entry: its paths are relative to the repository root already.
const MetadataScanRoot = "scanRoot"

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

	// NarrativeSuppressed counts matches withheld because the algorithm was
	// named in text rather than used. Reported so that the reduction is
	// visible and recoverable with --include-narrative.
	NarrativeSuppressed int `json:"narrativeSuppressedCount"`

	// ByEvidence counts findings by the scanner rule that decided their
	// context (see the Evidence constants in evidence.go). It describes the
	// whole scan: findings withheld by the narrative rules are counted under
	// their rule too, so the values add up to TotalFindings plus
	// NarrativeSuppressed, and --include-narrative does not change the map.
	ByEvidence map[string]int `json:"byEvidence"`

	// WithheldByEvidence is the part of each ByEvidence count that is not in
	// Findings. It is not serialized; narrativeSuppressedCount is the total.
	WithheldByEvidence map[string]int `json:"-"`
}

// HasCritical returns true if any critical findings exist
func (r *Results) HasCritical() bool {
	return r.Summary.BySeverity["CRITICAL"] > 0
}

// HasFindingsAtOrAbove returns true if any findings exist at or above the given severity
func (r *Results) HasFindingsAtOrAbove(sev Severity) bool {
	for _, f := range r.Findings {
		if f.Severity >= sev {
			return true
		}
	}
	return false
}

// Scanner performs cryptographic scanning
type Scanner struct {
	config   Config
	patterns *patterns.Matcher
	mu       sync.Mutex
	findings []Finding
	tempDir  string // Temporary directory for cloned repos
	cloneGit string // The .git directory of a URL scan's clone, which the walk leaves out (see shouldSkipDir)
	root     string // Scan root; path rules see only paths below it (see relPath)
	stats    struct {
		filesScanned  int
		linesScanned  int
		bytesScanned  int64
		languageStats map[string]int
	}

	// narrativeWithheld holds matches kept out of the default report because
	// the algorithm was named in text rather than used. They are retained
	// rather than counted so that the reported number is exactly what
	// --include-narrative would add, after deduplication.
	narrativeWithheld []Finding

	// unanalyzed holds files whose analysis stopped on an internal error.
	unanalyzed []UnanalyzedFile

	// skipped holds files left out because they look minified or generated,
	// are dependency manifests the scanner does not read, or are reports
	// CryptoScan wrote.
	skipped []SkippedFile

	// dependencyDirs holds the node_modules directories the walk did not
	// enter, relative to the scan root.
	dependencyDirs []string

	// skippedDirs holds the directories a default rule kept out of the walk.
	skippedDirs []skippedDir

	// reportFile is the file at Config.ReportFile when the scan began, or nil.
	reportFile os.FileInfo

	// configWithheld holds, per configuration-file setting, the matches that
	// setting kept out of a report that would otherwise have contained them.
	// configSkipped counts the paths ignore.files kept out of the scan.
	configWithheld [configRuleCount][]Finding
	configSkipped  ConfigPathsSkipped
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
	cloneRoot := ""
	if isGitURL(target) {
		clonePath, err := s.cloneRepository(target)
		if err != nil {
			return nil, fmt.Errorf("failed to clone repository: %w", err)
		}
		// Clean up temp directory when done
		defer s.Cleanup()
		target = clonePath
		cloneRoot = clonePath
		s.cloneGit = filepath.Join(clonePath, ".git")
		s.streamRelativeTo(cloneRoot)
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot access target: %w", err)
	}

	if s.config.ReportFile != "" {
		if reportInfo, err := os.Stat(s.config.ReportFile); err == nil {
			s.reportFile = reportInfo
		}
	}

	if info.IsDir() {
		s.root = target
		err = s.scanDirectory(target)
	} else {
		// Check if single file should be scanned (apply same filters as directory scan)
		s.root = filepath.Dir(target)
		if s.shouldScanFile(filepath.Dir(target), target) {
			err = s.scanFile(target)
		}
	}

	if err != nil {
		return nil, err
	}

	// Deduplicate findings (same file+line+category, and library for a
	// dependency = keep highest priority)
	raw := s.findings
	s.findings = s.deduplicateFindings(s.findings)

	// Report exactly how many findings --include-narrative would add, not how
	// many raw matches were withheld. Some withheld matches deduplicate against
	// a finding that was reported anyway, so counting at the point of
	// suppression overstated the number by more than 70% on a documentation
	// tree, and a count a user cannot reproduce is a data-integrity defect.
	narrativeCount := 0
	scanned := s.findings
	if len(s.narrativeWithheld) > 0 {
		combined := make([]Finding, 0, len(raw)+len(s.narrativeWithheld))
		combined = append(combined, raw...)
		combined = append(combined, s.narrativeWithheld...)
		scanned = s.deduplicateFindings(combined)
		narrativeCount = len(scanned) - len(s.findings)
	}
	byEvidence, withheldByEvidence := countByEvidence(scanned, s.findings)

	var configReport *ConfigReport
	if s.config.ConfigFile != nil {
		configReport = s.configReport(raw)
	}

	// The clone of a URL scan is removed when the scan ends, so the report
	// gives each path relative to the repository root, where it is found in
	// any checkout. The path rules applied during the walk saw the clone's
	// paths, which is why the paths change only here.
	if cloneRoot != "" {
		for i := range s.findings {
			s.findings[i].File = repoRelative(cloneRoot, s.findings[i].File)
		}
		for i := range s.unanalyzed {
			s.unanalyzed[i].File = repoRelative(cloneRoot, s.unanalyzed[i].File)
		}
		for i := range s.skipped {
			s.skipped[i].File = repoRelative(cloneRoot, s.skipped[i].File)
		}
	}

	// Sort findings by priority, breaking ties on location so that the order
	// is fully determined by the scanned content rather than by the order
	// files happened to be walked.
	sort.SliceStable(s.findings, func(i, j int) bool {
		a, b := s.findings[i], s.findings[j]
		if a.Priority() != b.Priority() {
			return a.Priority() > b.Priority()
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.ID < b.ID
	})

	// Give every reported finding a command that shows the matched line and
	// one concrete change.
	remediation := analyzer.NewRemediationEngine()
	for i := range s.findings {
		remediation.Apply(&s.findings[i])
	}

	// Calculate migration score and enhance findings with QRAMM mapping.
	// Finding paths start with the walked directory, so directories above it
	// are not mistaken for test directories. A URL scan's paths are relative
	// to the repository root already, and it records no root.
	root := s.root
	metadata := map[string]string{}
	if cloneRoot != "" {
		root = ""
	} else {
		metadata[MetadataScanRoot] = root
	}
	migrationScore := analyzer.CalculateMigrationScoreForRoot(s.findings, root)

	// Sorted for the same reason as the findings: files are scanned in
	// parallel, and the report must not depend on which worker finished first.
	unanalyzed := make([]UnanalyzedFile, len(s.unanalyzed))
	copy(unanalyzed, s.unanalyzed)
	sort.Slice(unanalyzed, func(i, j int) bool {
		return unanalyzed[i].File < unanalyzed[j].File
	})
	skipped := make([]SkippedFile, len(s.skipped))
	copy(skipped, s.skipped)
	sort.Slice(skipped, func(i, j int) bool {
		return skipped[i].File < skipped[j].File
	})
	dependencyDirs := make([]string, len(s.dependencyDirs))
	copy(dependencyDirs, s.dependencyDirs)
	sort.Strings(dependencyDirs)
	skippedDirs := s.skippedDirectories()

	// Build results
	results := &Results{
		Tool:            ToolInfo{Name: toolName, Version: version.Get()},
		Findings:        s.findings,
		MigrationScore:  migrationScore,
		ScanRoot:        root,
		FilesScanned:    s.stats.filesScanned,
		LinesScanned:    s.stats.linesScanned,
		BytesScanned:    s.stats.bytesScanned,
		LanguageStats:   s.stats.languageStats,
		Metadata:        metadata,
		Config:          configReport,
		UnanalyzedFiles: unanalyzed,
		SkippedFiles:    skipped,

		SkippedDependencyDirs: dependencyDirs,
		Skipped:               skippedDirs,
	}

	results.Summary = s.calculateSummary()
	results.Summary.NarrativeSuppressed = narrativeCount
	results.Summary.ByEvidence = byEvidence
	results.Summary.WithheldByEvidence = withheldByEvidence
	results.Insights = s.generateInsights()

	return results, nil
}

// ErrCloneFailed reports that git could not clone the repository URL given as
// the scan target. git clone exits with status 128 both when the repository
// is not found and when the host cannot be reached, so the error does not try
// to tell those apart.
var ErrCloneFailed = errors.New("repository not found or not accessible")

// configReport counts what each configuration-file setting removed. As with
// the narrative count, each number is what removing that setting would add to
// the report after deduplication, not the raw number of matches it held back.
// The baseline count is added by the caller, which applies the baseline.
func (s *Scanner) configReport(raw []Finding) *ConfigReport {
	rules := s.config.ConfigFile
	report := &ConfigReport{
		Path:         rules.Path,
		Source:       rules.Source,
		PathsSkipped: s.configSkipped,
	}

	var counts [configRuleCount]int
	combined := append([]Finding(nil), raw...)
	prev := len(s.findings)
	for rule, withheld := range s.configWithheld {
		if len(withheld) == 0 {
			continue
		}
		combined = append(combined, withheld...)
		n := len(s.deduplicateFindings(combined))
		counts[rule] = n - prev
		prev = n
	}

	report.FindingsRemoved = ConfigFindingsRemoved{
		IgnorePatterns:   counts[configRulePatterns],
		IgnoreCategories: counts[configRuleCategories],
		MinSeverity:      counts[configRuleMinSeverity],
		Total:            counts[configRulePatterns] + counts[configRuleCategories] + counts[configRuleMinSeverity],
	}
	return report
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
		if errors.Is(err, exec.ErrNotFound) {
			return "", fmt.Errorf("git is required to scan a repository URL: %w", err)
		}
		return "", fmt.Errorf("%w (git clone: %v)", ErrCloneFailed, err)
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

// streamRelativeTo makes the streaming and progress callbacks of a URL scan
// see each path relative to the repository root cloned at root, the form the
// report gives it.
func (s *Scanner) streamRelativeTo(root string) {
	if onFinding := s.config.OnFinding; onFinding != nil {
		s.config.OnFinding = func(f Finding) {
			f.File = repoRelative(root, f.File)
			onFinding(f)
		}
	}
	if onFileScanned := s.config.OnFileScanned; onFileScanned != nil {
		s.config.OnFileScanned = func(path string) {
			onFileScanned(repoRelative(root, path))
		}
	}
}

// repoRelative returns path relative to root, slash-separated, or path as it
// is when it is not below root.
func repoRelative(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return path
	}
	return filepath.ToSlash(rel)
}

func (s *Scanner) scanDirectory(root string) error {
	// Collect files to scan (fast walk, no I/O)
	var filesToScan []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if err := s.shouldSkipDir(root, path, d.Name()); err != nil {
				return err
			}
			// A directory at the depth limit is not entered: the files in it
			// would sit one level deeper than the limit allows.
			if s.config.MaxDepth > 0 && depth(root, path) >= s.config.MaxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if s.shouldScanFile(root, path) {
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

// depth returns how many directories below the scan root path is: 0 for the
// root itself, 1 for a file or directory directly in it.
func depth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return strings.Count(rel, string(filepath.Separator)) + 1
}

// relPath returns path relative to the scan root, slash-separated and with a
// leading slash, so that a segment rule such as "/docs/" also matches a
// directory at the top of the target. The scan root itself is "/".
//
// Every built-in path rule tests this form, never the absolute path. A
// directory above the scan root is not part of what the user asked to scan,
// and its name must not change the result: tested against the absolute path,
// a checkout under ~/work/docs/ scanned zero files and exited 0.
func (s *Scanner) relPath(path string) string {
	rel, err := filepath.Rel(s.root, path)
	if err != nil {
		rel = filepath.Base(path)
	}
	if rel == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(rel)
}

// analyzeFile classifies a file by its scan-relative path, so that the
// documentation, test, vendor and generated rules see only directories inside
// the target. The returned context keeps the real path.
func (s *Scanner) analyzeFile(path string) *analyzer.FileContext {
	ctx := analyzer.Analyze(s.relPath(path))
	ctx.Path = path
	return ctx
}

// skipDirNames are the directory names the walk does not enter by default. A
// name matches only as written, as the directory names in DefaultExcludeGlobs
// do: the walk enters a directory named Dist.
var skipDirNames = map[string]bool{
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

// skipPathPatterns are matched against the scan-relative path of a directory,
// as relPath returns it, in the letter case it is written in, as skipDirNames
// are. A pattern that ends in a name from skipDirNames would keep nothing
// more out: the walk does not enter a directory with that name, so it
// reaches no path below one. Patterns such as "/dist/" were here, matched
// against the lowercased path, so the walk entered a directory named Dist
// and scanned the files directly in it, while a directory inside it, such as
// Dist/sub, was left out under the rule dist.
var skipPathPatterns = []string{
	"/standalone/",    // Next.js standalone builds
	"/target/apidocs", // Java generated API docs
	"/target/site/",   // Maven site docs
	"/.egg-info/",     // Python build artifacts
}

// builtinSkipRule returns the built-in rule that keeps a directory out of the
// walk, given its name and its scan-relative path, or "" when no built-in
// rule does. The rule is the directory name for skipDirNames and the pattern
// without its slashes for skipPathPatterns.
func builtinSkipRule(name, rel string) string {
	if skipDirNames[name] {
		return name
	}
	for _, pattern := range skipPathPatterns {
		if strings.Contains(rel, pattern) {
			return strings.Trim(pattern, "/")
		}
	}
	return ""
}

func (s *Scanner) shouldSkipDir(root, path, name string) error {
	// The .git directory of a URL scan's clone was made by the clone and is
	// not part of the repository's content, so it is left out without being
	// counted as skipped, and IncludeSkipped does not walk it either.
	if s.cloneGit != "" && path == s.cloneGit {
		return filepath.SkipDir
	}

	relPath, _ := filepath.Rel(root, path)

	// The scan root is what the user asked to scan, so the built-in skip
	// rules below never apply to it, whatever it is called. User exclude
	// patterns still do.
	isRoot := path == root

	if !isRoot && !s.config.IncludeSkipped {
		if rule := builtinSkipRule(name, s.relPath(path)); rule != "" {
			// An installed dependency tree holds the code of every package
			// the project uses, and the report names it so that its absence
			// is not read as an absence of cryptography.
			if name == "node_modules" {
				s.mu.Lock()
				s.dependencyDirs = append(s.dependencyDirs, filepath.ToSlash(relPath))
				s.mu.Unlock()
			}
			s.skipDefaultDir(root, path, relPath, rule)
			return filepath.SkipDir
		}
	}

	if s.excluded(relPath, true) {
		return filepath.SkipDir
	}

	if !s.config.IncludeSkipped {
		for _, pattern := range s.config.DefaultExcludes {
			if matchesExclude(pattern, relPath, true) {
				// The rule is named for the directory the pattern names, as
				// "vendor" for "vendor/*".
				rule, _ := dirPattern(pattern)
				s.skipDefaultDir(root, path, relPath, rule)
				return filepath.SkipDir
			}
		}
	}

	if s.ignoredByConfigFile(relPath, true) {
		s.mu.Lock()
		s.configSkipped.Directories++
		s.mu.Unlock()
		return filepath.SkipDir
	}

	return nil
}

// skipDefaultDir records the directory at path, which a default rule keeps
// out of the walk, with the number of files in it. A directory that would
// stay out of the scan without the default rules is not recorded, since
// --include-skipped would not scan it: one that an exclude pattern of the
// user's or the config file's ignore.files names, and one at the depth limit.
func (s *Scanner) skipDefaultDir(root, path, rel, rule string) {
	if s.excluded(rel, true) || s.ignoredByConfigFile(rel, true) {
		return
	}
	if s.config.MaxDepth > 0 && depth(root, path) >= s.config.MaxDepth {
		return
	}
	files := s.countFiles(root, path)
	s.mu.Lock()
	s.skippedDirs = append(s.skippedDirs, skippedDir{path: filepath.ToSlash(rel), rule: rule, files: files})
	s.mu.Unlock()
}

// countFiles returns the number of files the walk would reach under dir if it
// entered it: every entry that is not a directory, down to the depth limit.
// The files are not opened.
func (s *Scanner) countFiles(root, dir string) int {
	n := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != dir && s.config.MaxDepth > 0 && depth(root, path) >= s.config.MaxDepth {
				return fs.SkipDir
			}
			return nil
		}
		n++
		return nil
	})
	return n
}

// skippedDirectories returns what Results.Skipped reports, in an order that
// does not depend on the order of the walk.
func (s *Scanner) skippedDirectories() SkippedDirectories {
	out := SkippedDirectories{Rules: []string{}, Paths: []string{}}
	dirs := make([]skippedDir, len(s.skippedDirs))
	copy(dirs, s.skippedDirs)
	sort.Slice(dirs, func(i, j int) bool {
		return dirs[i].path < dirs[j].path
	})
	rules := make(map[string]bool)
	for _, d := range dirs {
		out.Files += d.files
		out.Paths = append(out.Paths, d.path)
		if !rules[d.rule] {
			rules[d.rule] = true
			out.Rules = append(out.Rules, d.rule)
		}
	}
	out.Directories = len(dirs)
	sort.Strings(out.Rules)
	return out
}

// dirPattern returns an exclude pattern without a leading "./" and without a
// "/", "/*" or "/**" ending, and reports whether it had such an ending: a
// pattern with one names a directory and everything in it.
func dirPattern(pattern string) (string, bool) {
	pattern = strings.TrimPrefix(pattern, "./")
	for _, suffix := range []string{"/**", "/*", "/"} {
		if strings.HasSuffix(pattern, suffix) {
			return strings.TrimSuffix(pattern, suffix), true
		}
	}
	return pattern, false
}

// excluded reports whether any exclude pattern matches rel, a path relative to
// the scan root.
func (s *Scanner) excluded(rel string, isDir bool) bool {
	for _, pattern := range s.config.ExcludeGlobs {
		if matchesExclude(pattern, rel, isDir) {
			return true
		}
	}
	return false
}

// defaultExcluded reports whether a DefaultExcludes pattern matches the file
// at rel, a path relative to the scan root. With IncludeSkipped, the patterns
// that name a directory and everything in it are not applied, since the
// directories they name are walked.
func (s *Scanner) defaultExcluded(rel string) bool {
	for _, pattern := range s.config.DefaultExcludes {
		if _, namesDir := dirPattern(pattern); namesDir && s.config.IncludeSkipped {
			continue
		}
		if matchesExclude(pattern, rel, false) {
			return true
		}
	}
	return false
}

// ignoredByConfigFile reports whether a pattern in the config file's
// ignore.files matches rel, a path relative to the scan root.
func (s *Scanner) ignoredByConfigFile(rel string, isDir bool) bool {
	rules := s.config.ConfigFile
	if rules == nil {
		return false
	}
	for _, pattern := range rules.IgnoreFiles {
		if matchesExclude(pattern, rel, isDir) {
			return true
		}
	}
	return false
}

// matchesExclude reports whether the file or directory at rel, a path relative
// to the scan root, is excluded by pattern.
//
//   - A pattern with no "/" matches a file or directory name at any depth
//     ("*_test.go", "vendor").
//   - A pattern ending in "/", "/*" or "/**" excludes the directories it names
//     and everything inside them ("vendor/*"). The part before the suffix is
//     matched by these same rules, so "vendor/*" names a vendor directory at
//     any depth and "src/generated/*" names the one under the scan root.
//   - Any other pattern is matched against the path from the scan root, and a
//     directory it matches is excluded with everything inside it
//     ("src/*.pb.go", "src/generated").
//
// The scan root itself is never excluded, so a directory can still be scanned
// by passing it as the target. Each "/"-separated segment is matched with
// path.Match, where "*" does not cross a "/".
func matchesExclude(pattern, rel string, isDir bool) bool {
	rel = filepath.ToSlash(rel)
	if rel == "" || rel == "." {
		return false
	}

	pattern, dirOnly := dirPattern(pattern)
	if pattern == "" {
		return false
	}

	// parts[:n] are the elements a match may land on. A file's own name is
	// the last element, and a directory-only pattern cannot name a file.
	parts := strings.Split(rel, "/")
	n := len(parts)
	if dirOnly && !isDir {
		n--
	}

	if !strings.Contains(pattern, "/") {
		for _, part := range parts[:n] {
			if matched, _ := path.Match(pattern, part); matched {
				return true
			}
		}
		return false
	}
	for i := 1; i <= n; i++ {
		if matched, _ := path.Match(pattern, strings.Join(parts[:i], "/")); matched {
			return true
		}
	}
	return false
}

func (s *Scanner) shouldScanFile(root, path string) bool {
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
	ctx := s.analyzeFile(path)

	// Skip documentation if not explicitly included
	if !s.config.IncludeDocs && ctx.FileType == analyzer.FileTypeDocumentation {
		return false
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

	// Skip minified files (contain bundled code with coincidental matches).
	// They can still hold cryptography, so each one is listed as skipped.
	// Checked after the documentation and include rules, so that a file is
	// listed only if it would otherwise have been scanned, and before the
	// exclude patterns, where DefaultExcludeGlobs matches *.min.js and
	// *.min.css as well.
	if suffix := minifiedNameSuffix(nameLower); suffix != "" {
		s.skip(path, "minified: the file name ends in "+suffix)
		return false
	}

	// Check exclude patterns
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = name
	}
	if s.excluded(rel, false) || s.defaultExcluded(rel) {
		return false
	}

	// Checked last, so that a file is counted only if it would otherwise have
	// been scanned.
	if s.ignoredByConfigFile(rel, false) {
		s.mu.Lock()
		s.configSkipped.Files++
		s.mu.Unlock()
		return false
	}

	return true
}

func (s *Scanner) scanFile(path string) error {
	// An internal error while analyzing one file must not end the run for
	// every other file. Recover, record the file as not analyzed, and let the
	// caller go on to the next one.
	currentLine := 0
	defer func() {
		if r := recover(); r != nil {
			s.mu.Lock()
			s.unanalyzed = append(s.unanalyzed, UnanalyzedFile{
				File:   path,
				Line:   currentLine,
				Reason: internalErrorReason + fmt.Sprint(r),
			})
			s.mu.Unlock()
		}
	}()

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

	// A report CryptoScan wrote is not source, and it is not read as a
	// dependency manifest either.
	if s.reportFile != nil && os.SameFile(s.reportFile, fileInfo) {
		s.skip(path, reportFileReason)
		return nil
	}
	if format := reportFormat(file); format != "" {
		s.skip(path, reportReasonPrefix+format)
		return nil
	}

	// Analyze file context
	fileCtx := s.analyzeFile(path)

	// countScanned is called once the file is known to be searched, so a file
	// listed as skipped is not also counted as scanned.
	countScanned := func() {
		s.mu.Lock()
		s.stats.filesScanned++
		s.stats.bytesScanned += fileSize
		s.stats.languageStats[string(fileCtx.Language)]++
		s.mu.Unlock()

		// Progress callback
		if s.config.OnFileScanned != nil {
			s.config.OnFileScanned(path)
		}
	}

	// Check if this is a dependency file
	if fileCtx.FileType == analyzer.FileTypeDependency {
		s.scanDependencyFile(path, countScanned)
		return nil
	}

	// Read all lines first for context extraction
	allLines, err := s.readFileLines(path)
	if err != nil {
		// A line too long for the reader marks a minified or generated file
		// as surely as the line lengths below do, and is reported the same way.
		if errors.Is(err, bufio.ErrTooLong) {
			s.skip(path, "minified or generated: a line is 1 MB or longer")
		}
		return nil
	}

	// Skip minified files (detected by average line length)
	if isMinifiedFile(allLines) {
		s.skip(path, fmt.Sprintf("minified or generated: its lines average %d bytes", averageLineLength(allLines)))
		return nil
	}

	countScanned()

	var prevLines []string

	for lineNum, line := range allLines {
		lineNum++ // Convert to 1-based
		currentLine = lineNum

		s.mu.Lock()
		s.stats.linesScanned++
		s.mu.Unlock()

		// Check for blanket ignore comment on this line or previous line
		if s.hasIgnoreComment(line, allLines, lineNum) {
			continue
		}

		// Pattern-specific ignore will be checked per-finding below

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

			// Check if pattern ID or category should be ignored (CI/CD flexibility)
			if s.shouldIgnorePattern(m.ID, m.Category) {
				continue
			}

			// Check for pattern-specific inline ignore (e.g., cryptoscan:ignore RSA-001)
			if s.hasPatternSpecificIgnore(line, allLines, lineNum, m.ID) {
				continue
			}

			// Add the source lines around the match, as many as the config asks for
			m.SourceContext = s.extractSourceContext(allLines, lineNum, s.config.ContextLines)

			// Apply severity filter
			if m.Severity < s.config.MinSeverity {
				continue
			}

			// The evidence check runs after every other filter, so that the
			// withheld set contains only matches that would otherwise have
			// been reported. Anything else makes the "N withheld" count larger
			// than what --include-narrative actually returns.
			//
			// The classification is recorded on the finding even when it is
			// reported, so that deduplication can prefer an operational match
			// over a narrative one at the same location.
			m.EvidenceKind, m.Narrative = s.evidenceKind(m, line, fileCtx)
			withheldAsNarrative := m.Narrative && !s.config.IncludeNarrative

			// Configuration-file rules run after the command-line filters, so
			// a match is held for counting only if the report would otherwise
			// have contained it. A narrative match the file removes is dropped
			// without being counted under either heading, as it was when the
			// file's rules were merged into the command-line ones.
			if rule, ok := s.configRuleFor(m); ok {
				if !withheldAsNarrative {
					s.mu.Lock()
					s.configWithheld[rule] = append(s.configWithheld[rule], m)
					s.mu.Unlock()
				}
				continue
			}

			if withheldAsNarrative {
				s.mu.Lock()
				s.narrativeWithheld = append(s.narrativeWithheld, m)
				s.mu.Unlock()
				continue
			}

			s.mu.Lock()
			s.findings = append(s.findings, m)
			s.mu.Unlock()

			// Stream finding via callback
			if s.config.OnFinding != nil {
				s.config.OnFinding(m)
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
// This is the basic check - returns true if the line has any ignore directive
func (s *Scanner) hasIgnoreComment(line string, allLines []string, lineNum int) bool {
	lowerLine := strings.ToLower(line)

	// Check inline comment on same line (blanket ignore)
	if strings.Contains(lowerLine, "cryptoscan:ignore") ||
		strings.Contains(lowerLine, "crypto-scan:ignore") ||
		strings.Contains(lowerLine, "noscan") {
		// Check if it's a blanket ignore (no specific pattern)
		if s.isBlanketIgnore(line) {
			return true
		}
	}

	// Check the previous line, but only for the explicit next-line form.
	//
	// This used to accept any ignore directive on the previous line, so a
	// trailing `# cryptoscan:ignore` also blinded the line below it. One
	// suppression comment silently hid an adjacent line the author never asked
	// to hide, which in a security scanner is a false negative the user cannot
	// see. A directive now applies to its own line unless it says -next-line.
	if lineNum >= 2 && lineNum-2 < len(allLines) {
		prevLine := allLines[lineNum-2]
		if isNextLineDirective(prevLine) && s.isBlanketIgnore(prevLine) {
			return true
		}
	}

	return false
}

// isNextLineDirective reports whether a line carries an ignore directive that
// explicitly applies to the following line.
func isNextLineDirective(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "cryptoscan:ignore-next-line") ||
		strings.Contains(lower, "crypto-scan:ignore-next-line")
}

// isBlanketIgnore checks if an ignore directive is a blanket ignore (no specific pattern)
func (s *Scanner) isBlanketIgnore(line string) bool {
	// idx is found in lowerLine and used to slice line.
	lowerLine := analyzer.LowerSameOffsets(line)

	// Find the ignore directive
	idx := strings.Index(lowerLine, "cryptoscan:ignore")
	if idx == -1 {
		idx = strings.Index(lowerLine, "crypto-scan:ignore")
	}
	if idx == -1 {
		idx = strings.Index(lowerLine, "noscan")
		if idx != -1 {
			return true // noscan is always a blanket ignore
		}
		return false
	}

	// Get the remainder after the directive
	remainder := strings.TrimSpace(line[idx+17:]) // len("cryptoscan:ignore") = 17
	if strings.HasPrefix(strings.ToLower(remainder), "-next-line") {
		remainder = strings.TrimSpace(remainder[10:]) // len("-next-line") = 10
	}

	// If nothing follows, it's a blanket ignore
	return remainder == "" || strings.HasPrefix(remainder, "//") || strings.HasPrefix(remainder, "*/") ||
		strings.HasPrefix(remainder, "#") || strings.HasPrefix(remainder, "--")
}

// hasPatternSpecificIgnore checks if a specific pattern should be ignored based on inline comments
func (s *Scanner) hasPatternSpecificIgnore(line string, allLines []string, lineNum int, patternID string) bool {
	// Check current line
	if patterns := s.extractIgnorePatterns(line); len(patterns) > 0 {
		for _, p := range patterns {
			if config.MatchesPattern(patternID, p) {
				return true
			}
		}
	}

	// Check the previous line, but only for the explicit next-line form, for
	// the same reason as hasIgnoreComment: an ignore directive applies to the
	// line it sits on unless it says otherwise.
	if lineNum >= 2 && lineNum-2 < len(allLines) {
		prevLine := allLines[lineNum-2]
		if isNextLineDirective(prevLine) {
			if patterns := s.extractIgnorePatterns(prevLine); len(patterns) > 0 {
				for _, p := range patterns {
					if config.MatchesPattern(patternID, p) {
						return true
					}
				}
			}
		}
	}

	return false
}

// extractIgnorePatterns extracts pattern IDs from an ignore comment
// Examples:
//
//	"// cryptoscan:ignore RSA-001" -> ["RSA-001"]
//	"// cryptoscan:ignore RSA-001,CERT-*" -> ["RSA-001", "CERT-*"]
//	"// cryptoscan:ignore" -> [] (blanket ignore, no specific patterns)
func (s *Scanner) extractIgnorePatterns(line string) []string {
	// idx is found in lowerLine and used to slice line.
	lowerLine := analyzer.LowerSameOffsets(line)

	// Find the ignore directive
	var idx int
	if i := strings.Index(lowerLine, "cryptoscan:ignore"); i != -1 {
		idx = i + 17 // len("cryptoscan:ignore")
	} else if i := strings.Index(lowerLine, "crypto-scan:ignore"); i != -1 {
		idx = i + 18 // len("crypto-scan:ignore")
	} else {
		return nil
	}

	// Handle -next-line suffix
	remainder := line[idx:]
	if strings.HasPrefix(strings.ToLower(remainder), "-next-line") {
		remainder = remainder[10:] // len("-next-line")
	}

	// Trim and get pattern list
	remainder = strings.TrimSpace(remainder)
	if remainder == "" {
		return nil
	}

	// Stop at comment terminators
	for _, term := range []string{"//", "*/", "#", "--", "*/"} {
		if i := strings.Index(remainder, term); i != -1 {
			remainder = strings.TrimSpace(remainder[:i])
		}
	}

	if remainder == "" {
		return nil
	}

	// Split by comma or whitespace
	var patterns []string
	parts := strings.FieldsFunc(remainder, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			patterns = append(patterns, p)
		}
	}

	return patterns
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

// scanDependencyFile reports the crypto libraries a dependency manifest lists,
// calling countScanned once the manifest has been read and decoded. A
// manifest the scanner has no reader for, such as build.gradle, is listed as
// skipped, and one that cannot be decoded is listed as not analyzed, with the
// line where decoding stopped, rather than counted as a scanned file with
// nothing in it. One that cannot be read is left out of the counts without a
// notice, as an unreadable source file is.
func (s *Scanner) scanDependencyFile(path string, countScanned func()) {
	if !analyzer.ReadsManifest(path) {
		s.skip(path, unreadManifestReason)
		return
	}
	deps, err := analyzer.ScanDependencies(path)
	if err != nil {
		var manifestErr *analyzer.ManifestError
		if errors.As(err, &manifestErr) {
			s.mu.Lock()
			s.unanalyzed = append(s.unanalyzed, UnanalyzedFile{
				File:   path,
				Line:   manifestErr.Line,
				Reason: manifestErr.Reason,
			})
			s.mu.Unlock()
		}
		return
	}
	countScanned()

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

			EvidenceKind: EvidenceDependency,
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

// evidenceKind reports the evidence kind of a match and whether it names an
// algorithm in text rather than using it, in which case it is withheld from
// the default report.
//
// line is the full source line. f.Context is truncated to 120 characters for
// display and must never be used for classification: the match offset would
// not line up.
//
// Detected key material is exempt. A private key pasted into a comment is
// still an exposed private key, and that is why the scan loop reads comments
// containing "key" or "secret" at all.
func (s *Scanner) evidenceKind(f types.Finding, line string, fileCtx *analyzer.FileContext) (string, bool) {
	if f.FindingType == types.FindingTypeSecret {
		return EvidenceKeyMaterial, false
	}

	mc := matchContext{
		Line:  line,
		Start: f.Column - 1,
		End:   f.Column - 1 + len(f.Match),
	}
	if fileCtx != nil {
		mc.Language = string(fileCtx.Language)
		mc.FileType = string(fileCtx.FileType)
	}

	class, reason := classifyMatch(mc)
	if class == evidenceNarrative {
		return reason, true
	}
	return EvidenceOperational, false
}

// countByEvidence counts scanned, the deduplicated set of every finding the
// scan produced including withheld ones, by evidence kind, and reports how
// many of each kind are missing from reported.
func countByEvidence(scanned, reported []Finding) (byKind, withheld map[string]int) {
	byKind = make(map[string]int)
	for _, f := range scanned {
		byKind[f.EvidenceKind]++
	}

	shown := make(map[string]int)
	for _, f := range reported {
		shown[f.EvidenceKind]++
	}

	withheld = make(map[string]int)
	for kind, n := range byKind {
		if missing := n - shown[kind]; missing > 0 {
			withheld[kind] = missing
		}
	}
	return byKind, withheld
}

// shouldIncludeFinding applies noise reduction filters.
// Returns false if the finding should be suppressed based on config.
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

	// Skip findings in files whose names indicate API docs or documentation
	fileLower := strings.ToLower(s.relPath(f.File))
	if strings.Contains(fileLower, "-documentation") || strings.Contains(fileLower, "-docs") ||
		strings.Contains(fileLower, "_documentation") || strings.Contains(fileLower, "_docs") ||
		strings.Contains(fileLower, "/docs/") || strings.Contains(fileLower, "/documentation/") {
		return false
	}

	return true
}

// shouldIgnorePattern checks if a finding should be ignored based on config
func (s *Scanner) shouldIgnorePattern(id, category string) bool {
	// Check exact ID match or prefix match
	for _, ignore := range s.config.IgnoreIDs {
		if config.MatchesPattern(id, ignore) {
			return true
		}
	}

	// Check category match
	for _, ignoreCat := range s.config.IgnoreCategories {
		if config.MatchesCategory(category, ignoreCat) {
			return true
		}
	}

	return false
}

// configRuleFor reports which configuration-file setting, if any, removes f,
// checking them in the order the report attributes them.
func (s *Scanner) configRuleFor(f Finding) (int, bool) {
	rules := s.config.ConfigFile
	if rules == nil {
		return 0, false
	}
	for _, ignore := range rules.IgnoreIDs {
		if config.MatchesPattern(f.ID, ignore) {
			return configRulePatterns, true
		}
	}
	for _, ignoreCat := range rules.IgnoreCategories {
		if config.MatchesCategory(f.Category, ignoreCat) {
			return configRuleCategories, true
		}
	}
	if rules.HasMinSeverity && f.Severity < rules.MinSeverity {
		return configRuleMinSeverity, true
	}
	return 0, false
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
		// Go randomises map iteration order, so without this sort two scans
		// of the same tree could list the libraries in different orders.
		sort.Strings(libList)
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
// Keeps the highest priority finding for each file+line+category combination,
// and for a dependency finding, for each file and library
func (s *Scanner) deduplicateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	// Key: file:line:category -> best finding, with the package added for a
	// dependency finding.
	//
	// The result used to be built by ranging over this map, and Go randomises
	// map iteration order, so two scans of an unchanged tree emitted the same
	// findings in a different order every time. That breaks diffable CI output,
	// golden-file tests and reproducible CBOMs, and it made the text report's
	// "#N" numbering meaningless. Insertion order is recorded separately and
	// used to rebuild the slice.
	seen := make(map[string]Finding)
	order := make([]string, 0, len(findings))

	for _, f := range findings {
		key := fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.Category)
		// Every dependency finding is put on line 1 of its manifest, whichever
		// line names the library, so file, line and category are the same for
		// each library a manifest lists. The package tells them apart, and a
		// library the manifest names twice is still one finding.
		if f.FindingType == types.FindingTypeDependency {
			key += ":" + f.Match
		}

		existing, exists := seen[key]
		if !exists {
			seen[key] = f
			order = append(order, key)
		} else if betterRepresentative(f, existing) {
			seen[key] = f
		}
	}

	deduped := make([]Finding, 0, len(order))
	for _, key := range order {
		deduped = append(deduped, seen[key])
	}

	return deduped
}

// betterRepresentative reports whether a should represent a location instead
// of b, when both matched the same file, line and category.
//
// An operational match always wins over a narrative one, regardless of
// severity. Without that rule, running --include-narrative could REPLACE a
// finding the default report showed with a higher-priority narrative match at
// the same location, so the flag that claims to show more showed something
// different. The default report must be a subset of it.
func betterRepresentative(a, b Finding) bool {
	if a.Narrative != b.Narrative {
		return !a.Narrative
	}
	return a.Priority() > b.Priority()
}

// skip records a file left out of the scan because it looks minified or
// generated, because it is a dependency manifest the scanner has no reader
// for, or because it is a report CryptoScan wrote, with the reason given.
func (s *Scanner) skip(path, reason string) {
	s.mu.Lock()
	s.skipped = append(s.skipped, SkippedFile{File: path, Reason: reason})
	s.mu.Unlock()
}

// minifiedNameSuffix returns the suffix that marks nameLower, a lowercased
// file name, as minified, or "" when it has none.
func minifiedNameSuffix(nameLower string) string {
	for _, suffix := range []string{".min.js", ".min.css", "-min.js", "-min.css"} {
		if strings.HasSuffix(nameLower, suffix) {
			return suffix
		}
	}
	return ""
}

// averageLineLength returns the mean length of lines in bytes, rounded down,
// as isMinifiedFile computes it.
func averageLineLength(lines []string) int {
	if len(lines) == 0 {
		return 0
	}
	total := 0
	for _, line := range lines {
		total += len(line)
	}
	return total / len(lines)
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
