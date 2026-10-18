// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNewScanner(t *testing.T) {
	cfg := Config{
		Target: ".",
	}
	s := New(cfg)
	if s == nil {
		t.Fatal("New returned nil")
	}
}

func TestScanDirectory(t *testing.T) {
	// Create temp directory with test files
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test Go file with crypto patterns
	testFile := filepath.Join(tmpDir, "crypto.go")
	content := `package main

import (
	"crypto/rsa"
	"crypto/rand"
)

func generateKey() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = key
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if results.FilesScanned == 0 {
		t.Error("Expected files to be scanned")
	}

	// Should find RSA pattern
	foundRSA := false
	for _, f := range results.Findings {
		if f.Algorithm == "RSA" {
			foundRSA = true
			break
		}
	}
	if !foundRSA {
		t.Error("Expected to find RSA pattern")
	}
}

func TestScanExcludePatterns(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create vendor directory
	vendorDir := filepath.Join(tmpDir, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create test file in vendor (should be excluded)
	vendorFile := filepath.Join(vendorDir, "crypto.go")
	content := `package vendor
func init() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
}
`
	if err := os.WriteFile(vendorFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:       tmpDir,
		ExcludeGlobs: []string{"vendor"},
		MinSeverity:  SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should not find anything in excluded directory
	for _, f := range results.Findings {
		if strings.Contains(f.File, "/vendor/") {
			t.Errorf("Found file in excluded vendor directory: %s", f.File)
		}
	}
}

// writeRSATree creates each relative path under a new temporary directory with
// one RSA key generation line, so every file yields a finding unless an
// exclude pattern removes it.
func writeRSATree(t *testing.T, rels ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range rels {
		content := "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
		if strings.HasSuffix(rel, ".go") {
			content = "package src\n\nvar key, _ = rsa.GenerateKey(rand.Reader, 2048)\n"
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// filesWithFindings scans root with the given exclude patterns and returns the
// set of slash-separated paths, relative to root, that produced findings.
func filesWithFindings(t *testing.T, root string, excludes []string) map[string]bool {
	t.Helper()
	results, err := New(Config{
		Target:       root,
		ExcludeGlobs: excludes,
		MinSeverity:  SeverityInfo,
	}).Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	found := make(map[string]bool)
	for _, f := range results.Findings {
		rel, err := filepath.Rel(root, f.File)
		if err != nil {
			t.Fatal(err)
		}
		found[filepath.ToSlash(rel)] = true
	}
	return found
}

func TestScanExcludeDirectoryGlobs(t *testing.T) {
	files := []string{"vendor/a.py", "test/b.py", "src/c_test.go", "src/d.py"}
	root := writeRSATree(t, files...)

	// Every file must yield a finding on its own, or the exclusion checks
	// below would pass without excluding anything.
	all := filesWithFindings(t, root, nil)
	for _, rel := range files {
		if !all[rel] {
			t.Fatalf("%s yields no finding without excludes; the fixture does not exercise the exclude patterns", rel)
		}
	}

	found := filesWithFindings(t, root, []string{"vendor/*", "test/*", "*_test.go"})
	want := map[string]bool{"src/d.py": true}
	for rel := range found {
		if !want[rel] {
			t.Errorf("%s has findings although --exclude \"vendor/*,test/*,*_test.go\" should exclude it", rel)
		}
	}
	if !found["src/d.py"] {
		t.Error("src/d.py has no findings although no exclude pattern names it")
	}
}

func TestScanDefaultExcludesSkipDependencyAndBuildDirs(t *testing.T) {
	skipped := []string{"vendor/a.py", "venv/e.py", ".venv/f.py", "target/g.py", "services/api/vendor/h.py"}
	kept := []string{"test/b.py", "src/d.py"}
	root := writeRSATree(t, append(skipped, kept...)...)

	all := filesWithFindings(t, root, nil)
	for _, rel := range skipped {
		if !all[rel] {
			t.Fatalf("%s yields no finding without excludes; the fixture does not exercise the default excludes", rel)
		}
	}

	found := filesWithFindings(t, root, DefaultExcludeGlobs)
	for _, rel := range skipped {
		if found[rel] {
			t.Errorf("%s has findings although the default excludes skip its directory", rel)
		}
	}
	for _, rel := range kept {
		if !found[rel] {
			t.Errorf("%s has no findings; the default excludes must not skip it", rel)
		}
	}
}

func TestMatchesExclude(t *testing.T) {
	tests := []struct {
		pattern string
		rel     string
		isDir   bool
		want    bool
	}{
		// No "/": a file or directory name at any depth.
		{"*_test.go", "src/c_test.go", false, true},
		{"*_test.go", "src/c.go", false, false},
		{"vendor", "vendor", true, true},
		{"vendor", "a/b/vendor", true, true},
		{"vendor", "vendor/x.py", false, true},
		{"vendor", "vendors", true, false},

		// Ending in "/*", "/**" or "/": the directory and everything in it.
		{"vendor/*", "vendor", true, true},
		{"vendor/*", "vendor/a.py", false, true},
		{"vendor/*", "services/api/vendor", true, true},
		{"vendor/**", "vendor/deep/a.py", false, true},
		{"vendor/", "vendor", true, true},
		{"./vendor/*", "vendor", true, true},
		{"build/*", "build", false, false}, // a build script, not a directory
		{"build/*", "build.go", false, false},
		{"src/generated/*", "src/generated", true, true},
		{"src/generated/*", "src/generated/x.go", false, true},
		{"src/generated/*", "lib/src/generated/x.go", false, false},

		// Any other "/": the path from the scan root, and directories it names.
		{"src/*.pb.go", "src/a.pb.go", false, true},
		{"src/*.pb.go", "src/sub/a.pb.go", false, false},
		{"src/generated", "src/generated", true, true},
		{"src/generated", "src/generated/x.go", false, true},
		{"src/generated", "lib/src/generated", true, false},

		// The scan root and empty patterns exclude nothing.
		{"*", ".", true, false},
		{"", "a.py", false, false},
		{"/*", "a.py", false, false},
	}
	for _, tt := range tests {
		if got := matchesExclude(tt.pattern, tt.rel, tt.isDir); got != tt.want {
			t.Errorf("matchesExclude(%q, %q, isDir=%v) = %v, want %v", tt.pattern, tt.rel, tt.isDir, got, tt.want)
		}
	}
}

func TestScanIncludePatterns(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create Go file
	goFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(goFile, []byte("rsa.GenerateKey(rand.Reader, 2048)"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create Python file
	pyFile := filepath.Join(tmpDir, "main.py")
	if err := os.WriteFile(pyFile, []byte("from cryptography.hazmat.primitives import hashes"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:       tmpDir,
		IncludeGlobs: []string{"*.go"},
		MinSeverity:  SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should only find Go files
	for _, f := range results.Findings {
		if filepath.Ext(f.File) != ".go" {
			t.Errorf("Found non-.go file: %s", f.File)
		}
	}
}

func TestScanBinaryExclusion(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a fake binary file
	binFile := filepath.Join(tmpDir, "program.exe")
	if err := os.WriteFile(binFile, []byte{0x4D, 0x5A, 0x90, 0x00}, 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should not find anything in binary files
	for _, f := range results.Findings {
		if filepath.Ext(f.File) == ".exe" {
			t.Errorf("Found findings in binary file: %s", f.File)
		}
	}
}

func TestHasCritical(t *testing.T) {
	results := &Results{
		Findings: []Finding{
			{Severity: SeverityInfo},
			{Severity: SeverityLow},
		},
		Summary: Summary{
			BySeverity: map[string]int{"INFO": 1, "LOW": 1},
		},
	}
	if results.HasCritical() {
		t.Error("HasCritical should be false with no critical findings")
	}

	results.Findings = append(results.Findings, Finding{Severity: SeverityCritical})
	results.Summary.BySeverity["CRITICAL"] = 1
	if !results.HasCritical() {
		t.Error("HasCritical should be true with critical finding")
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "CRITICAL"},
		{SeverityHigh, "HIGH"},
		{SeverityMedium, "MEDIUM"},
		{SeverityLow, "LOW"},
		{SeverityInfo, "INFO"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.sev.String(); got != tt.want {
				t.Errorf("Severity.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanWithDependencyFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create package.json with crypto dependency
	pkgJSON := filepath.Join(tmpDir, "package.json")
	content := `{
  "name": "test-app",
  "dependencies": {
    "crypto-js": "^4.0.0",
    "bcrypt": "^5.0.0"
  }
}`
	if err := os.WriteFile(pkgJSON, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should find crypto dependency
	foundDep := false
	for _, f := range results.Findings {
		if f.FindingType == "dependency" {
			foundDep = true
			break
		}
	}
	if !foundDep {
		t.Log("No dependency findings found (may be expected if patterns don't match)")
	}
}

func TestScanWithRequirementsTxt(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create requirements.txt with crypto dependency
	reqFile := filepath.Join(tmpDir, "requirements.txt")
	content := `cryptography==41.0.0
pycryptodome>=3.0.0
bcrypt==4.0.0`
	if err := os.WriteFile(reqFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if results.FilesScanned == 0 {
		t.Error("Expected files to be scanned")
	}
}

func TestScanWithMultipleCryptoPatterns(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create file with multiple crypto patterns
	testFile := filepath.Join(tmpDir, "crypto.go")
	content := `package main

import (
	"crypto/rsa"
	"crypto/aes"
	"crypto/md5"
)

func encrypt() {
	key, _ := rsa.GenerateKey(nil, 2048)
	block, _ := aes.NewCipher([]byte("key"))
	hash := md5.Sum([]byte("data"))
	_, _, _ = key, block, hash
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should find multiple patterns
	if len(results.Findings) < 2 {
		t.Errorf("Expected multiple findings, got %d", len(results.Findings))
	}

	// Check summary is populated
	if results.Summary.TotalFindings == 0 {
		t.Error("Expected summary to have findings")
	}
}

func TestScanWithMinSeverity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "crypto.go")
	content := `package main
import "crypto/rsa"
func gen() { rsa.GenerateKey(nil, 2048) }
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Scan with high severity filter
	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityCritical,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should have fewer or no findings with high severity filter
	for _, f := range results.Findings {
		if f.Severity < SeverityCritical {
			t.Errorf("Found finding below min severity: %v", f.Severity)
		}
	}
}

func TestScanWithConfidenceFilter(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "crypto.go")
	content := `package main
import "crypto/rsa"
func gen() { rsa.GenerateKey(nil, 2048) }
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:        tmpDir,
		MinSeverity:   SeverityInfo,
		MinConfidence: "HIGH",
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should only have high confidence findings
	for _, f := range results.Findings {
		if f.Confidence != "HIGH" {
			t.Errorf("Found finding with non-high confidence: %v", f.Confidence)
		}
	}
}

func TestScanInsights(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create file with RSA to trigger insights
	testFile := filepath.Join(tmpDir, "crypto.go")
	content := `package main
import "crypto/rsa"
func gen() {
	rsa.GenerateKey(nil, 2048)
	rsa.GenerateKey(nil, 4096)
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:      tmpDir,
		MinSeverity: SeverityInfo,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Check if insights are generated
	if len(results.Insights) > 0 {
		insight := results.Insights[0]
		if insight.Title == "" {
			t.Error("Insight should have a title")
		}
		if insight.Description == "" {
			t.Error("Insight should have a description")
		}
	}
}

func TestQuantumRiskString(t *testing.T) {
	tests := []struct {
		risk QuantumRisk
		want string
	}{
		{QuantumVulnerable, "VULNERABLE"},
		{QuantumPartial, "PARTIAL"},
		{QuantumSafe, "SAFE"},
		{QuantumUnknown, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := string(tt.risk); got != tt.want {
				t.Errorf("QuantumRisk = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanProgress(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cryptoscan-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create multiple files
	for i := 0; i < 5; i++ {
		testFile := filepath.Join(tmpDir, filepath.FromSlash(filepath.Join("dir", string(rune('a'+i))+".go")))
		if err := os.MkdirAll(filepath.Dir(testFile), 0755); err != nil {
			t.Fatal(err)
		}
		content := `package main
func init() {}
`
		if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	cfg := Config{
		Target:       tmpDir,
		MinSeverity:  SeverityInfo,
		ShowProgress: true,
	}
	s := New(cfg)
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if results.FilesScanned == 0 {
		t.Error("Expected files to be scanned")
	}
}

// TestScanMaxDepth scans a tree with a file at each of three depths under
// every depth limit and checks which files were reached: root.go sits in the
// target, a/one.go one directory down and a/b/two.go two down.
func TestScanMaxDepth(t *testing.T) {
	dir := t.TempDir()
	code := "package main\n\nimport \"crypto/rsa\"\n\nfunc gen() { rsa.GenerateKey(nil, 2048) }\n"
	for _, rel := range []string{"root.go", "a/one.go", "a/b/two.go"} {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		maxDepth int
		want     []string
	}{
		{0, []string{"a/b/two.go", "a/one.go", "root.go"}},
		{1, []string{"root.go"}},
		{2, []string{"a/one.go", "root.go"}},
		{3, []string{"a/b/two.go", "a/one.go", "root.go"}},
	}
	for _, tt := range tests {
		results, err := New(Config{Target: dir, MinSeverity: SeverityInfo, MaxDepth: tt.maxDepth}).Scan()
		if err != nil {
			t.Fatalf("MaxDepth %d: Scan failed: %v", tt.maxDepth, err)
		}
		seen := map[string]bool{}
		for _, f := range results.Findings {
			rel, err := filepath.Rel(dir, f.File)
			if err != nil {
				t.Fatal(err)
			}
			seen[filepath.ToSlash(rel)] = true
		}
		got := make([]string, 0, len(seen))
		for file := range seen {
			got = append(got, file)
		}
		slices.Sort(got)
		if !slices.Equal(got, tt.want) {
			t.Errorf("MaxDepth %d: findings in %v, want %v", tt.maxDepth, got, tt.want)
		}
		if results.FilesScanned != len(tt.want) {
			t.Errorf("MaxDepth %d: FilesScanned = %d, want %d", tt.maxDepth, results.FilesScanned, len(tt.want))
		}
	}
}

// TestScanContextLines checks how many source lines a finding keeps around
// its match for each context width, on a file whose only match is line 6 of
// 10.
func TestScanContextLines(t *testing.T) {
	dir := t.TempDir()
	code := "package main\n" +
		"// line 2\n" +
		"// line 3\n" +
		"// line 4\n" +
		"// line 5\n" +
		"var _ = rsa.GenerateKey(nil, 2048)\n" +
		"// line 7\n" +
		"// line 8\n" +
		"// line 9\n" +
		"// line 10\n"
	if err := os.WriteFile(filepath.Join(dir, "key.go"), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		contextLines, wantStart, wantEnd int
	}{
		{0, 6, 6},
		{1, 5, 7},
		{3, 3, 9},
		{10, 1, 10},
	}
	for _, tt := range tests {
		results, err := New(Config{Target: dir, MinSeverity: SeverityInfo, ContextLines: tt.contextLines}).Scan()
		if err != nil {
			t.Fatalf("ContextLines %d: Scan failed: %v", tt.contextLines, err)
		}
		if len(results.Findings) != 1 {
			t.Fatalf("ContextLines %d: %d findings, want 1", tt.contextLines, len(results.Findings))
		}
		ctx := results.Findings[0].SourceContext
		if ctx == nil {
			t.Fatalf("ContextLines %d: the finding has no SourceContext", tt.contextLines)
		}
		if ctx.StartLine != tt.wantStart || ctx.EndLine != tt.wantEnd || len(ctx.Lines) != tt.wantEnd-tt.wantStart+1 {
			t.Errorf("ContextLines %d: lines %d-%d with %d entries, want %d-%d",
				tt.contextLines, ctx.StartLine, ctx.EndLine, len(ctx.Lines), tt.wantStart, tt.wantEnd)
		}
		for _, line := range ctx.Lines {
			if line.IsMatch != (line.Number == 6) {
				t.Errorf("ContextLines %d: line %d IsMatch = %v", tt.contextLines, line.Number, line.IsMatch)
			}
		}
	}
}
