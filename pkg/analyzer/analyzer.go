// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package analyzer provides intelligent file analysis capabilities
package analyzer

import (
	"path/filepath"
	"strings"
)

// FileType represents the type of file being analyzed
type FileType string

const (
	FileTypeCode          FileType = "code"
	FileTypeConfig        FileType = "config"
	FileTypeDocumentation FileType = "documentation"
	FileTypeTest          FileType = "test"
	FileTypeDependency    FileType = "dependency"
	FileTypeCertificate   FileType = "certificate"
	FileTypeKey           FileType = "key"
	FileTypeUnknown       FileType = "unknown"
)

// Language represents a programming language
type Language string

const (
	LangGo         Language = "go"
	LangPython     Language = "python"
	LangJava       Language = "java"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangRuby       Language = "ruby"
	LangRust       Language = "rust"
	LangC          Language = "c"
	LangCPP        Language = "cpp"
	LangCSharp     Language = "csharp"
	LangPHP        Language = "php"
	LangSwift      Language = "swift"
	LangKotlin     Language = "kotlin"
	LangShell      Language = "shell"
	LangYAML       Language = "yaml"
	LangJSON       Language = "json"
	LangTOML       Language = "toml"
	LangXML        Language = "xml"
	LangMarkdown   Language = "markdown"
	LangUnknown    Language = "unknown"
)

// FileContext contains analyzed information about a file
type FileContext struct {
	Path        string
	Name        string
	Extension   string
	FileType    FileType
	Language    Language
	IsTest      bool
	IsVendor    bool
	IsGenerated bool
}

// Analyze returns context information about a file
func Analyze(path string) *FileContext {
	name := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))

	ctx := &FileContext{
		Path:      path,
		Name:      name,
		Extension: ext,
		Language:  detectLanguage(name, ext),
	}

	ctx.FileType = detectFileType(path, name, ext, ctx.Language)
	ctx.IsTest = isTestFile(path, name)
	ctx.IsVendor = isVendorFile(path)
	ctx.IsGenerated = isGeneratedFile(path, name)

	return ctx
}

func detectLanguage(name, ext string) Language {
	// Check by extension first
	switch ext {
	case ".go":
		return LangGo
	case ".py", ".pyw", ".pyx":
		return LangPython
	case ".java":
		return LangJava
	case ".js", ".mjs", ".cjs":
		return LangJavaScript
	case ".ts", ".tsx":
		return LangTypeScript
	case ".rb":
		return LangRuby
	case ".rs":
		return LangRust
	case ".c", ".h":
		return LangC
	case ".cpp", ".cc", ".cxx", ".hpp", ".hxx":
		return LangCPP
	case ".cs":
		return LangCSharp
	case ".php":
		return LangPHP
	case ".swift":
		return LangSwift
	case ".kt", ".kts":
		return LangKotlin
	case ".sh", ".bash", ".zsh":
		return LangShell
	case ".yaml", ".yml":
		return LangYAML
	case ".json":
		return LangJSON
	case ".toml":
		return LangTOML
	case ".xml":
		return LangXML
	case ".md", ".markdown", ".rst":
		return LangMarkdown
	}

	// Check by filename
	switch strings.ToLower(name) {
	case "dockerfile", "containerfile":
		return LangShell
	case "makefile", "gnumakefile":
		return LangShell
	case "gemfile", "rakefile":
		return LangRuby
	}

	return LangUnknown
}

func detectFileType(path, name, ext string, lang Language) FileType {
	nameLower := strings.ToLower(name)
	pathLower := strings.ToLower(path)

	// Dependency manifests
	dependencyFiles := map[string]bool{
		"package.json": true, "package-lock.json": true, "yarn.lock": true,
		"go.mod": true, "go.sum": true,
		"requirements.txt": true, "pipfile": true, "pipfile.lock": true, "pyproject.toml": true,
		"pom.xml": true, "build.gradle": true, "build.gradle.kts": true,
		"gemfile": true, "gemfile.lock": true,
		"cargo.toml": true, "cargo.lock": true,
		"composer.json": true, "composer.lock": true,
		"nuget.config": true, "packages.config": true,
	}
	if dependencyFiles[nameLower] {
		return FileTypeDependency
	}

	// Certificates and keys
	if ext == ".pem" || ext == ".crt" || ext == ".cer" || ext == ".der" {
		return FileTypeCertificate
	}
	if ext == ".key" || ext == ".p12" || ext == ".pfx" || ext == ".jks" {
		return FileTypeKey
	}

	// Documentation
	if lang == LangMarkdown || ext == ".txt" || ext == ".rst" {
		return FileTypeDocumentation
	}
	docDirs := []string{"/docs/", "/doc/", "/documentation/", "/wiki/"}
	for _, dir := range docDirs {
		if strings.Contains(pathLower, dir) {
			return FileTypeDocumentation
		}
	}
	if strings.HasPrefix(nameLower, "readme") || strings.HasPrefix(nameLower, "changelog") ||
		strings.HasPrefix(nameLower, "contributing") || strings.HasPrefix(nameLower, "license") {
		return FileTypeDocumentation
	}

	// Configuration
	configExts := map[string]bool{
		".yaml": true, ".yml": true, ".json": true, ".toml": true,
		".xml": true, ".ini": true, ".cfg": true, ".conf": true,
		".env": true, ".properties": true,
	}
	if configExts[ext] {
		return FileTypeConfig
	}

	// Test files
	if isTestFile(path, name) {
		return FileTypeTest
	}

	// Code files
	if lang != LangUnknown && lang != LangMarkdown {
		return FileTypeCode
	}

	return FileTypeUnknown
}

func isTestFile(path, name string) bool {
	pathLower := strings.ToLower(path)
	nameLower := strings.ToLower(name)

	// Test directories
	testDirs := []string{"/test/", "/tests/", "/spec/", "/specs/", "/__tests__/", "/testing/"}
	for _, dir := range testDirs {
		if strings.Contains(pathLower, dir) {
			return true
		}
	}

	// Test file patterns
	if strings.HasSuffix(nameLower, "_test.go") ||
		strings.HasSuffix(nameLower, "_test.py") ||
		strings.HasSuffix(nameLower, ".test.js") ||
		strings.HasSuffix(nameLower, ".test.ts") ||
		strings.HasSuffix(nameLower, ".spec.js") ||
		strings.HasSuffix(nameLower, ".spec.ts") ||
		strings.HasPrefix(nameLower, "test_") ||
		strings.Contains(nameLower, "_test_") {
		return true
	}

	return false
}

func isVendorFile(path string) bool {
	pathLower := strings.ToLower(path)
	vendorDirs := []string{
		"/vendor/", "/node_modules/", "/bower_components/",
		"/third_party/", "/third-party/", "/external/",
		"/deps/", "/lib/", "/libs/",
	}
	for _, dir := range vendorDirs {
		if strings.Contains(pathLower, dir) {
			return true
		}
	}
	return false
}

func isGeneratedFile(path, name string) bool {
	pathLower := strings.ToLower(path)
	nameLower := strings.ToLower(name)

	// Generated directories
	genDirs := []string{"/generated/", "/gen/", "/build/", "/dist/", "/out/"}
	for _, dir := range genDirs {
		if strings.Contains(pathLower, dir) {
			return true
		}
	}

	// Generated file patterns
	if strings.HasSuffix(nameLower, ".gen.go") ||
		strings.HasSuffix(nameLower, ".generated.go") ||
		strings.HasSuffix(nameLower, ".pb.go") ||
		strings.HasSuffix(nameLower, "_generated.js") ||
		strings.Contains(nameLower, ".min.") {
		return true
	}

	return false
}

// ContextWeight returns a weight modifier based on file context
// Higher weights indicate more important/actionable findings
func (ctx *FileContext) ContextWeight() float64 {
	weight := 1.0

	// Code files are most important
	if ctx.FileType == FileTypeCode {
		weight = 1.0
	} else if ctx.FileType == FileTypeConfig {
		weight = 0.9 // Config is important too
	} else if ctx.FileType == FileTypeDependency {
		weight = 0.8 // Dependencies are actionable
	} else if ctx.FileType == FileTypeTest {
		weight = 0.4 // Tests are less critical
	} else if ctx.FileType == FileTypeDocumentation {
		weight = 0.2 // Docs are informational
	}

	// Vendor/generated files are less important
	if ctx.IsVendor {
		weight *= 0.3
	}
	if ctx.IsGenerated {
		weight *= 0.3
	}

	return weight
}

// ShouldSuppress returns true if findings from this file should be suppressed
func (ctx *FileContext) ShouldSuppress() bool {
	// Don't suppress anything by default, but could be used for vendor files
	return false
}
