// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"testing"
)

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantLang     Language
		wantFileType FileType
	}{
		{"Go file", "/src/main.go", LangGo, FileTypeCode},
		{"Python file", "/src/main.py", LangPython, FileTypeCode},
		{"Java file", "/src/Main.java", LangJava, FileTypeCode},
		{"JavaScript file", "/src/app.js", LangJavaScript, FileTypeCode},
		{"TypeScript file", "/src/app.ts", LangTypeScript, FileTypeCode},
		{"Rust file", "/src/main.rs", LangRust, FileTypeCode},
		{"Ruby file", "/src/app.rb", LangRuby, FileTypeCode},
		{"C file", "/src/main.c", LangC, FileTypeCode},
		{"C++ file", "/src/main.cpp", LangCPP, FileTypeCode},
		{"C# file", "/src/Program.cs", LangCSharp, FileTypeCode},
		{"PHP file", "/src/index.php", LangPHP, FileTypeCode},
		{"Swift file", "/src/app.swift", LangSwift, FileTypeCode},
		{"Kotlin file", "/src/app.kt", LangKotlin, FileTypeCode},
		{"Shell file", "/src/script.sh", LangShell, FileTypeCode},
		{"YAML config", "/config/app.yaml", LangYAML, FileTypeConfig},
		{"JSON config", "/config/app.json", LangJSON, FileTypeConfig},
		{"TOML config", "/config/app.toml", LangTOML, FileTypeConfig},
		{"XML config", "/config/app.xml", LangXML, FileTypeConfig},
		{"Markdown", "/docs/README.md", LangMarkdown, FileTypeDocumentation},
		{"Dockerfile", "/Dockerfile", LangShell, FileTypeCode},
		{"Makefile", "/Makefile", LangShell, FileTypeCode},
		{"Gemfile", "/Gemfile", LangRuby, FileTypeDependency},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := Analyze(tt.path)
			if ctx.Language != tt.wantLang {
				t.Errorf("Language = %v, want %v", ctx.Language, tt.wantLang)
			}
			if ctx.FileType != tt.wantFileType {
				t.Errorf("FileType = %v, want %v", ctx.FileType, tt.wantFileType)
			}
		})
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		name string
		ext  string
		want Language
	}{
		{"Go", ".go", LangGo},
		{"Python", ".py", LangPython},
		{"Python wheel", ".pyw", LangPython},
		{"Python Cython", ".pyx", LangPython},
		{"Java", ".java", LangJava},
		{"JavaScript", ".js", LangJavaScript},
		{"JavaScript module", ".mjs", LangJavaScript},
		{"CommonJS", ".cjs", LangJavaScript},
		{"TypeScript", ".ts", LangTypeScript},
		{"TSX", ".tsx", LangTypeScript},
		{"Ruby", ".rb", LangRuby},
		{"Rust", ".rs", LangRust},
		{"C", ".c", LangC},
		{"C header", ".h", LangC},
		{"C++", ".cpp", LangCPP},
		{"C++ cc", ".cc", LangCPP},
		{"C++ header", ".hpp", LangCPP},
		{"C#", ".cs", LangCSharp},
		{"PHP", ".php", LangPHP},
		{"Swift", ".swift", LangSwift},
		{"Kotlin", ".kt", LangKotlin},
		{"Kotlin script", ".kts", LangKotlin},
		{"Shell", ".sh", LangShell},
		{"Bash", ".bash", LangShell},
		{"Zsh", ".zsh", LangShell},
		{"YAML", ".yaml", LangYAML},
		{"YML", ".yml", LangYAML},
		{"JSON", ".json", LangJSON},
		{"TOML", ".toml", LangTOML},
		{"XML", ".xml", LangXML},
		{"Markdown", ".md", LangMarkdown},
		{"RST", ".rst", LangMarkdown},
		{"Unknown", ".xyz", LangUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectLanguage("file"+tt.ext, tt.ext)
			if got != tt.want {
				t.Errorf("detectLanguage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectFileType(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		filename string
		ext      string
		lang     Language
		want     FileType
	}{
		{"Package.json", "/project/package.json", "package.json", ".json", LangJSON, FileTypeDependency},
		{"Go mod", "/project/go.mod", "go.mod", ".mod", LangUnknown, FileTypeDependency},
		{"Requirements", "/project/requirements.txt", "requirements.txt", ".txt", LangUnknown, FileTypeDependency},
		{"Pom XML", "/project/pom.xml", "pom.xml", ".xml", LangXML, FileTypeDependency},
		{"Cargo.toml", "/project/Cargo.toml", "Cargo.toml", ".toml", LangTOML, FileTypeDependency},
		{"PEM cert", "/certs/server.pem", "server.pem", ".pem", LangUnknown, FileTypeCertificate},
		{"CRT cert", "/certs/server.crt", "server.crt", ".crt", LangUnknown, FileTypeCertificate},
		{"Key file", "/keys/private.key", "private.key", ".key", LangUnknown, FileTypeKey},
		{"P12 keystore", "/keys/cert.p12", "cert.p12", ".p12", LangUnknown, FileTypeKey},
		{"JKS keystore", "/keys/keystore.jks", "keystore.jks", ".jks", LangUnknown, FileTypeKey},
		{"Markdown", "/docs/guide.md", "guide.md", ".md", LangMarkdown, FileTypeDocumentation},
		{"Doc dir", "/documentation/api.txt", "api.txt", ".txt", LangUnknown, FileTypeDocumentation},
		{"README", "/README.txt", "README.txt", ".txt", LangUnknown, FileTypeDocumentation},
		{"CHANGELOG", "/CHANGELOG.md", "CHANGELOG.md", ".md", LangMarkdown, FileTypeDocumentation},
		{"LICENSE", "/LICENSE", "LICENSE", "", LangUnknown, FileTypeDocumentation},
		{"INI config", "/config.ini", "config.ini", ".ini", LangUnknown, FileTypeConfig},
		{"ENV file", "/.env", ".env", ".env", LangUnknown, FileTypeConfig},
		{"Properties", "/app.properties", "app.properties", ".properties", LangUnknown, FileTypeConfig},
		{"Test file Go", "/pkg/scanner_test.go", "scanner_test.go", ".go", LangGo, FileTypeTest},
		{"Test file Py", "/tests/test_main.py", "test_main.py", ".py", LangPython, FileTypeTest},
		{"Code file", "/src/main.go", "main.go", ".go", LangGo, FileTypeCode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFileType(tt.path, tt.filename, tt.ext, tt.lang)
			if got != tt.want {
				t.Errorf("detectFileType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		path string
		name string
		want bool
	}{
		{"/tests/main_test.go", "main_test.go", true},
		{"/test/app.py", "app.py", true},
		{"/spec/models.rb", "models.rb", true},
		{"/__tests__/component.test.js", "component.test.js", true},
		{"/testing/util.go", "util.go", true},
		{"/src/test_helper.py", "test_helper.py", true},
		{"/src/main.go", "main.go", false},
		{"/src/app.js", "app.js", false},
		{"/component.spec.ts", "component.spec.ts", true},
		{"/utils_test_helper.go", "utils_test_helper.go", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isTestFile(tt.path, tt.name)
			if got != tt.want {
				t.Errorf("isTestFile(%s) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsVendorFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/vendor/github.com/pkg/errors/errors.go", true},
		{"/node_modules/lodash/index.js", true},
		{"/bower_components/jquery/jquery.js", true},
		{"/third_party/protobuf/message.go", true},
		{"/third-party/lib/crypto.js", true},
		{"/external/deps/lib.go", true},
		{"/deps/libcrypto.h", true},
		{"/lib/utils.go", true},
		{"/libs/crypto.js", true},
		{"/src/main.go", false},
		{"/internal/app.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isVendorFile(tt.path)
			if got != tt.want {
				t.Errorf("isVendorFile(%s) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsGeneratedFile(t *testing.T) {
	tests := []struct {
		path string
		name string
		want bool
	}{
		{"/generated/types.go", "types.go", true},
		{"/gen/api.go", "api.go", true},
		{"/build/output.js", "output.js", true},
		{"/dist/bundle.js", "bundle.js", true},
		{"/out/main.js", "main.js", true},
		{"/src/types.gen.go", "types.gen.go", true},
		{"/src/api.generated.go", "api.generated.go", true},
		{"/src/message.pb.go", "message.pb.go", true},
		{"/dist/app_generated.js", "app_generated.js", true},
		{"/dist/app.min.js", "app.min.js", true},
		{"/src/main.go", "main.go", false},
		{"/src/app.js", "app.js", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isGeneratedFile(tt.path, tt.name)
			if got != tt.want {
				t.Errorf("isGeneratedFile(%s) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestContextWeight(t *testing.T) {
	tests := []struct {
		name       string
		ctx        *FileContext
		wantWeight float64
	}{
		{"Code file", &FileContext{FileType: FileTypeCode}, 1.0},
		{"Config file", &FileContext{FileType: FileTypeConfig}, 0.9},
		{"Dependency file", &FileContext{FileType: FileTypeDependency}, 0.8},
		{"Test file", &FileContext{FileType: FileTypeTest}, 0.4},
		{"Doc file", &FileContext{FileType: FileTypeDocumentation}, 0.2},
		{"Vendor code", &FileContext{FileType: FileTypeCode, IsVendor: true}, 0.3},
		{"Generated code", &FileContext{FileType: FileTypeCode, IsGenerated: true}, 0.3},
		{"Vendor generated", &FileContext{FileType: FileTypeCode, IsVendor: true, IsGenerated: true}, 0.09},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ctx.ContextWeight()
			if got != tt.wantWeight {
				t.Errorf("ContextWeight() = %v, want %v", got, tt.wantWeight)
			}
		})
	}
}

func TestShouldSuppress(t *testing.T) {
	ctx := &FileContext{
		FileType: FileTypeCode,
		IsVendor: true,
	}
	// Currently doesn't suppress anything
	if ctx.ShouldSuppress() {
		t.Error("ShouldSuppress should return false")
	}
}
