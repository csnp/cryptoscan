// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"regexp"
	"strings"

	"github.com/csnp/cryptoscan/pkg/types"
)

// LineContext provides context about a specific line of code
type LineContext struct {
	Line       string
	LineNumber int
	IsComment  bool
	IsString   bool
	IsImport   bool
	IsFunction bool
	IsVariable bool
	Confidence types.Confidence
	Purpose    string // What this crypto is being used for
}

// AnalyzeLine analyzes a line of code for context
func AnalyzeLine(line string, lang Language, prevLines []string) *LineContext {
	ctx := &LineContext{
		Line:       line,
		Confidence: types.ConfidenceHigh,
	}

	trimmed := strings.TrimSpace(line)

	// Detect if line is a comment
	ctx.IsComment = isCommentLine(trimmed, lang)

	// Detect if in a string literal (basic heuristic)
	ctx.IsString = isStringContext(trimmed)

	// Detect if this is an import statement
	ctx.IsImport = isImportLine(trimmed, lang)

	// Detect function definitions
	ctx.IsFunction = isFunctionDef(trimmed, lang)

	// Detect variable assignments
	ctx.IsVariable = isVariableAssignment(trimmed, lang)

	// Determine confidence based on context
	ctx.Confidence = determineConfidence(ctx, lang)

	// Try to determine purpose
	ctx.Purpose = determinePurpose(line, prevLines, lang)

	return ctx
}

func isCommentLine(line string, lang Language) bool {
	switch lang {
	case LangPython, LangRuby, LangShell, LangYAML:
		return strings.HasPrefix(line, "#")
	case LangGo, LangJava, LangJavaScript, LangTypeScript, LangC, LangCPP, LangCSharp, LangSwift, LangKotlin, LangRust, LangPHP:
		return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*")
	case LangMarkdown:
		return strings.HasPrefix(line, "<!--")
	}
	return false
}

func isStringContext(line string) bool {
	// Simple heuristic: check if the line is likely documentation
	docPatterns := []string{
		"@param", "@return", "@deprecated", "@see", "@link",
		"TODO", "FIXME", "NOTE", "XXX",
		"Example:", "Usage:", "e.g.", "i.e.",
	}
	for _, pattern := range docPatterns {
		if strings.Contains(line, pattern) {
			return true
		}
	}
	return false
}

// IsHelpText detects if a line looks like help/usage text or documentation
// These often mention algorithms but aren't actual crypto usage
func IsHelpText(line string) bool {
	lineLower := strings.ToLower(line)

	// CLI help/usage patterns
	helpPatterns := []string{
		"usage:", "options:", "flags:", "arguments:", "commands:",
		"--help", "-help", "help:", "synopsis:",
		"description:", "default:", "example:",
		"supported algorithms", "available algorithms", "algorithm:",
		"choose from:", "one of:", "valid values:",
		"allowed:", "accepts:", "supported:",
	}
	for _, p := range helpPatterns {
		if strings.Contains(lineLower, p) {
			return true
		}
	}

	// API documentation / help text patterns
	apiDocPatterns := []string{
		"returns:", "parameters:", "response:", "request:",
		"enum:", "type:", "format:", "schema:",
		"api reference", "documentation", "specification",
	}
	for _, p := range apiDocPatterns {
		if strings.Contains(lineLower, p) {
			return true
		}
	}

	// Common help text structures (algorithm lists in docs)
	// e.g., "Supported: RSA, ECDSA, Ed25519"
	if strings.Contains(line, ": ") && (strings.Contains(lineLower, "supported") ||
		strings.Contains(lineLower, "available") ||
		strings.Contains(lineLower, "allowed")) {
		return true
	}

	return false
}

// IsURLOrPath detects if the match appears to be in a URL or file path context
func IsURLOrPath(line, match string) bool {
	matchLower := strings.ToLower(match)
	lineLower := strings.ToLower(line)

	// Find position of match in line
	pos := strings.Index(lineLower, matchLower)
	if pos == -1 {
		return false
	}

	// Check if match is part of a URL
	urlPrefixes := []string{"http://", "https://", "ftp://", "file://", "s3://", "gs://"}
	for _, prefix := range urlPrefixes {
		prefixPos := strings.LastIndex(lineLower[:pos+1], prefix)
		if prefixPos != -1 && prefixPos < pos {
			// Check if there's no space between URL prefix and match
			segment := lineLower[prefixPos:pos]
			if !strings.Contains(segment, " ") && !strings.Contains(segment, "\t") {
				return true
			}
		}
	}

	// Check if match is part of a file path
	// Look for path separators before/after the match
	beforeMatch := ""
	if pos > 0 {
		beforeMatch = line[max(0, pos-20):pos]
	}
	afterMatch := ""
	if pos+len(match) < len(line) {
		afterMatch = line[pos+len(match) : min(len(line), pos+len(match)+20)]
	}

	// Path indicators - must have actual path separator
	if strings.Contains(beforeMatch, "/") || strings.Contains(beforeMatch, "\\") ||
		strings.HasPrefix(afterMatch, "/") || strings.HasPrefix(afterMatch, "\\") {
		return true
	}

	// Check for file extension pattern (e.g., "rsa.pem", "ecdsa.key")
	// But NOT method calls (e.g., "rsa.GenerateKey")
	if strings.HasPrefix(afterMatch, ".") && len(afterMatch) > 1 {
		// Extract the extension/method name
		extEnd := strings.IndexAny(afterMatch[1:], " \t\n(){}[]<>,;:\"'")
		if extEnd == -1 {
			extEnd = len(afterMatch)
		} else {
			extEnd++ // account for starting at index 1
		}
		if extEnd > 1 { // Ensure we have something to extract
			ext := strings.ToLower(afterMatch[1:extEnd])
			// File extensions that indicate a path
			fileExts := map[string]bool{
				"pem": true, "key": true, "crt": true, "cer": true, "der": true,
				"p12": true, "pfx": true, "jks": true, "pub": true, "sig": true,
				"txt": true, "json": true, "yaml": true, "yml": true, "xml": true,
			}
			if fileExts[ext] {
				return true
			}
		}
	}

	return false
}

// IsVariableOrFunctionName detects if the match is part of an identifier name
// e.g., rsaKeySize, getRSAKey, showECDSAInfo - these are less actionable
func IsVariableOrFunctionName(line, match string) bool {
	matchLower := strings.ToLower(match)
	lineLower := strings.ToLower(line)

	pos := strings.Index(lineLower, matchLower)
	if pos == -1 {
		return false
	}

	// Check character before match (if exists)
	if pos > 0 {
		charBefore := line[pos-1]
		// If preceded by a letter, it's part of an identifier
		if (charBefore >= 'a' && charBefore <= 'z') || (charBefore >= 'A' && charBefore <= 'Z') {
			return true
		}
	}

	// Check character after match (if exists)
	endPos := pos + len(match)
	if endPos < len(line) {
		charAfter := line[endPos]
		// If followed by a letter (not just typical suffixes), might be identifier
		if (charAfter >= 'a' && charAfter <= 'z') || (charAfter >= 'A' && charAfter <= 'Z') {
			// Exception: common crypto suffixes that indicate actual usage
			afterStr := strings.ToLower(line[endPos:min(len(line), endPos+10)])
			validSuffixes := []string{"key", "cert", "sign", "encrypt", "decrypt", "hash"}
			for _, suffix := range validSuffixes {
				if strings.HasPrefix(afterStr, suffix) {
					return false // This is likely real crypto usage
				}
			}
			return true
		}
	}

	return false
}

func isImportLine(line string, lang Language) bool {
	switch lang {
	case LangPython:
		return strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "from ")
	case LangGo:
		return strings.HasPrefix(line, "import ") || strings.Contains(line, `"`) && !strings.Contains(line, "=")
	case LangJava:
		return strings.HasPrefix(line, "import ")
	case LangJavaScript, LangTypeScript:
		return strings.HasPrefix(line, "import ") || strings.Contains(line, "require(")
	case LangRust:
		return strings.HasPrefix(line, "use ")
	case LangRuby:
		return strings.HasPrefix(line, "require ")
	case LangCSharp:
		return strings.HasPrefix(line, "using ")
	case LangC, LangCPP:
		return strings.HasPrefix(line, "#include")
	}
	return false
}

func isFunctionDef(line string, lang Language) bool {
	switch lang {
	case LangPython:
		return strings.HasPrefix(line, "def ") || strings.HasPrefix(line, "async def ")
	case LangGo:
		return strings.HasPrefix(line, "func ")
	case LangJava, LangCSharp:
		return (strings.Contains(line, "public ") || strings.Contains(line, "private ") ||
			strings.Contains(line, "protected ")) && strings.Contains(line, "(")
	case LangJavaScript, LangTypeScript:
		return strings.HasPrefix(line, "function ") || strings.Contains(line, "=>") ||
			strings.Contains(line, ": function")
	case LangRust:
		return strings.HasPrefix(line, "fn ") || strings.HasPrefix(line, "pub fn ")
	case LangRuby:
		return strings.HasPrefix(line, "def ")
	}
	return false
}

func isVariableAssignment(line string, lang Language) bool {
	switch lang {
	case LangGo:
		return strings.Contains(line, ":=") || (strings.Contains(line, "=") && strings.Contains(line, "var "))
	case LangPython, LangRuby:
		return strings.Contains(line, " = ") && !strings.Contains(line, "==")
	case LangJavaScript, LangTypeScript:
		return strings.Contains(line, "const ") || strings.Contains(line, "let ") || strings.Contains(line, "var ")
	case LangJava, LangCSharp:
		return strings.Contains(line, " = ") && !strings.Contains(line, "==") && !strings.Contains(line, "!=")
	case LangRust:
		return strings.HasPrefix(line, "let ") || strings.HasPrefix(line, "const ")
	}
	return false
}

func determineConfidence(ctx *LineContext, lang Language) types.Confidence {
	// Comments and strings are low confidence
	if ctx.IsComment || ctx.IsString {
		return types.ConfidenceLow
	}

	// Imports are high confidence for library detection
	if ctx.IsImport {
		return types.ConfidenceHigh
	}

	// Function definitions with crypto names are high confidence
	if ctx.IsFunction {
		return types.ConfidenceHigh
	}

	// Variable assignments are medium-high confidence
	if ctx.IsVariable {
		return types.ConfidenceMedium
	}

	return types.ConfidenceMedium
}

func determinePurpose(line string, prevLines []string, lang Language) string {
	lineLower := strings.ToLower(line)
	context := strings.ToLower(strings.Join(prevLines, " "))

	// Check for authentication patterns
	authPatterns := []string{"auth", "login", "session", "token", "jwt", "oauth", "credential", "password"}
	for _, p := range authPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "authentication"
		}
	}

	// Check for encryption patterns
	encryptPatterns := []string{"encrypt", "decrypt", "cipher", "plaintext", "ciphertext"}
	for _, p := range encryptPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "encryption"
		}
	}

	// Check for signing patterns
	signPatterns := []string{"sign", "verify", "signature", "certificate", "cert"}
	for _, p := range signPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "signing"
		}
	}

	// Check for hashing patterns
	hashPatterns := []string{"hash", "digest", "checksum", "integrity"}
	for _, p := range hashPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "hashing"
		}
	}

	// Check for key exchange patterns
	kexPatterns := []string{"key exchange", "key agreement", "handshake", "negotiate"}
	for _, p := range kexPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "key-exchange"
		}
	}

	// Check for TLS/SSL patterns
	tlsPatterns := []string{"tls", "ssl", "https", "certificate"}
	for _, p := range tlsPatterns {
		if strings.Contains(lineLower, p) || strings.Contains(context, p) {
			return "tls-configuration"
		}
	}

	return "general"
}

// ContextPatterns contains patterns that indicate specific crypto contexts
var ContextPatterns = map[string]*regexp.Regexp{
	"key_generation": regexp.MustCompile(`(?i)(generate|create|new).*key`),
	"encryption":     regexp.MustCompile(`(?i)(encrypt|cipher|encode)`),
	"decryption":     regexp.MustCompile(`(?i)(decrypt|decipher|decode)`),
	"signing":        regexp.MustCompile(`(?i)(sign|signature)`),
	"verification":   regexp.MustCompile(`(?i)(verify|validate)`),
	"hashing":        regexp.MustCompile(`(?i)(hash|digest|checksum)`),
	"key_exchange":   regexp.MustCompile(`(?i)(exchange|agree|handshake|negotiate)`),
	"password":       regexp.MustCompile(`(?i)(password|passphrase|secret)`),
	"certificate":    regexp.MustCompile(`(?i)(cert|x509|pem|der)`),
	"random":         regexp.MustCompile(`(?i)(random|entropy|seed)`),
}

// DetectCryptoContext detects what cryptographic operation is happening
func DetectCryptoContext(line string) []string {
	var contexts []string
	for name, pattern := range ContextPatterns {
		if pattern.MatchString(line) {
			contexts = append(contexts, name)
		}
	}
	return contexts
}
