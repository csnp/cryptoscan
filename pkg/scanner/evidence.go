// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import "strings"

// Evidence classification for a single pattern match.
//
// The scanner needs to separate "this codebase uses MD5" from "this line of
// prose mentions MD5". The previous implementation answered that question by
// testing the whole source line against a list of about a hundred substrings
// and dropping the finding on any hit. That is unsound in a way that produced
// silent false negatives:
//
//	a.md5(b)                                  suppressed by ".md"
//	return hashlib.md5(b"data").hexdigest()   suppressed by ".md"
//	Cipher cipher = Cipher.getInstance("DES") suppressed by "cipher ="
//	const rc4 = CryptoJS.RC4.encrypt(d, k)    suppressed by "const "
//
// None of those substrings had anything to do with the matched token. ".md"
// was meant to catch Markdown filenames and instead matched every ".md5(" in
// the corpus; "const " and "cipher =" matched the most idiomatic way to write
// crypto in JavaScript and Java respectively. The tool's own crypto-samples
// tree contained deliberately vulnerable code that the scanner could not see.
//
// The replacement asks two better-posed questions, both anchored to where the
// match actually sits on the line:
//
//  1. Is the matched token part of an operational construct (a call, a member
//     access, an argument to a crypto factory)? If so it is evidence of use and
//     is never suppressed, whatever else appears on the line.
//  2. Otherwise, is the token inside narrative text (prose, a log message, a
//     documentation or configuration key's value, a URL or path)? Only then is
//     it treated as low-value.
//
// Anything that is neither is reported. The default is to report, because a
// missed finding in a security scanner costs more than an extra line of output.

// evidenceClass describes what a matched token tells us about the codebase.
type evidenceClass int

const (
	// evidenceOperational means the token participates in a cryptographic
	// operation: a call, an instantiation, a member access, or an algorithm
	// name handed to a crypto factory.
	evidenceOperational evidenceClass = iota

	// evidenceNarrative means the token appears in text rather than in code:
	// prose, a log message, a documentation or config key's value, a URL, or
	// a file path.
	evidenceNarrative
)

// classifyMatch reports what kind of evidence the token at [start,end) in line
// represents, along with the rule that decided it. The reason string is used
// for diagnostics and tests; callers should not parse it.
//
// start and end are byte offsets into line. Out-of-range offsets classify as
// operational, since an unclassifiable match must not be silently dropped.
func classifyMatch(line string, start, end int) (evidenceClass, string) {
	if start < 0 || end > len(line) || start >= end {
		return evidenceOperational, "unclassifiable"
	}

	quoteStart, quoteEnd, inString := stringLiteralAt(line, start, end)

	// An import names a library the codebase actually depends on, so it is
	// evidence of use even though the module path looks like a file path.
	// This is checked before the path rule for exactly that reason.
	if isImportLine(line) {
		return evidenceOperational, "import"
	}

	// A crypto call whose result is logged is still a crypto call, so the log
	// test only applies when the match is inside the logged string itself.
	if inString && isLoggingCall(line[:quoteStart]) {
		return evidenceNarrative, "log-message"
	}

	if commentStartsAt(line) >= 0 && commentStartsAt(line) < start {
		return evidenceNarrative, "comment"
	}

	if isPathLikeToken(tokenAround(line, start, end)) {
		return evidenceNarrative, "url-or-path"
	}

	if reason, ok := operationalUse(line, start, end, quoteStart, inString); ok {
		return evidenceOperational, reason
	}

	// A comparison against an algorithm name is code that handles the
	// algorithm, not code that uses it: `if alg == "RSA"` tells you the
	// program can recognise RSA, not that it encrypts with it.
	if inString && isComparisonOperand(line, quoteStart, quoteEnd) {
		return evidenceNarrative, "comparison"
	}

	// Prose: an algorithm named inside a sentence rather than used. Three or
	// more whitespace-separated words is the threshold, which keeps single
	// tokens such as "RC4", "aes-256-gcm" and "AES/GCM/NoPadding" operational
	// while catching "publicKey must be a valid Ed25519 public key".
	if inString && wordCount(line[quoteStart+1:quoteEnd]) >= 3 {
		return evidenceNarrative, "prose"
	}

	if key, ok := precedingKey(line, start); ok {
		return evidenceNarrative, "key-value:" + key
	}

	// Prose outside a string literal: body text in HTML and Markdown, where
	// the sentence is the line rather than a quoted argument.
	if !inString && isProseLine(line) {
		return evidenceNarrative, "prose-line"
	}

	return evidenceOperational, "default"
}

// operationalUse reports whether the token at [start,end) participates in a
// cryptographic operation.
func operationalUse(line string, start, end, quoteStart int, inString bool) (string, bool) {
	// A call: md5(...), MD5(...), or the whole matched span ending in a call
	// such as DES.encrypt(...).
	if next := skipSpaces(line, end); next < len(line) && line[next] == '(' {
		return "call", true
	}

	// The matched span is itself a call. Several patterns match a whole
	// construct rather than a bare token, for example
	// `crypto.createCipheriv('des` or `Cipher.getInstance("DES")`. Those spans
	// straddle the opening quote, so they are not "inside" a string literal and
	// the factory rule below cannot see them.
	if strings.Contains(line[start:end], "(") {
		return "call-in-match", true
	}

	// A member access or member call on the matched token: md5.New(),
	// des.NewCipher(k), CryptoJS.MD5.encrypt(d).
	if end < len(line) && line[end] == '.' && end+1 < len(line) && isIdentChar(line[end+1]) {
		return "member-call", true
	}

	// The token is a member of something: hashlib.md5, a.md5, CryptoJS.MD5.
	// Requires an identifier before the dot so that ".md5" inside a filename
	// or a sentence does not qualify.
	if start > 0 && line[start-1] == '.' && start >= 2 && isIdentChar(line[start-2]) {
		return "member-access", true
	}

	// An algorithm name passed to a crypto factory:
	// Cipher.getInstance("RC4"), crypto.createHash('md5'),
	// crypto.createCipheriv('aes-256-gcm', key, iv).
	if inString && isCryptoFactoryCall(line[:quoteStart]) {
		return "factory-argument", true
	}

	return "", false
}

// loggingCallees are the call prefixes whose string arguments are program
// output rather than program behaviour.
var loggingCallees = []string{
	"log.", "logger.", "logging.", "logrus.", "slog.", "zap.",
	"console.log", "console.error", "console.warn", "console.info", "console.debug",
	"fmt.print", "fmt.sprint", "fmt.fprint", "fmt.errorf",
	"print(", "println(", "puts ", "echo ",
	"errors.new", "fmt.errorf",
}

// isLoggingCall reports whether prefix, the text preceding a string literal on
// the same line, ends in a call to a logging, printing or error-construction
// function.
func isLoggingCall(prefix string) bool {
	lower := strings.ToLower(prefix)
	// Only the tail matters: the call that owns this string literal is the
	// nearest one to its left. Anything further away is unrelated code on the
	// same line.
	if len(lower) > 64 {
		lower = lower[len(lower)-64:]
	}
	for _, callee := range loggingCallees {
		if strings.Contains(lower, callee) {
			return true
		}
	}
	return false
}

// cryptoFactoryCallees are call prefixes whose string argument names the
// algorithm being instantiated. A match inside one of these is a use, not a
// mention.
var cryptoFactoryCallees = []string{
	"getinstance(", "createcipher", "createdecipher", "createhash(", "createhmac(",
	"createsign(", "createverify(", "creatediffiehellman(",
	"messagedigest", "keypairgenerator", "keygenerator", "keyfactory",
	"secretkeyspec", "ivparameterspec", "mac.getinstance", "signature.getinstance",
	"new cipher", "cipher(", "digest(", "hmac(", "hashlib.new(", "hmac.new(",
	"algorithms.", "crypto.subtle", "subtle.digest(", "subtle.importkey(",
	"evp_get_cipherbyname(", "openssl_encrypt(", "openssl_digest(",
}

// isCryptoFactoryCall reports whether prefix, the text preceding a string
// literal, ends in a call that takes an algorithm name as an argument.
func isCryptoFactoryCall(prefix string) bool {
	lower := strings.ToLower(prefix)
	if len(lower) > 64 {
		lower = lower[len(lower)-64:]
	}
	for _, callee := range cryptoFactoryCallees {
		if strings.Contains(lower, callee) {
			return true
		}
	}
	return false
}

// narrativeKeys are field names whose value is descriptive text or declared
// configuration data rather than an executed operation.
//
// The key has to sit immediately before the match and be followed by ':' or
// ',', so this recognises `"algorithm": "RSA-2048"`,
// `description: "uses SHA-256"` and `c.Locals("authenticated_via", "ed25519")`
// without matching a line that merely contains the word somewhere.
var narrativeKeys = []string{
	// Documentation and presentation.
	"description", "summary", "title", "label", "placeholder", "tooltip",
	"help", "note", "remarks", "usage", "example", "comment", "display_name",
	// Declared configuration data.
	// "type" and "method" are deliberately absent: they are too generic, and
	// their values (`type: 'MLDSA65-ECDSA-P256'`) are exactly the algorithm
	// inventory this tool exists to collect.
	"algorithm", "algorithms", "cipher", "ciphers", "hash", "digest",
	"key_type", "crypto_type", "auth_method",
	"authenticated_via", "authentication_type", "signing_algorithm",
	"encryption_algorithm", "algorithm_name", "supported_algorithms",
	"allowed_algorithms", "preferred_algorithm",
	// Test data.
	"test_vector", "test_data", "test_case", "test_input", "test_output",
	"expected_hash", "expected_signature",
}

// precedingKey reports whether the match at start is the value of a narrative
// key, returning the key that matched.
func precedingKey(line string, start int) (string, bool) {
	prefix := strings.ToLower(line[:start])
	for _, key := range narrativeKeys {
		idx := strings.LastIndex(prefix, key)
		if idx == -1 {
			continue
		}
		// Whole word only: "algorithm" must not match inside "myalgorithms".
		if idx > 0 && isIdentChar(prefix[idx-1]) {
			continue
		}
		rest := prefix[idx+len(key):]
		// Allow a closing quote and whitespace between the key and its
		// separator, covering `"algorithm": x` and `'algorithm' : x`.
		rest = strings.TrimLeft(rest, "\"' \t")
		if strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, ",") ||
			strings.HasPrefix(rest, "=>") {
			return key, true
		}
	}
	return "", false
}

// isComparisonOperand reports whether the string literal at [quoteStart,
// quoteEnd] is an operand of an equality comparison.
func isComparisonOperand(line string, quoteStart, quoteEnd int) bool {
	before := strings.TrimRight(line[:quoteStart], " \t")
	for _, op := range []string{"==", "!=", "===", "!==", "<>"} {
		if strings.HasSuffix(before, op) {
			return true
		}
	}
	for _, call := range []string{".equals(", ".equalsignorecase(", "strcmp(", "strcasecmp(", "string.compare(", ".startswith(", ".endswith("} {
		if strings.HasSuffix(strings.ToLower(before), call) {
			return true
		}
	}

	after := strings.TrimLeft(line[quoteEnd+1:], " \t")
	for _, op := range []string{"==", "!=", "===", "!==", "<>"} {
		if strings.HasPrefix(after, op) {
			return true
		}
	}
	return false
}

// isProseLine reports whether a line is natural-language text rather than code.
//
// Body text in HTML and Markdown puts the algorithm name in a sentence with no
// enclosing string literal, so the quoted-prose rule cannot see it. The test is
// word count against code-punctuation density: a sentence has many words and
// few braces, semicolons and operators.
func isProseLine(line string) bool {
	stripped := stripMarkup(line)
	if wordCount(stripped) < 6 {
		return false
	}

	code := 0
	for i := 0; i < len(stripped); i++ {
		switch stripped[i] {
		case '{', '}', ';', '=', '[', ']', '|', '&', '(', ')':
			code++
		}
	}
	return code <= 2
}

// stripMarkup removes HTML tags so that the words of a sentence can be counted
// without the surrounding markup.
func stripMarkup(line string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
				continue
			}
			b.WriteByte(line[i])
		default:
			if depth == 0 {
				b.WriteByte(line[i])
			}
		}
	}
	return b.String()
}

// isImportLine reports whether a line brings a module into scope.
//
// A Go import block lists bare quoted paths one per line, so a line whose only
// content is a quoted string is treated as an import entry. Without this,
// `"golang.org/x/crypto/bcrypt"` would be classified as a URL and the
// dependency would go unreported.
func isImportLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)

	for _, prefix := range []string{"import ", "import(", "import\t", "from ", "#include", "using ", "require ", "use "} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	if strings.Contains(lower, "require(") || strings.Contains(lower, "import(") {
		return true
	}

	// A bare quoted path on its own line: a Go import-block entry, optionally
	// with an alias or a trailing comma.
	body := strings.TrimSuffix(strings.TrimSpace(trimmed), ",")
	if i := strings.IndexAny(body, `"`+"`"); i != -1 {
		head := strings.TrimSpace(body[:i])
		if head == "" || head == "_" || head == "." || isIdentifier(head) {
			rest := body[i:]
			if len(rest) >= 2 && (rest[0] == '"' || rest[0] == '`') &&
				rest[len(rest)-1] == rest[0] &&
				!strings.Contains(rest[1:len(rest)-1], string(rest[0])) {
				return true
			}
		}
	}
	return false
}

// commentStartsAt returns the offset where a line comment begins, or -1. Only
// comment markers outside string literals count, so a "//" inside a URL string
// does not turn the rest of the line into a comment.
func commentStartsAt(line string) int {
	inQuote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote != 0 {
			if c == inQuote && (i == 0 || line[i-1] != '\\') {
				inQuote = 0
			}
			continue
		}
		switch {
		case c == '"' || c == '\'' || c == '`':
			inQuote = c
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return i
		case c == '/' && i+1 < len(line) && line[i+1] == '*':
			return i
		case c == '#':
			return i
		case c == '-' && i+1 < len(line) && line[i+1] == '-':
			return i
		}
	}
	// A javadoc or block-comment continuation line: leading "*" before any code.
	if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "*") {
		return strings.Index(line, "*")
	}
	return -1
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentChar(s[i]) {
			return false
		}
	}
	return true
}

// documentExtensions are file suffixes whose contents are prose about code
// rather than code.
var documentExtensions = map[string]bool{
	"md": true, "markdown": true, "html": true, "htm": true, "rst": true,
	"txt": true, "adoc": true, "pdf": true,
}

// isPathLikeToken reports whether a whitespace-delimited token is a URL or a
// file path.
//
// The extension test looks at the token's real suffix rather than doing a
// substring search, which is what stopped ".md" from matching ".md5(".
func isPathLikeToken(token string) bool {
	if token == "" {
		return false
	}
	trimmed := strings.Trim(token, `"'`+"`,;()[]{}<>")
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)

	if strings.Contains(lower, "://") {
		return true
	}

	// A path has a separator and either an absolute/relative prefix or a host
	// segment. "crypto/rsa" is a Go import path, not a document, and is
	// classified by its own Library Import category instead.
	if strings.Contains(lower, "/") && !strings.Contains(lower, "(") {
		if strings.HasPrefix(lower, "/") || strings.HasPrefix(lower, "./") ||
			strings.HasPrefix(lower, "../") {
			return true
		}
		if head := lower[:strings.Index(lower, "/")]; strings.Contains(head, ".") {
			return true
		}
	}

	// A bare document filename such as README.md or api.html.
	if dot := strings.LastIndex(lower, "."); dot != -1 && dot+1 < len(lower) {
		if documentExtensions[lower[dot+1:]] {
			return true
		}
	}

	return false
}

// tokenAround returns the whitespace-delimited token containing [start,end).
func tokenAround(line string, start, end int) string {
	left := start
	for left > 0 && !isSpaceByte(line[left-1]) {
		left--
	}
	right := end
	for right < len(line) && !isSpaceByte(line[right]) {
		right++
	}
	return line[left:right]
}

// stringLiteralAt reports whether [start,end) falls inside a quoted string on
// this line, returning the offsets of the opening and closing quotes.
//
// This is a single-line scan: it cannot see multi-line strings, and it treats
// an unterminated quote as not-a-string so that an apostrophe in a comment does
// not swallow the rest of the line.
func stringLiteralAt(line string, start, end int) (quoteStart, quoteEnd int, ok bool) {
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c != '"' && c != '\'' && c != '`' {
			continue
		}
		// Skip an escaped quote.
		if i > 0 && line[i-1] == '\\' {
			continue
		}
		closing := -1
		for j := i + 1; j < len(line); j++ {
			if line[j] == c && line[j-1] != '\\' {
				closing = j
				break
			}
		}
		if closing == -1 {
			return 0, 0, false
		}
		if start > i && end <= closing {
			return i, closing, true
		}
		i = closing
	}
	return 0, 0, false
}

// wordCount counts whitespace-separated words in s.
func wordCount(s string) int {
	return len(strings.Fields(s))
}

func skipSpaces(line string, i int) int {
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	return i
}

func isIdentChar(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t'
}
