// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import "strings"

// Evidence classification for a single pattern match.
//
// The scanner needs to separate "this codebase uses MD5" from "this line of
// prose mentions MD5". The original implementation answered that question by
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
// the corpus.
//
// # Ordering is the safety property
//
// The replacement asks the operational question FIRST, and never suppresses a
// match that answers it. This ordering is not cosmetic. An earlier revision of
// this file ran the log-message, comment and URL rules ahead of the
// operational check, and that alone reintroduced the same bug class through a
// different door:
//
//	outputs = Cipher.getInstance("RC4")   suppressed: "puts " matched "outputs "
//	inputs = crypto.createHash("md5")     suppressed: "puts " matched "inputs "
//	h = hashlib.md5(load("a.md"))         suppressed: ".md" again, via the token
//
// Any narrative rule is a heuristic over weak evidence. Running them after the
// operational check bounds the damage a wrong heuristic can do to lines that
// are not obviously code.
//
// # Suppression is bounded, counted and recoverable
//
// Narrative rules are deliberately narrow, because a missed finding in a
// security scanner costs far more than an extra line of output:
//
// Only three narrative rules survive, and all three are structural. They ask
// what the match belongs to, never which words surround it:
//
//   - The match is inside a string owned by a logging or error call. The callee
//     is matched on identifier boundaries, so "puts" does not match "outputs".
//   - The match is inside a comment, in a language that actually has that
//     comment marker. "#" is a comment in Python and a private field in
//     JavaScript; "--" is a comment in SQL and a decrement in Java.
//   - The match is inside a URL or a document path, tested on the token's real
//     suffix rather than by substring.
//
// Rules that classified by vocabulary were tried and removed. A quoted string
// of three or more words was treated as prose, which hid
// `password_encryption TO 'md5'` and a dozen other real settings; a leading
// `description:` or `title:` owned the rest of its line, which lost a CRITICAL
// finding to every key that was not on the list. Configuration is where
// algorithm names legitimately live, so no rule may key off the words in a
// value.
//
// Everything the classifier does withhold is counted and recoverable with
// --include-narrative.

// evidenceClass describes what a matched token tells us about the codebase.
type evidenceClass int

const (
	// evidenceOperational means the token participates in a cryptographic
	// operation: a call, an instantiation, a member access, an import, or an
	// algorithm name handed to a crypto factory.
	evidenceOperational evidenceClass = iota

	// evidenceNarrative means the token appears in text rather than in code:
	// prose, a log message, a comment, a URL, or a documentation label.
	evidenceNarrative
)

// matchContext carries what the classifier knows about where a match came
// from. Language and file type come from the file analyzer and are needed to
// interpret comment markers and to decide whether whole-line prose detection
// applies at all.
type matchContext struct {
	Line     string
	Start    int
	End      int
	Language string
	FileType string
}

// classifyMatch reports what kind of evidence a matched token represents,
// along with the rule that decided it. The reason string is for diagnostics
// and tests; callers should not parse it.
//
// Start and End are byte offsets into Line. An offset the classifier cannot
// interpret yields evidenceOperational: an unclassifiable match must be
// reported, never silently dropped.
func classifyMatch(mc matchContext) (evidenceClass, string) {
	line := mc.Line
	if mc.Start < 0 || mc.End > len(line) || mc.Start >= mc.End {
		return evidenceOperational, "unclassifiable"
	}

	quoteStart, _, inString := stringLiteralAt(line, mc.Start, mc.End)

	// An import names a library the codebase depends on. Evidence of use, even
	// though a module path looks like a file path.
	if isImportLine(line) {
		return evidenceOperational, "import"
	}

	// The operational question, asked before any heuristic.
	if reason, ok := operationalUse(line, mc.Start, mc.End, quoteStart, inString); ok {
		return evidenceOperational, reason
	}

	// The match sits inside a string that is being logged or turned into an
	// error message. The call prefix is matched on identifier boundaries.
	if inString && isLoggingCall(line[:quoteStart]) {
		return evidenceNarrative, "log-message"
	}

	if at := commentStartsAt(line, mc.Language); at >= 0 && at < mc.Start {
		return evidenceNarrative, "comment"
	}

	if isPathLikeToken(tokenAround(line, mc.Start, mc.End)) {
		return evidenceNarrative, "url-or-path"
	}

	// Everything else is reported.
	//
	// There used to be two more rules here and both were false-negative
	// generators, so they are gone rather than tuned:
	//
	//   - A quoted string of three or more words counted as prose. A quoted
	//     string is the single most common place an algorithm name legitimately
	//     appears as configuration, so this hid
	//     `db.Exec("ALTER SYSTEM SET password_encryption TO 'md5'")`,
	//     `props.put("jdk.tls.client.cipherSuites", "RC4 and DES ...")` and ten
	//     other real settings. Log and error strings are still withheld, but by
	//     the structural rule above, which asks what call the string belongs to
	//     rather than what words are in it.
	//   - A leading documentation label (`description:`, `title:`) owned the
	//     rest of the line. Every revision of that rule lost a CRITICAL finding
	//     to a key that was not on the list: first `note:`, then `"title" :`
	//     with a space, then `:title =>`, then any key ending in a label such
	//     as `ssl-title:`. The word list was never the problem; handing a label
	//     the rest of the line is.
	//
	// What remains is structural: a string belonging to a logging call, a
	// comment in a language that has that comment marker, and a URL or document
	// path. None of those depend on which words a value happens to contain.
	return evidenceOperational, "default"
}

// operationalUse reports whether the token at [start,end) participates in a
// cryptographic operation.
func operationalUse(line string, start, end, quoteStart int, inString bool) (string, bool) {
	// A call: md5(...), MD5(...), or a matched span ending in a call such as
	// DES.encrypt(...).
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
	//
	// Both forms require the surrounding token to be an identifier chain. A
	// dot inside a filename looks identical: "legacy-md5.md" would otherwise
	// read as a member call on md5.
	if !isPathLikeToken(tokenAround(line, start, end)) {
		if end < len(line) && line[end] == '.' && end+1 < len(line) && isIdentChar(line[end+1]) {
			return "member-call", true
		}

		// The token is a member of something: hashlib.md5, a.md5, CryptoJS.MD5.
		// Requires an identifier before the dot so that ".md5" inside a
		// filename or a sentence does not qualify.
		if start > 0 && line[start-1] == '.' && start >= 2 && isIdentChar(line[start-2]) {
			return "member-access", true
		}
	}

	// An algorithm name passed to a crypto factory:
	// Cipher.getInstance("RC4"), crypto.createHash('md5'),
	// crypto.createCipheriv('aes-256-gcm', key, iv).
	if inString && isCryptoFactoryCall(line[:quoteStart]) {
		return "factory-argument", true
	}

	return "", false
}

// loggingCallees are call prefixes whose string arguments are program output
// rather than program behaviour. Each is matched on an identifier boundary.
var loggingCallees = []string{
	"log", "logger", "logging", "logrus", "slog", "zap",
	"console.log", "console.error", "console.warn", "console.info", "console.debug",
	"fmt.print", "fmt.printf", "fmt.println", "fmt.sprint", "fmt.sprintf",
	"fmt.fprint", "fmt.fprintf", "fmt.errorf",
	"print", "println", "printf", "puts", "echo", "warn", "panic",
	"errors.new", "t.logf", "t.errorf", "t.fatalf",
}

// isLoggingCall reports whether prefix, the text preceding a string literal on
// the same line, ends in a call to a logging, printing or error-construction
// function.
//
// Matching is identifier-anchored. A substring test here is what made "puts "
// match "outputs = ..." and "log." match "catalog.", hiding real crypto behind
// a variable name.
func isLoggingCall(prefix string) bool {
	return hasCalleeSuffix(prefix, loggingCallees)
}

// cryptoFactoryCallees are call prefixes whose string argument names the
// algorithm being instantiated. A match inside one of these is a use.
var cryptoFactoryCallees = []string{
	"getinstance", "createcipher", "createcipheriv", "createdecipher",
	"createdecipheriv", "createhash", "createhmac", "createsign", "createverify",
	"creatediffiehellman", "messagedigest", "keypairgenerator", "keygenerator",
	"keyfactory", "secretkeyspec", "ivparameterspec",
	"hashlib.new", "hmac.new", "cipher.new", "digest.new",
}

// isCryptoFactoryCall reports whether prefix ends in a call that takes an
// algorithm name as an argument.
func isCryptoFactoryCall(prefix string) bool {
	return hasCalleeSuffix(prefix, cryptoFactoryCallees)
}

// hasCalleeSuffix reports whether prefix ends in a call to one of callees.
//
// The prefix is expected to end at an opening quote, so the shape being
// matched is `... callee ( args? "`. The callee has to end at an identifier
// boundary, which is what stops "puts" from matching inside "outputs".
func hasCalleeSuffix(prefix string, callees []string) bool {
	// Walk back over the argument list to the opening parenthesis of the call
	// that owns this string literal.
	trimmed := strings.TrimRight(prefix, " \t")
	depth := 0
	open := -1
	for i := len(trimmed) - 1; i >= 0; i-- {
		switch trimmed[i] {
		case ')':
			depth++
		case '(':
			if depth == 0 {
				open = i
				i = -1
				continue
			}
			depth--
		}
		if open >= 0 {
			break
		}
	}
	if open < 0 {
		return false
	}

	name := strings.ToLower(strings.TrimRight(trimmed[:open], " \t"))
	for _, callee := range callees {
		if !strings.HasSuffix(name, callee) {
			continue
		}
		// Identifier boundary: the character before the callee must not
		// continue an identifier. A dot is allowed so that "fmt.print" and
		// "console.log" match, and so that "crypto.createHash" matches the
		// bare "createhash" entry.
		if at := len(name) - len(callee); at == 0 || !isIdentChar(name[at-1]) {
			return true
		}
	}
	return false
}

// commentMarkers returns the line-comment and block-comment openers for a
// language.
//
// An unknown language gets no markers rather than a permissive default: the
// cost of missing a comment is one noisy finding, and the cost of guessing
// wrong is a silently hidden one.
func commentMarkers(language string) []string {
	switch language {
	case "go", "java", "javascript", "typescript", "c", "cpp", "csharp",
		"swift", "kotlin", "rust", "php":
		return []string{"//", "/*"}
	case "python", "ruby", "shell", "yaml", "toml":
		return []string{"#"}
	case "markdown", "xml":
		return []string{"<!--"}
	default:
		return nil
	}
}

// commentStartsAt returns the offset where a comment begins on this line, or
// -1. Markers inside string literals do not count.
func commentStartsAt(line, language string) int {
	markers := commentMarkers(language)
	if len(markers) == 0 {
		return -1
	}

	inQuote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote != 0 {
			if c == inQuote && (i == 0 || line[i-1] != '\\') {
				inQuote = 0
			}
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			inQuote = c
			continue
		}
		for _, m := range markers {
			if !strings.HasPrefix(line[i:], m) {
				continue
			}
			// "#" opens a comment only at the start of a line or after
			// whitespace. Mid-token it is a URL fragment:
			// "jdbcUrl: jdbc:mysql://h/db?cipher=DES-CBC#legacy" is one value.
			if m == "#" && i > 0 && !isSpaceByte(line[i-1]) {
				continue
			}
			return i
		}
	}

	// A block-comment continuation line: a leading "*" before any code.
	for _, m := range markers {
		if m == "/*" {
			if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "*") {
				return strings.Index(line, "*")
			}
		}
	}
	return -1
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

	body := strings.TrimSuffix(trimmed, ",")
	if i := strings.IndexAny(body, "\"`"); i != -1 {
		head := strings.TrimSpace(body[:i])
		if head == "" || head == "_" || head == "." || isIdentifier(head) {
			rest := body[i:]
			if len(rest) >= 2 && rest[len(rest)-1] == rest[0] &&
				!strings.Contains(rest[1:len(rest)-1], string(rest[0])) {
				return true
			}
		}
	}
	return false
}

// documentExtensions are file suffixes whose contents are prose about code.
var documentExtensions = map[string]bool{
	"md": true, "markdown": true, "html": true, "htm": true, "rst": true, "adoc": true,
}

// isPathLikeToken reports whether a token is a URL or a file path.
//
// The extension test looks at the token's real suffix rather than doing a
// substring search, which is what stopped ".md" from matching ".md5(".
func isPathLikeToken(token string) bool {
	if token == "" {
		return false
	}
	lower := strings.ToLower(token)

	if strings.Contains(lower, "://") {
		return true
	}

	// A path has a separator and either an absolute or relative prefix or a
	// host segment. "crypto/rsa" is a Go import path, not a document, and is
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

// tokenAround returns the token containing [start,end).
//
// Quotes and brackets end a token as well as whitespace. Splitting on
// whitespace alone made `Nodes["crypto/rsa.GenerateKey"]` a single token, so
// the path rule fired on an ordinary Go selector expression.
func tokenAround(line string, start, end int) string {
	isBoundary := func(c byte) bool {
		switch c {
		case ' ', '\t', '"', '\'', '`', '(', ')', '[', ']', '{', '}', ',', ';', '<', '>', '=':
			return true
		}
		return false
	}
	left := start
	for left > 0 && !isBoundary(line[left-1]) {
		left--
	}
	right := end
	for right < len(line) && !isBoundary(line[right]) {
		right++
	}
	return line[left:right]
}

// stringLiteralAt reports whether [start,end) falls inside a quoted string on
// this line, returning the offsets of the opening and closing quotes.
//
// This is a single-line scan: it cannot see multi-line strings. An
// unterminated quote ends the search, and the match is reported as not being
// in a string, which routes it toward being reported rather than suppressed.
func stringLiteralAt(line string, start, end int) (quoteStart, quoteEnd int, ok bool) {
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c != '"' && c != '\'' && c != '`' {
			continue
		}
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

func skipSpaces(line string, i int) int {
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	return i
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t'
}

func isIdentChar(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
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
