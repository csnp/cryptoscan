// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

// TestOperationalCryptoIsNeverSuppressed is the false-negative regression
// suite. Every line here is a real way to write the algorithm, and every one
// of them reported zero findings at some point during this fix.
//
// The first group is the original defect: a substring blocklist over the whole
// line, where ".md" matched every ".md5(", "cipher =" matched the conventional
// Java variable name, and "const " matched idiomatic JavaScript.
//
// The second group is the regression the first replacement introduced, and is
// the reason the evidence classifier now asks the operational question before
// any heuristic. Running the log, comment and path rules first meant a
// variable named "outputs" (containing "puts ") or a decrement operator
// (containing "--") hid a CRITICAL finding. Those are semantics-preserving
// edits, which made the scanner steerable by the author of the code it scans.
func TestOperationalCryptoIsNeverSuppressed(t *testing.T) {
	cases := []struct {
		name  string
		file  string
		line  string
		token string // must appear in the fixture, so the case cannot go vacuous
	}{
		// Original blocklist defects.
		{"python bare call", "a.py", `md5(b)`, "md5"},
		{"python method call", "a.py", `a.md5(b)`, "md5"},
		{"python assigned method call", "a.py", `x = a.md5(b)`, "md5"},
		{"python hashlib", "a.py", `hashlib.md5(b"a")`, "md5"},
		{"python hashlib returned", "a.py", `return hashlib.md5(b"data").hexdigest()`, "md5"},
		{"python variable named cipher", "a.py", `cipher = md5(b"a")`, "md5"},
		{"go des constructor", "a.go", `block, err := des.NewCipher(key)`, "des.NewCipher"},
		{"go triple des constructor", "a.go", `block, err := des.NewTripleDESCipher(key)`, "des.NewTripleDESCipher"},
		{"js let binding", "a.js", `let   x = crypto.createHash('md5')`, "md5"},
		{"js const binding", "a.js", `const x = crypto.createHash('md5')`, "md5"},
		{"js const cipher binding", "a.js", `const cipher = crypto.createCipheriv('des-ede3-cbc', k, iv)`, "des"},
		{"js library member call", "a.js", `const rc4 = CryptoJS.RC4.encrypt(data, key)`, "RC4"},
		{"java anonymous variable", "a.java", `Cipher q      = Cipher.getInstance("RC4");`, "RC4"},
		{"java conventional variable", "a.java", `Cipher cipher = Cipher.getInstance("RC4");`, "RC4"},
		{"java des instance", "a.java", `Cipher cipher = Cipher.getInstance("DES");`, "DES"},

		// Variable names that contain a logging callee as a substring.
		{"variable named outputs", "a.java", `outputs = Cipher.getInstance("RC4");`, "RC4"},
		{"variable named inputs", "a.js", `inputs = crypto.createHash("md5").update(x)`, "md5"},

		// A document filename sharing a token with a real call.
		{"md filename argument", "a.py", `h = hashlib.md5(load("a.md"))`, "md5"},

		// Comment markers that are not comment markers in this language.
		{"java decrement operator", "a.java", `int z = 0; z--; Cipher c = Cipher.getInstance("DES");`, "DES"},
		{"shell long flag", "run.sh", `gpg --cipher-algo 3DES --symmetric secrets.tar`, "3DES"},
		{"js private field", "a.js", `class V { #c = crypto.createCipheriv("des-ede3-cbc", k, iv); }`, "des"},

		// Configuration is inventory, not narrative. Every one of these keys
		// was on the narrative-label list at some point, and each one hid a
		// CRITICAL DES finding that `main` reported. Renaming a config key
		// from "cipher" to "note" must not change what the scanner sees.
		{"yaml cipher key", "c.yaml", `cipher: DES-CBC`, "DES"},
		{"yaml note key", "c.yaml", `note: DES-CBC`, "DES"},
		{"yaml remarks key", "c.yaml", `remarks: DES-CBC`, "DES"},
		{"yaml comment key", "c.yaml", `comment: DES-CBC`, "DES"},
		{"yaml help key", "c.yaml", `help: DES-CBC`, "DES"},
		{"yaml usage key", "c.yaml", `usage: DES-CBC`, "DES"},
		{"yaml example key", "c.yaml", `example: DES-CBC`, "DES"},
		{"json usage key", "c.json", `{"usage": "DES-CBC"}`, "DES"},
		{"kebab case key", "c.yaml", `key-usage: DES-CBC`, "DES"},

		// A comma is not a key/value separator: a neighbouring list element
		// ending in a label word must not suppress the next one.
		{"list neighbour", "a.go", `var t = []string{"key usage", "DES-CBC"}`, "DES"},
		{"ruby keyword argument", "a.rb", `c = OpenSSL::Cipher.new(cipher: 'DES-CBC')`, "DES"},
		{"sshd macs directive", "sshd_config", `MACs hmac-md5 hmac-sha1 umac-64 hmac-ripemd160 hmac-sha1-96`, "md5"},
		{"sshd host key algorithms", "sshd_config", `HostKeyAlgorithms ssh-rsa ssh-dss ecdsa-sha2-nistp256 ssh-ed25519 rsa-sha2-256`, "rsa"},
		{"apache ssl protocol", "httpd.conf", `SSLProtocol -all +SSLv3 +TLSv1 +TLSv1.1 +TLSv1.2`, "SSLv3"},

		// Shelling out to a crypto tool is still using crypto.
		{"shell keygen", "gen.sh", `ssh-keygen -t rsa -b 1024 -f id_rsa -N ""`, "rsa"},
		{"go exec of openssl", "a.go", `exec.Command("sh", "-c", "openssl dgst -md5 file.bin")`, "md5"},
		{"shell variable holding command", "run.sh", `CMD="openssl enc -rc4 -in a -out b"`, "rc4"},

		// Configuration inside a quoted string. A quoted string used to count
		// as prose if it had three words and one ordinary English word, which
		// hid a dozen real settings. Postgres and the JDK put their whole
		// crypto configuration in strings like these.
		{"postgres password encryption", "db.go", `db.Exec("ALTER SYSTEM SET password_encryption TO 'md5'")`, "md5"},
		{"jdk cipher suites", "Sec.java", `props.put("jdk.tls.client.cipherSuites", "RC4 and DES are not supported here")`, "RC4"},
		{"jdk protocols", "Sec.java", `System.setProperty("https.protocols", "TLSv1 SSLv3 and TLSv1.1 are enabled")`, "SSLv3"},
		{"sql literal", "app.go", `q := "SELECT alg FROM certs WHERE alg = 'RSA-1024' AND revoked = 0"`, "RSA"},
		{"hive ssl ciphers", "Main.java", `conf.set("hive.ssl.ciphers", "DES-CBC3-SHA and RC4-MD5 for all peers")`, "RC4"},
		{"openvpn invocation", "deploy.py", `os.system("openvpn config.ovpn cipher DES-CBC auth SHA1 in tls mode")`, "DES"},
		{"php pdo exec", "app.php", `$pdo->exec("UPDATE users SET pw = 'RC4' WHERE id IN (1,2)");`, "RC4"},

		// Documentation labels used to own the rest of their line.
		{"json title", "schema.json", `  "title": "RSA-1024",`, "RSA"},
		{"json spaced separator", "conf.json", `  "description" : "DES-CBC",`, "DES"},
		{"ruby hash rocket", "site.rb", `  :title => "DES-CBC",`, "DES"},
		{"key ending in a label", "c.yaml", `ssl-title: DES-CBC`, "DES"},

		// A "#" mid-token is a URL fragment, not a comment.
		{"jdbc url fragment", "c.yaml", `jdbcUrl: jdbc:mysql://h/db?cipher=DES-CBC#legacy`, "DES"},

		// An assignment ends a token, and a document reference must not be the
		// algorithm name itself.
		{"checksum filename", "b.sh", `CHECKSUM=md5.txt`, "md5"},

		// A Go selector expression indexing a crypto path key.
		{"go map key with import path", "a.go", `a.graph.Nodes["crypto/rsa.GenerateKey"] = &CallNode{}`, "rsa"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(strings.ToLower(tc.line), strings.ToLower(tc.token)) {
				t.Fatalf("fixture does not contain %q; the case would prove nothing", tc.token)
			}
			if n := scanLine(t, tc.file, tc.line); n == 0 {
				t.Errorf("operational crypto was suppressed: %q produced 0 findings, want at least 1", tc.line)
			}
		})
	}
}

// TestNarrativeMentionsAreStillWithheld guards the other direction. If the
// classifier reported everything, the fix would trade false negatives for an
// unusable amount of noise.
//
// Every rule left is structural: it asks what the match belongs to (a logging
// call, a comment, a URL) rather than which words surround it.
//
// Note what is deliberately absent. `description: uses SHA-1 ...` and
// `"summary": "... accepts SHA-1 signatures"` are now REPORTED. Suppressing
// them needs a rule that classifies by vocabulary, and three revisions of that
// idea each lost a CRITICAL finding: a quoted-prose rule hid
// `password_encryption TO 'md5'`, and a leading-label rule hid `note: DES-CBC`.
// Configuration is where algorithm names legitimately live, so an extra
// finding on a description field is the cheaper error.
func TestNarrativeMentionsAreStillWithheld(t *testing.T) {
	cases := []struct {
		name string
		file string
		line string
	}{
		{"log message", "a.go", `log.Printf("falling back to md5 for legacy peers")`},
		{"error string", "a.go", `return errors.New("publicKey must be a valid Ed25519 public key")`},
		{"go comment", "a.go", `// Remediation: migrate this RSA key to ML-KEM before 2030`},
		{"python comment", "a.py", `# the old RSA key path is deprecated, use ML-KEM`},
		{"markdown link", "a.go", `x := loadDoc("docs/legacy-md5.md")`},
		{"url", "a.go", `const ref = "https://example.test/wiki/md5.html"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if n := scanLine(t, tc.file, tc.line); n != 0 {
				t.Errorf("narrative mention was reported: %q produced %d findings, want 0", tc.line, n)
			}
		})
	}
}

// TestWithheldCountMatchesWhatTheFlagRecovers pins the two properties that
// separate a defensible noise filter from a silent false negative: the user is
// told how many findings were withheld, and the flag returns exactly that many.
//
// The count used to be incremented at the point of suppression, before
// deduplication, so it overstated the recoverable set by more than 70% on a
// documentation tree. A user-facing number that cannot be reproduced by
// running the command it recommends is a data-integrity defect.
func TestWithheldCountMatchesWhatTheFlagRecovers(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.go"), `package main

// Remediation: migrate this RSA key to ML-KEM before the 2030 deadline
func main() {
	log.Printf("falling back to md5 for legacy peers")
	log.Printf("sha1 signatures are no longer accepted by this server")
}
`)

	withheld := scanDir(t, dir, false)
	shown := scanDir(t, dir, true)

	got := withheld.Summary.NarrativeSuppressed
	want := len(shown.Findings) - len(withheld.Findings)

	if got == 0 {
		t.Fatal("nothing was counted as withheld; the fixture no longer exercises suppression")
	}
	if got != want {
		t.Errorf("summary reports %d withheld, but --include-narrative adds %d (%d vs %d findings)",
			got, want, len(shown.Findings), len(withheld.Findings))
	}

	// A count alone cannot see a finding being replaced rather than added.
	// Deduplication keys on file:line:category, so a withheld match with a
	// higher priority used to displace the reported one and the totals still
	// balanced. Assert containment on the identity of each finding.
	shownKeys := map[string]bool{}
	for _, f := range shown.Findings {
		shownKeys[findingKey(f)] = true
	}
	for _, f := range withheld.Findings {
		if !shownKeys[findingKey(f)] {
			t.Errorf("--include-narrative dropped a finding the default report shows: %s", findingKey(f))
		}
	}
}

func findingKey(f Finding) string {
	return fmt.Sprintf("%s:%d:%d:%s:%s", f.File, f.Line, f.Column, f.Match, f.Category)
}

// TestIgnoreCommentAppliesToItsOwnLineOnly covers the off-by-one where a
// trailing cryptoscan:ignore also blinded the following line.
func TestIgnoreCommentAppliesToItsOwnLineOnly(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.py"), `import hashlib
A = hashlib.sha1(b"1")  # cryptoscan:ignore
B = hashlib.sha1(b"2")
C = hashlib.sha1(b"3")
`)

	lines := findingLines(t, scanDir(t, dir, false))
	if lines[2] {
		t.Error("line 2 carries cryptoscan:ignore and must be suppressed")
	}
	for _, want := range []int{3, 4} {
		if !lines[want] {
			t.Errorf("line %d has no ignore directive but was suppressed; got findings on %v", want, lines)
		}
	}
}

// TestIgnoreNextLineStillWorks confirms the explicit next-line form was not
// broken by the fix above. It asserts on line numbers rather than on a count,
// so it cannot stay green by finding something somewhere else.
func TestIgnoreNextLineStillWorks(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.py"), `import hashlib
# cryptoscan:ignore-next-line
A = hashlib.sha1(b"1")
B = hashlib.sha1(b"2")
`)

	lines := findingLines(t, scanDir(t, dir, false))
	if lines[3] {
		t.Error("line 3 is covered by cryptoscan:ignore-next-line and must be suppressed")
	}
	if !lines[4] {
		t.Errorf("line 4 is not covered by the directive and must still be reported; got %v", lines)
	}
}

// scanLine writes a single source line into a fresh directory and returns the
// number of findings a default scan reports for it.
func scanLine(t *testing.T, name, line string) int {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, name), line+"\n")
	return len(scanDir(t, dir, false).Findings)
}

func scanDir(t *testing.T, dir string, includeNarrative bool) *Results {
	t.Helper()
	results, err := New(Config{
		Target:           dir,
		MinSeverity:      types.SeverityInfo,
		IncludeNarrative: includeNarrative,
	}).Scan()
	if err != nil {
		t.Fatalf("scan %s: %v", dir, err)
	}
	return results
}

func findingLines(t *testing.T, results *Results) map[int]bool {
	t.Helper()
	lines := map[int]bool{}
	for _, f := range results.Findings {
		lines[f.Line] = true
	}
	return lines
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
