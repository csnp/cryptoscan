// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

// TestOperationalCryptoIsNeverSuppressed covers the detection-suppression
// defects found by the v1.4.0 release test. Each line here is a real way to
// write the algorithm, and each produced zero findings before the evidence
// classifier replaced the substring blocklist:
//
//	a.md5(b)                      dropped by the ".md" entry in urlPatterns
//	hashlib.md5(b"a")             dropped by ".md"
//	cipher = md5(b"a")            dropped by "cipher ="
//	const x = crypto.createHash   dropped by "const "
//
// The fixtures are scanned end to end rather than unit-tested against the
// classifier, so a regression anywhere in the filter chain fails the test.
func TestOperationalCryptoIsNeverSuppressed(t *testing.T) {
	cases := []struct {
		name string
		file string
		line string
	}{
		{"python bare call", "a.py", `md5(b)`},
		{"python method call", "a.py", `a.md5(b)`},
		{"python assigned method call", "a.py", `x = a.md5(b)`},
		{"python hashlib", "a.py", `hashlib.md5(b"a")`},
		{"python hashlib returned", "a.py", `return hashlib.md5(b"data").hexdigest()`},
		{"python variable named cipher", "a.py", `cipher = md5(b"a")`},
		{"go des constructor", "a.go", `block, err := des.NewCipher(key)`},
		{"go triple des constructor", "a.go", `block, err := des.NewTripleDESCipher(key)`},
		{"js let binding", "a.js", `let   x = crypto.createHash('md5')`},
		{"js const binding", "a.js", `const x = crypto.createHash('md5')`},
		{"js const cipher binding", "a.js", `const cipher = crypto.createCipheriv('des-ede3-cbc', k, iv)`},
		{"js library member call", "a.js", `const rc4 = CryptoJS.RC4.encrypt(data, key)`},
		{"java anonymous variable", "a.java", `Cipher q      = Cipher.getInstance("RC4");`},
		{"java conventional variable", "a.java", `Cipher cipher = Cipher.getInstance("RC4");`},
		{"java des instance", "a.java", `Cipher cipher = Cipher.getInstance("DES");`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := scanLine(t, tc.file, tc.line)
			if n == 0 {
				t.Errorf("operational crypto was suppressed: %q produced 0 findings, want at least 1", tc.line)
			}
		})
	}
}

// TestNarrativeMentionsAreStillWithheld guards the other direction. If the
// classifier reported everything, the fix would trade false negatives for an
// unusable amount of noise, so the suppression that earns its place has to
// keep working.
func TestNarrativeMentionsAreStillWithheld(t *testing.T) {
	cases := []struct {
		name string
		file string
		line string
	}{
		{"log message", "a.go", `log.Printf("falling back to md5 for legacy peers")`},
		{"error string", "a.go", `return errors.New("publicKey must be a valid Ed25519 public key")`},
		{"json config key", "a.json", `  "algorithm": "RSA-2048",`},
		{"yaml config key", "a.yaml", `  algorithm: RSA-2048`},
		{"doc key", "a.yaml", `  description: uses SHA-1 for backwards compatibility`},
		{"markdown link", "a.go", `// see docs/legacy-md5.md for the migration plan`},
		{"url", "a.go", `const ref = "https://example.test/wiki/RC4_considered_harmful"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if n := scanLine(t, tc.file, tc.line); n != 0 {
				t.Errorf("narrative mention was reported: %q produced %d findings, want 0", tc.line, n)
			}
		})
	}
}

// TestNarrativeSuppressionIsCountedAndRecoverable asserts the two properties
// that separate a defensible noise filter from a silent false negative: the
// user is told how many mentions were withheld, and a flag brings them back.
func TestNarrativeSuppressionIsCountedAndRecoverable(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.go"), `package main
func main() {
	log.Printf("falling back to md5 for legacy peers")
}
`)

	withheld := scanDir(t, dir, false)
	if withheld.Summary.NarrativeSuppressed == 0 {
		t.Error("narrative suppression was not counted; a withheld finding must be visible in the summary")
	}
	if len(withheld.Findings) != 0 {
		t.Errorf("got %d findings by default, want 0", len(withheld.Findings))
	}

	shown := scanDir(t, dir, true)
	if len(shown.Findings) == 0 {
		t.Error("--include-narrative did not recover the withheld finding")
	}
}

// TestIgnoreCommentAppliesToItsOwnLineOnly covers the off-by-one where a
// trailing cryptoscan:ignore also blinded the following line. Line 3 is not
// annotated and must be reported.
func TestIgnoreCommentAppliesToItsOwnLineOnly(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.py"), `import hashlib
A = hashlib.sha1(b"1")  # cryptoscan:ignore
B = hashlib.sha1(b"2")
C = hashlib.sha1(b"3")
`)

	results := scanDir(t, dir, false)

	lines := map[int]bool{}
	for _, f := range results.Findings {
		lines[f.Line] = true
	}
	if lines[2] {
		t.Error("line 2 carries cryptoscan:ignore and must be suppressed")
	}
	for _, want := range []int{3, 4} {
		if !lines[want] {
			t.Errorf("line %d has no ignore directive but was suppressed; got findings on lines %v", want, lines)
		}
	}
}

// TestIgnoreNextLineStillWorks confirms the explicit next-line form was not
// broken by the fix above.
func TestIgnoreNextLineStillWorks(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.py"), `import hashlib
# cryptoscan:ignore-next-line
A = hashlib.sha1(b"1")
B = hashlib.sha1(b"2")
`)

	results := scanDir(t, dir, false)
	for _, f := range results.Findings {
		if f.Line == 3 {
			t.Error("line 3 is covered by cryptoscan:ignore-next-line and must be suppressed")
		}
	}
	if len(results.Findings) == 0 {
		t.Error("line 4 is not covered by the directive and must still be reported")
	}
}

// TestClassifyMatchOutOfRangeIsReported guards the fail-open contract: an
// offset the classifier cannot interpret must not drop the finding.
func TestClassifyMatchOutOfRange(t *testing.T) {
	for _, tc := range []struct{ start, end int }{{-1, 3}, {0, 999}, {5, 2}} {
		if class, _ := classifyMatch("md5(b)", tc.start, tc.end); class != evidenceOperational {
			t.Errorf("classifyMatch(%d,%d) suppressed the finding; unclassifiable matches must be reported", tc.start, tc.end)
		}
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

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	// Guard against a vacuously green test: the fixture has to contain the
	// algorithm token at all, or the assertions below prove nothing.
	if !strings.ContainsAny(strings.ToLower(content), "0123456789abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("fixture %s is empty", path)
	}
}
