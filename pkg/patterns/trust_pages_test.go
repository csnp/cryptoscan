// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// trustPagesDir holds the finding page of each Trust pattern.
const trustPagesDir = "../../docs/findings"

// trustPages are the two finding pages: the pattern each documents and the
// status of the key table rows it lists.
var trustPages = []struct {
	file, id, status string
}{
	{"trust-compromised-key.md", TrustCompromisedKeyID, trustStatusCompromised},
	{"trust-distrusted-root.md", TrustDistrustedRootID, trustStatusDistrusted},
}

func readPage(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(trustPagesDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Each page is the one its pattern links to, names the finding in its title,
// and carries the Fix for each key use it lists, the dates and the two public
// sources.
func TestTrustPagesNameTheFindingAndCarryItsText(t *testing.T) {
	byID := trustPatternsByID(t)
	for _, p := range trustPages {
		page := readPage(t, p.file)
		pattern := byID[p.id]
		if len(pattern.References) != 1 || filepath.Base(pattern.References[0]) != p.file {
			t.Errorf("%s references %v, want the one page %s", p.id, pattern.References, p.file)
		}
		if title, _, _ := strings.Cut(page, "\n"); title != "# "+p.id+": "+pattern.Name {
			t.Errorf("%s: title %q, want %q", p.file, title, "# "+p.id+": "+pattern.Name)
		}
		var texts []string
		for _, k := range trustKeys().keys {
			if k.Status == p.status {
				texts = append(texts, trustFixes[k.Use])
			}
		}
		texts = append(texts, trustBugURL, trustBlogURL, "2026-10-17", "2026-10-18", "2026-10-27",
			"The scan reads only the files in the scanned tree.")
		for _, s := range texts {
			if !strings.Contains(page, s) {
				t.Errorf("%s does not carry %q", p.file, s)
			}
		}
		if strings.ContainsAny(page, "—–") {
			t.Errorf("%s holds an em or en dash", p.file)
		}
	}
}

// pageTableRows returns the rows of the key table between a page's markers,
// each split into its cells.
func pageTableRows(t *testing.T, page, name string) [][]string {
	t.Helper()
	start := strings.Index(page, "<!-- trust-key-table:start")
	end := strings.Index(page, "<!-- trust-key-table:end -->")
	if start < 0 || end < start {
		t.Fatalf("%s has no key table markers", name)
	}
	var rows [][]string
	for _, line := range strings.Split(page[start:end], "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| Key ") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		for i := range cells {
			cells[i] = strings.Trim(cells[i], "`")
		}
		rows = append(rows, cells)
	}
	return rows
}

// The table on each page is the key table: for every row of the page's
// status, grouped by use (TLS, then code signing, then root) and in the
// table's order within a use, the SPKI hash and then each certificate hash,
// in hex and in base64, labelled with the subject of the key's certificates.
// A table edited by hand, or a key table changed without go generate, fails.
func TestTrustPageTablesEqualTheKeyTable(t *testing.T) {
	labels := map[string]map[string]bool{}
	for _, b := range readFixtureBlocks(t, "tls", "codesigning", "root") {
		spki := sha256Hex(b.cert.RawSubjectPublicKeyInfo)
		if labels[spki] == nil {
			labels[spki] = map[string]bool{}
		}
		labels[spki][b.cert.Subject.CommonName] = true
	}
	for _, p := range trustPages {
		var want [][]string
		for _, use := range []string{"tls", "codeSigning", "root"} {
			for _, k := range trustKeys().keys {
				if k.Status != p.status || k.Use != use {
					continue
				}
				want = append(want, []string{"", k.Use, "SPKI", k.SPKISHA256, hexBase64(t, k.SPKISHA256)})
				for _, c := range k.CertSHA256 {
					want = append(want, []string{"", k.Use, "Certificate", c, hexBase64(t, c)})
				}
			}
		}
		got := pageTableRows(t, readPage(t, p.file), p.file)
		if len(got) != len(want) {
			t.Errorf("%s: %d table rows, want %d", p.file, len(got), len(want))
			continue
		}
		for i := range want {
			row := got[i]
			if len(row) != 5 {
				t.Errorf("%s row %d: %d cells, want 5: %v", p.file, i+1, len(row), row)
				continue
			}
			if row[1] != want[i][1] || row[2] != want[i][2] || row[3] != want[i][3] || row[4] != want[i][4] {
				t.Errorf("%s row %d = %v, want %v", p.file, i+1, row[1:], want[i][1:])
			}
		}
		// Every row of a key carries a subject of that key's certificates.
		for i := range want {
			spki := want[i][3]
			if want[i][2] != "SPKI" {
				for j := i; j >= 0; j-- {
					if want[j][2] == "SPKI" {
						spki = want[j][3]
						break
					}
				}
			}
			if !labels[spki][got[i][0]] {
				t.Errorf("%s row %d: label %q is not a subject of key %s", p.file, i+1, got[i][0], spki)
			}
		}
	}
}

func hexBase64(t *testing.T, h string) string {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// The pages name no host: no name the fixture leaf was issued to appears on
// either page.
func TestTrustPagesNameNoHostOfTheLeaf(t *testing.T) {
	leaf := readFixtureBlocks(t, "leaf")
	var names []string
	for _, b := range leaf {
		names = append(names, b.cert.Subject.CommonName)
		names = append(names, b.cert.DNSNames...)
		names = append(names, b.cert.EmailAddresses...)
		for _, ip := range b.cert.IPAddresses {
			names = append(names, ip.String())
		}
		for _, u := range b.cert.URIs {
			names = append(names, u.Host)
		}
	}
	if len(names) == 0 {
		t.Fatal("the fixture leaf names no host, so this test checks nothing")
	}
	for _, p := range trustPages {
		page := strings.ToLower(readPage(t, p.file))
		for _, n := range names {
			if n != "" && strings.Contains(page, strings.ToLower(n)) {
				t.Errorf("%s names a host the fixture leaf was issued to", p.file)
			}
		}
	}
}

// pageOpenSSL returns the openssl programs to run the pages' commands under:
// the colon-separated paths in CRYPTOSCAN_TEST_OPENSSL, or the openssl on
// PATH.
func pageOpenSSL(t *testing.T) []string {
	t.Helper()
	if list := os.Getenv("CRYPTOSCAN_TEST_OPENSSL"); list != "" {
		return filepath.SplitList(list)
	}
	path, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("no openssl on PATH; the pages' commands must run in CI")
		}
		t.Skip("no openssl on PATH")
	}
	return []string{path}
}

// runPageCommand runs a command block of a page with /bin/sh, in dir, with
// openssl resolving to bin and env added, and returns its standard output.
func runPageCommand(t *testing.T, bin, dir, block string, env []string) []byte {
	t.Helper()
	binDir := t.TempDir()
	if err := os.Symlink(bin, filepath.Join(binDir, "openssl")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", block)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+"/usr/bin"+string(os.PathListSeparator)+"/bin"), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Errorf("%v: %s\n%s", err, stderr.String(), block)
	}
	return out
}

// isLibreSSL reports whether bin is LibreSSL, whose verify command has
// neither -no_check_time nor -partial_chain.
func isLibreSSL(t *testing.T, bin string) bool {
	t.Helper()
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatalf("%s version: %v", bin, err)
	}
	return bytes.HasPrefix(out, []byte("LibreSSL"))
}

// serveChain serves chain over TLS, with key as the first certificate's
// private key, on a loopback listener that closes when the test ends, and
// returns its port. It returns false when the address cannot be listened on,
// as on a host without IPv6.
func serveChain(t *testing.T, addr string, chain [][]byte, key *ecdsa.PrivateKey) (string, bool) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Logf("listen %s: %v", addr, err)
		return "", false
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}})
	t.Cleanup(func() { _ = tlsLn.Close() })
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(20 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port, true
}

// pageCase is how one command block of a page is run and what it must print.
type pageCase struct {
	env         []string
	want        string
	opensslOnly bool // the block uses verify options LibreSSL does not have
}

var shBlock = regexp.MustCompile("(?s)```sh\n(.*?)```")

// Every command block on the two pages runs, as written, under every openssl
// given, and prints what the page says it prints: the hash commands the
// matched value of a certificate in a bundle, the signature checks OK, and
// the served-chain recipe the SPKI hash of each certificate a TLS server on a
// loopback address sends. A block without a case here fails the test.
func TestTrustPageCommandsRun(t *testing.T) {
	bins := pageOpenSSL(t)

	tlsBlocks := readFixtureBlocks(t, "tls")
	root := readFixtureBlocks(t, "root")[0]
	leaf := readFixtureBlocks(t, "leaf")[0]
	control := readFixtureBlocks(t, "control")
	m, ok := trustKeys().match(leaf.der, leaf.cert)
	if !ok || m.rule != 2 {
		t.Fatal("the fixture leaf does not meet rule 2")
	}
	var listed, served fixtureBlock
	for _, b := range tlsBlocks {
		if sha256Hex(b.cert.RawSubjectPublicKeyInfo) == m.key.SPKISHA256 {
			listed = b
		}
	}
	served = tlsBlocks[0]
	if listed.path == "" {
		t.Fatal("no fixture certificate carries the leaf's issuer key")
	}

	// A bundle that holds the certificates the hash commands are run on after
	// other certificates, so that LINE is not 1.
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.pem")
	var data []byte
	lineOf := map[string]int{}
	line := 1
	for _, b := range []fixtureBlock{control[0], served, leaf, root} {
		lineOf[b.path] = line + b.index
		data = append(data, strings.Join(b.lines, "\n")+"\n"...)
		line += len(b.lines)
	}
	if err := os.WriteFile(bundle, data, 0o644); err != nil {
		t.Fatal(err)
	}
	lineEnv := func(b fixtureBlock) []string {
		return []string{"FILE=" + bundle, "LINE=" + strconv.Itoa(lineOf[b.path])}
	}
	abs := func(p string) string {
		a, err := filepath.Abs(p)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	// The TLS servers: a generated certificate, whose key the test holds,
	// followed by a listed intermediate for the first page and by the removed
	// root for the second.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverDER, serverCert := generatedCert(t, 9, &key.PublicKey, key, false, nil)
	serverSPKI := sha256Hex(serverCert.RawSubjectPublicKeyInfo)

	// Every case runs: each under every openssl, or under OpenSSL only.
	declared, ran := map[string]bool{}, map[string]bool{}
	anyOpenSSL := false
	for _, p := range trustPages {
		chain := [][]byte{serverDER, served.der}
		next := served
		if p.status == trustStatusDistrusted {
			chain = [][]byte{serverDER, root.der}
			next = root
		}
		servedWant := "served-1.pem " + serverSPKI + "\nserved-2.pem " + sha256Hex(next.cert.RawSubjectPublicKeyInfo) + "\n"
		for _, host := range []string{"127.0.0.1", "::1"} {
			port, ok := serveChain(t, net.JoinHostPort(host, "0"), chain, key)
			if !ok {
				if host == "127.0.0.1" {
					t.Fatal("cannot listen on 127.0.0.1")
				}
				continue
			}
			blocks := shBlock.FindAllStringSubmatch(readPage(t, p.file), -1)
			if len(blocks) == 0 {
				t.Fatalf("%s has no command block", p.file)
			}
			for _, bin := range bins {
				libre := isLibreSSL(t, bin)
				// OpenSSL takes an IPv6 address in brackets and LibreSSL without
				// them, as the pages say.
				server := net.JoinHostPort(host, port)
				if libre && strings.Contains(host, ":") {
					server = host + ":" + port
				}
				cases := map[string]pageCase{
					"# Rule 1: print the certificate's SPKI hash":                              {env: lineEnv(served), want: sha256Hex(served.cert.RawSubjectPublicKeyInfo)},
					"# Rule 2: print the certificate's SHA-256":                                {env: lineEnv(leaf), want: sha256Hex(leaf.der)},
					"# Rule 2: confirm that the listed key signed the certificate (OpenSSL)":   {env: append(lineEnv(leaf), "LISTED="+abs(listed.path)), want: "flagged.pem: OK\n", opensslOnly: true},
					"# Rule 3: print the certificate's SPKI hash":                              {env: lineEnv(root), want: sha256Hex(root.cert.RawSubjectPublicKeyInfo)},
					"# Rule 4: print the certificate's SHA-256":                                {env: lineEnv(root), want: sha256Hex(root.der)},
					"# Rule 4: confirm that the root's key signed the certificate (OpenSSL)":   {env: append(lineEnv(root), "ROOT="+abs(root.path)), want: "flagged.pem: OK\n", opensslOnly: true},
					"# Save the certificates the server sends and print the SPKI hash of each": {env: []string{"SERVER=" + server, "NAME=localhost"}, want: servedWant},
					"# Check the last certificate the server sends against the root (OpenSSL)": {env: []string{"ROOT=" + abs(root.path)}, want: "served-2.pem: OK\n", opensslOnly: true},
				}
				for name, c := range cases {
					declared[name] = c.opensslOnly
				}
				anyOpenSSL = anyOpenSSL || !libre
				work := t.TempDir()
				for _, b := range blocks {
					first, _, _ := strings.Cut(b[1], "\n")
					c, ok := cases[first]
					if !ok {
						t.Errorf("%s: no test case for the block starting %q", p.file, first)
						continue
					}
					if c.opensslOnly && libre {
						continue
					}
					if got := runPageCommand(t, bin, work, b[1], c.env); string(got) != c.want {
						t.Errorf("%s, %s, server on %s: block %q printed %q, want %q", p.file, bin, host, first, got, c.want)
					}
					ran[first] = true
				}
			}
		}
	}
	for name, opensslOnly := range declared {
		if !ran[name] && (anyOpenSSL || !opensslOnly) {
			t.Errorf("no page has the block starting %q", name)
		}
	}
}
