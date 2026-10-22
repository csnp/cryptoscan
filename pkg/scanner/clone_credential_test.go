// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// The credential the test servers ask for. Both values are placeholders.
const (
	cloneUser     = "FAKE-USER"
	clonePassword = "FAKE-PASSWORD-1234"
)

// authRecorder counts the requests a test server received and those of them
// that carried an Authorization header.
type authRecorder struct {
	requests      atomic.Int32
	authorization atomic.Int32
}

// requireBasicAuth serves next to a request that carries cloneUser and
// clonePassword and answers any other request with 401, counting each
// request in rec.
func requireBasicAuth(next http.Handler, rec *authRecorder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.requests.Add(1)
		if r.Header.Get("Authorization") != "" {
			rec.authorization.Add(1)
		}
		if user, password, ok := r.BasicAuth(); !ok || user != cloneUser || password != clonePassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="cryptoscan test"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isolateCloneGit leaves the clones of the rest of the test to git and the
// test alone: no git configuration of the machine, no proxy, no askpass
// program, no prompt, and no credential in the environment.
func isolateCloneGit(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_COUNT", "0")
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
	for _, name := range []string{
		"GIT_ASKPASS", "SSH_ASKPASS", EnvGitUsername, EnvGitPassword,
		"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
	} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

// trustServer has git trust the certificate of server, an httptest TLS
// server, for the rest of the test.
func trustServer(t *testing.T, server *httptest.Server) {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "server.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}
	if err := os.WriteFile(ca, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSL_CAINFO", ca)
}

// credentialRepository returns a handler that serves a repository holding
// one MD5 call over smart HTTP at /repo.git.
func credentialRepository(t *testing.T) http.Handler {
	t.Helper()
	work := t.TempDir()
	writeTestFile(t, work, "hash.go",
		"package main\n\nimport \"crypto/md5\"\n\nfunc Sum(b []byte) [16]byte { return md5.Sum(b) }\n")
	return gitBackend(t, work)
}

// cloneOnce clones target the way a URL scan does and removes the clone.
func cloneOnce(target string) error {
	s := New(Config{Target: target})
	defer s.Cleanup()
	_, err := s.cloneRepository(target)
	return err
}

// A repository at an https URL that asks for a password is cloned with the
// user name and password in CRYPTOSCAN_GIT_USERNAME and
// CRYPTOSCAN_GIT_PASSWORD, so neither has to be written into the URL. The
// clone's .git/config holds neither value, and no credential helper either.
func TestURLCloneTakesItsCredentialFromTheEnvironment(t *testing.T) {
	backend := credentialRepository(t)
	isolateCloneGit(t)
	var rec authRecorder
	server := httptest.NewTLSServer(requireBasicAuth(backend, &rec))
	t.Cleanup(server.Close)
	trustServer(t, server)
	target := server.URL + "/repo.git"

	if err := cloneOnce(target); !errors.Is(err, ErrCloneFailed) {
		t.Fatalf("clone with no credential: err = %v, want ErrCloneFailed; the server must ask for a password", err)
	}

	t.Setenv(EnvGitUsername, cloneUser)
	t.Setenv(EnvGitPassword, clonePassword)

	s := New(Config{Target: target})
	t.Cleanup(s.Cleanup)
	dir, err := s.cloneRepository(target)
	if err != nil {
		t.Fatalf("clone with the credential in the environment: %v", err)
	}
	config, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{cloneUser, clonePassword, "credential", "helper"} {
		if strings.Contains(string(config), part) {
			t.Errorf("the clone's .git/config holds %q:\n%s", part, config)
		}
	}
	if !strings.Contains(string(config), "url = "+target+"\n") {
		t.Errorf("the clone's .git/config does not give the remote as %s:\n%s", target, config)
	}

	results := scanWithConfig(t, Config{Target: target})
	if len(results.Findings) == 0 {
		t.Error("a scan of the URL with the credential in the environment found nothing; the repository holds an MD5 call")
	}
}

// A credential helper in the user's own git configuration gives the clone
// its credential when CRYPTOSCAN_GIT_PASSWORD is not set, so the URL needs
// none. When the variable is set, no helper of the user's system or global
// git configuration is run for the clone: none supplies a credential or is
// asked to save this one.
func TestURLCloneRunsTheUsersCredentialHelperUnlessTheEnvironmentGivesOne(t *testing.T) {
	backend := credentialRepository(t)
	isolateCloneGit(t)
	var rec authRecorder
	server := httptest.NewTLSServer(requireBasicAuth(backend, &rec))
	t.Cleanup(server.Close)
	trustServer(t, server)
	target := server.URL + "/repo.git"

	// Each of the user's helpers records the operations it is run for and
	// answers "get" with the credential the server asks for.
	home := t.TempDir()
	calls := filepath.Join(home, "helper-calls")
	for _, level := range []string{"system", "global"} {
		helper := `!f() { echo "` + level + ` $1" >> '` + calls + `'; test "$1" = get || return 0; ` +
			`echo username=` + cloneUser + `; echo password=` + clonePassword + `; }; f`
		file := filepath.Join(home, level+".gitconfig")
		runGit(t, home, "config", "--file", file, "credential.helper", helper)
		t.Setenv("GIT_CONFIG_"+strings.ToUpper(level), file)
	}
	t.Setenv("GIT_CONFIG_NOSYSTEM", "")
	if err := os.Unsetenv("GIT_CONFIG_NOSYSTEM"); err != nil {
		t.Fatal(err)
	}

	if err := cloneOnce(target); err != nil {
		t.Fatalf("clone with the credential from the user's helper: %v", err)
	}
	// git asks the system helper first, and it answers.
	if data, err := os.ReadFile(calls); err != nil || !strings.Contains(string(data), "system get") {
		t.Fatalf("the helper in the system configuration was not asked for the credential (%v): %q", err, data)
	}
	if err := os.Remove(calls); err != nil {
		t.Fatal(err)
	}

	t.Setenv(EnvGitUsername, cloneUser)
	t.Setenv(EnvGitPassword, clonePassword)
	if err := cloneOnce(target); err != nil {
		t.Fatalf("clone with the credential in the environment: %v", err)
	}
	if data, err := os.ReadFile(calls); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the user's helper was run for the clone (%v): %q", err, data)
	}
}

// The password in CRYPTOSCAN_GIT_PASSWORD is offered to the host in the URL
// alone. A host the URL's host redirects the clone to, here the same address
// on another port, asks for a password and is not given it.
func TestURLCloneOffersTheEnvironmentPasswordToNoOtherHost(t *testing.T) {
	backend := credentialRepository(t)
	isolateCloneGit(t)
	var rec authRecorder
	other := httptest.NewTLSServer(requireBasicAuth(backend, &rec))
	t.Cleanup(other.Close)
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	trustServer(t, other)
	t.Setenv(EnvGitUsername, cloneUser)
	t.Setenv(EnvGitPassword, clonePassword)

	// The variables open the other host when it is the one in the URL, so a
	// refusal below is the redirect's doing.
	if err := cloneOnce(other.URL + "/repo.git"); err != nil {
		t.Fatalf("clone of the other host with the credential in the environment: %v", err)
	}
	rec.requests.Store(0)
	rec.authorization.Store(0)

	if err := cloneOnce(redirect.URL + "/repo.git"); !errors.Is(err, ErrCloneFailed) {
		t.Errorf("clone through the redirect: err = %v, want ErrCloneFailed", err)
	}
	if rec.requests.Load() == 0 {
		t.Fatal("git did not follow the redirect, so this test checked nothing")
	}
	if n := rec.authorization.Load(); n != 0 {
		t.Errorf("the host the redirect led to received %d requests with an Authorization header, want 0", n)
	}
}

// The helper is set for the URL's host in the name of a git configuration
// key, and git ends that name at the first "=" of a -c option: for the host
// h.helper=x.example, git would read the first option as a helper setting for
// https://h. The options are given only for a host name of ASCII letters,
// digits, dots and dashes or an IPv6 address in brackets with no zone, with or
// without a port number. For any other host there are none, as for an http
// URL.
func TestURLCloneSetsTheEnvironmentHelperOnlyForAHostNameOrIPv6Address(t *testing.T) {
	t.Setenv(EnvGitPassword, clonePassword)

	for _, host := range []string{
		"git.example.com",
		"Git-1.Example.COM:8443",
		"127.0.0.1:1",
		"[::1]",
		"[2001:db8::1]:8443",
		"[::ffff:192.0.2.1]",
	} {
		target := "https://" + host + "/team/app.git"
		key := "credential.https://" + host + ".helper"
		want := []string{"-c", key + "=", "-c", key + "=" + gitCredentialHelper}
		if got := cloneCredentialArgs(target); !slices.Equal(got, want) {
			t.Errorf("cloneCredentialArgs(%q) = %q, want %q", target, got, want)
		}
	}

	for _, host := range []string{
		"a=b.example",
		"h.helper=x.example",
		"git_server",
		"a;b.example",
		"a'b.example",
		"exämple.com",
		":443",
		"git.example.com:",
		"[::1%25en0]",
		"[::1%25a=b]:1",
		"[::1]:",
	} {
		target := "https://" + host + "/team/app.git"
		if u, err := url.Parse(target); err != nil || u.Host == "" {
			t.Errorf("url.Parse(%q) gives no host (%v), so this case does not check the host rule", target, err)
			continue
		}
		if got := cloneCredentialArgs(target); got != nil {
			t.Errorf("cloneCredentialArgs(%q) = %q, want no options", target, got)
		}
	}

	// url.Parse in Go 1.26 refuses these bracketed hosts, which are not IPv6
	// addresses, before the rule is reached, so the rule is checked on them
	// directly.
	for _, host := range []string{"[192.0.2.1]", "[1:2:3]"} {
		if isCredentialHost(host) {
			t.Errorf("isCredentialHost(%q) = true, want false", host)
		}
	}
}

// Over an http URL the connection is not encrypted, and the password in
// CRYPTOSCAN_GIT_PASSWORD is not sent.
func TestURLCloneSendsTheEnvironmentPasswordOnlyOverHTTPS(t *testing.T) {
	backend := credentialRepository(t)
	isolateCloneGit(t)
	var rec authRecorder
	server := httptest.NewServer(requireBasicAuth(backend, &rec))
	t.Cleanup(server.Close)
	t.Setenv(EnvGitUsername, cloneUser)
	t.Setenv(EnvGitPassword, clonePassword)

	if err := cloneOnce(server.URL + "/repo.git"); !errors.Is(err, ErrCloneFailed) {
		t.Errorf("clone over http: err = %v, want ErrCloneFailed", err)
	}
	if rec.requests.Load() == 0 {
		t.Fatal("git sent no request, so this test checked nothing")
	}
	if n := rec.authorization.Load(); n != 0 {
		t.Errorf("the http server received %d requests with an Authorization header, want 0", n)
	}
}
