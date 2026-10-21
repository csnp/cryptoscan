// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// runGit runs git in dir and fails the test if it does not succeed.
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// serveGitRepository commits the files in work to a new repository and serves
// it over smart HTTP on the loopback interface, so that a URL scan can clone
// it without a network. It returns the repository's URL.
func serveGitRepository(t *testing.T, work string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	// The user's own git configuration must not change the commit or the
	// clone (a signing requirement, a URL rewrite).
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	backend := filepath.Join(runGit(t, work, "--exec-path"), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("git-http-backend is not installed: %v", err)
	}

	runGit(t, work, "init", "-q")
	runGit(t, work, "add", ".")
	runGit(t, work, "-c", "user.name=CryptoScan Test", "-c", "user.email=test@example.invalid",
		"commit", "-q", "-m", "fixture")

	served := t.TempDir()
	runGit(t, served, "clone", "-q", "--bare", work, "repo.git")

	server := httptest.NewServer(&cgi.Handler{
		Path: backend,
		Env:  []string{"GIT_PROJECT_ROOT=" + served, "GIT_HTTP_EXPORT_ALL=1"},
	})
	t.Cleanup(server.Close)
	return server.URL + "/repo.git"
}

// A URL scan clones the repository into a temporary directory and removes it
// when the scan ends. The report used to give each path inside that
// directory, as in /var/folders/.../T/cryptoscan-261244270/paramiko/pkey.py,
// a file that no longer exists. It now gives each path relative to the
// repository root, and finds the same things a scan of a checkout finds.
func TestURLScanReportsPathsRelativeToRepositoryRoot(t *testing.T) {
	work := t.TempDir()
	for _, dir := range []string{"src", "tests", "web"} {
		if err := os.Mkdir(filepath.Join(work, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, work, "src/hash.go",
		"package src\n\nimport \"crypto/md5\"\n\nfunc Sum(b []byte) [16]byte { return md5.Sum(b) }\n")
	writeTestFile(t, work, "tests/test_keys.py",
		"from cryptography.hazmat.primitives.asymmetric import rsa\n\n"+
			"key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
	writeTestFile(t, work, "web/bundle.js", bundledLine()+"\n")
	// The comma after the last dependency leaves the manifest undecodable.
	writeTestFile(t, work, "web/package.json",
		"{\n  \"dependencies\": {\n    \"crypto-js\": \"^4.2.0\",\n  }\n}\n")

	url := serveGitRepository(t, work)

	// The clone goes under TMPDIR, so no report path may start with it.
	cloneParent := t.TempDir()
	t.Setenv("TMPDIR", cloneParent)

	var mu sync.Mutex
	var streamed, progressed []string
	results := scanWithConfig(t, Config{
		Target: url,
		OnFinding: func(f Finding) {
			mu.Lock()
			streamed = append(streamed, f.File)
			mu.Unlock()
		},
		OnFileScanned: func(path string) {
			mu.Lock()
			progressed = append(progressed, path)
			mu.Unlock()
		},
	})
	local := scanWithConfig(t, Config{Target: work})

	rel := func(path string) string {
		r, err := filepath.Rel(work, path)
		if err != nil {
			t.Fatalf("%s is not under %s: %v", path, work, err)
		}
		return filepath.ToSlash(r)
	}

	if len(local.Findings) == 0 {
		t.Fatal("the fixture gave no findings; the test needs at least one")
	}
	if len(results.Findings) != len(local.Findings) {
		t.Fatalf("URL scan: %d findings, local scan of the same files: %d", len(results.Findings), len(local.Findings))
	}
	reported := make(map[string]bool)
	for i, f := range results.Findings {
		want := rel(local.Findings[i].File)
		if f.File != want || f.Line != local.Findings[i].Line || f.ID != local.Findings[i].ID {
			t.Errorf("finding %d: got %s:%d %s, want %s:%d %s",
				i, f.File, f.Line, f.ID, want, local.Findings[i].Line, local.Findings[i].ID)
		}
		reported[f.File] = true
	}

	if len(streamed) == 0 {
		t.Error("no finding was streamed")
	}
	for _, file := range streamed {
		if filepath.IsAbs(file) || !reported[file] {
			t.Errorf("streamed finding path %q is not a path the report gives", file)
		}
	}
	for _, path := range progressed {
		if filepath.IsAbs(path) {
			t.Errorf("progress path %q is absolute, want it relative to the repository root", path)
		}
	}

	if len(local.SkippedFiles) != 1 || len(local.UnanalyzedFiles) != 1 {
		t.Fatalf("the local scan should skip one file and leave one unanalyzed, got %+v and %+v",
			local.SkippedFiles, local.UnanalyzedFiles)
	}
	wantSkipped := SkippedFile{File: "web/bundle.js", Reason: local.SkippedFiles[0].Reason}
	if len(results.SkippedFiles) != 1 || results.SkippedFiles[0] != wantSkipped {
		t.Errorf("SkippedFiles = %+v, want [%+v]", results.SkippedFiles, wantSkipped)
	}
	wantUnanalyzed := local.UnanalyzedFiles[0]
	wantUnanalyzed.File = "web/package.json"
	if len(results.UnanalyzedFiles) != 1 || results.UnanalyzedFiles[0] != wantUnanalyzed {
		t.Errorf("UnanalyzedFiles = %+v, want [%+v]", results.UnanalyzedFiles, wantUnanalyzed)
	}

	got, want := results.MigrationScore, local.MigrationScore
	if got.Score != want.Score || got.TestDirectoryFindings != want.TestDirectoryFindings {
		t.Errorf("migration score %v with %d test-directory findings, want %v with %d as for a local scan",
			got.Score, got.TestDirectoryFindings, want.Score, want.TestDirectoryFindings)
	}
	if want.TestDirectoryFindings == 0 {
		t.Error("the fixture has no finding under tests/; the score check needs one")
	}
	if len(got.TopRiskFiles) != len(want.TopRiskFiles) {
		t.Fatalf("TopRiskFiles = %+v, want %d entries", got.TopRiskFiles, len(want.TopRiskFiles))
	}
	for i := range got.TopRiskFiles {
		if w := rel(want.TopRiskFiles[i].File); got.TopRiskFiles[i].File != w {
			t.Errorf("TopRiskFiles[%d].File = %q, want %q", i, got.TopRiskFiles[i].File, w)
		}
	}

	if root, ok := results.Metadata[MetadataScanRoot]; ok {
		t.Errorf("metadata %s = %q; a URL scan's paths are relative, so it records no root", MetadataScanRoot, root)
	}
	if results.ScanRoot != "" {
		t.Errorf("ScanRoot = %q, want empty for paths relative to the repository root", results.ScanRoot)
	}

	data, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), cloneParent); n > 0 {
		t.Errorf("the JSON report names the removed clone under %s %d times", cloneParent, n)
	}
	if verify := results.Findings[0].Verify; verify != "sed -n '5p' src/hash.go" {
		t.Errorf("first finding's verify command = %q, want it to print src/hash.go line 5 from the repository root", verify)
	}
	entries, err := os.ReadDir(cloneParent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the clone was not removed: %s holds %d entries", cloneParent, len(entries))
	}
}
