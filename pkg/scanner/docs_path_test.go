// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// md5Source is one line of operational crypto that every scan below should
// report wherever the scan root happens to live on disk.
const md5Source = "import hashlib\nh = hashlib.md5(b\"a\")\n"

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func scanTarget(t *testing.T, target string) *Results {
	t.Helper()
	s := New(Config{Target: target, MinSeverity: SeverityInfo})
	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan(%s) failed: %v", target, err)
	}
	return results
}

func md5Findings(results *Results) []Finding {
	var out []Finding
	for _, f := range results.Findings {
		if f.Algorithm == "MD5" {
			out = append(out, f)
		}
	}
	return out
}

// TestScanRootLocationDoesNotChangeTheReport scans the same file from roots
// whose own path, or a directory above them, carries a name the filters treat
// as documentation, tests, vendored or generated code. Those directories are
// outside what the user asked to scan, so each scan must read the file and
// report the same finding as a scan from an ordinary directory.
func TestScanRootLocationDoesNotChangeTheReport(t *testing.T) {
	controlRoot := filepath.Join(t.TempDir(), "plain", "project")
	writeFixture(t, filepath.Join(controlRoot, "a.py"), md5Source)
	control := scanTarget(t, controlRoot)
	controlMD5 := md5Findings(control)
	if control.FilesScanned != 1 || len(controlMD5) != 1 {
		t.Fatalf("control scan: filesScanned=%d md5Findings=%d, want 1 and 1",
			control.FilesScanned, len(controlMD5))
	}
	want := controlMD5[0]

	roots := []string{
		// Documentation names, including every row measured on 1.4.0.
		"docs/project",
		"DOCS/project",
		"project/docs",
		"doc/project",
		"documentation/project",
		"wiki/project",
		"my-docs/project",
		"api-docs/project",
		"api_docs/project",
		"user-documentation/project",
		"docsy/project",
		"Documents/project",
		"target/apidocs/project",
		"target/site/project",
		// Directory names the walker skips inside a scan.
		"build/project",
		"dist/project",
		"bin/project",
		"project/build",
		"project/examples",
		// Names that lower a finding's severity or confidence.
		"test/project",
		"vendor/project",
		"lib/project",
		"generated/project",
	}
	for _, rel := range roots {
		t.Run(rel, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), filepath.FromSlash(rel))
			writeFixture(t, filepath.Join(root, "a.py"), md5Source)

			results := scanTarget(t, root)
			got := md5Findings(results)
			if results.FilesScanned != 1 || len(got) != 1 {
				t.Fatalf("filesScanned=%d md5Findings=%d, want 1 and 1",
					results.FilesScanned, len(got))
			}
			f := got[0]
			if f.FileType != want.FileType || f.Severity != want.Severity || f.Confidence != want.Confidence {
				t.Errorf("finding classified as fileType=%s severity=%s confidence=%s, want %s %s %s as in the control scan",
					f.FileType, f.Severity, f.Confidence, want.FileType, want.Severity, want.Confidence)
			}
		})
	}
}

// TestSingleFileTargetUnderDocsDirectoryIsScanned covers a target that is one
// file rather than a directory. The directories above it are not part of the
// target either.
func TestSingleFileTargetUnderDocsDirectoryIsScanned(t *testing.T) {
	target := filepath.Join(t.TempDir(), "docs", "project", "a.py")
	writeFixture(t, target, md5Source)

	results := scanTarget(t, target)
	if results.FilesScanned != 1 || len(md5Findings(results)) != 1 {
		t.Fatalf("filesScanned=%d md5Findings=%d, want 1 and 1",
			results.FilesScanned, len(md5Findings(results)))
	}
}

// TestRelativeTargetMatchesAbsoluteTarget checks that the result depends on
// the tree being scanned and not on how its path was written. Tested against
// the walked path, "." kept a top-level docs/ directory in the scan while the
// absolute path of the same tree left it out.
func TestRelativeTargetMatchesAbsoluteTarget(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "a.py"), md5Source)
	writeFixture(t, filepath.Join(root, "docs", "guide.py"), md5Source)

	absolute := scanTarget(t, root)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Errorf("restoring working directory: %v", err)
		}
	})
	relative := scanTarget(t, ".")

	if absolute.FilesScanned != 1 || len(md5Findings(absolute)) != 1 {
		t.Errorf("absolute target: filesScanned=%d md5Findings=%d, want 1 and 1",
			absolute.FilesScanned, len(md5Findings(absolute)))
	}
	if relative.FilesScanned != absolute.FilesScanned || len(md5Findings(relative)) != len(md5Findings(absolute)) {
		t.Errorf("relative target: filesScanned=%d md5Findings=%d, want %d and %d as for the absolute target",
			relative.FilesScanned, len(md5Findings(relative)),
			absolute.FilesScanned, len(md5Findings(absolute)))
	}
}

// TestDocumentationInsideScanRootIsStillSkipped is the mirror case: the same
// names inside the scan root keep their purpose.
func TestDocumentationInsideScanRootIsStillSkipped(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "a.py"), md5Source)
	writeFixture(t, filepath.Join(root, "docs", "readme.py"), md5Source)
	writeFixture(t, filepath.Join(root, "docs", "guide.py"), md5Source)
	writeFixture(t, filepath.Join(root, "Documentation", "guide.py"), md5Source)
	writeFixture(t, filepath.Join(root, "api-docs", "b.py"), md5Source)
	writeFixture(t, filepath.Join(root, "build", "c.py"), md5Source)
	writeFixture(t, filepath.Join(root, "test", "t.py"), md5Source)

	results := scanTarget(t, root)

	// a.py, api-docs/b.py and test/t.py are read. The docs directories are
	// left out of discovery and build/ is never walked.
	if results.FilesScanned != 3 {
		t.Errorf("filesScanned=%d, want 3", results.FilesScanned)
	}

	byFile := map[string]Finding{}
	for _, f := range md5Findings(results) {
		rel, err := filepath.Rel(root, f.File)
		if err != nil {
			t.Fatalf("finding path %s is outside the scan root: %v", f.File, err)
		}
		byFile[filepath.ToSlash(rel)] = f
	}
	if _, ok := byFile["a.py"]; !ok {
		t.Errorf("a.py: missing MD5 finding")
	}
	for _, skipped := range []string{"docs/readme.py", "docs/guide.py", "Documentation/guide.py", "api-docs/b.py", "build/c.py"} {
		if _, ok := byFile[skipped]; ok {
			t.Errorf("%s: reported, want it left out as documentation or build output", skipped)
		}
	}
	if f, ok := byFile["test/t.py"]; !ok {
		t.Errorf("test/t.py: missing MD5 finding")
	} else if f.FileType != "test" {
		t.Errorf("test/t.py: fileType=%s, want test", f.FileType)
	}
}
