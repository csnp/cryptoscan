// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// moduleRoot is the repository root, where go.mod sits.
const moduleRoot = "../.."

// gofmtProblems formats each .go file under root with go/format.Source, which
// applies canonical gofmt style, and returns one message per file that does not
// parse or whose content differs from the formatted result, along with the
// number of files it checked. It skips directories named testdata and
// directories whose names begin with "." or "_", which the go tool ignores, and
// vendor directories, which hold code from other modules. The root itself is
// walked whatever its name, since a root such as ".." begins with a dot.
func gofmtProblems(root string) (problems []string, files int, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") ||
				name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(name) != ".go" {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++

		formatted, err := format.Source(src)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: gofmt cannot parse the file: %v", rel, err))
			return nil
		}
		if !bytes.Equal(src, formatted) {
			problems = append(problems, fmt.Sprintf(
				"%s:%d: not gofmt-formatted (first change on this line); from the repository root, gofmt -d %s shows the change and gofmt -w %s applies it",
				rel, firstChangedLine(src, formatted), rel, rel))
		}
		return nil
	})
	return problems, files, err
}

// firstChangedLine returns the 1-based number of the line in src that holds
// the first byte where src and formatted differ.
func firstChangedLine(src, formatted []byte) int {
	i := 0
	for i < len(src) && i < len(formatted) && src[i] == formatted[i] {
		i++
	}
	return bytes.Count(src[:i], []byte("\n")) + 1
}

func TestGoFilesAreGofmtFormatted(t *testing.T) {
	problems, files, err := gofmtProblems(moduleRoot)
	if err != nil {
		t.Fatalf("walk %s: %v", moduleRoot, err)
	}
	if files == 0 {
		t.Fatalf("found no .go files under %s, so this test checked nothing", moduleRoot)
	}
	t.Logf("checked %d .go files under %s", files, moduleRoot)
	for _, problem := range problems {
		t.Error(problem)
	}
}

func TestGofmtProblems(t *testing.T) {
	const (
		formatted = "package p\n\nvar rows = []string{\n\t\"a\",\n\t\"b\",\n}\n"
		// Two rows on one line, separated by two tabs: gofmt puts one space
		// between them.
		twoRowsOnOneLine = "package p\n\nvar rows = []string{\n\t\"a\",\t\t\"b\",\n}\n"
	)

	tests := []struct {
		name    string
		files   map[string]string // content by slash-separated path under the root
		checked int
		problem string // text the one expected problem contains; empty when none is expected
	}{
		{
			name:    "formatted file",
			files:   map[string]string{"a.go": formatted},
			checked: 1,
		},
		{
			name:    "two rows on one line",
			files:   map[string]string{"pkg/a_test.go": twoRowsOnOneLine},
			checked: 1,
			problem: "pkg/a_test.go:4: not gofmt-formatted",
		},
		{
			name:    "no newline at the end of the file",
			files:   map[string]string{"a.go": strings.TrimSuffix(formatted, "\n")},
			checked: 1,
			problem: "a.go:6: not gofmt-formatted",
		},
		{
			name:    "file that does not parse",
			files:   map[string]string{"a.go": "package p\n\nfunc {\n"},
			checked: 1,
			problem: "a.go: gofmt cannot parse the file",
		},
		{
			name: "directories the check skips",
			files: map[string]string{
				"a.go":          formatted,
				"testdata/b.go": twoRowsOnOneLine,
				"vendor/c.go":   twoRowsOnOneLine,
				".hidden/d.go":  twoRowsOnOneLine,
				"_scratch/e.go": twoRowsOnOneLine,
			},
			checked: 1,
		},
		{
			name:    "file that is not Go",
			files:   map[string]string{"notes.txt": twoRowsOnOneLine},
			checked: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The root's own name begins with a dot, as the ".." of moduleRoot
			// does, and the root is still walked.
			root := filepath.Join(t.TempDir(), ".checkout")
			for path, content := range tt.files {
				full := filepath.Join(root, filepath.FromSlash(path))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			problems, checked, err := gofmtProblems(root)
			if err != nil {
				t.Fatalf("gofmtProblems(%s): %v", root, err)
			}
			if checked != tt.checked {
				t.Errorf("checked %d files, want %d", checked, tt.checked)
			}
			if tt.problem == "" {
				if len(problems) != 0 {
					t.Errorf("got problems %q, want none", problems)
				}
				return
			}
			if len(problems) != 1 || !strings.Contains(problems[0], tt.problem) {
				t.Errorf("got problems %q, want one containing %q", problems, tt.problem)
			}
		})
	}
}
