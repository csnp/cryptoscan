// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// requirement is one module named in a require directive of go.mod.
type requirement struct {
	path     string
	line     int  // 1-based line in go.mod
	indirect bool // marked // indirect
}

// parseRequirements returns the modules goMod requires, from both the
// one-line form of the require directive and the block form.
func parseRequirements(goMod string) []requirement {
	var reqs []requirement
	inBlock := false
	for i, line := range strings.Split(goMod, "\n") {
		code, comment, _ := strings.Cut(line, "//")
		fields := strings.Fields(code)
		switch {
		case inBlock && len(fields) == 1 && fields[0] == ")":
			inBlock = false
			continue
		case inBlock:
		case len(fields) == 2 && fields[0] == "require" && fields[1] == "(":
			inBlock = true
			continue
		case len(fields) == 3 && fields[0] == "require":
			fields = fields[1:]
		default:
			continue
		}
		if len(fields) != 2 {
			continue
		}
		comment = strings.TrimSpace(comment)
		reqs = append(reqs, requirement{
			path:     fields[0],
			line:     i + 1,
			indirect: comment == "indirect" || strings.HasPrefix(comment, "indirect;"),
		})
	}
	return reqs
}

// tidyReads reports whether go mod tidy reads a file whose build constraint
// is expr. Tidy treats every build tag except ignore as both set and unset, so
// a file is left out only when its constraint needs ignore to be set. want is
// the value the enclosing expression needs expr to have.
func tidyReads(expr constraint.Expr, want bool) bool {
	switch e := expr.(type) {
	case *constraint.TagExpr:
		if e.Tag == "ignore" {
			return false
		}
		return want
	case *constraint.NotExpr:
		return !tidyReads(e.X, !want)
	case *constraint.AndExpr:
		return tidyReads(e.X, want) && tidyReads(e.Y, want)
	case *constraint.OrExpr:
		return tidyReads(e.X, want) || tidyReads(e.Y, want)
	}
	return true
}

// moduleImports maps each path imported by a .go file under root that go mod
// tidy reads to the first such file, slash-separated and relative to root. It
// skips the directories gofmtProblems skips.
func moduleImports(root string) (map[string]string, error) {
	imports := make(map[string]string)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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

		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.ParseComments)
		if err != nil {
			return err
		}
		// A build constraint is a //go:build line above the package clause.
		for _, group := range f.Comments {
			if group.End() >= f.Package {
				break
			}
			for _, c := range group.List {
				if !constraint.IsGoBuild(c.Text) {
					continue
				}
				expr, err := constraint.Parse(c.Text)
				if err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
				if !tidyReads(expr, true) {
					return nil
				}
			}
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, spec := range f.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return fmt.Errorf("%s: import %s: %w", path, spec.Path.Value, err)
			}
			if _, seen := imports[p]; !seen {
				imports[p] = filepath.ToSlash(rel)
			}
		}
		return nil
	})
	return imports, err
}

// providingModule returns the required module whose path is the longest
// prefix of the package path p, or "" when no required module provides p.
func providingModule(reqs []requirement, p string) string {
	best := ""
	for _, r := range reqs {
		if (p == r.path || strings.HasPrefix(p, r.path+"/")) && len(r.path) > len(best) {
			best = r.path
		}
	}
	return best
}

// goModProblems returns one message per requirement whose // indirect marking
// differs from the one go mod tidy writes. Tidy lists a module that provides a
// package imported by this module, tests included, as a direct requirement,
// and marks every other module it keeps // indirect. imports maps each
// imported path to a file that imports it.
func goModProblems(reqs []requirement, imports map[string]string) []string {
	importer := make(map[string]string) // module path to the first file importing a package it provides
	for p, file := range imports {
		mod := providingModule(reqs, p)
		if mod == "" {
			continue
		}
		if first, ok := importer[mod]; !ok || file < first {
			importer[mod] = file
		}
	}

	var problems []string
	for _, r := range reqs {
		file, imported := importer[r.path]
		switch {
		case imported && r.indirect:
			problems = append(problems, fmt.Sprintf(
				"go.mod:%d: %s is marked // indirect, but %s imports it; from the repository root, go mod tidy moves it to the direct requirements",
				r.line, r.path, file))
		case !imported && !r.indirect:
			problems = append(problems, fmt.Sprintf(
				"go.mod:%d: %s is a direct requirement, but no .go file imports it; from the repository root, go mod tidy marks it // indirect or removes it",
				r.line, r.path))
		}
	}
	return problems
}

// TestGoModMarksDirectRequirements fails when go.mod differs from what go mod
// tidy writes in which requirements are direct. The release build runs go mod
// tidy before building, so such a go.mod is rewritten during the release.
func TestGoModMarksDirectRequirements(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	reqs := parseRequirements(string(data))
	if len(reqs) == 0 {
		t.Fatal("found no requirements in go.mod, so this test checked nothing")
	}
	imports, err := moduleImports(moduleRoot)
	if err != nil {
		t.Fatalf("read imports under %s: %v", moduleRoot, err)
	}
	t.Logf("checked %d requirements against %d imported paths", len(reqs), len(imports))
	for _, problem := range goModProblems(reqs, imports) {
		t.Error(problem)
	}
}

func TestGoModProblems(t *testing.T) {
	const header = "module example.com/m\n\ngo 1.21\n\n"

	tests := []struct {
		name     string
		goMod    string            // go.mod after header
		files    map[string]string // content by slash-separated path under the root
		problems []string          // text each expected problem contains, in go.mod order
	}{
		{
			name:  "tidy",
			goMod: "require (\n\texample.com/a v1.0.0\n)\n\nrequire example.com/b v1.0.0 // indirect\n",
			files: map[string]string{"a.go": "package m\n\nimport _ \"example.com/a/sub\"\n"},
		},
		{
			name:     "module imported by a test file is marked indirect",
			goMod:    "require (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0 // indirect\n)\n",
			files:    map[string]string{"a.go": "package m\n\nimport _ \"example.com/a\"\n", "pkg/b_test.go": "package pkg\n\nimport _ \"example.com/b\"\n"},
			problems: []string{"go.mod:7: example.com/b is marked // indirect, but pkg/b_test.go imports it"},
		},
		{
			name:     "one-line require directive",
			goMod:    "require example.com/a v1.0.0 // indirect\n",
			files:    map[string]string{"a.go": "package m\n\nimport _ \"example.com/a\"\n"},
			problems: []string{"go.mod:5: example.com/a is marked // indirect, but a.go imports it"},
		},
		{
			name:     "direct requirement that nothing imports",
			goMod:    "require (\n\texample.com/a v1.0.0\n)\n",
			files:    map[string]string{"a.go": "package m\n"},
			problems: []string{"go.mod:6: example.com/a is a direct requirement, but no .go file imports it"},
		},
		{
			name:  "module path that begins with another module's path",
			goMod: "require (\n\texample.com/a v1.0.0\n\texample.com/ab v1.0.0 // indirect\n)\n",
			files: map[string]string{"a.go": "package m\n\nimport _ \"example.com/ab\"\n"},
			problems: []string{
				"go.mod:6: example.com/a is a direct requirement, but no .go file imports it",
				"go.mod:7: example.com/ab is marked // indirect, but a.go imports it",
			},
		},
		{
			name:  "package provided by a module nested in another",
			goMod: "require (\n\texample.com/a/b v1.0.0\n\texample.com/a v1.0.0 // indirect\n)\n",
			files: map[string]string{"a.go": "package m\n\nimport _ \"example.com/a/b/c\"\n"},
		},
		{
			name:  "files and directories go mod tidy does not read",
			goMod: "require (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0 // indirect\n)\n",
			files: map[string]string{
				"a.go":          "//go:build linux && !windows\n\npackage m\n\nimport _ \"example.com/a\"\n",
				"sample.go":     "//go:build ignore\n\npackage main\n\nimport _ \"example.com/b\"\n",
				"testdata/c.go": "package c\n\nimport _ \"example.com/b\"\n",
				"vendor/d.go":   "package d\n\nimport _ \"example.com/b\"\n",
				".hidden/e.go":  "package e\n\nimport _ \"example.com/b\"\n",
				"_scratch/f.go": "package f\n\nimport _ \"example.com/b\"\n",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for path, content := range tt.files {
				full := filepath.Join(root, filepath.FromSlash(path))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			imports, err := moduleImports(root)
			if err != nil {
				t.Fatalf("moduleImports(%s): %v", root, err)
			}
			problems := goModProblems(parseRequirements(header+tt.goMod), imports)
			if len(problems) != len(tt.problems) {
				t.Fatalf("got problems %q, want %d", problems, len(tt.problems))
			}
			for i, want := range tt.problems {
				if !strings.Contains(problems[i], want) {
					t.Errorf("problem %d = %q, want one containing %q", i, problems[i], want)
				}
			}
		})
	}
}
