// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	// readmeFile is the repository README. Its header carries a row of badges.
	readmeFile = "../../README.md"

	// workflowDir holds the GitHub Actions workflows a CI badge reports on.
	workflowDir = "../../.github/workflows"

	// repoSlug is the GitHub repository a workflow badge has to report on.
	repoSlug = "csnp/cryptoscan"
)

// badgePattern matches a linked Markdown image, [![alt](image)](target),
// the form each README badge takes. It captures the alt text and the image.
var badgePattern = regexp.MustCompile(`\[!\[([^\]]*)\]\(([^)\s]+)\)\]\([^)\s]+\)`)

// readmeBadgeProblems checks each badge in readme and returns one message per
// badge whose image does not come from a source that still renders a value,
// along with the number of badges it checked. goreportcard.com retired its
// service, and its badge renders "go report: retired" in place of a grade. A
// badge may come from shields.io, or from GitHub Actions for a workflow file
// in workflows: GitHub answers a workflow badge with a 404 when the workflow
// file does not exist.
func readmeBadgeProblems(readme, workflows string) (problems []string, badges int) {
	for i, line := range strings.Split(readme, "\n") {
		for _, m := range badgePattern.FindAllStringSubmatch(line, -1) {
			badges++
			alt, image := m[1], m[2]

			u, err := url.Parse(image)
			if err != nil {
				problems = append(problems, fmt.Sprintf("README.md:%d: badge %q: image URL %q does not parse: %v",
					i+1, alt, image, err))
				continue
			}

			switch u.Host {
			case "img.shields.io":
			case "github.com":
				// <owner>/<repo>/actions/workflows/<file>/badge.svg
				parts := strings.Split(strings.Trim(u.Path, "/"), "/")
				if len(parts) != 6 || parts[0]+"/"+parts[1] != repoSlug ||
					parts[2] != "actions" || parts[3] != "workflows" || parts[5] != "badge.svg" {
					problems = append(problems, fmt.Sprintf("README.md:%d: badge %q: %s is not a workflow badge for %s",
						i+1, alt, image, repoSlug))
					continue
				}
				info, err := os.Stat(filepath.Join(workflows, parts[4]))
				if err != nil || !info.Mode().IsRegular() {
					problems = append(problems, fmt.Sprintf(
						"README.md:%d: badge %q reports on workflow %q, which is not a file in .github/workflows",
						i+1, alt, parts[4]))
				}
			default:
				problems = append(problems, fmt.Sprintf(
					"README.md:%d: badge %q is served by %s; use a shields.io badge or a GitHub Actions workflow badge for %s",
					i+1, alt, u.Host, repoSlug))
			}
		}
	}
	return problems, badges
}

func TestReadmeBadgesComeFromSourcesThatAnswer(t *testing.T) {
	data, err := os.ReadFile(readmeFile)
	if err != nil {
		t.Fatalf("read %s: %v", readmeFile, err)
	}

	problems, badges := readmeBadgeProblems(string(data), workflowDir)
	if badges == 0 {
		t.Fatalf("found no [![alt](image)](target) badges in %s, so this test checked nothing", readmeFile)
	}
	for _, problem := range problems {
		t.Error(problem)
	}
}

func TestReadmeBadgeProblems(t *testing.T) {
	workflows := t.TempDir()
	if err := os.WriteFile(filepath.Join(workflows, "ci.yml"), []byte("name: CI\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		readme  string
		badges  int
		problem string // text the one expected problem contains; empty when none is expected
	}{
		{
			name: "workflow badge and shields.io badge",
			readme: "[![CI](https://github.com/csnp/cryptoscan/actions/workflows/ci.yml/badge.svg)](https://github.com/csnp/cryptoscan/actions/workflows/ci.yml) " +
				"[![License](https://img.shields.io/github/license/csnp/cryptoscan)](LICENSE)",
			badges: 2,
		},
		{
			name:    "retired Go Report Card service",
			readme:  "[![Go Report Card](https://goreportcard.com/badge/github.com/csnp/cryptoscan?v=2)](https://goreportcard.com/report/github.com/csnp/cryptoscan)",
			badges:  1,
			problem: "is served by goreportcard.com",
		},
		{
			name:    "workflow file that does not exist",
			readme:  "[![Lint](https://github.com/csnp/cryptoscan/actions/workflows/lint.yml/badge.svg)](https://github.com/csnp/cryptoscan/actions)",
			badges:  1,
			problem: `reports on workflow "lint.yml"`,
		},
		{
			name:    "workflow path that names no file",
			readme:  "[![CI](https://github.com/csnp/cryptoscan/actions/workflows//badge.svg)](https://github.com/csnp/cryptoscan/actions)",
			badges:  1,
			problem: `reports on workflow ""`,
		},
		{
			name:    "workflow of another repository",
			readme:  "[![CI](https://github.com/csnp/cryptodeps/actions/workflows/ci.yml/badge.svg)](https://github.com/csnp/cryptodeps/actions)",
			badges:  1,
			problem: "is not a workflow badge for csnp/cryptoscan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems, badges := readmeBadgeProblems(tt.readme, workflows)
			if badges != tt.badges {
				t.Errorf("checked %d badges, want %d", badges, tt.badges)
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
