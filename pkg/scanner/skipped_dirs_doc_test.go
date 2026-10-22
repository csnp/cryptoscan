// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// howItWorks lists the directories a scan leaves out by default, in the
// skippedDirsSection.
const howItWorks = "../../docs/how-it-works.md"

// skippedDirsSection is the heading of that list.
const skippedDirsSection = "### Directories left out by default"

// skippedDirsDocProblems compares the skippedDirsSection of page, the text of
// docs/how-it-works.md, with the directory rules the scanner applies. It
// returns one message per directory name the section's table leaves out or
// lists without the scanner leaving it out, and per path rule the section
// does not name, along with the number of names the table lists.
func skippedDirsDocProblems(page string) ([]string, int) {
	_, section, found := strings.Cut(page, skippedDirsSection+"\n")
	if !found {
		return []string{fmt.Sprintf("there is no %q section", skippedDirsSection)}, 0
	}
	if end := strings.Index(section, "\n#"); end >= 0 {
		section = section[:end]
	}

	codeSpan := regexp.MustCompile("`([^`]+)`")
	listed := make(map[string]bool)
	for _, line := range strings.Split(section, "\n") {
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if !strings.HasPrefix(line, "|") || len(cells) != 2 {
			continue
		}
		for _, m := range codeSpan.FindAllStringSubmatch(cells[1], -1) {
			listed[m[1]] = true
		}
	}

	// The scan command passes DefaultExcludeGlobs, so the directories their
	// patterns name are left out as well as the built-in ones.
	applied := make(map[string]bool)
	for name := range skipDirNames {
		applied[name] = true
	}
	for _, pattern := range DefaultExcludeGlobs {
		if name, isDir := dirPattern(pattern); isDir {
			applied[name] = true
		}
	}

	var problems []string
	for name := range applied {
		if !listed[name] {
			problems = append(problems, "the scanner leaves out "+name+", which the table does not list")
		}
	}
	for name := range listed {
		if !applied[name] {
			problems = append(problems, "the table lists "+name+", which the scanner does not leave out")
		}
	}

	// A path rule leaves out the directories below a path. One whose path, or
	// the directory at the start of it, is a directory rule as well needs no
	// word of its own, since the table lists that directory and it is left
	// out whole. The section must name any other.
	for _, pattern := range skipPathPatterns {
		rule := strings.Trim(pattern, "/")
		top, _, _ := strings.Cut(rule, "/")
		if applied[rule] || applied[top] {
			continue
		}
		if !strings.Contains(section, "`"+rule+"`") {
			problems = append(problems, "the scanner leaves out the directories below "+rule+", which the section does not name")
		}
	}
	sort.Strings(problems)
	return problems, len(listed)
}

// readHowItWorks returns the text of docs/how-it-works.md.
func readHowItWorks(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(howItWorks)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The page's list must be the one the scanner applies: a name missing from it
// is a directory a reader cannot know is left out, and a name the scanner
// does not have is a promise the scan does not keep.
func TestHowItWorksListsTheDirectoriesLeftOutByDefault(t *testing.T) {
	problems, listed := skippedDirsDocProblems(readHowItWorks(t))
	if listed == 0 {
		t.Fatalf("%s: the %q section has no table of directory names, so this test checked nothing", howItWorks, skippedDirsSection)
	}
	for _, p := range problems {
		t.Errorf("%s: %s", howItWorks, p)
	}
}

// Each kind of difference between the page and the scanner is reported: the
// page is changed in one place, and the problems must name that change.
func TestSkippedDirsDocProblems(t *testing.T) {
	page := readHowItWorks(t)
	cases := []struct {
		name     string
		old, new string
		want     string
	}{
		{
			name: "a directory the table leaves out",
			old:  "`vendor`, ", new: "",
			want: "the scanner leaves out vendor, which the table does not list",
		},
		{
			name: "a directory the scanner reads",
			old:  "`examples`, ", new: "`examples`, `docs`, ",
			want: "the table lists docs, which the scanner does not leave out",
		},
		{
			name: "a path rule the section does not name",
			old:  "`standalone`", new: "standalone",
			want: "the scanner leaves out the directories below standalone, which the section does not name",
		},
		{
			name: "no section",
			old:  skippedDirsSection, new: "### Other directories",
			want: fmt.Sprintf("there is no %q section", skippedDirsSection),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			changed := strings.Replace(page, c.old, c.new, 1)
			if changed == page {
				t.Fatalf("%s holds no %q to change", howItWorks, c.old)
			}
			if problems, _ := skippedDirsDocProblems(changed); !slices.Contains(problems, c.want) {
				t.Errorf("problems = %q, want them to include %q", problems, c.want)
			}
		})
	}
}
