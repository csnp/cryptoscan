// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	// makefileFile is the repository Makefile. Its lint target runs
	// golangci-lint.
	makefileFile = "../../Makefile"

	// lintActionPrefix begins the uses value of a workflow step that installs
	// golangci-lint and runs it.
	lintActionPrefix = "golangci/golangci-lint-action@"

	// lintRun is the text a lint recipe line carries when it runs
	// golangci-lint at the release GOLANGCI_LINT_VERSION names, as in
	// go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run.
	lintRun = "/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)"
)

// lintVersionPattern matches a Makefile line that sets GOLANGCI_LINT_VERSION
// with = or :=, and captures the value. A ?= line does not match: it leaves a
// GOLANGCI_LINT_VERSION set in the environment in place, so make lint would
// run that release.
var lintVersionPattern = regexp.MustCompile(`^GOLANGCI_LINT_VERSION[ \t]*:?=[ \t]*([^#\s]*)[ \t]*(#.*)?$`)

// releasePattern matches one golangci-lint release, such as v1.64.8.
var releasePattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// lintRulePattern matches the line of the Makefile rule for the lint target.
var lintRulePattern = regexp.MustCompile(`^lint[ \t]*:([^=]|$)`)

// latestReleases maps the uses value of a golangci-lint step whose version is
// latest to the release that step installs. The lint job log of the CI run on
// commit 61fe200 prints "Installing golangci-lint binary v1.64.8..." for
// golangci/golangci-lint-action@v4 with version latest.
var latestReleases = map[string]string{
	"golangci/golangci-lint-action@v4": "v1.64.8",
}

// workflowLintSteps holds the part of a GitHub Actions workflow that names the
// actions its job steps use and the inputs each step passes.
type workflowLintSteps struct {
	Jobs map[string]struct {
		Steps []struct {
			Uses yaml.Node            `yaml:"uses"`
			With map[string]yaml.Node `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// makefileLintProblems checks that makefile sets GOLANGCI_LINT_VERSION to one
// release and that the recipe of its lint target runs golangci-lint at that
// release. It returns the release, or "" when there is none, and one message
// per problem.
func makefileLintProblems(makefile string) (release string, problems []string) {
	lines := strings.Split(makefile, "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}

	versionLine := 0
	for i, line := range lines {
		if m := lintVersionPattern.FindStringSubmatch(line); m != nil {
			release, versionLine = m[1], i+1
		}
	}
	switch {
	case versionLine == 0:
		problems = append(problems,
			"Makefile does not set GOLANGCI_LINT_VERSION with = or :=, so make lint does not name the golangci-lint release it runs")
	case !releasePattern.MatchString(release):
		problems = append(problems, fmt.Sprintf(
			"Makefile:%d: GOLANGCI_LINT_VERSION is %q, which is not one golangci-lint release such as v1.64.8",
			versionLine, release))
		release = ""
	}

	ruleLine := 0
	runs := 0
	for i, line := range lines {
		if ruleLine == 0 {
			if lintRulePattern.MatchString(line) {
				ruleLine = i + 1
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "\t") {
			break // the recipe ends at the first line that is not indented by a tab
		}
		if !strings.Contains(line, "golangci-lint") {
			continue
		}
		if !strings.Contains(line, lintRun) {
			problems = append(problems, fmt.Sprintf(
				"Makefile:%d: the lint recipe runs golangci-lint without naming the release in GOLANGCI_LINT_VERSION: %s; run go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run, with /v2 before /cmd for a v2 release",
				i+1, strings.TrimSpace(line)))
			continue
		}
		runs++
	}
	switch {
	case ruleLine == 0:
		problems = append(problems, "Makefile has no rule for the lint target")
	case runs == 0:
		problems = append(problems, fmt.Sprintf(
			"Makefile:%d: the lint recipe does not run golangci-lint at the release in GOLANGCI_LINT_VERSION", ruleLine))
	}
	return release, problems
}

// makeLintProblems checks that make lint runs the golangci-lint release that
// the golangci-lint steps of the workflows install. workflows maps each
// workflow file name to its content. It returns one message per problem,
// along with the number of golangci-lint steps it checked.
func makeLintProblems(makefile string, workflows map[string]string) (problems []string, steps int) {
	var release string
	release, problems = makefileLintProblems(makefile)

	names := make([]string, 0, len(workflows))
	for name := range workflows {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		var wf workflowLintSteps
		if err := yaml.Unmarshal([]byte(workflows[name]), &wf); err != nil {
			problems = append(problems, fmt.Sprintf("%s: the workflow does not parse: %v", name, err))
			continue
		}
		jobs := make([]string, 0, len(wf.Jobs))
		for job := range wf.Jobs {
			jobs = append(jobs, job)
		}
		sort.Strings(jobs)

		for _, job := range jobs {
			for _, step := range wf.Jobs[job].Steps {
				uses := step.Uses.Value
				if !strings.HasPrefix(uses, lintActionPrefix) {
					continue
				}
				steps++

				version, line := "", step.Uses.Line
				if node, ok := step.With["version"]; ok {
					version, line = node.Value, node.Line
				}
				installs := ""
				switch {
				case releasePattern.MatchString(version):
					installs = version
				case version == "latest" && latestReleases[uses] != "":
					installs = latestReleases[uses]
				default:
					problems = append(problems, fmt.Sprintf(
						"%s:%d: job %s: %s with version %q does not name one golangci-lint release; set version to the release in GOLANGCI_LINT_VERSION in the Makefile",
						name, line, job, uses, version))
					continue
				}
				if release != "" && installs != release {
					problems = append(problems, fmt.Sprintf(
						"%s:%d: job %s installs golangci-lint %s, but make lint runs %s, the release in GOLANGCI_LINT_VERSION in the Makefile; change the two together",
						name, line, job, installs, release))
				}
			}
		}
	}
	return problems, steps
}

// TestMakeLintRunsTheGolangciLintReleaseCIInstalls fails when make lint and
// the CI lint job run different golangci-lint releases. On commit 61fe200,
// golangci-lint 2.12.2 reported errcheck and staticcheck issues that v1.64.8,
// the release the CI lint job installs, did not report.
func TestMakeLintRunsTheGolangciLintReleaseCIInstalls(t *testing.T) {
	makefile, err := os.ReadFile(makefileFile)
	if err != nil {
		t.Fatalf("read %s: %v", makefileFile, err)
	}

	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("read %s: %v", workflowDir, err)
	}
	workflows := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() || (filepath.Ext(e.Name()) != ".yml" && filepath.Ext(e.Name()) != ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(workflowDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		workflows[e.Name()] = string(data)
	}

	problems, steps := makeLintProblems(string(makefile), workflows)
	for _, problem := range problems {
		t.Error(problem)
	}
	if steps == 0 {
		t.Fatalf("found no step that uses %s in %s, so this test checked nothing", lintActionPrefix, workflowDir)
	}
}

func TestMakeLintProblems(t *testing.T) {
	const pinnedMakefile = "BINARY_NAME=cryptoscan\n" +
		"GOLANGCI_LINT_VERSION=v1.64.8\n" +
		"\n" +
		".PHONY: lint\n" +
		"\n" +
		"## lint: Run golangci-lint\n" +
		"lint:\n" +
		"\tgo run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run\n" +
		"\n" +
		"## fmt: Format code\n" +
		"fmt:\n" +
		"\tgo fmt ./...\n"

	const latestV4Workflow = "name: CI\n" +
		"jobs:\n" +
		"  lint:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    steps:\n" +
		"      - uses: actions/checkout@v4\n" +
		"      - name: golangci-lint\n" +
		"        uses: golangci/golangci-lint-action@v4\n" +
		"        with:\n" +
		"          version: latest\n"

	// lintStep returns a workflow whose lint job has one golangci-lint step.
	lintStep := func(uses, with string) string {
		return "name: CI\n" +
			"jobs:\n" +
			"  lint:\n" +
			"    runs-on: ubuntu-latest\n" +
			"    steps:\n" +
			"      - uses: " + uses + "\n" +
			with
	}

	tests := []struct {
		name      string
		makefile  string
		workflows map[string]string
		steps     int
		problems  []string // text each expected problem contains, in order
	}{
		{
			name:      "make lint runs the release that version latest installs with the v4 action",
			makefile:  pinnedMakefile,
			workflows: map[string]string{"ci.yml": latestV4Workflow},
			steps:     1,
		},
		{
			name: "make lint runs the release the workflow names",
			makefile: strings.Replace(strings.Replace(pinnedMakefile, "v1.64.8", "v2.12.2", 1),
				"golangci-lint/cmd", "golangci-lint/v2/cmd", 1),
			workflows: map[string]string{
				"ci.yml": lintStep("golangci/golangci-lint-action@v8", "        with:\n          version: v2.12.2\n"),
			},
			steps: 1,
		},
		{
			name:      "lint recipe runs the golangci-lint on the PATH",
			makefile:  ".PHONY: lint\n\n## lint: Run linters\nlint:\n\tgolangci-lint run\n\n## fmt: Format code\nfmt:\n\tgo fmt ./...\n",
			workflows: map[string]string{"ci.yml": latestV4Workflow},
			steps:     1,
			problems: []string{
				"Makefile does not set GOLANGCI_LINT_VERSION",
				"Makefile:5: the lint recipe runs golangci-lint without naming the release in GOLANGCI_LINT_VERSION: golangci-lint run",
				"Makefile:4: the lint recipe does not run golangci-lint at the release in GOLANGCI_LINT_VERSION",
			},
		},
		{
			name:      "GOLANGCI_LINT_VERSION set with ?=",
			makefile:  strings.Replace(pinnedMakefile, "GOLANGCI_LINT_VERSION=", "GOLANGCI_LINT_VERSION ?= ", 1),
			workflows: map[string]string{"ci.yml": latestV4Workflow},
			steps:     1,
			problems:  []string{"Makefile does not set GOLANGCI_LINT_VERSION with = or :="},
		},
		{
			name:      "GOLANGCI_LINT_VERSION set with := and spaces",
			makefile:  strings.Replace(pinnedMakefile, "GOLANGCI_LINT_VERSION=", "GOLANGCI_LINT_VERSION := ", 1),
			workflows: map[string]string{"ci.yml": latestV4Workflow},
			steps:     1,
		},
		{
			name:      "GOLANGCI_LINT_VERSION line with a trailing comment",
			makefile:  strings.Replace(pinnedMakefile, "=v1.64.8\n", "=v1.64.8 # the release CI installs\n", 1),
			workflows: map[string]string{"ci.yml": latestV4Workflow},
			steps:     1,
		},
		{
			name:      "Makefile with CRLF line endings",
			makefile:  strings.ReplaceAll(pinnedMakefile, "\n", "\r\n"),
			workflows: map[string]string{"ci.yml": latestV4Workflow},
			steps:     1,
		},
		{
			name:      "GOLANGCI_LINT_VERSION is not one release",
			makefile:  strings.Replace(pinnedMakefile, "v1.64.8", "latest", 1),
			workflows: map[string]string{"ci.yml": latestV4Workflow},
			steps:     1,
			problems:  []string{`Makefile:2: GOLANGCI_LINT_VERSION is "latest", which is not one golangci-lint release`},
		},
		{
			name:     "workflow installs another release",
			makefile: pinnedMakefile,
			workflows: map[string]string{
				"ci.yml": lintStep("golangci/golangci-lint-action@v4", "        with:\n          version: v1.63.4\n"),
			},
			steps:    1,
			problems: []string{"ci.yml:8: job lint installs golangci-lint v1.63.4, but make lint runs v1.64.8"},
		},
		{
			name:     "version latest with an action whose latest release this test does not know",
			makefile: pinnedMakefile,
			workflows: map[string]string{
				"ci.yml": lintStep("golangci/golangci-lint-action@v8", "        with:\n          version: latest\n"),
			},
			steps:    1,
			problems: []string{`ci.yml:8: job lint: golangci/golangci-lint-action@v8 with version "latest" does not name one golangci-lint release`},
		},
		{
			name:     "version names a minor release line",
			makefile: pinnedMakefile,
			workflows: map[string]string{
				"ci.yml": lintStep("golangci/golangci-lint-action@v4", "        with:\n          version: v1.64\n"),
			},
			steps:    1,
			problems: []string{`ci.yml:8: job lint: golangci/golangci-lint-action@v4 with version "v1.64" does not name one golangci-lint release`},
		},
		{
			name:     "step without a version",
			makefile: pinnedMakefile,
			workflows: map[string]string{
				"ci.yml": lintStep("golangci/golangci-lint-action@v4", ""),
			},
			steps:    1,
			problems: []string{`ci.yml:6: job lint: golangci/golangci-lint-action@v4 with version "" does not name one golangci-lint release`},
		},
		{
			name:     "golangci-lint steps in two workflows",
			makefile: pinnedMakefile,
			workflows: map[string]string{
				"ci.yml":   latestV4Workflow,
				"lint.yml": lintStep("golangci/golangci-lint-action@v4", "        with:\n          version: v1.62.2\n"),
			},
			steps:    2,
			problems: []string{"lint.yml:8: job lint installs golangci-lint v1.62.2, but make lint runs v1.64.8"},
		},
		{
			name:      "workflow without a golangci-lint step",
			makefile:  pinnedMakefile,
			workflows: map[string]string{"ci.yml": lintStep("actions/checkout@v4", "")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems, steps := makeLintProblems(tt.makefile, tt.workflows)
			if steps != tt.steps {
				t.Errorf("checked %d golangci-lint steps, want %d", steps, tt.steps)
			}
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
