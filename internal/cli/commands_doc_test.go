// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// commandsDoc is the command reference. Its Scan flags section says that its
// descriptions are the ones cryptoscan scan --help prints.
const commandsDoc = "../../docs/commands.md"

// helpFlagRows returns the lines cmd --help prints under Flags:, as the flag
// column mapped to the description column.
func helpFlagRows(cmd *cobra.Command) map[string]string {
	cmd.InitDefaultHelpFlag()
	rows := make(map[string]string)
	for _, line := range strings.Split(cmd.LocalFlags().FlagUsages(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Cobra pads the flag column with at least two spaces.
		flag, desc, _ := strings.Cut(line, "  ")
		rows[flag] = strings.TrimSpace(desc)
	}
	return rows
}

// docFlagRows returns the two-column table rows in the section of doc headed
// heading, as the flag cell mapped to the description cell. Backquotes are
// removed: the page sets the flag, and patterns such as vendor/* that Markdown
// would otherwise read as emphasis, in code spans.
func docFlagRows(doc, heading string) map[string]string {
	rows := make(map[string]string)
	inSection := false
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "## ") {
			inSection = line == heading
			continue
		}
		if !inSection || !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 2 {
			continue
		}
		flag := strings.ReplaceAll(strings.TrimSpace(cells[0]), "`", "")
		desc := strings.ReplaceAll(strings.TrimSpace(cells[1]), "`", "")
		if flag == "Flag" || strings.Trim(flag, "-") == "" {
			continue // the header row and the line under it
		}
		rows[flag] = desc
	}
	return rows
}

// sortedKeys returns the keys of m in order, so that failures are reported in
// the same order on every run.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestCommandsDocScanFlagsMatchHelp(t *testing.T) {
	data, err := os.ReadFile(commandsDoc)
	if err != nil {
		t.Fatal(err)
	}
	doc := docFlagRows(string(data), "## Scan flags")
	if len(doc) == 0 {
		t.Fatalf("%s has no flag table under ## Scan flags, so this test checked nothing", commandsDoc)
	}
	help := helpFlagRows(scanCmd)

	for _, flag := range sortedKeys(help) {
		want := help[flag]
		got, ok := doc[flag]
		switch {
		case !ok:
			t.Errorf("docs/commands.md: the Scan flags tables have no row for %s; scan --help prints %q", flag, want)
		case got != want:
			t.Errorf("docs/commands.md: the Scan flags row for %s reads\n\t%q\nscan --help prints\n\t%q", flag, got, want)
		}
	}
	for _, flag := range sortedKeys(doc) {
		if _, ok := help[flag]; !ok {
			t.Errorf("docs/commands.md: the Scan flags tables have a row for %s, which scan --help does not print", flag)
		}
	}
}

func TestDocFlagRows(t *testing.T) {
	const doc = "## Scan flags\n\n" +
		"| Flag | Description |\n" +
		"|------|-------------|\n" +
		"| `-e, --exclude string` | Skip a directory (`vendor/*`) |\n" +
		"| `--pretty` | Pretty print JSON output |\n\n" +
		"## Exit codes\n\n" +
		"| Code | When |\n" +
		"|------|------|\n" +
		"| `0` | No finding reached the threshold. |\n"

	got := docFlagRows(doc, "## Scan flags")
	want := map[string]string{
		"-e, --exclude string": "Skip a directory (vendor/*)",
		"--pretty":             "Pretty print JSON output",
	}
	if len(got) != len(want) {
		t.Fatalf("docFlagRows = %q, want %q", got, want)
	}
	for flag, desc := range want {
		if got[flag] != desc {
			t.Errorf("row %s = %q, want %q", flag, got[flag], desc)
		}
	}
}
