// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// sarifURIs returns the artifact URIs of the SARIF report at path: those of
// its results, each URI once, and those of the notifications for files the
// run could not analyze, both sorted.
func sarifURIs(t *testing.T, path string) (results, notifications []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no SARIF report written: %v", err)
	}
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	var report struct {
		Runs []struct {
			Results []struct {
				Locations []location `json:"locations"`
			} `json:"results"`
			Invocations []struct {
				ToolExecutionNotifications []struct {
					Locations []location `json:"locations"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid SARIF report: %v", err)
	}
	for _, run := range report.Runs {
		for _, result := range run.Results {
			for _, loc := range result.Locations {
				if uri := loc.PhysicalLocation.ArtifactLocation.URI; !slices.Contains(results, uri) {
					results = append(results, uri)
				}
			}
		}
		for _, invocation := range run.Invocations {
			for _, n := range invocation.ToolExecutionNotifications {
				for _, loc := range n.Locations {
					notifications = append(notifications, loc.PhysicalLocation.ArtifactLocation.URI)
				}
			}
		}
	}
	slices.Sort(results)
	slices.Sort(notifications)
	return results, notifications
}

// The reproduction from the report: run from the directory above a tree,
// "scan tree --format sarif" gave each result the absolute path of its file,
// while "scan <the tree's absolute path> --format sarif" gave the path
// relative to the tree, because the reporter related each absolute path to
// the target as typed. Each form of the target below gives the URIs relative
// to the directory the scan walked, slash-separated: the tree for a directory
// target, and the file's directory for a file target, where the absolute form
// gave "." before. The notification for the manifest that could not be
// decoded carries its path the same way.
func TestSARIFURIsAreRelativeWhicheverFormTheTargetIsGivenIn(t *testing.T) {
	parent := t.TempDir()
	tree := filepath.Join(parent, "tree")
	files := map[string]string{
		"app.py":           "import hashlib\n\ndigest = hashlib.md5(data).hexdigest()\n",
		"lib/keys.py":      "from Crypto.PublicKey import RSA\n\npair = RSA.generate(1024)\n",
		"lib/package.json": "{\"dependencies\": {\n",
	}
	for name, content := range files {
		path := filepath.Join(tree, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The reports are written outside the tree, so no scan reads one.
	reports := t.TempDir()

	treeURIs := []string{"app.py", "lib/keys.py"}
	manifest := []string{"lib/package.json"}
	for i, tc := range []struct {
		name, dir, target  string
		want, wantNotified []string
	}{
		{"relative directory", parent, "tree", treeURIs, manifest},
		{"dot", tree, ".", treeURIs, manifest},
		{"absolute directory", parent, tree, treeURIs, manifest},
		{"relative file", parent, filepath.Join("tree", "app.py"), []string{"app.py"}, nil},
		{"absolute file", parent, filepath.Join(tree, "app.py"), []string{"app.py"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chdirForTest(t, tc.dir)
			resetPipelineFlags(t)
			outputFormat = "sarif"
			outputFile = filepath.Join(reports, fmt.Sprintf("%d.sarif", i))
			captureStderr(func() {
				if _, err := scanTarget(scanCmd, tc.target); err != nil {
					t.Errorf("scan %s --format sarif: %v", tc.target, err)
				}
			})
			got, notified := sarifURIs(t, outputFile)
			if !slices.Equal(got, tc.want) {
				t.Errorf("scan %s: result URIs %q, want %q", tc.target, got, tc.want)
			}
			if !slices.Equal(notified, tc.wantNotified) {
				t.Errorf("scan %s: notification URIs %q, want %q", tc.target, notified, tc.wantNotified)
			}
		})
	}
}
