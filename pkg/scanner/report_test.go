// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Reports as CryptoScan writes them, cut down to one finding that names MD5.
// Read as source, each of them gives findings of its own.
const (
	prettyJSONReport = `{
  "tool": {
    "name": "CryptoScan",
    "version": "1.5.0"
  },
  "findings": [
    {
      "id": "MD5-001-2-5",
      "type": "MD5 Hash Function",
      "algorithm": "MD5",
      "context": "h = hashlib.md5(b\"a\")"
    }
  ]
}
`
	compactJSONReport = `{"tool":{"name":"CryptoScan","version":"1.5.0"},"findings":[{"id":"MD5-001-2-5","type":"MD5 Hash Function","algorithm":"MD5","context":"h = hashlib.md5(b\"a\")"}]}`

	sarifReport = `{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "CryptoScan",
          "version": "1.5.0",
          "rules": [
            {
              "id": "MD5-001-2-5",
              "name": "MD5 Hash Function",
              "help": {
                "text": "Replace hashlib.md5() with hashlib.sha256()"
              }
            }
          ]
        }
      },
      "results": []
    }
  ]
}
`

	cbomReport = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
  "version": 1,
  "metadata": {
    "timestamp": "2026-10-20T00:00:00Z",
    "tools": [
      {
        "vendor": "CSNP",
        "name": "CryptoScan",
        "version": "1.5.0"
      }
    ]
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "MD5",
      "description": "h = hashlib.md5(b\"a\")"
    }
  ]
}
`

	csvReport = "ID,Severity,Type,Category,Algorithm,Key Size,Quantum Risk,Confidence,File,Line,Column,Match,Language,File Type,Purpose,Description,Remediation,Impact,Effort,Tags,Priority Score\n" +
		"MD5-001-2-5,MEDIUM,MD5 Hash Function,Hash Function,MD5,,PARTIAL,HIGH,a.py,2,5,hashlib.md5,python,code,,MD5 is broken,Replace hashlib.md5() with hashlib.sha256(),,Low,,40\n"

	textReport = "\n" +
		"╔═══════════════════════════════════════════════════════════════╗\n" +
		"║              CRYPTOGRAPHIC SCAN RESULTS                       ║\n" +
		"║                    QRAMM CryptoScan                           ║\n" +
		"╚═══════════════════════════════════════════════════════════════╝\n" +
		"\n" +
		"  [MEDIUM] MD5 Hash Function\n" +
		"  │ h = hashlib.md5(b\"a\")\n" +
		"  │ Fix: Replace hashlib.md5() with hashlib.sha256()\n"

	// streamedText is what a scan prints on standard output when that is not
	// a terminal, as in "cryptoscan scan . > scan-output.log".
	streamedText = "  Scanning... (findings appear as discovered)\n" +
		"\n" +
		"  [MEDIUM] #1   MD5 Hash Function      a.py:2 [!]\n" +
		"  │ h = hashlib.md5(b\"a\")\n"

	// coloredStreamedText is streamedText with the header as a scan prints
	// it with colour on. With colour on, the scan prints the banner ahead of
	// the header; bannerText is its start.
	coloredStreamedText = "\x1b[36m\x1b[1m  ⏳ Scanning...\x1b[0m \x1b[2m(findings appear as discovered)\x1b[0m\n" +
		"\n" +
		"  [MEDIUM] #1   MD5 Hash Function      a.py:2 [!]\n" +
		"  │ h = hashlib.md5(b\"a\")\n"

	// bannerText is the start of the banner that scan and gate print ahead
	// of their text output when colour is on: its box, cut down to one line
	// of art, and the two lines below the box.
	bannerText = "\n" +
		"\x1b[36m\x1b[1m  ╔═══════════════════════════════════════════════════════════════╗\n" +
		"  ║    ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗            ║\n" +
		"  ╚═══════════════════════════════════════════════════════════════╝\x1b[0m\n" +
		"\n" +
		"\x1b[34m  Crypto Scan: QRAMM Cryptographic Discovery\x1b[0m\n" +
		"\x1b[2m  Quantum Readiness Assurance & Migration Tool\x1b[0m\n" +
		"\n"

	// quotedHeaderSource is source whose first line is a comment that ends
	// with the stream header.
	quotedHeaderSource = "# The scan prints: Scanning... (findings appear as discovered)\n" + md5Source
)

// coloredText is textReport as the text reporter writes it with colour on,
// each box line wrapped in a bold and a reset sequence.
var coloredText = strings.NewReplacer(
	"╔", "\x1b[1m╔", "╗\n", "╗\n\x1b[0m",
	"║ ", "\x1b[1m║ ", "║\n", "║\n\x1b[0m",
).Replace(textReport)

func TestReportFormat(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"pretty JSON report", prettyJSONReport, "JSON"},
		{"compact JSON report", compactJSONReport, "JSON"},
		{"pqc JSON view", `{"tool":{"name":"CryptoScan","version":"1.5.0"},"migrationScore":null,"pqcFindings":[]}`, "JSON"},
		{"JSON report with a byte order mark", "\xef\xbb\xbf" + prettyJSONReport, "JSON"},
		{"SARIF report", sarifReport, "SARIF"},
		{"CBOM", cbomReport, "CycloneDX CBOM"},
		{"CBOM listing tools as components",
			`{"bomFormat": "CycloneDX", "metadata": {"tools": {"components": [{"type": "application", "name": "CryptoScan"}]}}}`,
			"CycloneDX CBOM"},
		{"CSV report", csvReport, "CSV"},
		{"CSV report with CRLF line ends", strings.ReplaceAll(csvReport, "\n", "\r\n"), "CSV"},
		{"CSV report with no findings", strings.SplitAfter(csvReport, "\n")[0], "CSV"},
		{"text report", textReport, "text"},
		{"text report in colour", coloredText, "text"},
		{"pqc text view", strings.Replace(textReport, "CRYPTOGRAPHIC SCAN RESULTS", "POST-QUANTUM READINESS    ", 1), "text"},
		{"streamed scan output", streamedText, "text"},
		{"streamed scan output in colour", coloredStreamedText, "text"},
		{"streamed scan output in colour after the banner", bannerText + coloredStreamedText, "text"},
		{"text report in colour after the banner", bannerText + coloredText, "text"},

		// Files that are not CryptoScan reports are read as before.
		{"SARIF from another tool",
			strings.Replace(sarifReport, `"name": "CryptoScan"`, `"name": "OtherScanner"`, 1), ""},
		{"CycloneDX SBOM from another tool",
			strings.Replace(cbomReport, `"name": "CryptoScan"`, `"name": "cyclonedx-gomod"`, 1), ""},
		{"CryptoScan named as a tool outside a CycloneDX document",
			`{"metadata": {"tools": [{"name": "CryptoScan"}]}}`, ""},
		{"a package named CryptoScan", `{"name": "CryptoScan", "version": "1.0.0", "dependencies": {}}`, ""},
		{"another tool", `{"tool": {"name": "OtherScanner"}, "findings": []}`, ""},
		{"tool.name below the top level", `{"settings": {"tool": {"name": "CryptoScan"}}}`, ""},
		{"a JSON array", `[{"tool": {"name": "CryptoScan"}}]`, ""},
		{"another CSV", "ID,Severity,Type\n1,HIGH,md5\n", ""},
		{"a box with another title", strings.Replace(textReport, "QRAMM CryptoScan", "Release checklist", 1), ""},
		{"text naming the report title", "Notes\n\nThe report title reads QRAMM CryptoScan.\nmd5 is broken\n", ""},
		{"source with the stream header at the end of line 1", quotedHeaderSource, ""},
		{"the stream header with text after it", "Scanning... (findings appear as discovered) took 2s\nmd5 is broken\n", ""},
		{"the stream header on line 2", "Notes\nScanning... (findings appear as discovered)\nmd5 is broken\n", ""},
		{"a box with another line below it",
			strings.Replace(bannerText, "Crypto Scan: QRAMM Cryptographic Discovery", "Release checklist", 1), ""},
		{"the banner title with no box above it", "Crypto Scan: QRAMM Cryptographic Discovery\nmd5 is broken\n", ""},
		{"the banner on line 2", "Notes\n" + bannerText + coloredStreamedText, ""},
		{"a box with no line below it", "╔════════╗\n║ Notes  ║\n╚════════╝\n", ""},
		{"a box that does not close", "╔════════╗\n║ Notes  ║\n║ md5    ║\n", ""},
		{"source code", "import hashlib\nh = hashlib.md5(b\"a\")\n", ""},
		{"an empty file", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reportFormat(strings.NewReader(tt.content)); got != tt.want {
				t.Errorf("reportFormat = %q, want %q", got, tt.want)
			}
		})
	}
}

// Only the start of a file is read. A report names its tool before its
// findings, so one longer than the part read is still recognised, and a JSON
// file nested deeper than the fields looked for ends the walk without them.
func TestReportFormatReadsTheStartOfTheFile(t *testing.T) {
	long := `{"tool":{"name":"CryptoScan","version":"1.5.0"},"findings":[` +
		strings.Repeat(`{"id":"MD5-001-2-5","algorithm":"MD5"},`, 2*reportHeadSize/38) +
		`{"id":"MD5-001-2-5","algorithm":"MD5"}]}`
	if len(long) <= reportHeadSize {
		t.Fatalf("fixture is %d bytes, want more than %d", len(long), reportHeadSize)
	}
	if got := reportFormat(strings.NewReader(long)); got != "JSON" {
		t.Errorf("reportFormat on a %d-byte JSON report = %q, want %q", len(long), got, "JSON")
	}

	nested := `{"a":` + strings.Repeat("[", 4000) + strings.Repeat("]", 4000) + `,"tool":{"name":"CryptoScan"}}`
	if got := reportFormat(strings.NewReader(nested)); got != "" {
		t.Errorf("reportFormat on deeply nested JSON = %q, want \"\"", got)
	}
}

// The reproduction from the report: a report CryptoScan wrote into the tree
// was read as source on the next scan, and every algorithm it named became a
// finding. Each report is now listed as not scanned, and only the source file
// gives findings.
func TestScanLeavesOutCryptoScanReports(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "a.py")
	writeFixture(t, source, md5Source)
	reports := map[string]string{
		"findings.json":   prettyJSONReport,
		"baseline.json":   compactJSONReport,
		"results.sarif":   sarifReport,
		"crypto-bom.json": cbomReport,
		"findings.csv":    csvReport,
		"scan-output.log": streamedText,
		"scan-report.log": coloredText,
	}
	for name, content := range reports {
		writeFixture(t, filepath.Join(dir, "reports", name), content)
	}

	results := scanTarget(t, dir)

	for _, f := range results.Findings {
		if f.File != source {
			t.Errorf("finding %s in %s: only %s is source", f.ID, f.File, source)
		}
	}
	if len(md5Findings(results)) != 1 || results.FilesScanned != 1 {
		t.Errorf("md5Findings = %d, filesScanned = %d; want 1 and 1",
			len(md5Findings(results)), results.FilesScanned)
	}
	want := []SkippedFile{
		{File: filepath.Join(dir, "reports", "baseline.json"), Reason: "CryptoScan report: JSON"},
		{File: filepath.Join(dir, "reports", "crypto-bom.json"), Reason: "CryptoScan report: CycloneDX CBOM"},
		{File: filepath.Join(dir, "reports", "findings.csv"), Reason: "CryptoScan report: CSV"},
		{File: filepath.Join(dir, "reports", "findings.json"), Reason: "CryptoScan report: JSON"},
		{File: filepath.Join(dir, "reports", "results.sarif"), Reason: "CryptoScan report: SARIF"},
		{File: filepath.Join(dir, "reports", "scan-output.log"), Reason: "CryptoScan report: text"},
		{File: filepath.Join(dir, "reports", "scan-report.log"), Reason: "CryptoScan report: text"},
	}
	if !reflect.DeepEqual(results.SkippedFiles, want) {
		t.Errorf("skippedFiles = %+v\nwant %+v", results.SkippedFiles, want)
	}
	for _, sk := range results.SkippedFiles {
		if !sk.IsCryptoScanReport() || sk.IsUnreadManifest() {
			t.Errorf("%s: IsCryptoScanReport = %v, IsUnreadManifest = %v; want true and false",
				sk.File, sk.IsCryptoScanReport(), sk.IsUnreadManifest())
		}
	}
}

// A source file whose first line ends with the stream header, after other
// text, is source and not a report: it is scanned and its finding reported.
func TestScanReadsSourceThatQuotesTheStreamHeader(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "a.py"), quotedHeaderSource)

	results := scanTarget(t, dir)

	if len(md5Findings(results)) != 1 || results.FilesScanned != 1 || len(results.SkippedFiles) != 0 {
		t.Errorf("md5Findings = %d, filesScanned = %d, skippedFiles = %+v; want 1, 1 and none",
			len(md5Findings(results)), results.FilesScanned, results.SkippedFiles)
	}
}

// The file the scan's report goes to is left out whatever it holds, since
// the report replaces it. Without ReportFile, the same file is scanned.
func TestScanLeavesOutTheReportFile(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "scan-report")
	writeFixture(t, report, md5Source)

	control := scanTarget(t, dir)
	if len(md5Findings(control)) != 1 || len(control.SkippedFiles) != 0 {
		t.Fatalf("control scan: md5Findings = %d, skippedFiles = %+v; want 1 and none",
			len(md5Findings(control)), control.SkippedFiles)
	}

	results, err := New(Config{Target: dir, MinSeverity: SeverityInfo, ReportFile: report}).Scan()
	if err != nil {
		t.Fatal(err)
	}
	want := []SkippedFile{{File: report, Reason: "CryptoScan report: the --output file of this scan"}}
	if !reflect.DeepEqual(results.SkippedFiles, want) {
		t.Errorf("skippedFiles = %+v, want %+v", results.SkippedFiles, want)
	}
	if len(results.Findings) != 0 || results.FilesScanned != 0 {
		t.Errorf("findings = %d, filesScanned = %d; want 0 and 0", len(results.Findings), results.FilesScanned)
	}

	// A report file that does not exist yet leaves the scan as it was.
	missing, err := New(Config{Target: dir, MinSeverity: SeverityInfo, ReportFile: filepath.Join(dir, "new-report")}).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(md5Findings(missing)) != 1 || len(missing.SkippedFiles) != 0 {
		t.Errorf("scan with a new report file: md5Findings = %d, skippedFiles = %+v; want 1 and none",
			len(md5Findings(missing)), missing.SkippedFiles)
	}
}

func TestIsCryptoScanReport(t *testing.T) {
	for _, tt := range []struct {
		reason string
		want   bool
	}{
		{"CryptoScan report: SARIF", true},
		{"CryptoScan report: the --output file of this scan", true},
		{"minified: the file name ends in .min.js", false},
		{"minified or generated: its lines average 674 bytes", false},
		{"dependency manifest: the scanner does not read this format", false},
	} {
		if got := (SkippedFile{File: "f", Reason: tt.reason}).IsCryptoScanReport(); got != tt.want {
			t.Errorf("IsCryptoScanReport for %q = %v, want %v", tt.reason, got, tt.want)
		}
	}
}
