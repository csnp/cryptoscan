// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
)

// toolName is the name CryptoScan gives itself in its reports: the tool of a
// JSON report, the SARIF driver and the tool of a CBOM.
const toolName = "CryptoScan"

// reportReasonPrefix starts the Reason of a file left out of the scan because
// it is a report CryptoScan wrote. A report quotes the algorithm names and the
// code it found, so reading one as source reports those findings again, as
// findings in the report.
const reportReasonPrefix = "CryptoScan report: "

// reportFileReason is the Reason of the file Config.ReportFile names.
const reportFileReason = reportReasonPrefix + "the --output file of this scan"

// reportHeadSize is how much of a file reportFormat reads. CryptoScan writes
// the fields that name it at the start of each report, ahead of the findings.
const reportHeadSize = 8 << 10

// csvReportHeader is the first line of a CSV report.
const csvReportHeader = "ID,Severity,Type,Category,Algorithm,Key Size,Quantum Risk,Confidence,File,Line,Column,Match,Language,File Type,Purpose,Description,Remediation,Impact,Effort,Tags,Priority Score"

// byteOrderMark is the UTF-8 byte order mark. It marks a file's encoding and
// is not part of its content.
var byteOrderMark = []byte("\xef\xbb\xbf")

// textReportTitle is the line in the box at the top of a text report from
// scan, gate or pqc.
const textReportTitle = "QRAMM CryptoScan"

// textStreamHeader ends the line a scan prints on standard output before the
// findings it lists as it finds them.
const textStreamHeader = "Scanning... (findings appear as discovered)"

// ansiEscape matches the colour and style sequences a text report carries
// when it is written while standard output is a terminal.
var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;]*m")

// reportFormat returns the format of the CryptoScan report r holds, "JSON",
// "SARIF", "CycloneDX CBOM", "CSV" or "text", or "" when r does not start
// like one. It reads at most reportHeadSize bytes.
func reportFormat(r io.Reader) string {
	head, err := io.ReadAll(io.LimitReader(r, reportHeadSize))
	if err != nil {
		return ""
	}
	head = bytes.TrimPrefix(head, byteOrderMark)
	if trimmed := bytes.TrimLeft(head, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '{' {
		return jsonReportFormat(trimmed)
	}
	firstLine, _, _ := bytes.Cut(head, []byte("\n"))
	if string(bytes.TrimSuffix(firstLine, []byte("\r"))) == csvReportHeader {
		return "CSV"
	}
	if isTextReport(head) {
		return "text"
	}
	return ""
}

// isTextReport reports whether head starts like a text report: with the box
// whose third line is textReportTitle, or with textStreamHeader.
func isTextReport(head []byte) bool {
	var lines []string
	rest := ansiEscape.ReplaceAllString(string(head), "")
	for len(lines) < 3 && rest != "" {
		var line string
		line, rest, _ = strings.Cut(rest, "\n")
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	switch {
	case len(lines) > 0 && strings.HasSuffix(lines[0], textStreamHeader):
		return true
	case len(lines) == 3 && strings.HasPrefix(lines[0], "╔"):
		return strings.Trim(lines[2], "║ ") == textReportTitle
	}
	return false
}

// jsonReportFormat reads the JSON object at the start of head, which may stop
// part way through, and returns the report format that its fields name:
// tool.name for a JSON report (from scan, gate or pqc), runs[].tool.driver.name
// for SARIF, and metadata.tools[].name, with bomFormat "CycloneDX", for a CBOM.
func jsonReportFormat(head []byte) string {
	format := ""
	cycloneDX, cbomTool := false, false
	visit := func(path []string, value any) bool {
		s, _ := value.(string)
		switch {
		case pathIs(path, "tool", "name"):
			if s == toolName {
				format = "JSON"
			}
		case pathIs(path, "runs", "[]", "tool", "driver", "name"):
			if s == toolName {
				format = "SARIF"
			}
		case pathIs(path, "bomFormat"):
			cycloneDX = s == "CycloneDX"
		case pathIs(path, "metadata", "tools", "[]", "name"),
			pathIs(path, "metadata", "tools", "components", "[]", "name"):
			cbomTool = cbomTool || s == toolName
		}
		if cycloneDX && cbomTool {
			format = "CycloneDX CBOM"
		}
		return format != ""
	}
	// The walk ends with an error where head stops, which is expected: what
	// was read up to there decides.
	_ = walkJSON(json.NewDecoder(bytes.NewReader(head)), nil, visit)
	return format
}

// pathIs reports whether path, as walkJSON builds it, is want.
func pathIs(path []string, want ...string) bool {
	return slices.Equal(path, want)
}

// errStopWalk ends walkJSON early.
var errStopWalk = errors.New("stop walking")

// maxJSONDepth is how deep walkJSON reads. The fields jsonReportFormat looks
// for are at most five levels down.
const maxJSONDepth = 8

// walkJSON reads one JSON value from dec and calls visit with each scalar in
// it and the path to that scalar: the object keys, with "[]" for an array
// element. It stops at the first error, at a container nested deeper than
// maxJSONDepth, or when visit returns true.
func walkJSON(dec *json.Decoder, path []string, visit func(path []string, value any) bool) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, isContainer := tok.(json.Delim)
	if !isContainer {
		if visit(path, tok) {
			return errStopWalk
		}
		return nil
	}
	if len(path) >= maxJSONDepth {
		return errStopWalk
	}
	for dec.More() {
		elem := "[]"
		if delim == '{' {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			elem, _ = key.(string)
		}
		if err := walkJSON(dec, append(path, elem), visit); err != nil {
			return err
		}
	}
	_, err = dec.Token() // the closing '}' or ']'
	return err
}
