// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/csnp/cryptoscan/pkg/scanner"
	"github.com/csnp/cryptoscan/pkg/types"
	"github.com/csnp/cryptoscan/pkg/version"
)

// SARIFReporter generates SARIF 2.1.0 format output
type SARIFReporter struct{}

// NewSARIFReporter creates a new SARIF reporter
func NewSARIFReporter() *SARIFReporter {
	return &SARIFReporter{}
}

// SARIF structures following SARIF 2.1.0 specification
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
	Results     []sarifResult     `json:"results"`
}

// sarifInvocation carries the files the scanner could not analyze, as SARIF
// 2.1.0 toolExecutionNotifications, and records how the run was configured
// when a config file was applied, so that a consumer of the SARIF file can see
// that rules from outside the command line shaped the results. It also says
// how many files the directories the default rules left out hold. It is
// written only when there is something to say.
type sarifInvocation struct {
	ExecutionSuccessful            bool                       `json:"executionSuccessful"`
	ToolExecutionNotifications     []sarifNotification        `json:"toolExecutionNotifications,omitempty"`
	ToolConfigurationNotifications []sarifNotification        `json:"toolConfigurationNotifications,omitempty"`
	Properties                     *sarifInvocationProperties `json:"properties,omitempty"`
}

type sarifNotification struct {
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifInvocationProperties struct {
	ConfigFile *scanner.ConfigReport       `json:"configFile,omitempty"`
	Skipped    *scanner.SkippedDirectories `json:"skipped,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules"`
	SemanticVersion string      `json:"semanticVersion"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription,omitempty"`
	Help             sarifMessage        `json:"help,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	DefaultConfig    sarifDefaultConfig  `json:"defaultConfiguration"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags        []string `json:"tags,omitempty"`
	QuantumRisk string   `json:"quantumRisk,omitempty"`
	Category    string   `json:"category,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    sarifMessage     `json:"message"`
	Locations  []sarifLocation  `json:"locations"`
	Properties sarifResultProps `json:"properties,omitempty"`
}

type sarifResultProps struct {
	// FindingID is the finding's own ID, the result's ruleId followed by
	// where the finding is, as the JSON report writes it.
	FindingID   string `json:"findingId"`
	QuantumRisk string `json:"quantumRisk,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
	KeySize     int    `json:"keySize,omitempty"`

	// A trust finding's metadata, under the names the JSON report uses.
	// TrustRule is the rule number the JSON report carries as a decimal
	// string.
	Kind             string `json:"kind,omitempty"`
	MatchedValue     string `json:"matchedValue,omitempty"`
	ValueType        string `json:"valueType,omitempty"`
	IssuerSPKISHA256 string `json:"issuerSpkiSha256,omitempty"`
	KeyUse           string `json:"keyUse,omitempty"`
	TrustRule        int    `json:"trustRule,omitempty"`
	DistrustDate     string `json:"distrustDate,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	// Region is omitted when no line is known; SARIF requires startLine >= 1.
	Region *sarifRegion `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func severityToSARIFLevel(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical, scanner.SeverityHigh:
		return "error"
	case scanner.SeverityMedium:
		return "warning"
	case scanner.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// sarifURI converts an absolute path to a URI relative to the scan target.
func sarifURI(scanTarget, path string) string {
	uri := path
	if filepath.IsAbs(uri) {
		if rel, err := filepath.Rel(scanTarget, uri); err == nil {
			uri = rel
		}
	}
	return strings.ReplaceAll(uri, "\\", "/")
}

// sarifRuleID returns the ID of the rule a finding's result points at: the ID
// of the pattern that raised the finding, without the line and offset the
// finding's own ID adds, so that code scanning groups results by pattern and
// a result keeps its rule when a line above it moves. A finding built without
// a pattern ID is its own rule.
func sarifRuleID(f scanner.Finding) string {
	if f.PatternID != "" {
		return f.PatternID
	}
	return f.ID
}

// newSARIFRule describes the rule id from the scanner's pattern of that ID,
// which says the same for every result of the rule: a finding's severity is
// lowered by where its match sits, and a trust finding's description and
// remediation depend on the key rule it met. An ID that names no pattern,
// that of a finding built without a pattern ID, is described from first, the
// finding of the rule's first result.
func newSARIFRule(id string, first scanner.Finding) sarifRule {
	p, ok := scanner.LookupPattern(id)
	if !ok {
		p = scanner.PatternInfo{
			ID:          id,
			Name:        first.Type,
			Category:    first.Category,
			Severity:    first.Severity,
			Quantum:     first.Quantum,
			Description: first.Description,
			Remediation: first.Remediation,
			References:  first.References,
			Tags:        first.Tags,
		}
	}
	// A trust rule's one reference is its finding page.
	helpURI := ""
	if p.Category == types.CategoryTrust && len(p.References) > 0 {
		helpURI = p.References[0]
	}
	return sarifRule{
		ID:      id,
		Name:    p.Name,
		HelpURI: helpURI,
		ShortDescription: sarifMessage{
			Text: p.Description,
		},
		FullDescription: sarifMessage{
			Text: p.Description,
		},
		Help: sarifMessage{
			Text: p.Remediation,
		},
		DefaultConfig: sarifDefaultConfig{
			Level: severityToSARIFLevel(p.Severity),
		},
		Properties: sarifRuleProperties{
			Tags:        p.Tags,
			QuantumRisk: string(p.Quantum),
			Category:    p.Category,
		},
	}
}

// Generate creates the SARIF report
func (r *SARIFReporter) Generate(results *scanner.Results) (string, error) {
	// One rule per pattern that has a result, in the order of its first
	// result, so that an unchanged tree produces the same rules array.
	ruleIndex := make(map[string]int)
	rules := make([]sarifRule, 0)
	for _, f := range results.Findings {
		id := sarifRuleID(f)
		if _, seen := ruleIndex[id]; !seen {
			ruleIndex[id] = len(rules)
			rules = append(rules, newSARIFRule(id, f))
		}
	}

	// Build results
	sarifResults := make([]sarifResult, 0, len(results.Findings))
	for _, f := range results.Findings {
		uri := sarifURI(results.ScanTarget, f.File)
		ruleID := sarifRuleID(f)

		// A finding whose description is not its rule's, such as a trust
		// finding on a certificate signed by a listed key, under the pattern
		// that describes a certificate whose own key is listed, adds its own.
		rule := rules[ruleIndex[ruleID]]
		message := fmt.Sprintf("%s: %s", f.Type, f.Match)
		if f.Description != "" && f.Description != rule.FullDescription.Text {
			message += ". " + f.Description
		}
		// So does a finding whose remediation is not its rule's help: a trust
		// finding's remediation is the action for the use of the listed key
		// it matched, where the help of TRUST-COMPROMISED-KEY-001 gives the
		// action for a TLS key and for a code-signing key, and the removed
		// root's own certificate gets the action for each kind of file that
		// holds it, where the help of TRUST-DISTRUSTED-ROOT-001 is the action
		// for a certificate the root signed.
		if f.Remediation != "" && f.Remediation != rule.Help.Text {
			if !strings.HasSuffix(message, ".") {
				message += "."
			}
			message += " Remediation: " + f.Remediation
		}

		result := sarifResult{
			RuleID: ruleID,
			Level:  severityToSARIFLevel(f.Severity),
			Message: sarifMessage{
				Text: message,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: uri,
						},
						Region: &sarifRegion{
							StartLine:   f.Line,
							StartColumn: f.Column,
						},
					},
				},
			},
			Properties: sarifResultProps{
				FindingID:   f.ID,
				QuantumRisk: string(f.Quantum),
				Algorithm:   f.Algorithm,
				KeySize:     f.KeySize,
			},
		}
		if f.IsTrust() {
			md := f.Metadata
			result.Properties.Kind = md["kind"]
			result.Properties.MatchedValue = md["matchedValue"]
			result.Properties.ValueType = md["valueType"]
			result.Properties.IssuerSPKISHA256 = md["issuerSpkiSha256"]
			result.Properties.KeyUse = md["keyUse"]
			result.Properties.TrustRule, _ = strconv.Atoi(md["trustRule"])
			result.Properties.DistrustDate = md["distrustDate"]
		}
		sarifResults = append(sarifResults, result)
	}

	// The run itself completed, so executionSuccessful stays true; each file
	// that could not be analyzed is an error-level notification.
	var invocations []sarifInvocation
	if len(results.UnanalyzedFiles) > 0 {
		notifications := make([]sarifNotification, 0, len(results.UnanalyzedFiles))
		for _, u := range results.UnanalyzedFiles {
			location := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: sarifURI(results.ScanTarget, u.File)},
				},
			}
			if u.Line > 0 {
				location.PhysicalLocation.Region = &sarifRegion{StartLine: u.Line}
			}
			notifications = append(notifications, sarifNotification{
				Level:     "error",
				Message:   sarifMessage{Text: "File could not be analyzed, so findings for it may be incomplete: " + u.Reason},
				Locations: []sarifLocation{location},
			})
		}
		invocations = []sarifInvocation{{
			ExecutionSuccessful:        true,
			ToolExecutionNotifications: notifications,
		}}
	}
	if cfg := sarifConfigInvocations(results.Config); len(cfg) > 0 {
		if len(invocations) == 0 {
			invocations = cfg
		} else {
			invocations[0].ToolConfigurationNotifications = cfg[0].ToolConfigurationNotifications
			invocations[0].Properties = cfg[0].Properties
		}
	}
	// The directories the default rules left out are a matter of how the
	// tool is configured, so the note goes with the config file's, and the
	// counts go in the invocation's properties for a consumer to read.
	if results.Skipped.Files > 0 {
		if len(invocations) == 0 {
			invocations = []sarifInvocation{{ExecutionSuccessful: true}}
		}
		invocations[0].ToolConfigurationNotifications = append(invocations[0].ToolConfigurationNotifications, sarifNotification{
			Level:   "note",
			Message: sarifMessage{Text: SkippedDirectoriesSummary(results.Skipped) + " " + IncludeSkippedHint},
		})
		if invocations[0].Properties == nil {
			invocations[0].Properties = &sarifInvocationProperties{}
		}
		skipped := results.Skipped
		invocations[0].Properties.Skipped = &skipped
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "CryptoScan",
						Version:         version.Get(),
						SemanticVersion: version.Get(),
						InformationURI:  "https://qramm.org",
						Rules:           rules,
					},
				},
				Invocations: invocations,
				Results:     sarifResults,
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// sarifConfigInvocations describes the applied config file as a SARIF
// invocation, or returns nil when no config file was applied. The notification
// is a warning when the file removed findings or kept files out of the scan.
func sarifConfigInvocations(c *scanner.ConfigReport) []sarifInvocation {
	if c == nil {
		return nil
	}

	text := fmt.Sprintf("Config file %s applied (%s).", c.Path, configSourceText(c.Source))
	level := "note"
	if effects := configEffects(c); len(effects) > 0 {
		text += " " + strings.Join(effects, "; ") + "."
		level = "warning"
	} else {
		text += " It removed no findings and kept no files out of the scan."
	}

	return []sarifInvocation{
		{
			ExecutionSuccessful: true,
			ToolConfigurationNotifications: []sarifNotification{
				{Level: level, Message: sarifMessage{Text: text}},
			},
			Properties: &sarifInvocationProperties{ConfigFile: c},
		},
	}
}
