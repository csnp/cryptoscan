// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/csnp/cryptoscan/pkg/scanner"
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
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
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
	DefaultConfig    sarifDefaultConfig  `json:"defaultConfiguration"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags         []string `json:"tags,omitempty"`
	QuantumRisk  string   `json:"quantumRisk,omitempty"`
	Category     string   `json:"category,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string             `json:"ruleId"`
	Level     string             `json:"level"`
	Message   sarifMessage       `json:"message"`
	Locations []sarifLocation    `json:"locations"`
	Properties sarifResultProps  `json:"properties,omitempty"`
}

type sarifResultProps struct {
	QuantumRisk string `json:"quantumRisk,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
	KeySize     int    `json:"keySize,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
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

// Generate creates the SARIF report
func (r *SARIFReporter) Generate(results *scanner.Results) (string, error) {
	// Build rules from unique finding types
	rulesMap := make(map[string]sarifRule)
	for _, f := range results.Findings {
		if _, exists := rulesMap[f.ID]; !exists {
			rulesMap[f.ID] = sarifRule{
				ID:   f.ID,
				Name: f.Type,
				ShortDescription: sarifMessage{
					Text: f.Description,
				},
				FullDescription: sarifMessage{
					Text: f.Description,
				},
				Help: sarifMessage{
					Text: f.Remediation,
				},
				DefaultConfig: sarifDefaultConfig{
					Level: severityToSARIFLevel(f.Severity),
				},
				Properties: sarifRuleProperties{
					Tags:        f.Tags,
					QuantumRisk: string(f.Quantum),
					Category:    f.Category,
				},
			}
		}
	}

	rules := make([]sarifRule, 0, len(rulesMap))
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	// Build results
	sarifResults := make([]sarifResult, 0, len(results.Findings))
	for _, f := range results.Findings {
		// Convert absolute path to relative URI
		uri := f.File
		if filepath.IsAbs(uri) {
			if rel, err := filepath.Rel(results.ScanTarget, uri); err == nil {
				uri = rel
			}
		}
		uri = strings.ReplaceAll(uri, "\\", "/")

		result := sarifResult{
			RuleID: f.ID,
			Level:  severityToSARIFLevel(f.Severity),
			Message: sarifMessage{
				Text: fmt.Sprintf("%s: %s", f.Type, f.Match),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: uri,
						},
						Region: sarifRegion{
							StartLine:   f.Line,
							StartColumn: f.Column,
						},
					},
				},
			},
			Properties: sarifResultProps{
				QuantumRisk: string(f.Quantum),
				Algorithm:   f.Algorithm,
				KeySize:     f.KeySize,
			},
		}
		sarifResults = append(sarifResults, result)
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "CryptoScan",
						Version:         "1.0.0",
						SemanticVersion: "1.0.0",
						InformationURI:  "https://qramm.org",
						Rules:           rules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
