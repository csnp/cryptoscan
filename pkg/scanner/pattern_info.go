// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"sync"

	"github.com/csnp/cryptoscan/pkg/analyzer"
	"github.com/csnp/cryptoscan/pkg/patterns"
)

// DependencyPatternPrefix starts the pattern ID of a crypto library found in
// a dependency manifest, which is the prefix followed by the library's name,
// as in DEP-crypto-js.
const DependencyPatternPrefix = "DEP-"

// The type and category of every dependency finding.
const (
	dependencyFindingType = "Crypto Library Dependency"
	dependencyCategory    = "dependency"
)

// dependencyTags returns the tags of a dependency finding for lib.
func dependencyTags(lib analyzer.CryptoLibrary) []string {
	tags := []string{"dependency", string(lib.Language)}
	if lib.QuantumSafe {
		tags = append(tags, "pqc-ready")
	}
	return tags
}

// PatternInfo is what the scanner says about every finding of one pattern
// ID. A finding can say something else: the matcher lowers a finding's
// severity by where its match sits, and a trust finding's description and
// remediation depend on the key rule it met.
type PatternInfo struct {
	ID          string
	Name        string
	Category    string
	Severity    Severity
	Quantum     QuantumRisk
	Description string
	Remediation string
	References  []string
	Tags        []string
}

// LookupPattern returns the pattern with the given ID: one that "cryptoscan
// patterns list" prints, or DependencyPatternPrefix followed by the name of
// a library the dependency reader knows. A finding's ID, which adds where the
// finding is, names no pattern.
func LookupPattern(id string) (PatternInfo, bool) {
	info, ok := patternIndex()[id]
	return info, ok
}

// patternIndex maps each pattern ID to its PatternInfo. It is built once, on
// first use.
var patternIndex = sync.OnceValue(func() map[string]PatternInfo {
	index := make(map[string]PatternInfo)
	add := func(info PatternInfo) {
		if _, taken := index[info.ID]; !taken {
			index[info.ID] = info
		}
	}
	for _, p := range patterns.NewMatcher().Patterns() {
		add(PatternInfo{
			ID:          p.ID,
			Name:        p.Name,
			Category:    p.Category,
			Severity:    p.Severity,
			Quantum:     p.Quantum,
			Description: p.Description,
			Remediation: p.Remediation,
			References:  p.References,
			Tags:        p.Tags,
		})
	}
	for _, lib := range analyzer.KnownCryptoLibraries {
		dep := analyzer.LibraryFinding(lib)
		add(PatternInfo{
			ID:          DependencyPatternPrefix + lib.Name,
			Name:        dependencyFindingType,
			Category:    dependencyCategory,
			Severity:    dep.Severity,
			Quantum:     dep.Quantum,
			Description: dep.Description,
			Remediation: dep.Remediation,
			Tags:        dependencyTags(lib),
		})
	}
	return index
})
