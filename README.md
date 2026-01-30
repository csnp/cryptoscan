<h1 align="center">CryptoScan</h1>

<h3 align="center">Cryptographic Discovery for the Post-Quantum Era</h3>

<p align="center">
  <strong>Find every cryptographic algorithm in your codebase. Know your quantum risk. Get a Migration Readiness Score. Plan your migration.</strong>
</p>

<p align="center">
  <a href="https://github.com/csnp/cryptoscan/actions/workflows/ci.yml"><img src="https://github.com/csnp/cryptoscan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/csnp/cryptoscan"><img src="https://goreportcard.com/badge/github.com/csnp/cryptoscan?v=2" alt="Go Report Card"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white" alt="Go Version"></a>
</p>

<p align="center">
  <a href="#why-cryptoscan">Why CryptoScan</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="https://qramm.org/learn/cryptoscan-guide.html">Full Documentation</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## The Quantum Computing Challenge

**Quantum computers will break RSA, ECDSA, and Diffie-Hellman within the next decade.** This isn't speculation—the NSA, NIST, and major technology companies are already migrating to post-quantum cryptography (PQC).

The challenge? **You can't migrate what you can't find.**

Most organizations have no visibility into which cryptographic algorithms are used across their codebases, configurations, and dependencies. CryptoScan solves this by providing a complete cryptographic inventory in seconds—with full source code context so you know exactly what needs to change and where.

## Why CryptoScan

CryptoScan is purpose-built for quantum readiness assessment:

| Capability | CryptoScan | grep/ripgrep | Commercial Tools |
|------------|:----------:|:------------:|:----------------:|
| Remote Git URL scanning | **Yes** | No | Some |
| Source code context | **Yes** | No | Rarely |
| Quantum risk classification | **Yes** | No | Some |
| **Post-Quantum Crypto detection** | **Yes** | No | Rarely |
| **Migration Readiness Score** | **Yes** | No | No |
| **Hybrid crypto recognition** | **Yes** | No | Rarely |
| **QRAMM framework mapping** | **Yes** | No | No |
| Context-aware confidence | **Yes** | No | Varies |
| CBOM output | **Yes** | No | Rarely |
| SARIF for GitHub Security | **Yes** | No | Yes |
| Inline ignore comments | **Yes** | No | Some |
| Migration guidance | **Yes** | No | Varies |
| Dependency scanning | **Yes** | No | Some |
| Open source | **Yes** | Yes | No |

### What These Capabilities Mean

<details>
<summary><strong>Click to expand capability descriptions</strong></summary>

**Remote Git URL scanning** — Scan any public or private Git repository directly by URL without cloning it first. Just run `cryptoscan scan https://github.com/org/repo.git` and get results immediately.

**Source code context** — Every finding includes the 3 lines before and after the match, so you can immediately understand the context without opening the file. Know if it's in a comment, test, or production code at a glance.

**Quantum risk classification** — Each finding is tagged with its quantum computing threat level: VULNERABLE (broken by Shor's algorithm), PARTIAL (weakened by Grover's algorithm), SAFE (quantum-resistant), or UNKNOWN. This tells you exactly what needs to migrate first.

**Post-Quantum Crypto detection** — Detects NIST-standardized PQC algorithms including ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and draft FN-DSA (FIPS 206). Also detects stateful hash-based signatures (XMSS, LMS per SP 800-208). Recognizes both new FIPS names and legacy names (Kyber, Dilithium, SPHINCS+).

**Migration Readiness Score** — Get an instant percentage score showing how prepared your codebase is for the post-quantum transition. The score weighs quantum-safe algorithms (100%), hybrid implementations (80%), and partial safety (30%) against vulnerable and critical findings. Includes top-risk files to prioritize.

**Hybrid crypto recognition** — Identifies hybrid cryptographic implementations that combine classical and post-quantum algorithms for defense-in-depth. Detects patterns like X25519+ML-KEM key exchange and ECDSA+ML-DSA composite signatures—the recommended transition approach.

**QRAMM framework mapping** — Maps all findings to the Quantum Readiness Assurance Maturity Model (QRAMM) Dimension 1: Cryptographic Visibility & Inventory. Shows your maturity level for Discovery (Practice 1.1), Vulnerability Assessment (Practice 1.2), and Dependency Mapping (Practice 1.3).

**Context-aware confidence** — Not all matches are equal. CryptoScan reduces confidence for findings in comments, documentation, log messages, and test files. High-confidence findings in production code are prioritized over low-confidence matches in docs.

**CBOM output** — Generate a Cryptographic Bill of Materials—a machine-readable inventory of all cryptographic algorithms in your codebase. Required for federal compliance (OMB M-23-02) and essential for tracking quantum migration progress.

**SARIF for GitHub Security** — Output findings in SARIF format for direct integration with GitHub Code Scanning. See cryptographic issues as security alerts in your pull requests and repository Security tab.

**Inline ignore comments** — Suppress false positives directly in your code with `// cryptoscan:ignore`. No need to maintain separate exclusion files or configure complex ignore rules.

**Migration guidance** — Every finding includes specific remediation advice: which NIST PQC algorithm to migrate to (ML-KEM, ML-DSA, SLH-DSA), links to standards, and effort estimates.

**Dependency scanning** — Scans package manifests (package.json, go.mod, requirements.txt, pom.xml, etc.) to identify crypto libraries in your dependencies. Covers 20+ package manager formats.

</details>

## Quick Start

### Installation

#### Option 1: Build from Source

Requires **Go 1.21+** ([install Go](https://go.dev/dl/)) — always use the latest patch version for security fixes

Copy and paste this entire block:

```bash
git clone https://github.com/csnp/cryptoscan.git
cd cryptoscan
go build -o cryptoscan ./cmd/cryptoscan
sudo mv cryptoscan /usr/local/bin/
cd ..
cryptoscan version
```

#### Option 2: Go Install

For Go developers:

```bash
go install github.com/csnp/cryptoscan/cmd/cryptoscan@latest
```

#### Option 3: Download Binary

Download pre-built binaries from [GitHub Releases](https://github.com/csnp/cryptoscan/releases/latest).

### Basic Usage

```bash
# Scan a local directory
cryptoscan scan .

# Scan a remote Git repository
cryptoscan scan https://github.com/your-org/your-repo.git

# Output to JSON for automation
cryptoscan scan . --format json --output findings.json

# Generate SARIF for GitHub Security integration
cryptoscan scan . --format sarif --output results.sarif
```

### Try It Out

This repository includes sample cryptographic code for testing:

```bash
# Clone and build
git clone https://github.com/csnp/cryptoscan.git
cd cryptoscan
go build -o cryptoscan ./cmd/cryptoscan

# Scan the sample files (Go, Python, Java, JavaScript)
./cryptoscan scan ./crypto-samples

# Expected: ~100+ findings showing various crypto patterns including:
# - Post-Quantum: ML-KEM, ML-DSA, SLH-DSA, XMSS, LMS
# - Hybrid: X25519+ML-KEM, ECDSA+ML-DSA composite
# - Quantum vulnerable: RSA, ECDSA, Ed25519
# - MACs: HMAC-SHA256/512, KMAC
# - KDFs: HKDF, PBKDF2, Argon2id, bcrypt
# - With Migration Readiness Score and QRAMM mapping
```

## Features

### Comprehensive Detection

CryptoScan identifies cryptographic usage across your entire technology stack:

| Category | What We Detect |
|----------|----------------|
| **Post-Quantum Cryptography** | ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), FN-DSA (Falcon), XMSS, LMS |
| **Hybrid Cryptography** | X25519+ML-KEM, ECDSA+ML-DSA composite signatures, hybrid TLS key exchange |
| **Asymmetric Encryption** | RSA (all key sizes), ECDSA, DSA, DH, ECDH, Ed25519, X25519 |
| **Symmetric Encryption** | AES (CBC, GCM, ECB, CTR), ChaCha20-Poly1305, DES, 3DES, RC4, Blowfish |
| **Hash Functions** | SHA-2, SHA-3, SHAKE128/256, BLAKE2, BLAKE3, MD5, SHA-1 |
| **MACs** | HMAC-SHA256/384/512, HMAC-SHA3, KMAC128/256, CMAC, GMAC, Poly1305 |
| **Key Derivation (KDFs)** | HKDF, PBKDF2, Argon2id, scrypt, bcrypt |
| **TLS/SSL** | Protocol versions, cipher suites, weak configurations |
| **Key Material** | Private keys (RSA, EC, SSH, PGP, PKCS#8), JWT secrets, HMAC keys |
| **Cloud KMS** | AWS KMS, Azure Key Vault, GCP Cloud KMS, HashiCorp Vault |
| **Dependencies** | Crypto libraries across 20+ package managers |
| **Configurations** | Hardcoded key sizes, algorithm selections, TLS settings |

**[100+ detection patterns](PATTERNS.md)** with context-aware confidence scoring to minimize false positives.

### Quantum Risk Classification

Every finding is classified by quantum computing threat level:

| Risk Level | Meaning | Threat | Recommended Action |
|------------|---------|--------|-------------------|
| **VULNERABLE** | Broken by quantum computers | Shor's algorithm | Migrate to PQC now |
| **PARTIAL** | Security reduced by quantum | Grover's algorithm | Increase key sizes |
| **HYBRID** | Combined classical + PQC | Defense in depth | Good transition approach |
| **SAFE** | Quantum-resistant | N/A | No action needed |
| **UNKNOWN** | Cannot determine | Unknown | Manual review required |

### Migration Readiness Score

CryptoScan calculates a **Migration Readiness Score** that tells you at a glance how prepared your codebase is for the post-quantum transition:

```
═══════════════════════════════════════════════════════════════════════════════
                         MIGRATION READINESS SCORE
═══════════════════════════════════════════════════════════════════════════════

  Score: 41.9%  [██████████░░░░░░░░░░░░░░░░░░░░]  CRITICAL

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  Safe (Quantum-Resistant)     33  ████████████████████████████████      │
  │  Hybrid (Transition)           4  ████                                  │
  │  Partial (Needs Upgrade)      44  ████████████████████████████████████  │
  │  Vulnerable (Quantum Risk)    28  ████████████████████████████          │
  │  Critical (Immediate Risk)     9  █████████                             │
  └─────────────────────────────────────────────────────────────────────────┘
```

The score formula: `(Safe + Hybrid×0.8 + Partial×0.3) / Total × 100`

**Score Levels:**
- **EXCELLENT** (90%+): Ready for post-quantum transition
- **GOOD** (70-89%): Minor remediation needed
- **MODERATE** (50-69%): Significant work required
- **POOR** (30-49%): Major migration effort needed
- **CRITICAL** (<30%): Urgent action required

### QRAMM Framework Integration

CryptoScan maps findings to the **Quantum Readiness Assurance Maturity Model (QRAMM)** Dimension 1: Cryptographic Visibility & Inventory (CVI):

```
  QRAMM CVI Readiness:
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  Practice 1.1 (Discovery)     Level 3/5  ████████████░░░░░░░░           │
  │  Practice 1.2 (Assessment)    Level 3/5  ████████████░░░░░░░░           │
  │  Practice 1.3 (Mapping)       Level 3/5  ████████████░░░░░░░░           │
  └─────────────────────────────────────────────────────────────────────────┘
```

This helps you understand where you stand in your quantum readiness journey using the industry-standard QRAMM framework.

### Context-Aware Analysis

CryptoScan goes beyond simple pattern matching:

- **Source code context**: See 3 lines before and after each finding
- **Confidence scoring**: Findings in comments, logs, or docs are marked low confidence
- **File type awareness**: Different severity for code vs. test vs. documentation
- **Language detection**: 15+ programming languages recognized
- **Noise reduction**: Automatically filters minified files, lock files, and build artifacts

### Multiple Output Formats

```bash
# Human-readable text (default)
cryptoscan scan .

# JSON for automation and integration
cryptoscan scan . --format json --output findings.json

# CSV for spreadsheet analysis
cryptoscan scan . --format csv --output findings.csv

# SARIF for GitHub Code Scanning
cryptoscan scan . --format sarif --output results.sarif

# CBOM (Cryptographic Bill of Materials) for compliance
cryptoscan scan . --format cbom --output crypto-bom.json
```

## Documentation

> **Full Documentation**: For comprehensive guides, tutorials, and examples, visit **[qramm.org/learn/cryptoscan-guide](https://qramm.org/learn/cryptoscan-guide.html)**

### CLI Reference

```
cryptoscan scan [path] [flags]

Arguments:
  path    Local directory, file, or Git URL to scan (default: current directory)

Flags:
  -f, --format string       Output format: text, json, csv, sarif, cbom (default "text")
  -o, --output string       Output file path (default: stdout)
  -i, --include string      File patterns to include (comma-separated globs)
  -e, --exclude string      File patterns to exclude (comma-separated globs)
  -d, --max-depth int       Maximum directory depth (0 = unlimited)
  -g, --group-by string     Group output by: file, severity, category, quantum
  -c, --context int         Lines of source context to show (default 3)
  -p, --progress            Show scan progress indicator
      --min-severity string Minimum severity to report: info, low, medium, high, critical
      --no-color            Disable colored output
      --pretty              Pretty print JSON output
  -h, --help                Show help
```

### Common Workflows

```bash
# Focus on high-priority issues only
cryptoscan scan . --min-severity high

# Scan and group findings by file for review
cryptoscan scan . --group-by file

# Scan only specific file types
cryptoscan scan . --include "*.go,*.py,*.java,*.js,*.ts"

# Exclude vendor and test directories
cryptoscan scan . --exclude "vendor/*,node_modules/*,*_test.go"

# CI/CD: Fail if critical issues found
cryptoscan scan . --min-severity critical --format json | jq '.findings | length'
```

### Suppressing False Positives

Use inline comments to suppress findings that are intentional or not applicable:

```go
// Suppress a specific line
key := rsa.GenerateKey(rand.Reader, 2048) // cryptoscan:ignore

// Suppress the next line
// cryptoscan:ignore-next-line
legacyKey := oldCrypto.NewKey()
```

Supported directives:
- `cryptoscan:ignore` — Ignore finding on this line
- `cryptoscan:ignore-next-line` — Ignore finding on the following line
- `crypto-scan:ignore` — Alternative format
- `noscan` — Quick ignore

### CI/CD Integration

#### GitHub Actions with SARIF

```yaml
# .github/workflows/crypto-scan.yml
name: Cryptographic Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  crypto-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install CryptoScan
        run: go install github.com/csnp/cryptoscan/cmd/cryptoscan@latest

      - name: Run Scan
        run: cryptoscan scan . --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

#### GitLab CI

```yaml
crypto-scan:
  stage: security
  image: golang:1.21
  script:
    - go install github.com/csnp/cryptoscan/cmd/cryptoscan@latest
    - cryptoscan scan . --format json --output crypto-findings.json
  artifacts:
    reports:
      sast: crypto-findings.json
    paths:
      - crypto-findings.json
```

#### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

if command -v cryptoscan &> /dev/null; then
    cryptoscan scan . --min-severity critical --format text
    if [ $? -ne 0 ]; then
        echo "Critical cryptographic issues found. Commit blocked."
        exit 1
    fi
fi
```

### Output Formats Explained

#### SARIF (Static Analysis Results Interchange Format)

SARIF output integrates with GitHub Code Scanning, VS Code SARIF Viewer, and other security tools:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CryptoScan",
        "informationUri": "https://github.com/csnp/cryptoscan"
      }
    },
    "results": [...]
  }]
}
```

#### CBOM (Cryptographic Bill of Materials)

**What is CBOM?** Just as an SBOM (Software Bill of Materials) inventories your software dependencies, a CBOM inventories all cryptographic algorithms, keys, and certificates in your systems. It answers: "What cryptography are we using, where, and is it quantum-safe?"

**Why it matters:**
- **Compliance**: Required by emerging regulations (OMB M-23-02, NIST guidelines) for federal contractors and regulated industries
- **Visibility**: Single source of truth for all cryptographic assets across your organization
- **Migration Planning**: Identifies exactly what needs to change for post-quantum readiness
- **Audit Trail**: Documented evidence of cryptographic posture for security assessments

```json
{
  "bomFormat": "CryptoBOM",
  "specVersion": "1.0",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "timestamp": "2025-01-15T10:30:00Z",
  "components": [
    {
      "type": "algorithm",
      "name": "RSA-2048",
      "category": "asymmetric",
      "quantumSafe": false,
      "occurrences": 12,
      "locations": ["src/auth/jwt.go:45", "src/tls/config.go:23"]
    },
    {
      "type": "algorithm",
      "name": "AES-256-GCM",
      "category": "symmetric",
      "quantumSafe": true,
      "occurrences": 8,
      "locations": ["src/crypto/encrypt.go:67"]
    }
  ],
  "summary": {
    "totalAlgorithms": 15,
    "quantumVulnerable": 7,
    "quantumSafe": 8
  }
}
```

### Architecture

```
cryptoscan/
├── cmd/cryptoscan/      # CLI entry point
├── internal/cli/        # Command implementations
├── pkg/
│   ├── analyzer/        # File context, line analysis, and migration scoring
│   ├── patterns/        # Cryptographic pattern definitions (100+)
│   ├── reporter/        # Output formatters (text, json, csv, sarif, cbom)
│   ├── scanner/         # Core scanning engine with parallel processing
│   └── types/           # Shared type definitions (findings, QRAMM mappings)
└── crypto-samples/      # Sample files for testing (PQC, MACs, KDFs, hybrid)
```

## Roadmap

### v1.1 (Current Release)
- [x] Local and remote repository scanning
- [x] 100+ cryptographic patterns (expanded from 50+)
- [x] Multiple output formats (text, JSON, CSV, SARIF, CBOM)
- [x] Context-aware analysis with confidence scoring
- [x] Dependency scanning for 20+ package managers
- [x] Parallel scanning with worker pools
- [x] Inline ignore comments
- [x] **NEW: Post-Quantum Cryptography detection (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, XMSS, LMS)**
- [x] **NEW: Hybrid cryptography recognition (X25519+ML-KEM, composite signatures)**
- [x] **NEW: Comprehensive MAC detection (HMAC, KMAC, CMAC, GMAC, Poly1305)**
- [x] **NEW: KDF detection (HKDF, PBKDF2, Argon2id, scrypt, bcrypt)**
- [x] **NEW: Migration Readiness Score with visual dashboard**
- [x] **NEW: QRAMM framework integration (CVI Dimension mapping)**

### v1.2 (Next)
- [ ] Smart remediation engine with language-specific recommendations
- [ ] Enhanced CBOM output (CycloneDX 1.6 cryptoProperties)
- [ ] Git history scanning (find crypto in past commits)
- [ ] Configuration file templates

### v2.0 (Future)
- [ ] AWS resource scanning (KMS, ACM, Secrets Manager)
- [ ] Azure resource scanning (Key Vault, App Configuration)
- [ ] GCP resource scanning (Cloud KMS, Secret Manager)
- [ ] Infrastructure-as-Code analysis (Terraform, CloudFormation, Pulumi)
- [ ] Certificate chain analysis

## Contributing

We welcome contributions from the community! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/csnp/cryptoscan.git
cd cryptoscan

# Install dependencies
go mod download

# Run tests
go test -race ./...

# Build
go build -o cryptoscan ./cmd/cryptoscan

# Run linter
golangci-lint run
```

### Adding New Patterns

New detection patterns are added in `pkg/patterns/matcher.go`. Each pattern includes:

- Unique ID and descriptive name
- Category classification
- Compiled regex
- Severity and quantum risk levels
- Description and remediation guidance
- References to standards or documentation

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed instructions.

## About CSNP

CryptoScan is developed by the **CyberSecurity NonProfit (CSNP)**, a 501(c)(3) organization dedicated to making cybersecurity knowledge accessible to everyone through education, community, and practical resources.

### Our Mission

We believe that:

- **Accessibility**: Cybersecurity knowledge should be available to everyone, regardless of background or resources
- **Community**: Supportive communities help people learn, share knowledge, and grow together
- **Education**: Practical, actionable learning resources empower people to implement better security
- **Integrity**: The highest ethical standards in all operations and educational content

### QRAMM Toolkit

CryptoScan is part of the **Quantum Readiness Assurance Maturity Model (QRAMM)** toolkit—a suite of open-source tools designed to help organizations prepare for the post-quantum era:

- **CryptoScan** — Cryptographic discovery scanner (this project)
- **[CryptoDeps](https://github.com/csnp/qramm-cryptodeps)** — Quantum-safe dependency analysis for your software supply chain
- **QRAMM Assessment** — Quantum readiness maturity assessment
- **[TLS Analyzer](https://github.com/csnp/qramm-tls-analyzer)** — TLS/SSL configuration analysis with CNSA 2.0 compliance tracking

Learn more at [qramm.org](https://qramm.org) and [csnp.org](https://csnp.org).

## References

### NIST Post-Quantum Cryptography Standards

- [FIPS 203 - ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)](https://csrc.nist.gov/pubs/fips/203/final) — Replaces RSA/ECDH for key exchange
- [FIPS 204 - ML-DSA (Module-Lattice-Based Digital Signature Algorithm)](https://csrc.nist.gov/pubs/fips/204/final) — Replaces RSA/ECDSA for signatures
- [FIPS 205 - SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)](https://csrc.nist.gov/pubs/fips/205/final) — Alternative signature scheme
- [FIPS 206 - FN-DSA (FFT-Based Network Digital Signature Algorithm)](https://csrc.nist.gov/pubs/fips/206/ipd) — Draft standard (formerly Falcon)
- [SP 800-208 - XMSS and LMS Hash-Based Signatures](https://csrc.nist.gov/pubs/sp/800/208/final) — Stateful hash-based signatures
- [NIST SP 800-131A Rev 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) — Transitioning cryptographic algorithms and key lengths

### Additional Resources

- [NSA Cybersecurity Advisory on Post-Quantum Cryptography](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

Copyright 2025 CyberSecurity NonProfit (CSNP)

---

<p align="center">
  <sub>Built with purpose by <a href="https://csnp.org">CSNP</a> — Advancing cybersecurity for everyone</sub>
</p>

<p align="center">
  <a href="https://qramm.org">QRAMM</a> •
  <a href="https://csnp.org">CSNP</a> •
  <a href="https://github.com/csnp/cryptoscan/issues">Issues</a> •
  <a href="https://twitter.com/csnp_org">Twitter</a>
</p>
