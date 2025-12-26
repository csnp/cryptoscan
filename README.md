
<h3 align="center">Discover. Assess. Migrate.</h3>

<p align="center">
  <strong>The open-source cryptographic discovery tool for the post-quantum era</strong>
</p>

<p align="center">
  <a href="https://github.com/csnp/qramm-cryptoscan/actions/workflows/ci.yml"><img src="https://github.com/csnp/qramm-cryptoscan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/csnp/qramm-cryptoscan"><img src="https://codecov.io/gh/csnp/qramm-cryptoscan/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://goreportcard.com/report/github.com/csnp/qramm-cryptoscan"><img src="https://goreportcard.com/badge/github.com/csnp/qramm-cryptoscan" alt="Go Report Card"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white" alt="Go Version"></a>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-why-cryptoscan">Why CryptoScan</a> •
  <a href="#-output-formats">Output Formats</a> •
  <a href="#-docs">Docs</a>
</p>

---

## The Problem

**Quantum computers will break RSA, ECDSA, and DH within the next decade.** The NSA, NIST, and major tech companies are already migrating. But you can't migrate what you can't find.

Crypto Scan solves this by scanning your entire codebase in seconds, identifying every cryptographic algorithm, key, and configuration that needs attention — with full source code context so you can verify findings and know exactly where to make fixes.

## Quick Start

```bash
# Install
go install github.com/csnp/qramm-cryptoscan/cmd/cryptoscan@latest

# Scan your project
cryptoscan scan .

# Scan a remote Git repository
cryptoscan scan https://github.com/org/repo.git

# That's it. You now know your quantum risk.
```

### Try It Out

This repository includes sample cryptographic code for testing the scanner:

```bash
# Clone the repo
git clone https://github.com/csnp/qramm-cryptoscan.git
cd qramm-cryptoscan

# Build the scanner
go build -o cryptoscan ./cmd/cryptoscan

# Scan the sample crypto files (Go, Python, Java)
./cryptoscan scan ./crypto-samples

# Expected: ~35 findings across 3 files showing various crypto patterns
# - Quantum vulnerable: RSA, ECDSA, Ed25519
# - Broken/weak: MD5, SHA-1, DES, 3DES
# - With source context and remediation guidance
```

<details>
<summary><strong>Other installation methods</strong></summary>

```bash
# From source
git clone https://github.com/csnp/qramm-cryptoscan.git
cd qramm-cryptoscan
go build -o cryptoscan ./cmd/cryptoscan
```

</details>

## Features

| Category | What We Find |
|----------|--------------|
| **Asymmetric Crypto** | RSA, ECDSA, DSA, DH, ECDH, Ed25519 |
| **Symmetric Crypto** | AES, DES, 3DES, RC4, Blowfish, ChaCha20 |
| **Hash Functions** | MD5, SHA-1, SHA-2, SHA-3, BLAKE2 |
| **TLS/SSL** | Protocol versions, cipher suites, weak configs |
| **Keys & Secrets** | Private keys (RSA/EC/SSH/PGP), JWT secrets, HMAC keys |
| **Cloud KMS** | AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault |
| **Dependencies** | Crypto libraries in 20+ package manager formats |

**50+ detection patterns** with context-aware confidence scoring.

## Why Crypto Scan

|  | Crypto Scan | grep | Commercial Tools |
|--|-------------|------|------------------|
| **Remote Git URL scanning** | **Yes** | No | Some |
| **Source code context** | **Yes** | No | Rarely |
| Inline ignore comments | Yes | No | Some |
| Group-by-file output | Yes | No | Varies |
| Quantum risk classification | Yes | No | Some |
| Context-aware confidence | Yes | No | Varies |
| CBOM generation | Yes | No | Rarely |
| SARIF integration | Yes | No | Yes |
| Migration guidance | Yes | No | Varies |
| Open source | Yes | Yes | No |
| Price | Free | Free | $$$$ |

## Quantum Risk Levels

Crypto Scan classifies every finding by quantum threat:

| Risk | Meaning | What Breaks It | Action |
|------|---------|----------------|--------|
| **VULNERABLE** | Broken by quantum | Shor's algorithm | Migrate now |
| **PARTIAL** | Weakened by quantum | Grover's algorithm | Double key sizes |
| **SAFE** | Quantum-resistant | N/A | You're good |
| **UNKNOWN** | Needs review | Unknown | Investigate |

## Output Formats

```bash
# Human-readable (default)
cryptoscan scan .

# JSON for automation
cryptoscan scan . --format json --output findings.json

# CSV for spreadsheets
cryptoscan scan . --format csv --output findings.csv

# SARIF for GitHub Security
cryptoscan scan . --format sarif --output results.sarif

# CBOM for compliance
cryptoscan scan . --format cbom --output crypto-bom.json
```

### SARIF + GitHub Code Scanning

```yaml
# .github/workflows/crypto-scan.yml
name: Crypto Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install CryptoScan
        run: go install github.com/csnp/qramm-cryptoscan/cmd/cryptoscan@latest

      - name: Run Scan
        run: cryptoscan scan . --format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## CLI Reference

```
cryptoscan scan [path] [flags]

Flags:
  -f, --format string       Output format: text, json, csv, sarif, cbom (default "text")
  -o, --output string       Output file (default: stdout)
  -i, --include string      File patterns to include (comma-separated)
  -e, --exclude string      File patterns to exclude (comma-separated)
  -d, --max-depth int       Maximum directory depth (0 = unlimited)
  -g, --group-by string     Group output by: file, severity, category, quantum
  -c, --context int         Lines of source context to show (default 3)
  -p, --progress            Show scan progress
      --min-severity string Minimum severity: info, low, medium, high, critical
      --no-color            Disable colored output
      --pretty              Pretty print JSON output
```

### Common Workflows

```bash
# Focus on critical issues
cryptoscan scan . --min-severity high

# Group findings by file for easier review
cryptoscan scan . --group-by file

# Scan only source code
cryptoscan scan . --include "*.go,*.py,*.java,*.js"

# Exclude vendor directories
cryptoscan scan . --exclude "vendor/*,node_modules/*"

# Pre-commit hook
cryptoscan scan . --min-severity critical && echo "Clean!"
```

### Inline Ignore Comments

Suppress false positives with inline comments:

```go
key := rsa.GenerateKey(rand.Reader, 2048) // cryptoscan:ignore

// cryptoscan:ignore-next-line
legacyKey := oldCrypto.NewKey()
```

Supported directives:
- `cryptoscan:ignore` — ignore this line
- `cryptoscan:ignore-next-line` — ignore the following line
- `crypto-scan:ignore` — alternative format
- `noscan` — quick ignore

## Roadmap

### v1.0 (Current)
- [x] Local codebase scanning
- [x] 50+ crypto patterns
- [x] Multiple output formats (text, JSON, CSV, SARIF, CBOM)
- [x] Context-aware analysis
- [x] Dependency scanning

### v1.1
- [ ] Git history scanning
- [x] Remote repository URLs

### v2.0
- [ ] AWS scanning (KMS, ACM, Secrets Manager)
- [ ] Azure scanning (Key Vault)
- [ ] GCP scanning (Cloud KMS, Secret Manager)
- [ ] IaC analysis (Terraform, CloudFormation)

## Part of QRAMM

Crypto Scan is part of the **Quantum Readiness Assurance Maturity Model** toolkit by [CSNP](https://csnp.org).

| Tool | Purpose | Status |
|------|---------|--------|
| **Crypto Scan** | Cryptographic discovery | Available |
| **Crypto CBOM** | Bill of Materials | Planned |
| **TLS Analyzer** | TLS/SSL analysis | Planned |
| **QRAMM CLI** | Assessment interface | Planned |

Learn more at [qramm.org](https://qramm.org)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Run tests
go test -race ./...

# Build
go build -o cryptoscan ./cmd/cryptoscan
```

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

<p align="center">
  <sub>Built with conviction by <a href="https://csnp.org">CSNP</a> — Advancing cybersecurity for everyone</sub>
</p>

<p align="center">
  <a href="https://qramm.org">Website</a> •
  <a href="https://github.com/csnp/qramm-cryptoscan/issues">Issues</a> •
  <a href="https://twitter.com/csnp_org">Twitter</a>
</p>
