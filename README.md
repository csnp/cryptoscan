<h1 align="center">CryptoScan</h1>

<h3 align="center">Cryptographic Discovery for the Post-Quantum Era</h3>

<p align="center">
  <strong>Inventory the cryptography in your codebase. Know your quantum risk. Get a Migration Readiness Score. Plan your migration.</strong>
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

> **Part of the QRAMM Toolkit**. Open-source tools for quantum readiness:
>
> | Tool | Purpose |
> |------|---------|
> | **[CryptoScan](https://github.com/csnp/cryptoscan)** | Cryptographic discovery in source code ← You are here |
> | **[CryptoDeps](https://github.com/csnp/cryptodeps)** | Quantum-safe dependency analysis for your supply chain |
> | **[TLS-Analyzer](https://github.com/csnp/tls-analyzer)** | TLS/SSL configuration analysis with CNSA 2.0 compliance |
>
> Learn more at [qramm.org](https://qramm.org)

---

## The Quantum Computing Challenge

**Quantum computers will break RSA, ECDSA, and Diffie-Hellman within the next decade.** This isn't speculation. The NSA, NIST, and major technology companies are already migrating to post-quantum cryptography (PQC).

The challenge? **You can't migrate what you can't find.**

Most organizations have no visibility into which cryptographic algorithms are used across their codebases, configurations, and dependencies. CryptoScan solves this by providing a complete cryptographic inventory in seconds, with full source code context so you know exactly what needs to change and where.

## Quick Start

### Installation

#### Option 1: Build from Source

Requires **Go 1.21+** ([install Go](https://go.dev/dl/)). Always use the latest patch version for security fixes.

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

The scan exits with code 1 when it finds a CRITICAL issue or hits an error, and 0 otherwise; `--fail-on` changes the threshold (see Exit codes in the [command reference](docs/commands.md)).

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

### What it detects

CryptoScan identifies cryptographic usage across your technology stack:

| Category | What We Detect |
|----------|----------------|
| **Post-Quantum Cryptography** | ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), FN-DSA (Falcon), XMSS, LMS |
| **Hybrid Cryptography** | X25519+ML-KEM, ECDSA+ML-DSA composite signatures, hybrid TLS key exchange |
| **Asymmetric Encryption** | RSA (all key sizes), ECDSA, DH, ECDH, Ed25519, X25519 |
| **Symmetric Encryption** | AES (CBC, GCM, ECB, CTR), ChaCha20-Poly1305, DES, 3DES, RC4, Blowfish |
| **Hash Functions** | SHA-2, SHA-3, SHAKE128/256, BLAKE2, BLAKE3, MD5, SHA-1 |
| **Certificates** | X.509, CSR, PKCS#12/PFX, certificate chains, mTLS, validation bypass, expiration, JWK |
| **TLS/SSL** | Protocol versions, cipher suites, weak configurations, certificate pinning |
| **Key Material** | Private keys (RSA, EC, SSH, PGP, PKCS#8), JWT secrets, HMAC keys |
| **Dependencies** | Crypto libraries across 20+ package managers |

DSA is not detected, and detection matches whole words only, so a compound identifier such as `RSAPrivateKey` is not matched. MACs, key derivation, cloud KMS and configuration patterns are in the full detection table in [How CryptoScan works](docs/how-it-works.md), and every pattern is in [PATTERNS.md](PATTERNS.md).

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

CryptoScan calculates a **Migration Readiness Score** that tells you at a glance how prepared your codebase is for the post-quantum transition.

The score formula: `(Safe + Hybrid×0.8 + Partial×0.3) / Total × 100`

The report labels the score CRITICAL when any finding is CRITICAL or the score is below 25%, HIGH below 50%, MEDIUM below 75%, and LOW from 75% up. A sample of the score panel is in [How CryptoScan works](docs/how-it-works.md).

### QRAMM Framework Integration

CryptoScan maps findings to the **Quantum Readiness Assurance Maturity Model (QRAMM)** Dimension 1: Cryptographic Visibility & Inventory (CVI). The report shows a maturity level out of 5 for Practice 1.1 (Discovery), Practice 1.2 (Assessment) and Practice 1.3 (Mapping), so you can see where you stand in your quantum readiness work.

### Context-Aware Analysis

CryptoScan goes beyond simple pattern matching:

- **Source code context**: See 3 lines before and after each finding
- **Confidence scoring**: Findings in comments, logs, or docs are marked low confidence
- **File type awareness**: Different severity for code vs. test vs. documentation
- **Language detection**: 15+ programming languages recognized
- **Noise reduction**: Automatically filters minified files, lock files, and build artifacts

Algorithm names that appear only in prose, logs or comments are held back from the default report, and the scan summary says how many. [How CryptoScan works](docs/how-it-works.md) explains the rule.

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

- [Command reference](docs/commands.md): every command and flag, exit codes, common workflows, and what each output format contains
- [CI/CD integration](docs/ci.md): GitHub Actions, GitLab CI, a pre-commit hook, and failing only on new findings with a baseline
- [Configuration](docs/configuration.md): the `.cryptoscan.yaml` file and inline suppression comments
- [How CryptoScan works](docs/how-it-works.md): what is reported, detection coverage, scoring, architecture, and the maintainers' comparison with other approaches
- [Roadmap](docs/roadmap.md): what is done and what is planned
- [CryptoScan guide on qramm.org](https://qramm.org/learn/cryptoscan-guide.html): tutorials and examples
- [CHANGELOG.md](CHANGELOG.md): what changed in each release, and its known limitations
- [CONTRIBUTING.md](CONTRIBUTING.md): how to contribute

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

CryptoScan is part of the **Quantum Readiness Assurance Maturity Model (QRAMM)** toolkit, a suite of open-source tools designed to help organizations prepare for the post-quantum era:

- **CryptoScan**: Cryptographic discovery scanner (this project)
- **[CryptoDeps](https://github.com/csnp/cryptodeps)**: Quantum-safe dependency analysis for your software supply chain
- **QRAMM Assessment**: Quantum readiness maturity assessment
- **[TLS Analyzer](https://github.com/csnp/tls-analyzer)**: TLS/SSL configuration analysis with CNSA 2.0 compliance tracking

Learn more at [qramm.org](https://qramm.org) and [csnp.org](https://csnp.org).

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

Copyright 2025 CyberSecurity NonProfit (CSNP)

---

<p align="center">
  <sub>Built with purpose by <a href="https://csnp.org">CSNP</a>. Advancing cybersecurity for everyone</sub>
</p>

<p align="center">
  <a href="https://qramm.org">QRAMM</a> •
  <a href="https://csnp.org">CSNP</a> •
  <a href="https://github.com/csnp/cryptoscan/issues">Issues</a> •
  <a href="https://twitter.com/csnp_org">Twitter</a>
</p>
