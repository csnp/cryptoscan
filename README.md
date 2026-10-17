# CryptoScan

[![CI](https://github.com/csnp/cryptoscan/actions/workflows/ci.yml/badge.svg)](https://github.com/csnp/cryptoscan/actions/workflows/ci.yml) [![License](https://img.shields.io/github/license/csnp/cryptoscan)](LICENSE) [![Release](https://img.shields.io/github/v/release/csnp/cryptoscan)](https://github.com/csnp/cryptoscan/releases/latest)

> Part of the **QRAMM** toolkit by CSNP: CryptoScan, [CryptoDeps](https://github.com/csnp/cryptodeps), [TLS Analyzer](https://github.com/csnp/tls-analyzer). Framework: [qramm.org](https://qramm.org).

[Website](https://qramm.org) · [Docs](https://qramm.org/learn/cryptoscan-guide.html) · [Framework](https://github.com/csnp/qramm)

CryptoScan is a command-line scanner that finds the cryptography in your source code and configuration files, sorts each finding by its quantum risk, maps the results to QRAMM Dimension 1 (Cryptographic Visibility and Inventory), and writes them as text, JSON, CSV, SARIF or a CycloneDX CBOM.

It reads the files in the working tree, not Git history (`--git-history` is accepted but not yet implemented), and it does not detect DSA, as `cryptoscan scan --help` states.

Install it with Go (the binary goes into `$(go env GOPATH)/bin`), then scan the sample files that come with this repository:

```bash
go install github.com/csnp/cryptoscan/cmd/cryptoscan@latest
git clone https://github.com/csnp/cryptoscan.git && cd cryptoscan
cryptoscan scan crypto-samples
```

What `cryptoscan scan crypto-samples` prints, trimmed ([full output](docs/captures/scan-crypto-samples.txt)):

```text
  Scanning... (findings appear as discovered)

  [INFO] #1   ML-KEM Key Encapsul... ...scan/crypto-samples/pqc_algorithms.py:5   
  [INFO] #2   Post-Quantum Crypto... ...oscan/crypto-samples/hybrid_crypto.js:5   
  [INFO] #3   Post-Quantum Crypto... ...scan/crypto-samples/pqc_algorithms.py:7   
  ...

  Scan complete: 121 findings in 6 files (16ms)


╔═══════════════════════════════════════════════════════════════╗
║              CRYPTOGRAPHIC SCAN RESULTS                       ║
║                    QRAMM CryptoScan                           ║
╚═══════════════════════════════════════════════════════════════╝

┌─ QUANTUM MIGRATION READINESS ──────────────────────────────────┐
│  Score: █████████░░░░░░░░░░░░░░░░ 37.5% [CRITICAL]│
│─────────────────────────────────────────────────────────────────│
│  INVENTORY                                                     │
│    ✓ Safe (PQC):        32       ✗ Vulnerable:    39      │
│    ◐ Hybrid:            3        [!] Critical:      13      │
│    ◑ Partial:           23       Total:          110     │
│─────────────────────────────────────────────────────────────────│
│  QRAMM DIMENSION 1: Cryptographic Visibility & Inventory (CVI) │
│    Practice 1.1 Discovery:   Level 3/5 ●●●○○                    │
│    Practice 1.2 Assessment:  Level 3/5 ●●●○○                    │
│    Practice 1.3 Mapping:     Level 3/5 ●●●○○                    │
│─────────────────────────────────────────────────────────────────│
│  TOP PRIORITY FILES                                            │
│    1. ...scan/crypto-samples/crypto_samples.go   (29 findings)  │
│    2. ...scan/crypto-samples/crypto_samples.py   (21 findings)  │
│    3. ...can/crypto-samples/CryptoSamples.java   (8 findings)  │
│─────────────────────────────────────────────────────────────────│
│  RECOMMENDATIONS                                               │
│    • CRITICAL: Remove broken algorithms (MD5, SHA-1, DES, RC4)...│
│    • Plan migration from quantum-vulnerable algorithms to PQC ...│
└─────────────────────────────────────────────────────────────────┘

┌─ Scan Information ─────────────────────────────────────────────┐
│ Target:   crypto-samples                                      │
  ...
│ Duration: 16ms                                                │
│ Scanned:  6 files • 873 lines • 26.3 KB                       │
│ Speed:    383 files/sec • 1.6 MB/sec                          │
└─────────────────────────────────────────────────────────────────┘
```

Common jobs:

- Scan a project folder: `cryptoscan scan .` ([command reference](docs/commands.md#commands))
- Scan a remote repository: `cryptoscan scan https://github.com/your-org/your-repo.git` ([command reference](docs/commands.md#commands))
- Send findings to GitHub code scanning: `cryptoscan scan . --format sarif --output results.sarif` ([GitHub Actions with SARIF](docs/ci.md#github-actions-with-sarif))
- Write a Cryptographic Bill of Materials: `cryptoscan scan . --format cbom --output crypto-bom.json` ([CBOM output](docs/commands.md#cbom-cryptographic-bill-of-materials))
- Fail a CI build on serious findings: `cryptoscan scan . --fail-on high` ([exit code control](docs/ci.md#exit-code-control))
- Report only findings that are new since a baseline: `cryptoscan scan . --baseline baseline.json` ([baseline workflow](docs/ci.md#baseline-workflow))

The scan exits with code 1 when it finds a CRITICAL issue or hits an error, and 0 otherwise; `--fail-on` changes the threshold (see [Exit codes](docs/commands.md#exit-codes)).

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

The score formula: `(Safe + Hybrid×0.8 + Partial×0.3) / Total × 100`. Every finding counts once; test and example files count the same as production code.

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

`--format` takes `text` (the default), `json`, `csv`, `sarif` or `cbom`, and `--output` writes the report to a file. [Output formats](docs/commands.md#output-formats) shows the command for each and what each one contains.

## Install

The first example on this page installs with `go install`. You can also build from source or download a binary.

### Build from source

Requires Go at the version named in [go.mod](go.mod) or newer ([install Go](https://go.dev/dl/)). Always use the latest patch version for security fixes.

Copy and paste this entire block. It moves the binary into `/usr/local/bin`, so `sudo` asks for your password:

```bash
git clone https://github.com/csnp/cryptoscan.git
cd cryptoscan
go build -o cryptoscan ./cmd/cryptoscan
sudo mv cryptoscan /usr/local/bin/
cd ..
cryptoscan version
```

### Download a binary

Download pre-built binaries from [GitHub Releases](https://github.com/csnp/cryptoscan/releases/latest).

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
