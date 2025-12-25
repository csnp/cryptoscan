# CryptoScan

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)

**CryptoScan** is a powerful command-line tool for discovering cryptographic algorithms, key sizes, and quantum-vulnerable patterns in codebases. Part of the [QRAMM](https://qramm.org) (Quantum Readiness Assessment Maturity Model) toolkit by [CSNP](https://csnp.org).

## CSNP Mission

*Advancing cybersecurity through education, research, and open-source tools that empower organizations worldwide.*

## Features

- **Quantum Risk Assessment**: Identifies cryptographic implementations vulnerable to quantum computing attacks
- **Comprehensive Detection**: Scans for 50+ cryptographic patterns including:
  - Asymmetric algorithms: RSA, ECDSA, DSA, DH, ECDH, Ed25519
  - Symmetric algorithms: AES, DES, 3DES, RC4, Blowfish, ChaCha20
  - Hash functions: MD5, SHA-1, SHA-2 family, SHA-3
  - TLS/SSL configurations and cipher suites
  - Crypto library imports (Python, Java, Go, Node.js, OpenSSL)
  - Private keys and certificates (RSA, EC, DSA, SSH, PGP, PKCS#8)
  - Cloud KMS references (AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault)
  - JWT secrets, HMAC keys, and hardcoded encryption keys
  - Weak key derivation (PBKDF with low iterations)
- **Dependency Scanning**: Detects crypto libraries in 20+ dependency manifest formats
- **Context-Aware Analysis**: Adjusts confidence based on file type, language, and code context
- **Multiple Output Formats**:
  - Text (professional CLI with visual indicators)
  - JSON (for programmatic processing)
  - **CSV** (for spreadsheet analysis and reporting)
  - SARIF (for security tool integration)
  - CBOM (Cryptographic Bill of Materials - CycloneDX format)
- **Flexible Scanning**: Include/exclude patterns, severity filtering, directory depth limits
- **Actionable Remediation**: Each finding includes NIST PQC migration guidance

## Installation

### From Source

```bash
git clone https://github.com/csnp/qramm-cryptoscan.git
cd qramm-cryptoscan
go build -o cryptoscan ./cmd/cryptoscan
```

### Using Go Install

```bash
go install github.com/csnp/qramm-cryptoscan/cmd/cryptoscan@latest
```

## Quick Start

```bash
# Scan current directory
cryptoscan scan .

# Scan a specific path
cryptoscan scan /path/to/project

# Output as JSON
cryptoscan scan . --format json --output findings.json

# Generate CBOM (Cryptographic Bill of Materials)
cryptoscan scan . --format cbom --output crypto-bom.json

# Scan only specific file types
cryptoscan scan . --include "*.java,*.py,*.go"

# Exclude directories
cryptoscan scan . --exclude "vendor/*,node_modules/*"

# Only show high and critical findings
cryptoscan scan . --min-severity high
```

## Output Formats

### Text (Default)
Human-readable output with color-coded severity levels and quantum risk indicators.

### JSON
Structured JSON output for integration with other tools:
```json
{
  "findings": [...],
  "summary": {
    "totalFindings": 42,
    "bySeverity": {"CRITICAL": 3, "HIGH": 12, ...},
    "byQuantumRisk": {"VULNERABLE": 25, "PARTIAL": 10, ...}
  }
}
```

### SARIF
[Static Analysis Results Interchange Format](https://sarifweb.azurewebsites.net/) for integration with GitHub Code Scanning, VS Code, and other security tools.

### CBOM
[CycloneDX](https://cyclonedx.org/) Cryptographic Bill of Materials format for tracking cryptographic assets.

## Quantum Risk Classification

| Risk Level | Description | Action Required |
|------------|-------------|-----------------|
| **VULNERABLE** | Algorithm broken by Shor's algorithm | Immediate migration planning |
| **PARTIAL** | Security reduced by Grover's algorithm | Monitor, may need longer keys |
| **SAFE** | Quantum-resistant algorithm | No action needed |
| **UNKNOWN** | Cannot determine quantum risk | Manual review required |

## Severity Levels

- **CRITICAL**: Broken algorithms, exposed secrets, must fix immediately
- **HIGH**: Quantum-vulnerable algorithms requiring migration
- **MEDIUM**: Suboptimal configurations needing attention
- **LOW**: Minor issues or informational findings
- **INFO**: Library imports and configuration patterns to audit

## Command Reference

```
cryptoscan scan [path] [flags]

Flags:
  -f, --format string       Output format: text, json, csv, sarif, cbom (default "text")
  -o, --output string       Output file (default: stdout)
  -i, --include string      File patterns to include (comma-separated)
  -e, --exclude string      File patterns to exclude (comma-separated)
  -d, --max-depth int       Maximum directory depth (0 = unlimited)
  -p, --progress            Show scan progress
      --min-severity string Minimum severity: info, low, medium, high, critical (default "info")
      --no-color            Disable colored output
      --pretty              Pretty print JSON output
      --git-history         Scan Git history (coming soon)
```

### Export to CSV

```bash
# Export findings to CSV for spreadsheet analysis
cryptoscan scan . --format csv --output crypto-findings.csv

# Open in Excel, Google Sheets, or use with pandas
```

## Examples

### CI/CD Integration

```yaml
# GitHub Actions
- name: Run CryptoScan
  run: |
    cryptoscan scan . --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Generate CBOM for Compliance

```bash
cryptoscan scan . --format cbom --output crypto-inventory.json
```

### Pre-commit Hook

```bash
#!/bin/bash
cryptoscan scan . --min-severity high
if [ $? -ne 0 ]; then
  echo "Critical cryptographic issues found!"
  exit 1
fi
```

## Contributing

Contributions are welcome! Please see our [Contributing Guidelines](CONTRIBUTING.md).

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## Roadmap

### Current Release (v1.0)
- Local codebase scanning
- 50+ crypto patterns with quantum risk classification
- Multiple export formats (text, JSON, CSV, SARIF, CBOM)
- Context-aware analysis
- Dependency scanning

### Coming Soon
- **Git History Scanning**: Detect crypto in historical commits
- **Remote Repository Scanning**: Direct GitHub/GitLab URL scanning

### Future Releases
- **Cloud Environment Scanning**:
  - AWS: Scan KMS keys, ACM certificates, Secrets Manager, Parameter Store
  - Azure: Key Vault keys/secrets, App Configuration
  - GCP: Cloud KMS, Secret Manager, Certificate Authority Service
- **Infrastructure-as-Code Analysis**: Terraform, CloudFormation, Pulumi crypto configs
- **Container Image Scanning**: Detect crypto in Docker images
- **API Discovery**: Find crypto endpoints in OpenAPI/Swagger specs

## About QRAMM

The Quantum Readiness Assessment Maturity Model (QRAMM) is a comprehensive framework developed by [CSNP](https://csnp.org) to help organizations prepare for post-quantum cryptography. Learn more at [qramm.org](https://qramm.org).

### QRAMM Toolkit

CryptoScan is part of a planned suite of open-source quantum readiness tools:

| Tool | Purpose | Status |
|------|---------|--------|
| **CryptoScan** | Cryptographic discovery in codebases | Available |
| **CryptoCBOM** | Cryptographic Bill of Materials generator | Planned |
| **TLS-Analyzer** | TLS/SSL configuration analysis | Planned |
| **KeyRotate** | Key rotation automation | Planned |
| **QRAMM-CLI** | Assessment and planning interface | Planned |

## Related Resources

- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
