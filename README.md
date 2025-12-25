# CryptoScan

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)

**CryptoScan** is a powerful command-line tool for discovering cryptographic algorithms, key sizes, and quantum-vulnerable patterns in codebases. Part of the [QRAMM](https://qramm.org) (Quantum Readiness Assessment Maturity Model) toolkit by [CSNP](https://csnp.org).

## Features

- **Quantum Risk Assessment**: Identifies cryptographic implementations vulnerable to quantum computing attacks
- **Comprehensive Detection**: Scans for 30+ cryptographic patterns including:
  - Asymmetric algorithms: RSA, ECDSA, DSA, DH, ECDH, Ed25519
  - Symmetric algorithms: AES, DES, 3DES, RC4, Blowfish, ChaCha20
  - Hash functions: MD5, SHA-1, SHA-2 family, SHA-3
  - TLS/SSL configurations and cipher suites
  - Crypto library imports (Python, Java, Go, Node.js, OpenSSL)
  - Private keys and certificates in source code
- **Multiple Output Formats**:
  - Text (human-readable with color)
  - JSON (for programmatic processing)
  - SARIF (for security tool integration)
  - CBOM (Cryptographic Bill of Materials - CycloneDX format)
- **Flexible Scanning**: Include/exclude patterns, severity filtering, directory depth limits

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
  -f, --format string       Output format: text, json, sarif, cbom (default "text")
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

## About QRAMM

The Quantum Readiness Assessment Maturity Model (QRAMM) is a comprehensive framework developed by [CSNP](https://csnp.org) to help organizations prepare for post-quantum cryptography. Learn more at [qramm.org](https://qramm.org).

## Related Resources

- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
