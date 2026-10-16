# Command reference

This page lists every CryptoScan command and flag, the exit codes, and what each output format contains; for installation and a first scan, start with the [README](../README.md).

## Commands

| Command | What it does |
|---------|--------------|
| `cryptoscan scan <path or URL>` | Scan a directory or repository for cryptographic usage |
| `cryptoscan cbom <path or URL>` | Write a CycloneDX 1.6 Cryptographic Bill of Materials (equivalent to scan --format cbom) |
| `cryptoscan gate <path or URL>` | Fail a build when findings reach a severity (equivalent to scan --fail-on high) |
| `cryptoscan pqc <path or URL>` | Show post-quantum readiness: PQC and hybrid usage found, quantum-vulnerable usage, and the QRAMM Dimension 1 levels |
| `cryptoscan version` | Print version information |
| `cryptoscan completion <shell>` | Generate the autocompletion script for the specified shell |
| `cryptoscan help [command]` | Help about any command |

The shell is one of `bash`, `fish`, `powershell` and `zsh`, and `--no-descriptions` disables completion descriptions. The flags of `cbom`, `gate` and `pqc` are listed after the exit codes below.

## Scan flags

```
cryptoscan scan <path or URL> [flags]
```

The path is required. It is a local directory, a file, or a Git URL to scan; use `.` for the current directory.

The descriptions below are the ones `cryptoscan scan --help` prints. Four flags are accepted but not yet implemented, and their help text says so.

| Flag | Description |
|------|-------------|
| `-f, --format string` | Output format: text, json, csv, sarif, cbom (default "text") |
| `-o, --output string` | Output file (default: stdout) |
| `-i, --include string` | File patterns to include (comma-separated) |
| `-e, --exclude string` | File patterns to exclude (comma-separated) |
| `-d, --max-depth int` | Maximum directory depth (0 = unlimited). NOT YET IMPLEMENTED: the value is accepted and ignored |
| `-g, --group-by string` | Group output by: file. NOT YET IMPLEMENTED: severity, category and quantum are accepted and ignored |
| `-c, --context int` | Number of context lines to show around findings. NOT YET IMPLEMENTED: the report always shows 3 (default 3) |
| `--git-history` | Scan Git history (slower). NOT YET IMPLEMENTED: only the working tree is scanned |
| `-p, --progress` | Show scan progress |
| `--stream` | Show findings as they are discovered (default true) |
| `--min-severity string` | Minimum severity to report: info, low, medium, high, critical (default "info") |
| `--include-imports` | Include library import findings (normally suppressed as low-value) |
| `--include-quantum-safe` | Include quantum-safe algorithm findings (SHA-256, AES-256) |
| `--include-narrative` | Include algorithms named in prose, log messages, documentation and config keys |
| `-v, --verbose` | Show all findings including imports, quantum-safe algorithms and narrative mentions |
| `--no-color` | Disable colored output |
| `--pretty` | Pretty print JSON output |
| `-h, --help` | help for scan |

CI/CD flags:

| Flag | Description |
|------|-------------|
| `--ignore string` | Pattern IDs to ignore (comma-separated, e.g., "RSA-001,CERT-*") |
| `--ignore-category string` | Categories to ignore (comma-separated, e.g., "Certificate,Library Import") |
| `--fail-on string` | Exit non-zero if findings at this severity or higher (info, low, medium, high, critical), or if any file could not be analyzed |
| `--baseline string` | Baseline JSON file - only report new findings |
| `--config string` | Config file path (default: auto-detect .cryptoscan.yaml) |
| `--no-config` | Do not read a config file; use only command-line options |

How these flags are used in a pipeline is in [CI/CD integration](ci.md). The `.cryptoscan.yaml` keys that set the same values are in [Configuration](configuration.md).

## Exit codes

| Code | When |
|------|------|
| `0` | The scan finished and no finding reached the failure threshold. |
| `1` | Without `--fail-on`: at least one CRITICAL finding. With `--fail-on <severity>`: at least one finding at that severity or higher. Also any error, such as a missing path or a baseline file that cannot be read. |

By default the scan exits 1 on any CRITICAL finding and 0 otherwise. `--fail-on` replaces that default, and a `failOn` key in `.cryptoscan.yaml` does the same when the flag is not given. Findings removed by `--baseline`, `--ignore` or `--ignore-category` do not count. The logic is the `exitCode` function in `internal/cli/scan.go`.

An invalid `--fail-on` value is accepted silently in release 1.4.0 (see the known limitations in [CHANGELOG.md](../CHANGELOG.md)), so check the spelling of the severity in your pipeline.

```
cryptoscan cbom [path or URL] [flags]

Writes a CycloneDX 1.6 Cryptographic Bill of Materials (equivalent to
scan --format cbom). Prints only the CBOM JSON. Exits 0 whatever it finds;
non-zero only when the scan or the write fails. To fail a build on findings,
use cryptoscan gate.

Flags:
  -o, --output string           Output file (default: stdout)
  -i, --include string          File patterns to include (comma-separated globs)
  -e, --exclude string          File patterns to exclude (comma-separated globs)
      --ignore string           Pattern IDs to ignore (comma-separated, e.g., "RSA-001,CERT-*")
      --ignore-category string  Categories to ignore (e.g., "Certificate,Library Import")
      --config string           Config file path (default: auto-detect .cryptoscan.yaml)
```

```
cryptoscan gate [path or URL] [flags]

Fails a build when findings reach a severity (equivalent to
scan --fail-on high). Prints the report and exits 1 when any finding is at or
above --fail-on. The default is high: scan on its own fails only on CRITICAL,
which lets HIGH findings such as RSA-2048 key generation through.

Flags:
      --fail-on string          Exit 1 if findings at this severity or higher (default "high")
      --baseline string         Baseline JSON file - only report new findings
  -f, --format string           Output format: text, json, sarif (default "text")
      --ignore string           Pattern IDs to ignore (comma-separated, e.g., "RSA-001,CERT-*")
      --ignore-category string  Categories to ignore (e.g., "Certificate,Library Import")
      --config string           Config file path (default: auto-detect .cryptoscan.yaml)
```

```
cryptoscan pqc [path or URL] [flags]

Shows post-quantum readiness: the post-quantum algorithms found (ML-KEM,
ML-DSA, SLH-DSA, FN-DSA, XMSS, LMS, library imports) with up to three
file:line locations each, the hybrid constructions found, the
quantum-vulnerable algorithms with a count each, then the migration score and
the QRAMM Dimension 1 practice levels. Quantum-safe findings are always
included. Exits 0 whatever it finds; non-zero only when the scan fails. To
fail a build on findings, use cryptoscan gate.

Flags:
  -f, --format string           Output format: text, json (default "text")
  -i, --include string          File patterns to include (comma-separated globs)
  -e, --exclude string          File patterns to exclude (comma-separated globs)
      --ignore string           Pattern IDs to ignore (comma-separated, e.g., "RSA-001,CERT-*")
      --config string           Config file path (default: auto-detect .cryptoscan.yaml)
```

## Common workflows

```bash
# Focus on high-priority issues only
cryptoscan scan . --min-severity high

# Scan and group findings by file for review
cryptoscan scan . --group-by file

# Scan only specific file types
cryptoscan scan . --include "*.go,*.py,*.java,*.js,*.ts"

# Exclude vendor and test directories
cryptoscan scan . --exclude "vendor/*,node_modules/*,*_test.go"

# Count critical findings in JSON output
cryptoscan scan . --min-severity critical --format json | jq '.findings | length'
```

## Output formats

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

### SARIF (Static Analysis Results Interchange Format)

SARIF output integrates with GitHub Code Scanning, VS Code SARIF Viewer, and other security tools.

What `cryptoscan scan . --format sarif --pretty` wrote in `crypto-samples/`, built from the v1.4.0 tag on 2026-10-16, trimmed (the `...` lines mark elided output):

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "CryptoScan",
          ...
          "informationUri": "https://qramm.org",
          "rules": [
            ...
```

### CBOM (Cryptographic Bill of Materials)

**What is CBOM?** Just as an SBOM (Software Bill of Materials) inventories your software dependencies, a CBOM inventories all cryptographic algorithms, keys, and certificates in your systems. It answers: "What cryptography are we using, where, and is it quantum-safe?"

Every field the CBOM output writes, the code that sets it, and how the output lines up with the NTIA SBOM minimum elements are listed in [docs/cbom-fields.md](cbom-fields.md).

CryptoScan writes the CBOM as a CycloneDX 1.6 document, with each algorithm as a `cryptographic-asset` component and each place it was found as an evidence occurrence.

**What it is used for:**
- **Compliance**: Required by emerging regulations (OMB M-23-02, NIST guidelines) for federal contractors and regulated industries
- **Visibility**: Single source of truth for all cryptographic assets across your organization
- **Migration Planning**: Identifies exactly what needs to change for post-quantum readiness
- **Audit Trail**: Documented evidence of cryptographic posture for security assessments

What `cryptoscan scan . --format cbom --pretty` wrote in `crypto-samples/`, built from the v1.4.0 tag on 2026-10-16, trimmed (the `...` lines mark elided output):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3d1c7229-4f1c-4310-9f26-21c11e9c1bd2",
  "version": 1,
  "metadata": {
    ...
    "component": {
      "type": "cryptographic-asset",
      "bom-ref": "crypto-inventory-summary",
      "name": "Cryptographic Inventory Summary",
      "description": "Migration Readiness: 37.5% (CRITICAL)"
    }
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "bom-ref": "crypto-md5-0",
      "name": "MD5",
      "description": "MD5 detected. MD5 is cryptographically broken with practical collision attacks.",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "hash"
        }
      },
      "evidence": {
        "occurrences": [
          {
            "location": "CryptoSamples.java",
            "line": 96,
            "symbol": "MessageDigest md = MessageDigest.getInstance(\"MD5"
          },
          ...
```
