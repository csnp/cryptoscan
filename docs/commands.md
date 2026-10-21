# Command reference

This page lists every CryptoScan command and flag, the exit codes, and what each output format contains; for installation and a first scan, start with the [README](../README.md).

## Commands

| Command | What it does |
|---------|--------------|
| `cryptoscan scan <path or URL>` | Scan a directory or repository for cryptographic usage |
| `cryptoscan cbom <path or URL>` | Write a CycloneDX 1.6 Cryptographic Bill of Materials (equivalent to scan --format cbom) |
| `cryptoscan gate <path or URL>` | Fail a build when findings reach a severity (equivalent to scan --fail-on high) |
| `cryptoscan pqc <path or URL>` | Show post-quantum readiness: PQC and hybrid usage found, quantum-vulnerable usage, and the QRAMM Dimension 1 levels |
| `cryptoscan patterns list` | List every detection pattern, or those in one category or at one quantum risk |
| `cryptoscan patterns search <term>` | List the detection patterns that mention a term or whose expression matches it |
| `cryptoscan version` | Print version information |
| `cryptoscan completion <shell>` | Generate the autocompletion script for the specified shell |
| `cryptoscan help [command]` | Help about any command |

The shell is one of `bash`, `fish`, `powershell` and `zsh`, and `--no-descriptions` disables completion descriptions. The flags of `cbom`, `gate`, `pqc` and `patterns` are listed after the exit codes below.

## Scan flags

```
cryptoscan scan <path or URL> [flags]
```

The path is required. It is a local directory, a file, or a Git URL to scan; use `.` for the current directory. A Git URL is cloned into a temporary directory that is removed when the scan ends, so the report gives each path relative to the repository root, as in `src/app.py`.

The descriptions below are the ones `cryptoscan scan --help` prints.

| Flag | Description |
|------|-------------|
| `-f, --format string` | Output format: text, json, csv, sarif, cbom (default "text") |
| `-o, --output string` | Output file (default: stdout) |
| `-i, --include string` | File patterns to include (comma-separated) |
| `-e, --exclude string` | File and directory patterns to exclude (comma-separated): a pattern without `/` matches a name at any depth (`vendor`, `*_test.go`), a pattern ending in `/*` or `/**` skips that directory and everything in it (`vendor/*`), and any other pattern is matched against the path from the scan root (`src/*.pb.go`) |
| `-d, --max-depth int` | Maximum directory depth (0 = unlimited): 1 scans only the files directly in the target, 2 adds the files in its subdirectories, and so on |
| `-g, --group-by string` | Group the text report by: file |
| `-c, --context int` | Lines of source to show before and after each finding (default 3) |
| `-p, --progress` | Show scan progress: the number of files scanned so far, updated in place (text output on a terminal) |
| `--stream` | Show findings as they are discovered, up to the first 200 matches (default true) |
| `--min-severity string` | Minimum severity to report: info, low, medium, high, critical (default "info") |
| `--include-imports` | Include library import findings (normally suppressed as low-value) |
| `--include-quantum-safe` | Include the SHA-2 and AES findings left out by default, which the report classes as PARTIAL |
| `--include-narrative` | Include algorithms named in prose, log messages, documentation and config keys |
| `-v, --verbose` | Show all findings including imports, the SHA-2 and AES findings left out by default, and narrative mentions |
| `--no-color` | Disable colored output |
| `--pretty` | Pretty print JSON output |
| `-h, --help` | help for scan |

CI/CD flags:

| Flag | Description |
|------|-------------|
| `--ignore string` | Pattern IDs to ignore (comma-separated, e.g., "RSA-001,CERT-*") |
| `--ignore-category string` | Categories to ignore (comma-separated, e.g., "Certificate,Library Import") |
| `--fail-on string` | Exit non-zero if findings at this severity or higher (info, low, medium, high, critical), or if any file could not be analyzed. When neither this flag nor failOn in the config file is set, the scan exits 1 when any finding is CRITICAL |
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

Before 1.5.0, an invalid `--fail-on` value is accepted silently (see the 1.4.0 known limitations in [CHANGELOG.md](../CHANGELOG.md)), so in a pipeline that runs an earlier release, check the spelling of the severity. From 1.5.0, an unknown value is rejected before anything is scanned, with `Error: unknown --fail-on "hihg" (valid: info, low, medium, high, critical)` and exit code 1.

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
      --no-color                Disable colored output
```

```
cryptoscan pqc [path or URL] [flags]

Shows post-quantum readiness: the post-quantum algorithms found (ML-KEM,
ML-DSA, SLH-DSA, FN-DSA, XMSS, LMS, library imports) with up to three
file:line locations each, the hybrid constructions found, the
quantum-vulnerable algorithms with a count each, then the migration score and
the QRAMM Dimension 1 practice levels. The SHA-2 and AES findings that scan
leaves out by default are always included. Exits 0 whatever it finds; non-zero only when the scan fails. To
fail a build on findings, use cryptoscan gate.

Flags:
  -f, --format string           Output format: text, json (default "text")
  -i, --include string          File patterns to include (comma-separated globs)
  -e, --exclude string          File patterns to exclude (comma-separated globs)
      --ignore string           Pattern IDs to ignore (comma-separated, e.g., "RSA-001,CERT-*")
      --config string           Config file path (default: auto-detect .cryptoscan.yaml)
      --no-color                Disable colored output
```

```
cryptoscan patterns list [flags]
cryptoscan patterns search <term> [flags]

Lists the detection patterns a scan matches against the lines of the files
it reads, from the scanner's own pattern definitions, without scanning
anything: one line per pattern with its ID, severity, quantum risk, category
and name, in the order the scanner checks them. search keeps the patterns
whose ID, name, category, algorithm or description contains the term,
ignoring case, and those whose regular expression matches the term. The ID
is the one --ignore accepts, and the category the one --ignore-category
accepts. --format json adds each pattern's description, remediation,
references, tags and regular expression. Exits 0 when nothing matches.

Flags:
      --category string   Show only patterns in this category (e.g., "Certificate")
  -f, --format string     Output format: text, json (default "text")
      --quantum string    Show only patterns at this quantum risk: vulnerable, partial, safe, unknown
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
