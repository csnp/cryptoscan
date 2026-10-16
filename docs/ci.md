# CI/CD integration

This page shows how to run CryptoScan in GitHub Actions, GitLab CI and a pre-commit hook, and how to fail a build only on new findings; for installation and a first scan, start with the [README](../README.md).

CryptoScan supports CI use with ignore rules, baseline comparison, and configurable exit codes. Defaults for all of these can live in a `.cryptoscan.yaml` file, described in [Configuration](configuration.md).

## Baseline workflow

Use baselines to track progress and only fail on **new** issues:

```bash
# 1. Generate initial baseline (stores current known issues)
cryptoscan scan . --format json --output baseline.json

# 2. In CI, compare against baseline - only new issues cause failure
cryptoscan scan . --baseline baseline.json --fail-on high

# 3. After fixing issues, regenerate baseline
cryptoscan scan . --format json --output baseline.json
```

A baseline is portable across checkouts: each reviewed finding is matched on its path inside the scanned tree, its pattern and the text of its line, so the same baseline works on a CI runner that checks the repository out at a different path, and a line added above a reviewed finding does not make it new.

## Exit code control

Control when CI fails based on finding severity:

```bash
# Fail on any HIGH or CRITICAL findings
cryptoscan scan . --fail-on high

# Fail only on CRITICAL findings (most permissive)
cryptoscan scan . --fail-on critical

# Fail on MEDIUM and above (stricter)
cryptoscan scan . --fail-on medium
```

With `--fail-on` set, the scan also exits 1 when a file could not be analyzed,
because its findings may be incomplete. The file is listed in the text summary,
under `unanalyzedFiles` in JSON, and as an error in the SARIF run's
`invocations[].toolExecutionNotifications`. Without `--fail-on`, such a file
does not change the exit code.

Without `--fail-on`, the scan exits 1 on any CRITICAL finding. The full table is in [Exit codes](commands.md#exit-codes).

## Suppressing known issues

```bash
# Ignore specific pattern IDs
cryptoscan scan . --ignore "RSA-001,CERT-SELFSIGNED-001"

# Ignore entire categories
cryptoscan scan . --ignore-category "Certificate,Library Import"

# Combine with baseline for maximum flexibility
cryptoscan scan . --ignore "RSA-*" --baseline baseline.json --fail-on high
```

To suppress a single line in source code instead, use an inline comment, described in [Configuration](configuration.md#inline-suppression).

## GitHub Actions with SARIF

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
        run: |
          # Use baseline if it exists, fail on new HIGH+ findings
          if [ -f baseline.json ]; then
            cryptoscan scan . --baseline baseline.json --fail-on high --format sarif --output results.sarif
          else
            cryptoscan scan . --fail-on critical --format sarif --output results.sarif
          fi

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

In release 1.4.0, SARIF rule IDs are unique per occurrence rather than per pattern, so GitHub Code Scanning does not group results and a dismissal does not carry across runs (see the known limitations in [CHANGELOG.md](../CHANGELOG.md)).

## GitLab CI

```yaml
crypto-scan:
  stage: security
  image: golang:1.21
  script:
    - go install github.com/csnp/cryptoscan/cmd/cryptoscan@latest
    - cryptoscan scan . --baseline baseline.json --fail-on high --format json --output crypto-findings.json
  artifacts:
    paths:
      - crypto-findings.json
  allow_failure: false
```

The JSON output does not follow GitLab's SAST report schema, so the file is kept as a job artifact rather than declared as a `sast` report.

## Pre-commit hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

if command -v cryptoscan &> /dev/null; then
    # Scans the whole working tree, not only staged files; fails on critical
    cryptoscan scan . --fail-on critical --min-severity high
    if [ $? -ne 0 ]; then
        echo "Critical cryptographic issues found. Commit blocked."
        exit 1
    fi
fi
```
