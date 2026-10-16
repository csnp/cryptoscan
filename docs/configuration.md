# Configuration

This page describes the `.cryptoscan.yaml` configuration file and the inline comments that suppress findings in source code; for installation and a first scan, start with the [README](../README.md).

## Configuration file

Create a `.cryptoscan.yaml` in your project root to configure default behavior:

```yaml
# .cryptoscan.yaml - CryptoScan configuration
ignore:
  patterns:
    - CERT-SELFSIGNED-001   # Known dev certificates
    - RSA-001               # Legacy auth, migration tracked in JIRA-123
  categories:
    - Library Import        # Don't report import statements
  files:
    - "vendor/*"
    - "testdata/*"

failOn: high              # Exit non-zero on HIGH or CRITICAL findings
minSeverity: low          # Report LOW and above
baseline: baseline.json   # Only report new findings vs baseline
```

| Key | Same as | Values |
|-----|---------|--------|
| `ignore.patterns` | `--ignore` | Pattern IDs; a trailing `*` matches a family, such as `RSA-*` |
| `ignore.categories` | `--ignore-category` | Category names, such as `Certificate` or `Library Import` |
| `ignore.files` | `--exclude` | File patterns |
| `failOn` | `--fail-on` | info, low, medium, high, critical |
| `minSeverity` | `--min-severity` | info, low, medium, high, critical |
| `format` | `--format` | text, json, csv, sarif, cbom |
| `baseline` | `--baseline` | Path to a baseline JSON file |

A flag set on the command line to something other than its default takes precedence over the same key in the file. The three `ignore` lists are added to any `--ignore`, `--ignore-category` and `--exclude` values rather than replaced by them.

When `--config` is not given, CryptoScan looks for `.cryptoscan.yaml`, `.cryptoscan.yml`, `cryptoscan.yaml` or `cryptoscan.yml` in the scan target's directory and then in each parent directory. For a Git URL it starts from the current directory.

In release 1.4.0, a malformed file that was found automatically is ignored without a message, while the same file passed with `--config` stops the scan with an error. To confirm your rules are active, run once with `--config .cryptoscan.yaml`.

## Inline suppression

Use inline comments to suppress findings that are intentional or not applicable:

```go
// Suppress all findings on this line
key := rsa.GenerateKey(rand.Reader, 2048) // cryptoscan:ignore

// Suppress only RSA findings (ECDSA would still be reported)
import "crypto/rsa" // cryptoscan:ignore RSA-001

// Suppress an entire pattern family
legacyAuth() // cryptoscan:ignore CERT-*

// Suppress the next line
// cryptoscan:ignore-next-line
legacyKey := oldCrypto.NewKey()
```

Supported directives:
- `cryptoscan:ignore`: Ignore all findings on this line, and only this line
- `cryptoscan:ignore RSA-001`: Ignore specific pattern ID
- `cryptoscan:ignore RSA-*`: Ignore pattern family (wildcard)
- `cryptoscan:ignore-next-line`: Ignore finding on the following line
- `crypto-scan:ignore`: Alternative format
- `noscan`: Quick ignore all

To ignore a pattern or category across the whole project, use the `ignore` keys above or the flags in [CI/CD integration](ci.md#suppressing-known-issues).
