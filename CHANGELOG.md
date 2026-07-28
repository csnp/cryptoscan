# Changelog

All notable changes to CryptoScan are recorded here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Operational crypto was silently dropped by the noise filter.** The scanner
  decided whether a match was low-value by testing the whole source line
  against a list of about a hundred substrings, and dropped the finding on any
  hit. Three of those entries matched ordinary code:
  - `".md"`, intended for Markdown filenames, matched every `.md5(` in the
    corpus. `a.md5(b)`, `hashlib.md5(b"a")` and
    `return hashlib.md5(data).hexdigest()` all reported zero findings.
  - `"cipher ="` matched `Cipher cipher = Cipher.getInstance("DES")`, the
    conventional way to name a `javax.crypto.Cipher`.
  - `"const "` matched `const cipher = crypto.createCipheriv(...)`, which
    `prefer-const` makes the idiomatic form in JavaScript.

  The heuristic has been replaced by an evidence classifier anchored to the
  position of the match. The classifier asks whether the token is part of an
  operation *before* it applies any noise heuristic, so a call, a member
  access, an import or an argument to a crypto factory is always reported,
  whatever else appears on the line.

  That ordering is the safety property, and getting it wrong is subtle. An
  intermediate version of this change ran the log, comment and path rules
  first, which reintroduced the same defect class through a different door: a
  variable named `outputs` (containing `puts `) hid
  `Cipher.getInstance("RC4")`, a `z--` decrement hid a DES cipher in Java,
  `gpg --cipher-algo 3DES` read as a comment, and adding a fifth entry to an
  `sshd_config` `MACs` line took the file from three findings to zero. All of
  those are now regression tests.

- **Declared cryptographic configuration is reported, whatever the key is
  called.** `cipher: DES-CBC`, `note: DES-CBC` and `usage: DES-CBC` are the
  same finding. An intermediate version treated `note`, `remarks`, `comment`,
  `help`, `usage` and `example` as documentation labels, which meant renaming
  a config key by one word hid a CRITICAL DES finding and flipped
  `--fail-on critical` from exit 1 to exit 0. Also `cipher: DES-CBC`,
  `MACs hmac-md5 ...`, `SSLProtocol +SSLv3` and `ssh-keygen -t rsa -b 1024`
  are findings. For a cryptographic inventory a declared algorithm *is* the
  inventory, and an Apache config enabling SSLv3 must fail
  `--fail-on critical`. Scanning a repository that ships cryptographic
  reference data will now report a finding per row; use `--exclude`.

- **Suppression is counted and recoverable.** Findings held back as prose, log
  output, comments, URLs or documentation labels are reported as a count in the
  scan summary, and `--include-narrative` (also covered by `--verbose`) shows
  them. The count is computed after deduplication, so it is exactly the number
  of findings the flag adds, and the default report is a strict subset of what
  the flag shows: deduplication now prefers an operational match over a
  narrative one at the same location, so enabling the flag can only add.
  Detected key material is never held back, since a private key in a comment is
  still an exposed private key.

- **`cryptoscan:ignore` no longer blinds the following line.** A trailing
  directive suppressed both its own line and the next one. A directive now
  applies to its own line unless it says `cryptoscan:ignore-next-line`.

- **Go DES usage was undetectable.** `des.NewCipher` and
  `des.NewTripleDESCipher` are the Go standard library's only DES constructors
  and no pattern matched them.

- **Every output surface reported a different version.** One binary reported
  `1.4.0` from the `version` command, `1.0.0` in SARIF, `1.1.0` in CBOM, and no
  version at all in JSON. A CBOM naming the wrong producer is a false
  provenance record. All surfaces now read `pkg/version`, and JSON carries a
  `tool` object.

- **Finding order was nondeterministic.** Results were built by ranging over a
  map, so two scans of an unchanged tree emitted the same findings in a
  different order. This broke diffable CI output, golden-file tests and
  reproducible CBOMs.

### Added

- `--include-narrative` flag to show algorithm mentions held back as text.
- `tool` object in JSON output, carrying the scanner name and version.
- `narrativeSuppressedCount` in the scan summary.

## [1.3.0]

See the [release notes](https://github.com/csnp/cryptoscan/releases) for
versions 1.3.0 and earlier.
