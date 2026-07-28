# Changelog

All notable changes to CryptoScan are recorded here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-07-28

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

- **No rule classifies by vocabulary any more.** Two heuristics judged a match
  by the words around it, and both were false-negative generators that took
  three revisions to stop tuning and simply remove:

  - A quoted string of three or more words counted as prose. A quoted string is
    where configuration lives, so this hid
    `db.Exec("ALTER SYSTEM SET password_encryption TO 'md5'")`,
    `props.put("jdk.tls.client.cipherSuites", "RC4 and DES ...")`,
    `conf.set("hive.ssl.ciphers", "DES-CBC3-SHA and RC4-MD5 for all peers")`
    and nine other real settings.
  - A leading `description:` or `title:` owned the rest of its line, losing a
    CRITICAL finding to every key that was not on the list: `note:`, then
    `"title" :` with a space, then `:title =>`, then `ssl-title:`.

  What remains is structural. A match is withheld only when it belongs to a
  logging or error call, sits in a comment in a language that has that comment
  marker, or is inside a URL or document path. Suppressing a description field
  now needs no rule at all, because it is simply reported.

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
  reproducible CBOMs. The findings themselves are now in a stable order in
  every format, verified over repeated runs. The text report's "Categories
  Found" summary block is a separate map and is still nondeterministic; see
  the known limitations below.

### Added

- `--include-narrative` flag to show algorithm mentions held back as text.
- `tool` object in JSON output, carrying the scanner name and version.
- `narrativeSuppressedCount` in the scan summary.

### Known limitations

- **A `docs` directory anywhere in the absolute path of the scan target
  suppresses the scan.** The file filter tests the absolute path rather than
  the path relative to the scan target, so a checkout under, for example,
  `~/work/docs/myproject` reports `Scanned: 0 files` and exits 0. A `-docs`
  suffix anywhere in the path (`api-docs`, `user-docs`) is a second, separate
  case: the files are read, and every finding is then discarded. Both are
  present in 1.3.0 as well and are not introduced by this release. Until this
  is fixed, check the `Scanned:` line, or the `filesScanned` field in JSON
  output, against the number of files you expect. A fix is planned for 1.4.1.

- Invalid values for `--format`, `--min-severity` and `--fail-on` are accepted
  silently and the scan falls back to the text report. A typo in a CI pipeline
  therefore uploads a text file where a machine format was intended, and the
  job still passes. Also present in 1.3.0.

- A scan target containing no cryptography reports a migration readiness of
  `0.0% [CRITICAL]`. Nothing was measured, so the number describes an absence
  of evidence rather than a risk. The recommendations printed underneath state
  this correctly.

- SARIF `ruleId` values are unique per occurrence rather than per pattern, so
  GitHub Code Scanning cannot group results and a dismissal does not carry
  across runs. The same ids do not match the pattern ids `--ignore` accepts.

- **DSA is not detected.** Standalone DSA key generation, such as
  `DSA.generate(2048)`, matches no pattern under any combination of flags, so
  a codebase using DSA is not told that it is quantum vulnerable. The help
  text used to claim DSA support and no longer does. Detection also matches
  whole words only, so compound identifiers such as `RSAPrivateKey` and
  `AESCipher` are not matched.

- **Four flags are accepted and ignored:** `--context`, `--max-depth`,
  `--git-history`, and `--group-by` for the values `severity`, `category` and
  `quantum`. Their help text now says so. `--group-by file` works.

- **The text report's summary blocks are not reproducible.** The findings are
  in a stable order, but "Categories Found" is rendered from a map, so
  `cryptoscan scan . > report.txt` differs between two runs of an unchanged
  tree. Use `--format json` for anything you intend to diff. Also present in
  1.3.0.

- **A file the scanner cannot read is skipped silently.** An unreadable file
  in a scanned tree produces no warning, nothing on stderr, and exit 0, so the
  scan reports a clean result for code it never examined. Also present in
  1.3.0.

- **A malformed auto-detected `.cryptoscan.yaml` is ignored silently,** so
  suppression rules a user believes are active may not be. The same file
  passed explicitly with `--config` fails with a clear error.

- The text report's streaming line and its final total disagree, because
  deduplication happens after streaming. The final total is the correct one
  and is what every machine-readable format reports.

## [1.3.0]

See the [release notes](https://github.com/csnp/cryptoscan/releases) for
versions 1.3.0 and earlier.
