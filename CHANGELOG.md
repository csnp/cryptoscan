# Changelog

All notable changes to CryptoScan are recorded here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The scan summary counts findings by context.** Text output has a
  "Findings by context:" block after the severity breakdown, with one line per
  kind and the number reported or withheld. The kinds are the rules that
  decide a match's context: `operational` for code that uses the algorithm,
  `comment`, `log-message` and `url-or-path` for the narrative rules that
  withhold text naming it, and `key-material` and `dependency` for findings
  those rules never apply to. The counts cover the whole scan, withheld
  findings included, so they are the same with or without
  `--include-narrative` and add up to `totalFindings` plus
  `narrativeSuppressedCount`. JSON output carries them as `summary.byEvidence`.
  Context is decided by the scanner's rules, not by a model. SARIF and CSV
  output are unchanged. When `--baseline` is used, the summary is rebuilt from
  the new findings only and `byEvidence` is `null`, as
  `narrativeSuppressedCount` is `0` there today.
- **The text footer links the QRAMM quick assessment.** A line after the QRAMM
  Toolkit link points to https://qramm.org/quick-assessment.html, which
  assesses an organisation rather than one repository.
- **`cryptoscan cbom <path or URL>`** writes a CycloneDX 1.6 Cryptographic
  Bill of Materials. It runs the same scan as `scan --format cbom`, writes the
  JSON to standard output or to `-o <file>`, and prints nothing else to
  standard output. It exits 0 whatever it finds, because an inventory is not a
  verdict, and non-zero only when the scan or the write fails. `--fail-on` is
  not offered. A baseline or minimum severity set in `.cryptoscan.yaml` does
  not filter the CBOM; ignore rules still apply.
- **`cryptoscan gate <path or URL>`** fails a build when findings reach a
  severity. It runs the same scan as `scan --fail-on high`, prints the text,
  JSON or SARIF report, and exits 1 when any finding is at or above
  `--fail-on`. The default threshold is `high`, where `scan` on its own fails
  only on CRITICAL; at that default `scan` lets HIGH findings such as RSA-2048
  key generation through. A `failOn` in `.cryptoscan.yaml` applies when
  `--fail-on` is not given. `--baseline`, `--ignore`, `--ignore-category`,
  `--config` and `--no-color` work as they do on `scan`.
- **`cryptoscan pqc <path or URL>`** shows post-quantum readiness. It lists
  the post-quantum algorithms found (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, XMSS,
  LMS and post-quantum library imports, each with a count and up to three
  `file:line` locations), the hybrid constructions found, and the
  quantum-vulnerable algorithms with a count each, then the migration score
  line and the QRAMM Dimension 1 practice levels as the `scan` report prints
  them. Quantum-safe findings are always included, so its score can differ
  from the score of a default `scan`. `--format json` writes `tool`,
  `migrationScore` and `pqcFindings`, the findings whose IDs start with
  `PQC-` or `HYBRID-`. It exits 0 whatever it finds, and non-zero only when
  the scan fails. A baseline or minimum severity set in `.cryptoscan.yaml`
  does not filter the view; ignore rules still apply. `--no-color` works as it
  does on `scan`.

Adding `cbom`, `gate` and `pqc` removed or renamed no `scan` flag and did not
change how `scan` decides its exit code.

- **Reports name the config file they applied and count what it removed.**
  Without `--config`, the scanner applies the first config file it finds in
  the scan target or in any directory above it. Its ignore rules,
  `minSeverity` and `baseline` could remove every finding, and the text
  report then printed `Total Findings: 0` and a check mark with no mention of
  the file. The text report now names the file, says whether it was found
  above the scan target, and lists how many findings each of
  `ignore.patterns`, `ignore.categories`, `minSeverity` and `baseline` removed
  and how many files and directories `ignore.files` kept out of the scan.
  When the file removed findings and none are left, the line
  `No findings reported: the config file removed N findings` replaces
  `No cryptographic findings detected`. JSON output carries the same record
  in a `config` object, and SARIF output in `runs[0].invocations`. Tests
  check, for `ignore.patterns`, `ignore.categories` and `minSeverity`, that
  the count equals the number of findings a scan without the file reports in
  addition, after deduplication.

  The exit code is unchanged: with `--fail-on low`, a tree whose config file
  ignores every pattern still exits 0.

- **`--no-config`** runs the scan on command-line options alone, ignoring any
  config file. It cannot be combined with `--config`.

### Fixed

- **`cryptoscan --version` works.** It printed `Error: unknown flag: --version`.
  It now prints the same text as `cryptoscan version`, and `-v` is its short
  form on the top-level command. `cryptoscan scan -v` still means `--verbose`.

- **Runtime errors print one next step instead of the usage block.** Scanning a
  missing path, passing a `--config` or `--baseline` file that does not exist,
  or writing `--output` into a folder that does not exist printed the error
  followed by the full usage and flag list. Each now prints the `Error:` line
  and one line saying what to check. A mistake on the command line itself,
  such as a missing argument or an unknown flag, still prints the usage block.
  Exit codes are unchanged.

- **A failed clone says what went wrong.** Scanning a repository URL that git
  could not clone printed `git clone failed: exit status 128`. It now prints
  `repository not found or not accessible (git clone: exit status 128)` and
  suggests checking the URL. When git is not installed, the error says
  `git is required to scan a repository URL`.

- **A line with certain Unicode letters stopped the whole scan.**
  `IsURLOrPath` and `IsVariableOrFunctionName` found the match in a lowercased
  copy of the line and then sliced the original line at that position. U+023A
  and U+023E are two bytes long and lowercase to three-byte letters, so the
  line `var s = "` followed by four U+023A letters and `"; _ = rsa` made
  `cryptoscan scan` exit 2 with `slice bounds out of range` and write no
  report. Where the position stayed inside the line, the checks read the wrong
  bytes: with one U+023A first, `= rsa` was treated as part of an identifier
  and `rsa.pem` was not treated as a file name. The inline ignore parser had
  the same defect: one U+023A before `cryptoscan:ignore` panicked, and with two
  of them `cryptoscan:ignore RSA-*` was read as `SA-*` and did not suppress the
  finding. These positions are now found in a lowercased copy that keeps the
  byte offsets of the original line, and the line above reports its `rsa`
  finding.
- **An internal error in one file ended the run for every file.** The scanner
  now recovers, finishes the other files, and reports the file as not
  analyzed: under `unanalyzedFiles` in JSON (with the line it stopped at and
  the error), in the text summary, and as an error-level
  `toolExecutionNotifications` entry in SARIF. For JSON, SARIF, CSV and CBOM
  output the files are also named on stderr. With `--fail-on` set, an
  unanalyzed file makes the scan exit 1, since its findings may be incomplete.
  Without `--fail-on` the exit code does not change. JSON reports now carry
  `unanalyzedFiles` on every scan, as an empty array when every file was
  analyzed.

- **An auto-detected config file that is not valid YAML now prints a
  warning.** The file is still not applied, and stderr now carries a line
  naming its path and the parse error. Before, nothing was printed. A file
  passed with `--config` still stops the scan with an error.

- **`--exclude "vendor/*"` excluded nothing, and most of the default excludes
  did nothing either.** An exclude pattern was compared with a directory's name
  or a file's name on its own, so a pattern containing a `/` could never match.
  The example in `cryptoscan scan --help`, `--exclude "vendor/*,test/*"`, and
  the README example `--exclude "vendor/*,node_modules/*,*_test.go"` still
  scanned `vendor/` and `test/`; only base-name patterns such as `*_test.go` or
  `vendor` worked. The `ignore.files` list in `.cryptoscan.yaml` had the same
  problem.

  Patterns are now matched against the path from the scan root, for files and
  directories alike:
  - A pattern without `/` matches a file or directory name at any depth
    (`vendor`, `*_test.go`).
  - A pattern ending in `/*` or `/**` skips that directory and everything in
    it (`vendor/*`, `src/generated/*`). When the part before `/*` has no other
    `/`, it matches a directory at any depth. A trailing `/` works the same
    way, and a leading `./` is ignored.
  - Any other pattern is matched against the path from the scan root, and a
    directory it matches is skipped with its contents (`src/*.pb.go`).

  `cryptoscan scan --help` states these rules under `--exclude`, and the same
  rules apply to `ignore.files`. `--include` is unchanged and still matches
  file names only.

  **This changes default coverage.** The scan command always adds `vendor/*`,
  `venv/*`, `.venv/*` and `target/*` to the exclude list, and until now those
  four had no effect. Directories named `vendor`, `venv`, `.venv` or `target`,
  at any depth, are no longer scanned by default, so a repository with
  vendored dependencies, a virtual environment, or Maven or Cargo build output
  in its tree reports fewer findings than before. To scan one of them, pass it
  as the target, for example `cryptoscan scan ./vendor`. The other default
  directory excludes (`.git`, `.svn`, `.hg`, `node_modules`, `__pycache__`,
  `dist`, `build`) were already skipped by name and behave as before. The default patterns
  skip directories only: a file named `build` or `target` is not excluded.

- **Every finding now says how to check it and what to change.** Each finding
  in the text report has a `Verify:` line with a command that prints the
  matched line (`sed -n '96p' <file>`, using the path the finding prints, or a
  `grep` of the manifest for a dependency), and a `Fix:` line with one change
  for that algorithm in that language, for example
  `Replace MessageDigest.getInstance("MD5") with MessageDigest.getInstance("SHA-256")`.
  Where no language-specific text exists, the pattern's remediation sentence
  is the fix, and it is no longer printed twice. `--group-by file` prints both
  lines, and JSON findings carry them in the new `verify` and `fix` fields.
  SARIF and CSV output are unchanged.

- **Effort no longer says "Assessment needed".** On `crypto-samples/`, 65 of
  the 110 findings ended in that placeholder. Effort now comes from the
  remediation engine for the algorithms it covers: `Low` for MD5 and SHA-1,
  `Medium` for DES, 3DES, RC4 and Blowfish, and `Medium to High` for RSA,
  ECC, DSA and DH. Secrets, certificates and configuration findings keep
  their existing guidance. Every other finding has no Effort line, so
  category guesses such as "Algorithm replacement - medium effort" no longer
  appear on AES-GCM and other algorithms that need no replacement. ECC
  findings now get the same post-quantum remediation as RSA.

- **MD5, SHA-1, DES, 3DES, RC4 and Blowfish findings name the attack that
  breaks them today.** Their Impact line said "Data protected by this
  algorithm is vulnerable to harvest-now-decrypt-later attacks" or warned
  about future quantum computers. These algorithms are already broken
  without one, so the line now reads, for example, "Broken by classical
  attacks today: its 56-bit key can be recovered by brute force, without a
  quantum computer." RSA, ECC, DH and DSA keep the harvest-now-decrypt-later
  wording. Severity, quantum risk, scores and exit codes are unchanged.

- **The text report gives one count for a scan.** The line printed when the
  scan finishes counted every match as it was listed, before matches of the
  same kind on the same line were merged and before a baseline was applied,
  so it said `121 findings` above a report that said `Total Findings: 110`.
  It now leads with the number the report counts, and when the numbered list
  above it is longer it says why: `The list above has 121 matches.`, then how
  many repeat a match on the same line and how many are already in the
  baseline.

  The INVENTORY box and the Quantum Risk Assessment group the same findings
  by different fields, so their rows differ (`Safe (PQC): 32` against
  `SAFE 35` on `crypto-samples`). Each now names the field it groups by, the
  Quantum Risk Assessment prints a total, and both totals equal
  `Total Findings`. A finding whose quantum risk is not one of the printed
  rows is counted as `UNKNOWN` rather than left out. Tests scan
  `crypto-samples` and check that the text breakdowns add up to
  `Total Findings`, and that `summary.totalFindings`, the number of
  `findings` and `migrationScore.totalCount` in the JSON output are equal.

- **An unknown `--format`, `--fail-on` or `--min-severity` value is now an
  error.** Before, `--format xml` printed the text report, and an unknown
  severity such as `--fail-on hihg` or `--min-severity extreme` was read as
  `info`: `--fail-on` then failed the build on every finding with no message,
  and `--min-severity` reported everything. `--format jsn -o report.json`
  wrote the text report into a `.json` file. The scan now stops before
  scanning or writing anything, prints
  `Error: unknown --format "xml" (valid: text, json, csv, sarif, cbom)` and
  exits 1, the same exit code as an unknown flag. The `format`, `failOn` and
  `minSeverity` settings in `.cryptoscan.yaml` are checked the same way, and
  the error names the config file. Values are matched without regard to case,
  so `--fail-on HIGH` and `--format JSON` both work; before, `--format JSON`
  also fell back to the text report. The flag help and the error message are
  built from the same list of accepted values, and `cryptoscan scan --help`
  now describes the `csv` format, which it left out.

- **A project using hybrid post-quantum key exchange was told it had none.**
  The recommendation `No quantum-safe algorithms detected. Begin PQC adoption
  planning.` was printed whenever no fully post-quantum finding was present,
  even when the inventory listed hybrid findings. It now prints only when the
  scan finds neither.

- **A scan target inside a `docs` directory reported nothing.** The path rules
  that keep documentation, build output and test code out of the report were
  tested against the absolute path of each file, so directories above the scan
  target counted. A checkout under `~/work/docs/myproject` scanned 0 files and
  exited 0, and one under `~/work/api-docs/` read every file and then discarded
  every finding. This was listed as a known limitation in 1.4.0.

  The rules now test only the path relative to the scan target, at one point
  that every rule uses:
  - which files are read (documentation directories such as `docs/`, `doc/`,
    `documentation/` and `wiki/`);
  - which directories are walked (`build/`, `dist/`, `bin/`, `target/site/`
    and the rest of the built-in list);
  - which findings are discarded (names such as `api-docs` and `user_docs`);
  - how a file is classified, so a target under a `test/` directory is no
    longer reported with test-file severity.

  The same names inside the scan target are excluded as before. Two results
  change as a consequence, and both are intended:
  - The scan target itself is never skipped by the built-in directory list, so
    `cryptoscan scan ./build` or `cryptoscan scan ./examples` now scans that
    directory instead of reporting 0 files. `--exclude` patterns still apply
    to it.
  - The result no longer depends on how the target path is written. Scanning
    `.` used to include a top-level `docs/` directory that scanning the same
    tree by its absolute path left out. Both now leave it out.

- **`--baseline` reported reviewed findings as new on another checkout.** Each
  baseline entry was matched on the file's absolute path and the finding's line
  number. A copy of the same repository at another path, which is what every CI
  runner sees, or one line added above a reviewed finding made it read as new,
  so `--baseline baseline.json --fail-on high` exited 1 with no new
  cryptography. The CI recipe in the README uses `--baseline` and inherited
  this.

  A finding now matches a baseline entry on its path relative to the scanned
  tree, the pattern that found it, and the text of its line with runs of
  whitespace collapsed. The line number is no longer part of the match. Each
  entry covers one finding, so a second copy of a reviewed line is reported as
  new. JSON reports now record the scanned directory as `metadata.scanRoot`,
  which is what makes a saved report portable.

  Baselines written by 1.4.0 keep working for this release. They do not record
  `metadata.scanRoot`, so an absolute `scanTarget` is used as the root, and a
  relative one such as `.` is worked out from the paths the current scan
  reports. Regenerate the baseline once with this release so it records the
  root directly. The fallback is planned for removal in the next release.

### Changed

- **The migration readiness score now says how it was computed.** The text
  report prints a Method line directly under the score with the scan's own
  counts, for example `Method: (safe 32 + 0.8 x hybrid 3 + 0.3 x partial 23)
  / 110 findings, as a percentage. Every finding counts once; test and example
  files count the same as production code.` When findings sit in a directory
  named `test`, `tests`, `__tests__`, `spec` or `specs` below the scanned
  directory, a second line says how many, for example `3 of 6 findings are in
  test directories.` JSON output carries the same text as
  `migrationScore.method` and the count as
  `migrationScore.testDirectoryFindings`. The formula, weights and levels are
  unchanged, and CBOM and SARIF output are unchanged.

### Documentation

- **The CBOM fields are documented, and a test keeps the page accurate.**
  `docs/cbom-fields.md` lists every field the CBOM output writes, the line in
  the reporter that sets it and its CycloneDX 1.6 definition, and maps the
  output to the 2021 NTIA minimum elements for an SBOM. Supplier, component
  version and dependency relationships are not written today, and the page
  says so and names the follow-up work for each. The page also records that
  certificate and TLS findings carry no `certificateProperties` or
  `protocolProperties` yet.

  `pkg/reporter/cbom_fields_test.go` runs the real scanner over a small
  fixture, generates a CBOM, and fails if the page marks a field as written
  that the CBOM does not contain, or as not written when it does. CISA and
  NIST have not yet published minimum elements for a CBOM; the page is where
  CryptoScan will track them once they do.

- **The Scan flags table and the pattern count match the code, and tests
  check both.** The `-e, --exclude` row of the Scan flags table in
  `docs/commands.md` now carries the text `cryptoscan scan --help` prints,
  and `internal/cli/commands_doc_test.go` fails when a row of the Scan flags
  tables differs from the help. `PATTERNS.md` and `docs/how-it-works.md`
  said 90+ and 100+ patterns; both now say 90, and
  `pkg/patterns/patterns_doc_test.go` fails when either differs from the
  number of pattern IDs the matcher defines. The notes on invalid `--fail-on`
  values and malformed config files say they apply before 1.5.0 rather than
  naming 1.4.0 alone. The SARIF rule ID note in `docs/ci.md` no longer names
  a release, and it now says that a dismissal is lost when a result's line
  moves, where it said a dismissal does not carry across runs.
  `docs/roadmap.md` marks the language-specific remediation engine as done.

- **The README says how to build a working binary on macOS 26.** On an
  Apple silicon Mac running macOS 26, the README's build-from-source block run
  with Go 1.21 or 1.22 builds a binary that stops at launch with `missing
  LC_UUID load command`. The section now says so and gives two ways to build
  one that starts: Go 1.23 or later, or `CGO_ENABLED=0`, the setting the
  release binaries are built with.

### Known limitations

- A scan target containing no cryptography reports a migration readiness of
  `0.0% [CRITICAL]`. Nothing was measured, so the number describes an absence
  of evidence rather than a risk. The Method line under the score reads
  `No findings to score, so the score is 0.`

- SARIF `ruleId` values are unique per occurrence rather than per pattern.
  Each carries the line and column of its match, such as `MD5-001-96-8` for
  the pattern `MD5-001`, and the 110 results for `crypto-samples/` carry 110
  rule IDs. GitHub Code Scanning therefore cannot group results by pattern,
  and a result whose line moves gets a new rule ID, so its dismissal does not
  follow it.

- **DSA is not detected.** Standalone DSA key generation, such as
  `DSA.generate(2048)`, matches no pattern under any combination of flags, so
  a codebase using DSA is not told that it is quantum vulnerable. Detection
  also matches whole words only, so compound identifiers such as
  `RSAPrivateKey` and `AESCipher` are not matched.

- **Four flags are accepted and ignored:** `--context`, `--max-depth`,
  `--git-history`, and `--group-by` for the values `severity`, `category` and
  `quantum`. Their help text says so. `--group-by file` works.

- **Two text reports of an unchanged tree can differ beyond their timing
  lines.** The findings listed while the scan runs appear in the order the
  parallel workers find them, and the "Categories Found" block is rendered
  from a map: six runs on `crypto-samples/` listed the findings in six
  orders, and ten runs printed "Categories Found" in ten. With
  `--stream=false`, only the "Categories Found" order and the timing lines
  change. To compare runs, use `--format json`, which lists the findings in
  the same order on every run.

- **A file the scanner cannot read is skipped silently.** A file without read
  permission in the scanned tree produces no warning, nothing on stderr and
  no `unanalyzedFiles` entry, so `--fail-on` does not fail the scan for it: a
  tree whose only MD5 call sits in such a file exits 0 with `--fail-on low`.
  The only sign is that the file is left out of the `Scanned:` count and of
  `filesScanned` in JSON.

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
