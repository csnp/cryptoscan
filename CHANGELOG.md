# Changelog

All notable changes to CryptoScan are recorded here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A scan names the `node_modules` directories it did not enter.** Installed
  packages were left out of every scan without a word. The text report of
  `scan` now lists each `node_modules` directory the walk passed over,
  relative to the scan root, under
  `N dependency directories were not scanned, so the packages installed there are not in this report:`,
  and says that passing a package's directory to `cryptoscan scan` scans it.
  JSON output carries the list as `skippedDependencyDirs`, an empty array when
  there is none, and JSON, CSV, SARIF and CBOM output print it on stderr. A
  `node_modules` directory inside another one is not reached, so it is not
  listed.

### Changed

- **A JSON finding names its severity.** `--format json` wrote each finding's
  severity as a number from 0 to 4, as in `"severity": 3`, while
  `summary.bySeverity` is keyed by name. Each finding now carries the name, as
  in `"severity": "HIGH"`, the form `summary.bySeverity`, the text report, CSV
  and `cryptoscan patterns list --format json` use. A reader that compared the
  number has to compare the name. A JSON report written by an earlier release,
  with numbers, still loads as a `--baseline`.
- **Every JSON finding has `algorithm` and `keySize`.** Both keys were left out
  of a finding that had no value for them. They are now on every finding, as
  `null` when the pattern names no algorithm or records no key size, and they
  are the last two keys of the finding object.
- **CBOM components describe more of what was found.** In `--format cbom` and
  `cryptoscan cbom` output, AES-GCM and ChaCha20-Poly1305 have the primitive
  `ae`, the CycloneDX value for authenticated encryption, where they had
  `other` and `mac`. TLS findings are `protocol` assets with
  `protocolProperties` of type `tls` and the TLS version their match names,
  one component per version, where they were algorithm assets with primitive
  `other`. Findings in the `Configuration`, `Library Import` and
  `PQC Library Import` categories that name no algorithm, such as
  `Hardcoded Key Size` and `Post-Quantum Crypto Library`, are left out of the
  CBOM rather than written as algorithm components with no properties; the
  other formats still report them. A finding with a recorded key size is a
  component of its own, named with the size, such as `RSA-1024` with
  `classicalSecurityLevel` 80. One `RSA` component used to hold every RSA
  finding with the level of the first one, which on `crypto-samples` gave 80
  to all 15 occurrences; RSA findings with no recorded size now carry no
  level. [CBOM fields](docs/cbom-fields.md) lists each field as it is now.
- **The text report.** The footer no longer ends with the CSNP mission
  statement. A file with one finding reads `(1 finding)` in the TOP PRIORITY
  FILES rows and in the `--group-by file` headers, where it read
  `(1 findings)`. The list printed while the scan runs stops after 200
  matches with the line
  `Matches after the first 200 are not listed while the scan runs; the report lists every finding.`,
  and the stream footer says how many matches the scan found; the report
  after it still lists every finding.
- **Help text.** `cryptoscan --help` opens with what the tool finds, where it
  opened with `A powerful tool for discovering cryptographic algorithms`.
  `scan --help` says that the report classes SHA-2 and AES as PARTIAL and that
  `--include-quantum-safe` lists the SHA-2 findings, and the AES findings at
  INFO severity other than AES-GCM and AES-ECB, that a default scan leaves
  out, where it called them quantum-safe; `pqc --help` calls them PARTIAL too. The `--fail-on` help says
  that, when neither the flag nor `failOn` in the config file is set, the scan
  exits 1 when any finding is CRITICAL.
- **The release configuration uses the current GoReleaser keys.**
  `goreleaser check` (GoReleaser 2.17.1) reported `archives.format`,
  `archives.format_overrides.format` and `brews` as deprecated and exited 2.
  The archives now set `formats`, and the Homebrew definition is a cask
  (`homebrew_casks`), written to `dist/homebrew/Casks/cryptoscan.rb` in place
  of the formula in `dist/homebrew/Formula/cryptoscan.rb`. It is still not
  uploaded to the tap (`skip_upload: true`). A cask has no `install` or `test`
  block, so the formula's `bin.install` and `--version` test are gone; the
  cask's `binary "cryptoscan"` stanza installs the binary. `goreleaser check`
  now exits 0, and a snapshot build writes the same six archives as before:
  tar.gz for Linux and macOS, zip for Windows.

### Fixed

- **Files with the same risk score are listed in the same order on every
  run.** `migrationScore.topRiskFiles` in JSON output, and the
  `TOP PRIORITY FILES` box of the text report, ordered files by risk score
  alone, so files that tied came out in a different order from run to run.
  When the tie fell at the fifth place, which files made the list changed
  too. With three copies of `crypto-samples` in one directory, six runs of
  `cryptoscan scan <dir> --format json --no-config` gave six different
  lists. Files that tie are now ordered by path.

- **A scan that read no files no longer reports a clean result.** A scan of an
  empty directory, or of one where every file was left out, printed
  `Scanned:  0 files • 0 lines • 0 B` and then a check mark with
  `No cryptographic findings detected`, although nothing was checked. In
  color, the stream footer also opened with a check mark:
  `Scan complete: 0 findings in 0 files`. When no file is scanned, the text
  report now prints `Nothing was checked: no files were scanned under <target>`
  in place of the check mark line, and the stream footer prints the same line
  under `Scan complete: 0 findings in 0 files`, with no check mark. When a
  config file's `ignore.files` kept every file out, this line replaces
  `No findings reported: the config file kept N files out of the scan`; the
  config summary above it still names the file and what it kept out. The
  check mark line now appears only when at least one file was scanned. JSON
  output is unchanged and already records `filesScanned` as 0.

- **Reports CryptoScan wrote into the scanned tree are listed as not
  scanned, instead of being read as source.** The
  README and `docs/ci.md` write reports into the tree they scan, for example
  with `cryptoscan scan . --format sarif --output results.sarif`, and the next
  scan read them as source. Run twice in a copy of `crypto-samples`, that
  command wrote 110 results and then 903. A directory holding only the pretty
  JSON report of `crypto-samples` gave 1313 findings, its SARIF report 793 and
  its CBOM 184, and each of those scans exited 1. A scan now leaves out a file
  that starts like a CryptoScan report: JSON from `scan`, `gate` or `pqc`
  (`tool.name` is `CryptoScan`), SARIF (`runs[].tool.driver.name`), a
  CycloneDX CBOM (`metadata.tools[].name`), a CSV report (its header row), or
  a text report (its title box, or the `Scanning...` line of streamed
  output). It also leaves out the file `--output` names, whatever that file
  holds. Each such file is named as not scanned, with a reason such as
  `CryptoScan report: SARIF` or
  `CryptoScan report: the --output file of this scan`, in the text summary,
  on stderr for the other formats, and under `skippedFiles` in JSON. A report
  saved as documentation, such as `report.txt` or a file under `docs/`, was
  already left out of the scan and is still not listed. The text summary adds
  `To leave CryptoScan reports off this list, write them outside the scanned folder or pass their names to --exclude.`
  The same command now writes 110 results on both runs, and each of the
  three report directories gives 0 findings and exits 0. The CSV report and
  the single-line JSON report of `crypto-samples` were already left out, as
  minified; they are now named as CryptoScan reports.

- **Dependency findings for libraries without post-quantum algorithms name a
  change.** Eleven of the libraries the scanner recognizes in dependency
  manifests, among them `node-forge`, `tweetnacl`, `jose` and `pycryptodome`,
  printed `Fix: Plan migration to a PQC-capable library or enable hybrid mode when available.`,
  which names no change to make. Each library without post-quantum
  algorithms now names what to move and what to move it to and, for
  public-key algorithms in a Python, JavaScript, Go, Java or Rust library,
  the post-quantum library the remediation engine names for that language,
  for example
  `Add liboqs-node and move RSA from node-forge to ML-KEM-768 for encryption and key exchange and ML-DSA-65 for signatures`.
  The `cryptography` entry, which said
  `Add liboqs-python for PQC support alongside cryptography`, now names what
  to move as well. The text is the `Fix:` line of the text report and the
  `fix` and `remediation` fields of JSON findings; SARIF writes it as the
  `help.text` of the finding's rule, and CSV in its Remediation column.

- **The dependency insight lists its libraries in name order.** In
  `--format json` output, the `description` of the `dependency_update`
  insight names the quantum-vulnerable libraries found in dependency
  manifests after `Libraries detected:`. That list followed the iteration
  order of a Go map, which changes from run to run, so scans of the same tree
  could list the libraries in different orders. Eight scans of a directory
  whose `package.json` depends on `node-forge`, `tweetnacl` and `jose` and
  whose `requirements.txt` lists `pycryptodome`, `pynacl` and `cryptography`
  gave four different orders. The list is now sorted by name, as in
  `Libraries detected: cryptography, jose, node-forge, pycryptodome, pynacl, tweetnacl.`,
  and the same eight scans give that one order.

## [1.5.0] - 2026-10-18

### Added

- **`cryptoscan patterns list` and `cryptoscan patterns search <term>`** print
  the detection patterns a scan runs, read from the scanner's own pattern
  definitions, without scanning anything. Each line has the pattern's ID,
  severity, quantum risk, category and name, in the order the scanner checks
  them. `--category` keeps one category, compared as `--ignore-category`
  compares it, and `--quantum` keeps one quantum risk (`vulnerable`,
  `partial`, `safe` or `unknown`). `search` keeps the patterns whose ID, name,
  category, algorithm or description contains the term, ignoring case, and
  those whose regular expression matches the term, so `search kyber` lists
  the ML-KEM pattern. `--format json` adds each pattern's description,
  remediation, references, tags and regular expression. An unknown
  `--category`, `--quantum` or `--format` value is rejected with the accepted
  values, and a search that matches nothing says so and exits 0.
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

- **A file skipped as minified is now named in the report.** Scanning a
  directory that held only `app.js`, one 674-byte line calling
  `crypto.createHash("md5")`, printed `Scanned:  1 files • 0 lines • 675 B`
  and `No cryptographic findings detected`, and nothing said the file had
  been skipped as minified. A file named `app.min.js` was left out without a
  word as well. The text report of `scan` and `gate` now lists each such file
  after the severity breakdown, with the reason:
  `minified or generated: its lines average 674 bytes`,
  `minified: the file name ends in .min.js`, or, for a file with a line too
  long for the scanner to read, `minified or generated: a line is 1 MB or
  longer`. It names up to ten files and counts the rest. The JSON reports of
  `scan` and `gate` carry the files under `skippedFiles` on every scan, as an
  empty array when nothing was skipped, and for JSON, SARIF, CSV and CBOM
  output the files are also named on stderr. A minified file that `--include` or the documentation
  rule would have left out anyway is not listed. The exit code does not
  change, with or without `--fail-on`.

- **A file listed as not scanned is no longer counted as scanned.** A file
  skipped because its lines average above the minified threshold, or because
  a line is 1 MB or longer, was read before the skip and counted in the
  summary's `Scanned:` line, in `filesScanned` and `bytesScanned` in JSON, and
  in `languageStats`, while the same report listed it as not scanned. A
  directory holding only `app.js`, one 365-byte line calling
  `crypto.createHash("md5")`, printed `Scanned:  1 files • 0 lines • 366 B`;
  it now prints `Scanned:  0 files • 0 lines • 0 B`, and `filesScanned` is 0.
  A file skipped by its name, such as `app.min.js`, was already left out of
  these counts.

- **A package.json that starts with a UTF-8 byte order mark is now read.**
  npm 11.20.0 reads such a file, but the scanner could not decode it, and the
  report had no finding and no notice for it while counting it in the
  `Scanned:` line and in `filesScanned`. A directory holding only a
  package.json made of the bytes EF BB BF followed by
  `{"name": "fixture", "version": "1.0.0", "dependencies": {"crypto-js": "^4.2.0"}}`
  and a newline printed `Scanned:  1 files • 0 lines • 84 B` and
  `No cryptographic findings detected`; it now reports the
  `DEP-crypto-js-package.json` finding. The mark is removed before a
  dependency manifest is parsed, so a `requirements.txt` that starts with one
  and has `cryptography==41.0.0` on its first line now reports
  `DEP-cryptography-requirements.txt`, where it reported nothing.

- **A package.json that cannot be decoded is now named in the report.** It
  had no finding and no notice, and was counted as scanned. It is now listed
  under `unanalyzedFiles` in JSON, in the text summary and as an error-level
  `toolExecutionNotifications` entry in SARIF, with the line where decoding
  stopped and the reason, such as `not valid JSON: unexpected end of JSON
  input` or `unexpected JSON array in "dependencies"`, and for JSON, SARIF,
  CSV and CBOM output it is also named on stderr. It is left out of the
  `Scanned:` line, `filesScanned` and `bytesScanned`. With `--fail-on` set,
  and in `gate`, such a file makes the run exit 1, as a file whose analysis
  stopped on an internal error does; without `--fail-on`, `scan` exits as
  before. The text summary asks for the file to be reported at the issue
  tracker only when a listed file stopped on an internal error.

- **A manifest that lists two known crypto libraries now gives a finding for
  each.** Each dependency finding is put on line 1 of its manifest, and
  findings with the same file, line and category were merged into one, so the
  report kept one of the libraries a manifest lists and dropped the rest. A
  `requirements.txt` holding `cryptography==41.0.0` and
  `pycryptodome==3.20.0` reported only `DEP-cryptography-requirements.txt`,
  and its text report printed `Scan complete: 1 finding in 1 file` and
  `1 repeats a match of the same kind on the same line and is counted with
  it.` It now also reports `DEP-PyCryptodome-requirements.txt`, the text
  report prints `Scan complete: 2 findings in 1 file` without that line, and
  the JSON findings, SARIF results, CSV rows and CBOM components of the scan
  hold two entries each, where they held one. A package.json whose
  dependencies are `crypto-js` and `node-forge` reported one of them, and
  which one could change between runs: of 12 JSON scans of one such
  directory, 11 kept `crypto-js` and one kept `node-forge`. Each of 12 scans
  now reports `DEP-crypto-js-package.json` and `DEP-node-forge-package.json`.
  A post-quantum library lost to a quantum-vulnerable one: a go.mod requiring
  `github.com/cloudflare/circl` and `github.com/go-jose/go-jose/v4` reported
  only `DEP-go-jose-go.mod`. It now also reports `DEP-circl-go.mod`, and its
  JSON `migrationScore` moves from score 0, level `CRITICAL`, to score 50,
  level `MEDIUM`. A library named twice in one manifest is still one finding,
  as in a `requirements.txt` that lists `cryptography==41.0.0` on two lines,
  or a go.mod that names circl under `require` and in a `replace` line. A
  baseline saved before this change does not hold the libraries that were
  dropped: with the JSON report of the `requirements.txt` scan above, saved
  before this change, as the baseline, `scan --baseline` reports
  `DEP-PyCryptodome-requirements.txt` as its one finding, and
  `gate --fail-on medium --baseline` exits 1, where it exited 0.

- **A dependency manifest the scanner has no reader for is now named in the
  report.** `build.gradle`, `build.gradle.kts`, `Pipfile`, `composer.json`,
  `packages.config`, `nuget.config` and `go.sum` are classed as dependency
  manifests, so their lines are not searched, but the scanner has no reader
  for them, and the report had no finding and no notice for such a file while
  counting it in the `Scanned:` line and in `filesScanned`. A directory
  holding only a `build.gradle` that declares
  `implementation 'org.bouncycastle:bcprov-jdk18on:1.77'` printed
  `Scanned:  1 files • 0 lines • 75 B` and `No cryptographic findings
  detected`, while the same dependency in a `pom.xml` reports
  `DEP-Bouncy Castle-pom.xml`. Such a file is now listed with the files that
  were not scanned, with the reason `dependency manifest: the scanner does not
  read this format`, in the text summary, under `skippedFiles` in JSON, and on
  stderr for JSON, SARIF, CSV and CBOM output, and the text summary adds
  `Check the dependency manifests for cryptography libraries by hand.` It is
  left out of the `Scanned:` line, `filesScanned`, `bytesScanned` and
  `languageStats`. Findings and the exit code do not change, with or without
  `--fail-on`. A Go module's `go.sum` is listed this way too; the `go.mod`
  beside it is read as before. The README, the how-it-works page and the
  roadmap said dependency scanning covered 20+ package managers; they now
  name the seven manifests a scan reads: `package.json`, `requirements.txt`,
  `pyproject.toml`, `go.mod`, `pom.xml`, `Cargo.toml` and `Gemfile`.

- **A package.json key is read as `dependencies` or `devDependencies` only
  when it is written that way.** The scanner matched the two keys without
  regard to case, which npm 11.20.0 does not do. A directory holding only a
  package.json made of
  `{"name": "fixture", "version": "1.0.0", "dependencies": {"crypto-js": "^4.2.0"}, "DevDependencies": "none"}`
  and a newline, where `npm pkg get dependencies` prints `crypto-js`, had no
  finding, listed the file as not analyzed at line 1 with the reason
  `unexpected JSON string in "devDependencies"`, a key the file does not
  hold, printed `Scanned:  0 files • 0 lines • 0 B`, and `gate` exited 1. It
  now reports `DEP-crypto-js-package.json`, prints
  `Scanned:  1 files • 0 lines • 108 B`, and `gate` exits 0. A package.json
  whose only list is under `Dependencies`, where `npm pkg get dependencies`
  prints `{}`, reported `DEP-crypto-js-package.json`; it now reports no
  finding. The line and reason reported for a value of the wrong type under
  `dependencies` or `devDependencies` do not change. When a package.json
  repeats the `dependencies` key, `ScanDependencies` in `pkg/analyzer` now
  reads the last list, as `npm pkg get dependencies` prints it, where it read
  the packages under both copies.

- **The text report lists "Categories Found" in a stable order.** The block
  was rendered from a map, and six text scans of `crypto-samples` printed it
  in six orders. It now lists the category with the most findings first, and
  categories with the same count in name order, so six text scans of
  `crypto-samples` from the same build print it identically. Six text
  reports of `crypto-samples` run with `--stream=false` are identical apart
  from their Time, Duration and Speed lines.

- **Four `scan` flags that were parsed and ignored now work or are gone.**
  Their help text said so, and a flag that parses and does nothing is a dead
  end in the one place meant to unblock the user. `--max-depth` limits the
  walk: `--max-depth 1` scans only the files directly in the target, `2` adds
  the files in its subdirectories, and so on. `--context` sets how many
  source lines a finding keeps before and after its match, in the text report
  and in `sourceContext` of the JSON report; the default is still 3, and
  `--context 0` keeps the matched line alone. `--group-by` accepts `file`,
  the one value it implements; `severity`, `category` and `quantum` are
  rejected with `unknown --group-by "severity" (valid: file)` before anything
  is scanned.
  `--git-history` is removed: passing it fails with `unknown flag:
  --git-history` instead of scanning the working tree as if the history had
  been asked for. `--progress` was parsed and ignored as well, with no note
  in its help: the progress line appeared on a terminal after every 50 files
  whether or not the flag was given. It is now printed only with `-p` or
  `--progress`, for text output on a terminal, at the first file scanned and
  then every 50 files. A negative `--max-depth` or `--context` is rejected.
  A test scans a small tree with and without each flag and fails when the
  report, exit code and error are the same, so a flag cannot be listed
  without an effect. In the `scanner` package, `Config` gains `ContextLines`
  and loses `ScanGitHistory`, which nothing read; a `Config` built without
  `ContextLines` keeps only the matched line.

- **SARIF rules are listed in a stable order.** `runs[0].tool.driver.rules`
  was listed in a different order on each run of an unchanged tree. Rules are
  now written in the order of their first result, so two SARIF files of
  `crypto-samples` from the same build are byte-identical.

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

- **`--exclude "vendor/*"` skipped the subdirectories of `vendor/` but scanned
  the files directly in it, and the default excludes did the same.** A
  directory was skipped when a pattern matched its name or its path from the
  scan root, while a file was tested by its name alone, so `vendor/*` matched
  `vendor/lib2` and never `vendor/direct.go`. On a tree with
  `vendor/direct.go`, `vendor/lib2/nested.go` and `src/app.go`, 1.4.0 reported
  findings in `src/app.go` and `vendor/direct.go` and nothing from
  `nested.go`; this release reports `src/app.go` alone. The example in
  `cryptoscan scan --help`, `--exclude "vendor/*,test/*"`, and the README
  example `--exclude "vendor/*,node_modules/*,*_test.go"` therefore still
  scanned the files at the top of `vendor/` and `test/`; only base-name
  patterns such as `*_test.go` or `vendor` worked as intended. The
  `ignore.files` list in `.cryptoscan.yaml` had the same problem.

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
  four skipped only the subdirectories of such a directory at the top of the
  scan target, so the files directly in it were scanned. Directories named
  `vendor`, `venv`, `.venv` or `target`, at any depth, are no longer scanned
  by default, so a repository with vendored dependencies, a virtual
  environment, or Maven or Cargo build output in its tree reports fewer
  findings than before. To scan one of them, pass it as the target, for
  example `cryptoscan scan ./vendor`. The other default directory excludes
  (`.git`, `.svn`, `.hg`, `node_modules`, `__pycache__`, `dist`, `build`)
  were already skipped by name and behave as before. The default patterns
  skip directories only: a file named `build` or `target` is not excluded.

- **Every finding now says how to check it and what, if anything, to
  change.** Each finding in the text report has a `Verify:` line with a
  command that prints the matched line (`sed -n '96p' <file>`, using the path
  the finding prints, or a `grep` of the manifest for a dependency), and a
  `Fix:` line with one change for that algorithm in that language, for
  example
  `Replace MessageDigest.getInstance("MD5") with MessageDigest.getInstance("SHA-256")`.
  Where no language-specific text exists, the pattern's remediation sentence
  is the fix, and it is no longer printed twice. A finding that needs no
  change, one at INFO severity whose algorithm is not quantum vulnerable and
  has no language-specific replacement, such as a use of ML-KEM or
  AES-256-GCM, prints that sentence on a `Guidance:` line instead, so
  `ML-KEM is NIST-approved and quantum-safe.` is no longer labelled a fix. On `crypto-samples`, 53 of the 110 findings print `Fix:`
  and 57 print `Guidance:`. The `crypto-js` dependency finding names its
  replacement:
  `Replace crypto-js with node:crypto in Node.js or the Web Crypto API (crypto.subtle) in the browser, then remove crypto-js from package.json`.
  `--group-by file` prints these lines, and JSON findings carry them in the
  new `verify`, `fix` and `guidance` fields, with `fix` empty when `guidance`
  is set. SARIF output has no such field and CSV output no such column, but
  both carry the new `crypto-js` text where they carried
  `Consider using Web Crypto API or node:crypto for better security`: SARIF
  as the `help.text` of the `DEP-crypto-js-package.json` rule in
  `runs[0].tool.driver.rules`, and CSV in the Remediation column of that
  finding's row. CSV rows also carry the new Impact and Effort text. On
  `crypto-samples`, which has no `package.json` or other dependency
  manifest, SARIF output has the same rules and results as 1.4.0, with the
  rules in the order described under "SARIF rules are listed in a stable
  order". In the CSV output for `crypto-samples`, 109 of the 110 rows differ
  from 1.4.0, all of them in the Impact and Effort columns only.

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

- **The README and `docs/how-it-works.md` point to `cryptoscan patterns list`
  for the full pattern list.** Both said every pattern is in `PATTERNS.md`,
  whose tables list 85 pattern IDs: 14 of them are IDs the matcher does not
  define, and 19 IDs the matcher defines are missing. `PATTERNS.md` now says
  that its tables are written by hand and that the command shows what a scan
  runs. `docs/commands.md` lists the `patterns` commands and their flags.

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

- **The README's sample output is regenerated and checked by a test.** The
  block under "What `cryptoscan scan crypto-samples` prints" and the capture
  behind it, `docs/captures/scan-crypto-samples.txt`, were made with release
  1.4.0 and still showed `Scan complete: 121 findings` and an `INVENTORY` row
  without its label. Both are regenerated from a scan of this release.
  `TestReadmeExcerptIsCurrent` in `internal/cli` scans `crypto-samples` and
  fails when a line the README shows is no longer printed, and with
  `-update-capture=<directory>` it rewrites the capture, its metadata file and
  the README block from one scan. `TestReadmeExcerptMatchesCapture` fails
  when the three disagree.

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

- **Two text reports of an unchanged tree can differ beyond their timing
  lines.** The findings listed while the scan runs appear in the order the
  parallel workers find them: six runs on `crypto-samples/` listed the
  findings in six orders. With `--stream=false`, only the timing lines
  change. To compare runs, use `--stream=false`, or `--format json`, which
  lists the findings in the same order on every run.

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
