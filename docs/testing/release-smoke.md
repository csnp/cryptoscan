# Release smoke test: cryptoscan

Manual pre-release walkthrough. Run this before every tag push. Record the
actual output, not a summary. CryptoScan is a Go CLI, so build the
CI-equivalent binary rather than a plain `go build`: the release injects the
version, and a plain build carries the `dev` default, which hides every
version-provenance defect.

## 1. Build the artifact the release will ship

```bash
go build -ldflags "-X main.version=<version being released>" -o /tmp/cryptoscan ./cmd/cryptoscan
/tmp/cryptoscan version
```

- [ ] `go build ./...` succeeds.
- [ ] `go test -race ./...` passes.
- [ ] `go vet ./...` is clean.
- [ ] `cryptoscan version` prints the version being released, not `dev`.
- [ ] `main.version` is a `var`, not a `const` (a `const` silently ignores `-X`).

## 2. Detection: operational crypto is reported

Every line below must produce at least one finding. Each one reported zero
findings at some point in the tool's history, because a noise filter matched a
substring elsewhere on the line.

```bash
d=$(mktemp -d)
printf 'a.md5(b)\n'                                    > $d/a.py
printf 'return hashlib.md5(data).hexdigest()\n'        > $d/b.py
printf 'cipher = md5(b"a")\n'                          > $d/c.py
printf 'block, err := des.NewCipher(key)\n'            > $d/d.go
printf "const x = crypto.createHash('md5')\n"          > $d/e.js
printf 'const rc4 = CryptoJS.RC4.encrypt(data, key)\n' > $d/f.js
printf 'Cipher cipher = Cipher.getInstance("RC4");\n'  > $d/g.java
/tmp/cryptoscan scan $d --format json | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["findings"]),"findings")'
```

- [ ] At least 7 findings (one per file). Zero for any file is a release blocker.
- [ ] Scan the repo's own `crypto-samples/` tree: the deliberately vulnerable
      samples are reported, including the DES, 3DES, RC4 and MD5 cases.

## 3. Detection: mentions in text are withheld, visibly and recoverably

- [ ] A log line (`log.Printf("falling back to md5")`) produces no finding.
- [ ] The summary states how many mentions were withheld.
- [ ] `--include-narrative` brings them back.
- [ ] Detected key material is never withheld, even inside a comment.

## 4. Suppression comments

```bash
printf 'import hashlib\nA=hashlib.sha1(b"1")  # cryptoscan:ignore\nB=hashlib.sha1(b"2")\nC=hashlib.sha1(b"3")\n' > $d/ig.py
```

- [ ] Findings are reported on lines 3 and 4 only. Line 2 is suppressed and no
      other line is affected by it.
- [ ] `# cryptoscan:ignore-next-line` suppresses the following line.
- [ ] `cryptoscan:ignore RSA-001` suppresses only that pattern.

## 5. Every output surface agrees

```bash
for f in json sarif cbom; do /tmp/cryptoscan scan $d --format $f; done
```

- [ ] JSON `tool.version`, SARIF `runs[0].tool.driver.version` and
      `.semanticVersion`, and CBOM `metadata.tools[0].version` all equal the
      output of `cryptoscan version`.
- [ ] The CBOM validates against the official CycloneDX 1.6 schema, fetched
      from the CycloneDX specification repository, not against the tool's own
      tests. Resolve the `jsf-0.82` and `spdx` `$ref`s and validate with
      python `jsonschema`.
- [ ] SARIF result locations point at real files.

## 6. Determinism

```bash
for i in 1 2 3; do
  /tmp/cryptoscan scan crypto-samples --format json \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print([(f["file"],f["line"],f["id"]) for f in d["findings"]])' \
    | shasum -a 256
done
```

- [ ] All three hashes match. Finding order must not vary between runs of an
      unchanged tree, or CI diffs and CBOMs are not reproducible.

## 7. Output and exit codes

- [ ] Piped (non-TTY) output contains no ANSI escape sequences.
- [ ] `--no-color` output contains no ANSI escape sequences and no emoji.
- [ ] `--help` lists every flag, and every flag it lists actually parses.
- [ ] An invalid `--format` value is rejected with a clear message and a
      non-zero exit code, rather than silently falling back to text.
- [ ] Exit codes match what `--fail-on` documents.

## 8. Findings read well

For each finding in a real scan, check all five:

- [ ] It names the file and line.
- [ ] It says what specifically is wrong.
- [ ] The remediation is a concrete action, not general advice.
- [ ] Severity is coherent against the other findings on the same file.
- [ ] A non-developer security manager would understand what to do.

## 9. Security and hygiene

- [ ] No secrets in committed files.
- [ ] `.env` and credential files are gitignored and excluded.
- [ ] `npx hackmyagent secure --ci` reports no CRITICAL or HIGH findings, or
      each one is a documented and verified false positive.

## Result

- Version:
- Date:
- Tester:
- Verdict: PASS / FAIL
- Notes:
