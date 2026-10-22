# How CryptoScan works

This page explains what CryptoScan reports and what it holds back, what it detects, how the Migration Readiness Score is set, how the code is laid out, and how the maintainers compare it with other approaches; for installation and a first scan, start with the [README](../README.md).

## What is reported, and what is held back

CryptoScan asks one question first: is the matched token part of an operation?
A call, an instantiation, a member access, an import, or an algorithm name
passed to a crypto factory is always reported, whatever else appears on the
line. So all of these produce findings:

```
hashlib.md5(data)
des.NewCipher(key)
const cipher = crypto.createCipheriv('des-ede3-cbc', k, iv)
Cipher.getInstance("RC4")
```

Declared configuration is also reported. For a cryptographic inventory, an
algorithm named in a config file is the inventory:

```
cipher: DES-CBC
MACs hmac-md5 hmac-sha1 umac-64
SSLProtocol -all +SSLv3 +TLSv1
ssh-keygen -t rsa -b 1024 -f id_rsa
```

Only mentions in *text* are held back: prose, log and error messages, comments,
URLs, and the values of documentation labels such as `description:` and
`title:`. The scan summary always says how many were held back, and the number
is exactly what the flag returns. What `cryptoscan scan .` printed in `crypto-samples/`, built from the v1.4.0 tag on 2026-10-16, trimmed to the two summary lines:

```
  21 finding(s) withheld as documentation, log or comment text.
  Show them with: cryptoscan scan . --include-narrative
```

Scanning a repository that ships cryptographic reference data (a database of
packages and the algorithms they use, for example) will report a finding per
row. Use `--exclude` to skip those paths.

Library imports, SHA-2 findings, and AES findings at INFO severity other than AES-GCM and AES-ECB are also left out of the default report; the report classes SHA-2 and AES as PARTIAL, weakened but not broken by a quantum computer. `--include-imports`, `--include-quantum-safe` and `--include-narrative` bring each group back, and `--verbose` brings back all three.

### Directories left out by default

A scan does not read these directories, or anything inside them, wherever they sit below the scan target:

| Kind | Directory names |
|------|-----------------|
| Version control | `.git`, `.svn`, `.hg` |
| Dependencies | `node_modules`, `vendor`, `venv`, `.venv`, `.terraform` |
| Editor state | `.idea`, `.vscode` |
| Build and test output | `.next`, `dist`, `build`, `out`, `.output`, `.nuxt`, `.cache`, `__pycache__`, `coverage`, `.nyc_output`, `bin`, `target` |
| Examples and fixtures | `examples`, `example`, `samples`, `sample`, `demo`, `demos`, `mock`, `mocks`, `fixtures`, `testdata`, `test-fixtures` |

The directories below one named `standalone` or `.egg-info` are left out too. These names match only in the letter case shown: a directory named `Dist` or `Examples` is read like any other. The scan target itself is read whatever it is called.

When these directories hold files, the text report and the `pqc` text view count the files, without reading them, and name the rules that matched. For a tree with one Python file in each of `src`, `examples`, `fixtures` and `testdata`, `cryptoscan scan .` reports findings from `src` alone and prints these two lines in its summary:

```
  3 files in 3 directories were not scanned (default rules: examples, fixtures, testdata).
  Scan them with --include-skipped.
```

JSON output carries the count under `skipped`: the number of files and of directories, the rules that matched, and the path of each directory. SARIF output adds the two sentences as a note in the run's `invocations[].toolConfigurationNotifications`, and JSON, SARIF, CSV and CBOM output print them on stderr. The count does not change the exit code. A directory that `--exclude`, the config file's `ignore.files` or `--max-depth` keeps out as well is not counted.

`--include-skipped`, which `scan`, `gate`, `cbom` and `pqc` take, scans these directories. `--exclude` patterns, the config file's `ignore.files` and `--max-depth` still apply, and so do the default patterns that name files, such as `*.lock`. When the target is a repository URL, the `.git` directory of the clone the scan makes is neither counted nor scanned, since the clone creates it.

Code under `docs`, `doc`, `documentation` and `wiki` directories is classified as documentation and is not read, with or without `--include-skipped`.

## Detection coverage

| Category | What We Detect |
|----------|----------------|
| **Post-Quantum Cryptography** | ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), FN-DSA (Falcon), XMSS, LMS |
| **Hybrid Cryptography** | X25519+ML-KEM, ECDSA+ML-DSA composite signatures, hybrid TLS key exchange |
| **Asymmetric Encryption** | RSA (all key sizes), ECDSA, DH, ECDH, Ed25519, X25519 |
| **Symmetric Encryption** | AES (CBC, GCM, ECB, CTR), ChaCha20-Poly1305, DES, 3DES, RC4, Blowfish |
| **Hash Functions** | SHA-2, SHA-3, SHAKE128/256, BLAKE2, BLAKE3, MD5, SHA-1 |
| **MACs** | HMAC-SHA256/384/512, HMAC-SHA3, KMAC128/256, CMAC, GMAC, Poly1305 |
| **Key Derivation (KDFs)** | HKDF, PBKDF2, Argon2id, scrypt, bcrypt |
| **Certificates** | X.509, CSR, PKCS#12/PFX, certificate chains, mTLS, validation bypass, expiration, JWK |
| **TLS/SSL** | Protocol versions, cipher suites, weak configurations, certificate pinning |
| **Key Material** | Private keys (RSA, EC, SSH, PGP, PKCS#8), JWT secrets, HMAC keys |
| **Cloud KMS** | AWS KMS, Azure Key Vault, GCP Cloud KMS, HashiCorp Vault |
| **Dependencies** | Crypto libraries listed in package.json, requirements.txt, pyproject.toml, go.mod, pom.xml, Cargo.toml and Gemfile |
| **Configurations** | Hardcoded key sizes, algorithm selections, TLS settings |

DSA is not detected: standalone DSA key generation matches no pattern. Detection matches whole words only, so compound identifiers such as `RSAPrivateKey` and `AESCipher` are not matched. Both are listed with the other known limitations in [CHANGELOG.md](../CHANGELOG.md). `cryptoscan patterns list` prints every pattern the scanner runs ([command reference](commands.md#commands)), and [PATTERNS.md](../PATTERNS.md) explains how detection, confidence scoring and the risk levels work.

## Migration Readiness Score

The score formula: `(Safe + Hybrid×0.8 + Partial×0.3) / Total × 100`

The report labels the score with a risk level: CRITICAL when any finding is CRITICAL or the score is below 25%, HIGH below 50%, MEDIUM below 75%, and LOW from 75% up. The levels are set by `DetermineRiskLevel` in `pkg/analyzer/scoring.go`. A target with no cryptography in it scores `0.0% [CRITICAL]`; nothing was measured, so read that as an absence of evidence rather than a risk.

The same panel shows the QRAMM Dimension 1 practice levels. What `cryptoscan scan .` printed in `crypto-samples/`, built from the v1.4.0 tag on 2026-10-16, trimmed to the score and QRAMM rows:

```
┌─ QUANTUM MIGRATION READINESS ──────────────────────────────────┐
│  Score: █████████░░░░░░░░░░░░░░░░ 37.5% [CRITICAL]│
│─────────────────────────────────────────────────────────────────│
│  INVENTORY                                                     │
│    ✓ Safe (PQC):        32       ✗ Vulnerable:    39      │
│    ◐ Hybrid:            3        [!] Critical:      13      │
│    ◑ Partial:           23       Total:          110     │
│─────────────────────────────────────────────────────────────────│
│  QRAMM DIMENSION 1: Cryptographic Visibility & Inventory (CVI) │
│    Practice 1.1 Discovery:   Level 3/5 ●●●○○                    │
│    Practice 1.2 Assessment:  Level 3/5 ●●●○○                    │
│    Practice 1.3 Mapping:     Level 3/5 ●●●○○                    │
```

## How CryptoScan compares

This is the maintainers' own comparison. It has not been reviewed independently, and the "Commercial Tools" column is a general description rather than a test of named tools.

| Capability | CryptoScan | grep/ripgrep | Commercial Tools |
|------------|:----------:|:------------:|:----------------:|
| Remote Git URL scanning | **Yes** | No | Some |
| Source code context | **Yes** | No | Rarely |
| Quantum risk classification | **Yes** | No | Some |
| **Post-Quantum Crypto detection** | **Yes** | No | Rarely |
| **Migration Readiness Score** | **Yes** | No | No |
| **Hybrid crypto recognition** | **Yes** | No | Rarely |
| **QRAMM framework mapping** | **Yes** | No | No |
| **CI/CD baseline comparison** | **Yes** | No | Some |
| **Configurable exit codes** | **Yes** | No | Some |
| Context-aware confidence | **Yes** | No | Varies |
| CBOM output | **Yes** | No | Rarely |
| SARIF for GitHub Security | **Yes** | No | Yes |
| Inline ignore comments | **Yes** | No | Some |
| Pattern-specific suppression | **Yes** | No | Rarely |
| Migration guidance | **Yes** | No | Varies |
| Dependency scanning | **Yes** | No | Some |
| Configuration file | **Yes** | N/A | Yes |
| Open source | **Yes** | Yes | No |

### What these capabilities mean

**Remote Git URL scanning**: Scan any public or private Git repository directly by URL without cloning it first. Just run `cryptoscan scan https://github.com/org/repo.git` and get results immediately.

**Source code context**: Every finding includes the 3 lines before and after the match (`--context` sets the number), so you can immediately understand the context without opening the file. Know if it's in a comment, test, or production code at a glance.

**Quantum risk classification**: Each finding is tagged with its quantum computing threat level: VULNERABLE (broken by Shor's algorithm), PARTIAL (weakened by Grover's algorithm), SAFE (quantum-resistant), or UNKNOWN. This tells you exactly what needs to migrate first.

**Post-Quantum Crypto detection**: Detects NIST-standardized PQC algorithms including ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and draft FN-DSA (FIPS 206). Also detects stateful hash-based signatures (XMSS, LMS per SP 800-208). Recognizes both new FIPS names and legacy names (Kyber, Dilithium, SPHINCS+).

**Migration Readiness Score**: Get an instant percentage score showing how prepared your codebase is for the post-quantum transition. The score weighs quantum-safe algorithms (100%), hybrid implementations (80%), and partial safety (30%) against vulnerable and critical findings. Includes top-risk files to prioritize.

**Hybrid crypto recognition**: Identifies hybrid cryptographic implementations that combine classical and post-quantum algorithms for defense-in-depth. Detects patterns like X25519+ML-KEM key exchange and ECDSA+ML-DSA composite signatures, the recommended transition approach.

**QRAMM framework mapping**: Maps all findings to the Quantum Readiness Assurance Maturity Model (QRAMM) Dimension 1: Cryptographic Visibility & Inventory. Shows your maturity level for Discovery (Practice 1.1), Vulnerability Assessment (Practice 1.2), and Dependency Mapping (Practice 1.3).

**Context-aware confidence**: Not all matches are equal. CryptoScan reduces confidence for findings in comments, documentation, log messages, and test files. High-confidence findings in production code are prioritized over low-confidence matches in docs.

**CBOM output**: Generate a Cryptographic Bill of Materials, a machine-readable inventory of all cryptographic algorithms in your codebase. Required for federal compliance (OMB M-23-02) and essential for tracking quantum migration progress.

**SARIF for GitHub Security**: Output findings in SARIF format for direct integration with GitHub Code Scanning. See cryptographic issues as security alerts in your pull requests and repository Security tab.

**Inline ignore comments**: Suppress false positives directly in your code with `// cryptoscan:ignore`. No need to maintain separate exclusion files or configure complex ignore rules.

**Migration guidance**: Every finding includes specific remediation advice: which NIST PQC algorithm to migrate to (ML-KEM, ML-DSA, SLH-DSA), links to standards, and effort estimates.

**Dependency scanning**: Reads package.json, requirements.txt, pyproject.toml, go.mod, pom.xml, Cargo.toml and Gemfile to identify crypto libraries in your dependencies. The scanner has no reader for build.gradle, build.gradle.kts, Pipfile, composer.json, packages.config, nuget.config or go.sum; a scan names each such file it finds as not scanned, under `skippedFiles` in JSON, and does not count it as scanned. Lock files such as package-lock.json and Cargo.lock are left out of the scan.

## Architecture

```
cryptoscan/
├── cmd/cryptoscan/      # CLI entry point
├── internal/cli/        # Command implementations
├── pkg/
│   ├── analyzer/        # File context, line analysis, and migration scoring
│   ├── config/          # .cryptoscan.yaml loading and ignore matching
│   ├── patterns/        # Cryptographic pattern definitions (90)
│   ├── reporter/        # Output formatters (text, json, csv, sarif, cbom)
│   ├── scanner/         # Core scanning engine with parallel processing
│   ├── types/           # Shared type definitions (findings, QRAMM mappings)
│   └── version/         # Version information shared by every output format
└── crypto-samples/      # Sample files for testing (PQC, MACs, KDFs, hybrid)
```

## References

### NIST Post-Quantum Cryptography Standards

- [FIPS 203 - ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)](https://csrc.nist.gov/pubs/fips/203/final): Replaces RSA/ECDH for key exchange
- [FIPS 204 - ML-DSA (Module-Lattice-Based Digital Signature Algorithm)](https://csrc.nist.gov/pubs/fips/204/final): Replaces RSA/ECDSA for signatures
- [FIPS 205 - SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)](https://csrc.nist.gov/pubs/fips/205/final): Alternative signature scheme
- [FIPS 206 - FN-DSA (FFT-Based Network Digital Signature Algorithm)](https://csrc.nist.gov/pubs/fips/206/ipd): Draft standard (formerly Falcon)
- [SP 800-208 - XMSS and LMS Hash-Based Signatures](https://csrc.nist.gov/pubs/sp/800/208/final): Stateful hash-based signatures
- [NIST SP 800-131A Rev 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final): Transitioning cryptographic algorithms and key lengths

### Additional Resources

- [NSA Cybersecurity Advisory on Post-Quantum Cryptography](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
