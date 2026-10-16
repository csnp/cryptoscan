# Roadmap

This page lists what CryptoScan already does and what the maintainers plan next; for installation and a first scan, start with the [README](../README.md).

Status as of 2026-10-15, when 1.4.0 is the latest release. What each release changed, and its known limitations, is in [CHANGELOG.md](../CHANGELOG.md).

## v1.3
- [x] Local and remote repository scanning
- [x] 90+ cryptographic patterns
- [x] Multiple output formats (text, JSON, CSV, SARIF, CBOM)
- [x] Context-aware analysis with confidence scoring
- [x] Dependency scanning for 20+ package managers
- [x] Parallel scanning with worker pools
- [x] Inline ignore comments
- [x] Post-Quantum Cryptography detection (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, XMSS, LMS)
- [x] Hybrid cryptography recognition (X25519+ML-KEM, composite signatures)
- [x] Comprehensive MAC detection (HMAC, KMAC, CMAC, GMAC, Poly1305)
- [x] KDF detection (HKDF, PBKDF2, Argon2id, scrypt, bcrypt)
- [x] Migration Readiness Score with visual dashboard
- [x] QRAMM framework integration (CVI Dimension mapping)
- [x] Certificate detection (X.509, CSR, PKCS#12, chains, mTLS, JWK)
- [x] Certificate validation bypass detection (CRITICAL severity)
- [x] Weak certificate signature detection (SHA-1/MD5)
- [x] Enhanced false positive reduction with smart context analysis
- [x] CI/CD flexibility with `--ignore`, `--ignore-category`, `--fail-on`, `--baseline`
- [x] Configuration file support (`.cryptoscan.yaml`)
- [x] Pattern-specific inline suppression (`cryptoscan:ignore RSA-001`)
- [x] Baseline comparison for tracking new findings only

## v1.4
- [x] Enhanced CBOM output (CycloneDX 1.6 cryptoProperties), shipped in 1.4.0
- [ ] Smart remediation engine with language-specific recommendations
- [ ] Git history scanning (find crypto in past commits). The `--git-history` flag is accepted today and ignored.

## v2.0 (future)
- [ ] AWS resource scanning (KMS, ACM, Secrets Manager)
- [ ] Azure resource scanning (Key Vault, App Configuration)
- [ ] GCP resource scanning (Cloud KMS, Secret Manager)
- [ ] Infrastructure-as-Code analysis (Terraform, CloudFormation, Pulumi)
