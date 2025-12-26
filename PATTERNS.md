# CryptoScan Detection Patterns

CryptoScan uses 50+ detection patterns to identify cryptographic algorithms, protocols, keys, and configurations in your codebase. Each pattern includes quantum risk classification and remediation guidance.

## Table of Contents

- [How Detection Works](#how-detection-works)
- [Confidence Scoring](#confidence-scoring)
- [Pattern Categories](#pattern-categories)
  - [Asymmetric Encryption](#asymmetric-encryption)
  - [Symmetric Encryption](#symmetric-encryption)
  - [Hash Functions](#hash-functions)
  - [TLS/SSL Protocols](#tlsssl-protocols)
  - [Key Material & Secrets](#key-material--secrets)
  - [Cloud KMS Services](#cloud-kms-services)
  - [Crypto Library Imports](#crypto-library-imports)
- [Quantum Risk Levels](#quantum-risk-levels)
- [Severity Levels](#severity-levels)

---

## How Detection Works

CryptoScan performs multi-layer analysis:

1. **Pattern Matching**: Regex patterns identify cryptographic algorithms, function calls, and configurations
2. **Context Analysis**: Examines surrounding code to understand usage context
3. **Confidence Scoring**: Adjusts confidence based on file type, comments, and context
4. **Deduplication**: Removes redundant findings from the same location

### What Makes CryptoScan Different from grep

| Aspect | grep/ripgrep | CryptoScan |
|--------|--------------|------------|
| Finds "RSA" in code | Yes | Yes |
| Knows it's in a comment | No | Yes (lowers confidence) |
| Knows it's in test code | No | Yes (lowers severity) |
| Knows it's in documentation | No | Yes (filters out) |
| Provides remediation | No | Yes |
| Classifies quantum risk | No | Yes |
| Shows source context | No | Yes (3 lines before/after) |

---

## Confidence Scoring

Not all matches are equal. CryptoScan assigns confidence levels to help you prioritize:

### Confidence Levels

| Level | Meaning | When Applied |
|-------|---------|--------------|
| **HIGH** | Almost certainly real crypto usage | Direct API calls, key generation, encryption operations |
| **MEDIUM** | Likely real, needs verification | References in configuration, variable names |
| **LOW** | Possibly false positive | Comments, documentation, log messages, test assertions |

### What Reduces Confidence

CryptoScan automatically reduces confidence when findings appear in:

- **Comments**: `// Using RSA for backwards compatibility`
- **Log statements**: `log.Info("Encrypting with AES-256")`
- **Documentation strings**: `"""This module uses SHA-256 for hashing"""`
- **Error messages**: `"Invalid RSA key format"`
- **Test files**: `*_test.go`, `test_*.py`, `*.spec.js`
- **Documentation files**: `*.md`, `README`, `docs/`
- **Vendor/generated code**: `vendor/`, `node_modules/`, generated files

### Example

```go
// This comment mentions RSA but isn't actual crypto usage
// Confidence: LOW (detected as comment)

key, err := rsa.GenerateKey(rand.Reader, 2048)
// Confidence: HIGH (actual API call)
```

---

## Pattern Categories

### Asymmetric Encryption

Algorithms vulnerable to Shor's algorithm on quantum computers.

| Pattern ID | Name | Quantum Risk | Severity | What It Detects |
|------------|------|--------------|----------|-----------------|
| RSA-001 | RSA Algorithm | VULNERABLE | High | `RSA`, `rsa`, `RSA-2048`, etc. |
| RSA-1024 | RSA-1024 Key Size | VULNERABLE | Critical | 1024-bit RSA keys (broken classically) |
| RSA-2048 | RSA-2048 Key Size | VULNERABLE | Medium | 2048-bit RSA keys |
| ECC-001 | Elliptic Curve | VULNERABLE | High | `ECDSA`, `ECDH`, `P-256`, `secp256r1`, `Ed25519`, `Curve25519` |
| DSA-001 | DSA Algorithm | VULNERABLE | High | `DSA`, `ssh-dss`, DSA key generation |
| DH-001 | Diffie-Hellman | VULNERABLE | High | `DiffieHellman`, `DHE`, `ECDHE` |

**Remediation**: Migrate to NIST post-quantum standards:
- Key exchange → ML-KEM (FIPS 203)
- Signatures → ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)

---

### Symmetric Encryption

Symmetric algorithms have varying quantum resistance.

| Pattern ID | Name | Quantum Risk | Severity | What It Detects |
|------------|------|--------------|----------|-----------------|
| AES-001 | AES Algorithm | PARTIAL | Info | `AES-128`, `AES-256`, `AES-GCM`, `AES-CBC` |
| AES-ECB | AES-ECB Mode | PARTIAL | Critical | ECB mode (insecure regardless of quantum) |
| DES-001 | DES Algorithm | VULNERABLE | Critical | `DES`, `DES-CBC` (56-bit, completely broken) |
| 3DES-001 | Triple DES | VULNERABLE | High | `3DES`, `Triple-DES`, `DESede` |
| RC4-001 | RC4 Stream Cipher | VULNERABLE | Critical | `RC4`, `ARC4`, `ARCFOUR` |
| BLOWFISH-001 | Blowfish | PARTIAL | Medium | `Blowfish` (64-bit block, birthday attacks) |

**Remediation**:
- Use AES-256-GCM for symmetric encryption
- Never use ECB mode
- Replace DES, 3DES, RC4 immediately

---

### Hash Functions

| Pattern ID | Name | Quantum Risk | Severity | What It Detects |
|------------|------|--------------|----------|-----------------|
| MD5-001 | MD5 Hash | VULNERABLE | Critical | `MD5`, `md5()`, `hashlib.md5` |
| SHA1-001 | SHA-1 Hash | VULNERABLE | High | `SHA-1`, `sha1()`, `hashlib.sha1` |
| SHA2-001 | SHA-2 Family | PARTIAL | Info | `SHA-256`, `SHA-384`, `SHA-512` |

**Why MD5 and SHA-1 are Critical**:
- MD5: Collision attacks demonstrated in 2004
- SHA-1: Practical collision attack (SHAttered) in 2017
- Both are broken for security purposes, regardless of quantum

**Remediation**: Use SHA-256 or SHA-3 for integrity checks.

---

### TLS/SSL Protocols

| Pattern ID | Name | Quantum Risk | Severity | What It Detects |
|------------|------|--------------|----------|-----------------|
| TLS-001 | TLS 1.0/1.1/SSL | VULNERABLE | Critical | `TLSv1.0`, `TLSv1.1`, `SSLv2`, `SSLv3` |
| TLS-002 | TLS 1.2/1.3 | PARTIAL | Info | `TLSv1.2`, `TLSv1.3` |
| CIPHER-001 | Weak Cipher Suites | VULNERABLE | Critical | Export ciphers, NULL ciphers, anonymous DH |

**Remediation**:
- Minimum TLS 1.2, prefer TLS 1.3
- Use strong cipher suites only
- Monitor for hybrid PQC TLS when available

---

### Key Material & Secrets

Private keys and secrets in source code are critical security issues.

| Pattern ID | Name | Quantum Risk | Severity | What It Detects |
|------------|------|--------------|----------|-----------------|
| KEY-001 | RSA Private Key | VULNERABLE | Critical | `-----BEGIN RSA PRIVATE KEY-----` |
| KEY-002 | EC Private Key | VULNERABLE | Critical | `-----BEGIN EC PRIVATE KEY-----` |
| KEY-003 | DSA Private Key | VULNERABLE | Critical | `-----BEGIN DSA PRIVATE KEY-----` |
| KEY-004 | OpenSSH Private Key | VULNERABLE | Critical | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| KEY-005 | PGP Private Key | VULNERABLE | Critical | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| KEY-006 | PKCS#8 Private Key | VULNERABLE | Critical | `-----BEGIN PRIVATE KEY-----` |
| SECRET-JWT-001 | JWT Secret | PARTIAL | Critical | Hardcoded `jwt_secret`, `JWT_SECRET` |
| SECRET-KEY-001 | Encryption Key | PARTIAL | Critical | Hardcoded `encryption_key`, `aes_key` |
| SECRET-HMAC-001 | HMAC Secret | PARTIAL | High | Hardcoded `hmac_secret`, `signing_key` |

**Remediation**:
- Never commit private keys to source control
- Use secrets management (HashiCorp Vault, AWS Secrets Manager, etc.)
- Rotate any exposed credentials immediately

---

### Cloud KMS Services

References to cloud key management services that may use quantum-vulnerable algorithms.

| Pattern ID | Name | What It Detects |
|------------|------|-----------------|
| SECRET-KMS-001 | AWS KMS | `arn:aws:kms:...`, KMS key aliases |
| SECRET-KMS-002 | GCP Cloud KMS | `projects/.../cryptoKeys/...` |
| SECRET-VAULT-001 | Azure Key Vault | `*.vault.azure.net/keys/...` |
| SECRET-VAULT-002 | HashiCorp Vault | `vault read`, `VAULT_ADDR`, transit paths |

**Note**: These are informational findings to help inventory crypto dependencies.

---

### Crypto Library Imports

Detects imports of cryptographic libraries for inventory purposes.

| Pattern ID | Language | What It Detects |
|------------|----------|-----------------|
| LIB-PY-001 | Python | `from cryptography`, `from Crypto`, `import hashlib` |
| LIB-JAVA-001 | Java | `import javax.crypto`, `import java.security` |
| LIB-GO-001 | Go | `"crypto/rsa"`, `"crypto/aes"`, `"crypto/tls"` |
| LIB-NODE-001 | Node.js | `require('crypto')`, `import 'crypto'` |
| LIB-OPENSSL-001 | C/C++ | `#include <openssl/...>`, `EVP_`, `RSA_` |

**Note**: Library imports are LOW severity and help build a complete crypto inventory.

---

## Quantum Risk Levels

| Risk | Algorithm Examples | Threat | Timeline |
|------|-------------------|--------|----------|
| **VULNERABLE** | RSA, ECDSA, DH, DSA | Shor's algorithm breaks these completely | Migrate by 2030 |
| **PARTIAL** | AES-128, SHA-256 | Grover's algorithm halves security (128→64 bit) | Use larger keys |
| **SAFE** | AES-256, SHA-384, ML-KEM | Quantum-resistant | No action needed |
| **UNKNOWN** | Custom/proprietary | Cannot determine | Manual review |

---

## Severity Levels

| Severity | Meaning | Examples |
|----------|---------|----------|
| **CRITICAL** | Immediate security risk | MD5, DES, RC4, private keys in code, ECB mode |
| **HIGH** | Significant risk, plan migration | RSA, ECDSA, SHA-1, 3DES |
| **MEDIUM** | Moderate risk | RSA-2048, Blowfish |
| **LOW** | Minor concern | Hardcoded key sizes, configuration issues |
| **INFO** | Informational | AES-256, SHA-256, library imports |

---

## Adding Custom Patterns

See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on adding new detection patterns.

Each pattern requires:
- Unique ID (e.g., `RSA-001`)
- Descriptive name
- Category
- Compiled regex
- Severity and quantum risk levels
- Description and remediation guidance
- References to standards/documentation

---

## References

- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST SP 800-131A Rev 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
