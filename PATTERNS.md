# CryptoScan Detection Patterns

CryptoScan uses 90+ detection patterns to identify cryptographic algorithms, protocols, keys, certificates, and configurations in your codebase. Each pattern includes quantum risk classification and remediation guidance.

## Table of Contents

- [How Detection Works](#how-detection-works)
- [Confidence Scoring](#confidence-scoring)
- [Pattern Categories](#pattern-categories)
  - [Post-Quantum Cryptography](#post-quantum-cryptography)
  - [Hybrid Cryptography](#hybrid-cryptography)
  - [Asymmetric Encryption](#asymmetric-encryption)
  - [Symmetric Encryption](#symmetric-encryption)
  - [Hash Functions](#hash-functions)
  - [Message Authentication Codes (MACs)](#message-authentication-codes-macs)
  - [Key Derivation Functions (KDFs)](#key-derivation-functions-kdfs)
  - [Certificates](#certificates) *(NEW in v1.2)*
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

### Post-Quantum Cryptography

NIST-standardized algorithms resistant to quantum computer attacks.

| Pattern ID | Name | Quantum Risk | Severity | What It Detects |
|------------|------|--------------|----------|-----------------|
| PQC-MLKEM-001 | ML-KEM Key Encapsulation | SAFE | Info | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`, `Kyber512`, `Kyber768`, `Kyber1024` |
| PQC-MLDSA-001 | ML-DSA Digital Signatures | SAFE | Info | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`, `Dilithium2`, `Dilithium3`, `Dilithium5` |
| PQC-SLHDSA-001 | SLH-DSA Hash-Based Signatures | SAFE | Info | `SLH-DSA-128f`, `SLH-DSA-192s`, `SPHINCS+`, `SPHINCS+-SHA2-128f` |
| PQC-FNDSA-001 | FN-DSA (Falcon) Signatures | SAFE | Info | `FN-DSA-512`, `FN-DSA-1024`, `Falcon-512`, `Falcon-1024` |
| PQC-XMSS-001 | XMSS Stateful Signatures | SAFE | Low | `XMSS-SHA2_10_256`, `XMSS-SHAKE_20_256`, `XMSSMT` |
| PQC-LMS-001 | LMS Stateful Signatures | SAFE | Low | `LMS`, `HSS`, `LMS_SHA256_M24_H10` |

**Note on Naming**: CryptoScan recognizes both NIST FIPS names and legacy names:
- ML-KEM (FIPS 203) = Kyber
- ML-DSA (FIPS 204) = Dilithium
- SLH-DSA (FIPS 205) = SPHINCS+
- FN-DSA (FIPS 206 draft) = Falcon

**Stateful Signatures Warning**: XMSS and LMS require careful state management. Each key can only sign a limited number of messages.

---

### Hybrid Cryptography

Combines classical and post-quantum algorithms for defense-in-depth during the transition period.

| Pattern ID | Name | Quantum Risk | Severity | What It Detects |
|------------|------|--------------|----------|-----------------|
| HYBRID-KEM-001 | X25519+ML-KEM Hybrid Key Exchange | HYBRID | Info | `X25519MLKEM768`, `X25519Kyber768`, hybrid key exchange combinations |
| HYBRID-SIG-001 | ECDSA+ML-DSA Composite Signatures | HYBRID | Info | `MLDSA65-ECDSA-P256`, `Dilithium3-ECDSA`, composite signatures |
| HYBRID-SIG-002 | RSA+ML-DSA Composite Signatures | HYBRID | Info | `MLDSA65-RSA3072`, RSA+PQC composite combinations |

**Why Hybrid?**
- Security holds if EITHER algorithm remains secure
- Recommended transition approach by NIST and NSA
- Provides protection if PQC algorithms have undiscovered weaknesses

**Note**: Hybrid implementations add overhead but provide maximum security during the cryptographic transition period.

---

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
| AES-GCM-001 | AES-GCM (AEAD) | SAFE | Info | `AES-256-GCM`, `aes-256-gcm` (NIST SP 800-38D) |
| CHACHA-001 | ChaCha20-Poly1305 (AEAD) | SAFE | Info | `ChaCha20-Poly1305`, `chacha20-poly1305` (RFC 8439) |
| AES-001 | AES Algorithm | PARTIAL | Info | `AES-128`, `AES-256`, `AES-CBC` |
| AES-ECB | AES-ECB Mode | PARTIAL | Critical | ECB mode (insecure regardless of quantum) |
| DES-001 | DES Algorithm | VULNERABLE | Critical | `DES`, `DES-CBC` (56-bit, completely broken) |
| 3DES-001 | Triple DES | VULNERABLE | High | `3DES`, `Triple-DES`, `DESede` |
| RC4-001 | RC4 Stream Cipher | VULNERABLE | Critical | `RC4`, `ARC4`, `ARCFOUR` |
| BLOWFISH-001 | Blowfish | PARTIAL | Medium | `Blowfish` (64-bit block, birthday attacks) |

**Recommended AEAD Ciphers** (provide both encryption and authentication):
- **AES-256-GCM**: NIST-approved, widely supported
- **ChaCha20-Poly1305**: IETF standard, excellent for software implementations

**Remediation**:
- Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption
- Never use ECB mode
- Replace DES, 3DES, RC4 immediately

---

### Hash Functions

| Pattern ID | Name | Quantum Risk | Severity | What It Detects |
|------------|------|--------------|----------|-----------------|
| MD5-001 | MD5 Hash | VULNERABLE | Critical | `MD5`, `md5()`, `hashlib.md5` |
| SHA1-001 | SHA-1 Hash | VULNERABLE | High | `SHA-1`, `sha1()`, `hashlib.sha1` |
| SHA2-001 | SHA-2 Family | PARTIAL | Info | `SHA-256`, `SHA-384`, `SHA-512` |
| SHA3-001 | SHA-3 Family | SAFE | Info | `SHA3-256`, `SHA3-384`, `SHA3-512` (FIPS 202) |
| SHAKE-001 | SHAKE XOF | SAFE | Info | `SHAKE128`, `SHAKE256` (FIPS 202 - quantum-safe) |
| BLAKE2-001 | BLAKE2 | PARTIAL | Info | `BLAKE2b`, `BLAKE2s` (not NIST but widely used) |
| BLAKE3-001 | BLAKE3 | PARTIAL | Info | `BLAKE3` (not NIST but widely used) |

**Why MD5 and SHA-1 are Critical**:
- MD5: Collision attacks demonstrated in 2004
- SHA-1: Practical collision attack (SHAttered) in 2017
- Both are broken for security purposes, regardless of quantum

**Remediation**: Use SHA-256 or SHA-3 for integrity checks.

---

### Message Authentication Codes (MACs)

MACs provide integrity and authenticity verification.

| Pattern ID | Name | Quantum Risk | Severity | What It Detects |
|------------|------|--------------|----------|-----------------|
| MAC-HMAC-256 | HMAC-SHA256 | PARTIAL | Info | `HMAC-SHA256`, `hmac.New(sha256.New)`, `createHmac('sha256')` |
| MAC-HMAC-384 | HMAC-SHA384 | SAFE | Info | `HMAC-SHA384`, `hmac.New(sha384.New)` |
| MAC-HMAC-512 | HMAC-SHA512 | SAFE | Info | `HMAC-SHA512`, `hmac.New(sha512.New)` |
| MAC-HMAC-SHA3 | HMAC-SHA3 | SAFE | Info | `HMAC-SHA3-256`, `hmac.New(sha3.New256)` |
| MAC-KMAC-001 | KMAC-128/256 | SAFE | Info | `KMAC128`, `KMAC256`, `sha3.NewKMAC256` (SP 800-185 quantum-safe) |
| MAC-CMAC-001 | CMAC | PARTIAL | Info | `CMAC-AES`, `AES-CMAC` (NIST SP 800-38B) |
| MAC-GMAC-001 | GMAC | PARTIAL | Info | `GMAC`, `AES-GMAC`, GCM authentication tag |
| MAC-POLY1305-001 | Poly1305 | PARTIAL | Info | `Poly1305`, `chacha20-poly1305` authentication |
| MAC-CBC-001 | CBC-MAC | PARTIAL | Medium | `CBC-MAC` (not standalone approved, use CMAC) |

**NIST-Approved MACs**: HMAC (all SHA variants), KMAC, CMAC, GMAC
**Quantum-Safe**: KMAC is specifically designed for quantum resistance (SP 800-185)

**Remediation**:
- Prefer HMAC-SHA256/384/512 for most use cases
- Use KMAC for maximum quantum safety
- Replace CBC-MAC with CMAC

---

### Key Derivation Functions (KDFs)

KDFs derive cryptographic keys from passwords or other input material.

| Pattern ID | Name | Quantum Risk | Severity | What It Detects |
|------------|------|--------------|----------|-----------------|
| KDF-HKDF-001 | HKDF | PARTIAL | Info | `HKDF`, `hkdf.New`, `crypto.hkdfSync` (SP 800-56C) |
| KDF-PBKDF2-001 | PBKDF2 | PARTIAL | Info | `PBKDF2`, `pbkdf2.Key`, `crypto.pbkdf2` (SP 800-132) |
| KDF-ARGON2-001 | Argon2id | PARTIAL | Info | `Argon2id`, `Argon2i`, `Argon2d`, `argon2.IDKey` (RFC 9106) |
| KDF-SCRYPT-001 | scrypt | PARTIAL | Info | `scrypt`, `crypto.scrypt`, `x/crypto/scrypt` |
| KDF-BCRYPT-001 | bcrypt | PARTIAL | Info | `bcrypt`, `bcrypt.GenerateFromPassword` |
| KDF-PBKDF1-001 | PBKDF1 | VULNERABLE | High | `PBKDF1` (deprecated, use PBKDF2) |

**Password Hashing Recommendations** (OWASP 2024):
- **Argon2id**: Recommended for new applications (RFC 9106)
- **bcrypt**: Industry standard, well-tested
- **PBKDF2**: NIST-approved, 600,000+ iterations for SHA-256

**Key Derivation from Secrets**:
- **HKDF**: Use for deriving keys from high-entropy secrets (SP 800-56C)

**Note**: Argon2 and scrypt are not yet NIST-approved but are widely recommended by security researchers.

---

### Certificates

X.509 certificates, certificate chains, and PKI infrastructure. *(NEW in v1.2)*

| Pattern ID | Name | Quantum Risk | Severity | What It Detects |
|------------|------|--------------|----------|-----------------|
| CERT-001 | X.509 Certificate | UNKNOWN | Info | `-----BEGIN CERTIFICATE-----` |
| CERT-CSR-001 | Certificate Signing Request | UNKNOWN | Info | `-----BEGIN CERTIFICATE REQUEST-----` |
| CERT-PKCS12-001 | PKCS#12/PFX Container | UNKNOWN | Medium | `.p12`, `.pfx`, `PKCS12` references |
| CERT-CHAIN-001 | Certificate Chain | UNKNOWN | Info | `cert_chain`, `ca_bundle`, `root_ca`, `trust_anchor` |
| CERT-TRUSTED-001 | Trusted Certificate | UNKNOWN | Info | `-----BEGIN TRUSTED CERTIFICATE-----` |
| CERT-EXPIRY-001 | Certificate Expiration | UNKNOWN | Info | `NotAfter`, `validUntil`, expiration checks |
| CERT-SUBJECT-001 | Certificate Subject/Issuer | UNKNOWN | Info | `subjectDN`, `issuerDN`, `getSubject`, `getIssuer` |
| CERT-SIGALG-001 | Certificate Signature Algorithm | VULNERABLE | Medium | `sha256WithRSA`, `ecdsaWithSHA256` |
| CERT-SIGALG-WEAK-001 | Weak Certificate Signature | VULNERABLE | **Critical** | `sha1WithRSA`, `md5WithRSA` |
| CERT-KEYUSAGE-001 | Certificate Key Usage | UNKNOWN | Info | `keyUsage`, `extendedKeyUsage` |
| CERT-SAN-001 | Subject Alternative Name | UNKNOWN | Info | `subjectAltName`, `dnsNames` |
| CERT-PARSE-001 | X.509 Certificate Parsing | UNKNOWN | Info | `x509.ParseCertificate`, `X509Certificate` |
| CERT-VALIDATION-BYPASS-001 | Certificate Validation Bypass | UNKNOWN | **Critical** | `InsecureSkipVerify: true`, `verify=false`, `CERT_NONE` |
| CERT-SELFSIGNED-001 | Self-Signed Certificate | UNKNOWN | Medium | `self_signed`, `generateSelfSignedCert` |
| CERT-MTLS-001 | Mutual TLS (mTLS) | PARTIAL | Info | `mutual_tls`, `client_cert`, `RequireClientCert` |
| CERT-REVOCATION-001 | Certificate Revocation | UNKNOWN | Info | `OCSP`, `CRL`, `checkRevocation` |
| CERT-PINNING-001 | Certificate Pinning | UNKNOWN | Info | `cert_pin`, `TrustManagerFactory` |
| CERT-ACME-001 | ACME/Let's Encrypt | VULNERABLE | Info | `letsencrypt`, `certbot`, `acme_challenge` |
| KEY-JWK-001 | JSON Web Key (JWK) | VULNERABLE | Medium | `"kty": "RSA"`, `"kty": "EC"`, `.well-known/jwks` |

**Critical Findings**:
- **Certificate Validation Bypass**: Disabling certificate validation enables man-in-the-middle attacks. This should be fixed immediately.
- **Weak Certificate Signatures**: SHA-1 and MD5 signatures are deprecated and insecure. Replace certificates immediately.

**Remediation**:
- Use certificates with RSA-3072+ or ECC-P256+ keys
- Ensure SHA-256 or stronger signature algorithms
- Never disable certificate validation in production
- Plan for PQC certificate migration when standards finalize

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
| **VULNERABLE** | RSA, ECDSA, DH, DSA, Ed25519 | Shor's algorithm breaks these completely | Migrate by 2030 |
| **PARTIAL** | AES-128, SHA-256, HMAC-SHA256 | Grover's algorithm halves security (128→64 bit) | Use larger keys |
| **HYBRID** | X25519+ML-KEM, ECDSA+ML-DSA | Defense in depth during transition | Good transition approach |
| **SAFE** | AES-256, SHA-384, ML-KEM, ML-DSA, SLH-DSA, KMAC | Quantum-resistant | No action needed |
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

### Post-Quantum Cryptography
- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST FIPS 206 - FN-DSA (Draft)](https://csrc.nist.gov/pubs/fips/206/ipd)
- [NIST SP 800-208 - XMSS and LMS](https://csrc.nist.gov/pubs/sp/800/208/final)

### MACs and KDFs
- [NIST SP 800-185 - SHA-3 Derived Functions (KMAC)](https://csrc.nist.gov/pubs/sp/800/185/final)
- [NIST SP 800-38B - CMAC](https://csrc.nist.gov/pubs/sp/800/38/b/final)
- [NIST SP 800-56C - Key Derivation (HKDF)](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final)
- [NIST SP 800-132 - PBKDF](https://csrc.nist.gov/pubs/sp/800/132/final)
- [RFC 9106 - Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)

### Classical Cryptography
- [NIST SP 800-131A Rev 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
