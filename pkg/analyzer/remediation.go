// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package analyzer provides analysis utilities for cryptographic findings.
package analyzer

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/csnp/cryptoscan/pkg/types"
)

// RemediationEngine provides language-aware remediation suggestions
type RemediationEngine struct{}

// NewRemediationEngine creates a new remediation engine
func NewRemediationEngine() *RemediationEngine {
	return &RemediationEngine{}
}

// Remediation contains language-specific remediation details
type Remediation struct {
	Summary         string            `json:"summary"`
	Fix             string            `json:"fix,omitempty"` // One-line change for this algorithm in this language
	Priority        string            `json:"priority"`
	Effort          string            `json:"effort"`
	NISTReference   string            `json:"nistReference,omitempty"`
	CodeExample     string            `json:"codeExample,omitempty"`
	Library         string            `json:"library,omitempty"`
	LibraryInstall  string            `json:"libraryInstall,omitempty"`
	MigrationPath   string            `json:"migrationPath,omitempty"`
	HybridApproach  bool              `json:"hybridApproach"`
	AlternativeLibs map[string]string `json:"alternativeLibs,omitempty"`
}

// DetectLanguageFromFile determines the programming language from file path
func DetectLanguageFromFile(filename string) Language {
	name := filepath.Base(filename)
	ext := strings.ToLower(filepath.Ext(filename))
	return detectLanguage(name, ext)
}

// GetRemediation returns language-specific remediation for a finding
func (r *RemediationEngine) GetRemediation(finding *types.Finding, lang Language) *Remediation {
	// Determine migration status
	status := ClassifyMigrationStatus(finding)

	switch {
	case isAsymmetricVulnerable(finding):
		return r.getAsymmetricRemediation(finding, lang, status)
	case isHashBroken(finding):
		return r.getHashRemediation(finding, lang)
	case isSymmetricWeak(finding):
		return r.getSymmetricRemediation(finding, lang)
	case isKDFWeak(finding):
		return r.getKDFRemediation(finding, lang)
	default:
		return r.getGenericRemediation(finding, lang, status)
	}
}

// Apply fills the fields a reader needs to act on one finding: Verify, a
// command that prints the matched line, and Fix, one concrete change taken
// from the language-specific text when the engine has it and from the
// pattern's remediation otherwise.
func (r *RemediationEngine) Apply(f *types.Finding) {
	f.Verify = VerifyCommand(f)
	f.Fix = f.Remediation

	// A dependency finding names a library rather than a call site, so the
	// library-level remediation is the fix.
	if f.FindingType == types.FindingTypeDependency {
		return
	}

	if rem := r.GetRemediation(f, DetectLanguageFromFile(f.File)); rem.Fix != "" {
		f.Fix = rem.Fix
	}
}

// EstimateEffort returns the engine's effort estimate for the algorithm
// classes it has specific guidance for, and "" for everything else.
func (r *RemediationEngine) EstimateEffort(f *types.Finding) string {
	if !isAsymmetricVulnerable(f) && !isHashBroken(f) && !isSymmetricWeak(f) && !isKDFWeak(f) {
		return ""
	}
	return r.GetRemediation(f, LangUnknown).Effort
}

// VerifyCommand returns a POSIX shell command that prints the line a finding
// points at, using the same path the report prints. Dependency findings carry
// no real line number, so for those it searches the manifest for the package.
func VerifyCommand(f *types.Finding) string {
	if f.File == "" {
		return ""
	}
	if f.FindingType == types.FindingTypeDependency && f.Match != "" {
		return fmt.Sprintf("grep -n -F -e %s %s", shellQuote(f.Match), shellPath(f.File))
	}
	if f.Line < 1 {
		return ""
	}
	return fmt.Sprintf("sed -n '%dp' %s", f.Line, shellPath(f.File))
}

// shellPath quotes a path as a command argument, and keeps a path that starts
// with "-" from being read as an option.
func shellPath(p string) string {
	if strings.HasPrefix(p, "-") {
		p = "./" + p
	}
	return shellQuote(p)
}

// shellQuote returns s unchanged when every character is safe in a POSIX
// shell word, and single-quoted otherwise.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_-./+,:@%=", c)) {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

func isAsymmetricVulnerable(f *types.Finding) bool {
	vulnAlgos := []string{"RSA", "ECDSA", "DSA", "ECDH", "DH", "Ed25519", "X25519", "ECC"}
	for _, algo := range vulnAlgos {
		if strings.Contains(strings.ToUpper(f.Algorithm), strings.ToUpper(algo)) {
			return f.Quantum == types.QuantumVulnerable
		}
	}
	return false
}

func isHashBroken(f *types.Finding) bool {
	brokenHashes := []string{"MD5", "SHA-1", "SHA1"}
	for _, h := range brokenHashes {
		if strings.EqualFold(f.Algorithm, h) {
			return true
		}
	}
	return false
}

func isSymmetricWeak(f *types.Finding) bool {
	weakAlgos := []string{"DES", "3DES", "RC4", "Blowfish"}
	for _, algo := range weakAlgos {
		if strings.EqualFold(f.Algorithm, algo) {
			return true
		}
	}
	return false
}

func isKDFWeak(f *types.Finding) bool {
	return strings.EqualFold(f.Algorithm, "PBKDF1")
}

func (r *RemediationEngine) getAsymmetricRemediation(f *types.Finding, lang Language, status types.MigrationStatus) *Remediation {
	rem := &Remediation{
		Priority:       "HIGH",
		Effort:         "Medium to High",
		HybridApproach: true,
	}

	// Determine if key exchange or signature
	isKeyExchange := strings.Contains(strings.ToUpper(f.Algorithm), "DH") ||
		strings.Contains(strings.ToUpper(f.Algorithm), "X25519") ||
		strings.Contains(strings.ToUpper(f.Category), "KEY-EXCHANGE")

	if isKeyExchange {
		rem.Summary = "Migrate to ML-KEM (FIPS 203) for quantum-safe key encapsulation"
		rem.NISTReference = "https://csrc.nist.gov/pubs/fips/203/final"
		rem.MigrationPath = fmt.Sprintf("%s -> Hybrid (X25519+ML-KEM) -> ML-KEM-768", f.Algorithm)
	} else {
		rem.Summary = "Migrate to ML-DSA (FIPS 204) for quantum-safe digital signatures"
		rem.NISTReference = "https://csrc.nist.gov/pubs/fips/204/final"
		rem.MigrationPath = fmt.Sprintf("%s -> Hybrid (ECDSA+ML-DSA) -> ML-DSA-65", f.Algorithm)
	}

	// Language-specific code examples
	switch lang {
	case LangPython:
		rem.Library = "liboqs-python"
		rem.LibraryInstall = "pip install liboqs-python"
		if isKeyExchange {
			rem.CodeExample = `# ML-KEM-768 Key Encapsulation (FIPS 203)
from liboqs import oqs

# Generate keypair
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()

# Encapsulate (sender)
ciphertext, shared_secret_sender = kem.encap_secret(public_key)

# Decapsulate (receiver)
shared_secret_receiver = kem.decap_secret(ciphertext)`
		} else {
			rem.CodeExample = `# ML-DSA-65 Digital Signatures (FIPS 204)
from liboqs import oqs

# Generate keypair
sig = oqs.Signature("ML-DSA-65")
public_key = sig.generate_keypair()

# Sign message
message = b"Hello, quantum-safe world!"
signature = sig.sign(message)

# Verify signature
is_valid = sig.verify(message, signature, public_key)`
		}
		rem.AlternativeLibs = map[string]string{
			"pqcrypto":     "pip install pqcrypto",
			"cryptography": "pip install cryptography (PQC support coming)",
		}

	case LangGo:
		rem.Library = "cloudflare/circl"
		rem.LibraryInstall = "go get github.com/cloudflare/circl"
		if isKeyExchange {
			rem.CodeExample = `// ML-KEM-768 Key Encapsulation (FIPS 203)
import "github.com/cloudflare/circl/kem/mlkem/mlkem768"

// Generate keypair
pk, sk, _ := mlkem768.GenerateKeyPair(rand.Reader)

// Encapsulate (sender)
ct, ss, _ := mlkem768.Encapsulate(rand.Reader, pk)

// Decapsulate (receiver)
ss2, _ := mlkem768.Decapsulate(sk, ct)`
		} else {
			rem.CodeExample = `// ML-DSA-65 Digital Signatures (FIPS 204)
import "github.com/cloudflare/circl/sign/mldsa/mldsa65"

// Generate keypair
pk, sk, _ := mldsa65.GenerateKey(rand.Reader)

// Sign message
message := []byte("Hello, quantum-safe world!")
signature := mldsa65.Sign(sk, message, nil)

// Verify signature
valid := mldsa65.Verify(pk, message, nil, signature)`
		}
		rem.AlternativeLibs = map[string]string{
			"open-quantum-safe/liboqs-go": "go get github.com/open-quantum-safe/liboqs-go",
		}

	case LangJava:
		rem.Library = "BouncyCastle"
		rem.LibraryInstall = "Maven: org.bouncycastle:bcprov-jdk18on:1.78"
		if isKeyExchange {
			rem.CodeExample = `// ML-KEM-768 Key Encapsulation (FIPS 203)
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

Security.addProvider(new BouncyCastlePQCProvider());

KeyPairGenerator kpg = KeyPairGenerator.getInstance("KYBER", "BCPQC");
kpg.initialize(KyberParameterSpec.kyber768);
KeyPair kp = kpg.generateKeyPair();

// Encapsulate
KeyGenerator kg = KeyGenerator.getInstance("KYBER", "BCPQC");
kg.init(new KEMGenerateSpec(kp.getPublic(), "AES"));
SecretKeyWithEncapsulation secKey = (SecretKeyWithEncapsulation)kg.generateKey();`
		} else {
			rem.CodeExample = `// ML-DSA-65 Digital Signatures (FIPS 204)
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

Security.addProvider(new BouncyCastlePQCProvider());

KeyPairGenerator kpg = KeyPairGenerator.getInstance("DILITHIUM", "BCPQC");
kpg.initialize(DilithiumParameterSpec.dilithium3);
KeyPair kp = kpg.generateKeyPair();

Signature sig = Signature.getInstance("DILITHIUM", "BCPQC");
sig.initSign(kp.getPrivate());
sig.update(message);
byte[] signature = sig.sign();`
		}

	case LangJavaScript, LangTypeScript:
		rem.Library = "liboqs-node"
		rem.LibraryInstall = "npm install liboqs-node"
		if isKeyExchange {
			rem.CodeExample = `// ML-KEM-768 Key Encapsulation (FIPS 203)
const oqs = require('liboqs-node');

// Generate keypair
const kem = new oqs.KeyEncapsulation('ML-KEM-768');
const keypair = kem.generateKeypair();

// Encapsulate (sender)
const { ciphertext, sharedSecret } = kem.encapSecret(keypair.publicKey);

// Decapsulate (receiver)
const sharedSecret2 = kem.decapSecret(ciphertext);`
		} else {
			rem.CodeExample = `// ML-DSA-65 Digital Signatures (FIPS 204)
const oqs = require('liboqs-node');

// Generate keypair
const sig = new oqs.Signature('ML-DSA-65');
const keypair = sig.generateKeypair();

// Sign message
const message = Buffer.from('Hello, quantum-safe world!');
const signature = sig.sign(message);

// Verify signature
const isValid = sig.verify(message, signature, keypair.publicKey);`
		}

	case LangRust:
		rem.Library = "pqcrypto"
		rem.LibraryInstall = "cargo add pqcrypto"
		if isKeyExchange {
			rem.CodeExample = `// ML-KEM-768 Key Encapsulation (FIPS 203)
use pqcrypto::kem::kyber768::*;

// Generate keypair
let (pk, sk) = keypair();

// Encapsulate (sender)
let (ss1, ct) = encapsulate(&pk);

// Decapsulate (receiver)
let ss2 = decapsulate(&ct, &sk);`
		} else {
			rem.CodeExample = `// ML-DSA-65 Digital Signatures (FIPS 204)
use pqcrypto::sign::dilithium3::*;

// Generate keypair
let (pk, sk) = keypair();

// Sign message
let message = b"Hello, quantum-safe world!";
let signature = sign(message, &sk);

// Verify signature
let verified = open(&signature, &pk).is_ok();`
		}

	default:
		rem.CodeExample = "// See NIST PQC documentation for language-specific implementations"
	}

	if rem.Library != "" {
		rem.Fix = asymmetricFix(f.Algorithm, isKeyExchange, rem.Library)
	}

	return rem
}

// asymmetricFix names the post-quantum replacement for alg. RSA and ECC
// serve both encryption and signatures, so their fix names both targets.
func asymmetricFix(alg string, isKeyExchange bool, library string) string {
	upper := strings.ToUpper(alg)
	switch {
	case isKeyExchange:
		return fmt.Sprintf("Migrate %s key exchange to ML-KEM-768 using %s", alg, library)
	case strings.Contains(upper, "DSA") || strings.Contains(upper, "ED25519"):
		return fmt.Sprintf("Migrate %s signatures to ML-DSA-65 using %s", alg, library)
	default:
		return fmt.Sprintf("Migrate %s to ML-KEM-768 for encryption and key exchange, or to ML-DSA-65 for signatures, using %s", alg, library)
	}
}

func (r *RemediationEngine) getHashRemediation(f *types.Finding, lang Language) *Remediation {
	rem := &Remediation{
		Summary:        "Replace broken hash function with SHA-256 or SHA-3",
		Priority:       "CRITICAL",
		Effort:         "Low",
		NISTReference:  "https://csrc.nist.gov/pubs/fips/180/4/final",
		HybridApproach: false,
		MigrationPath:  fmt.Sprintf("%s -> SHA-256 (or SHA-3 for quantum safety)", f.Algorithm),
	}

	// Names of the broken hash in each language's standard API.
	digest, short := "MD5", "md5"
	if strings.Contains(strings.ToUpper(f.Algorithm), "SHA") {
		digest, short = "SHA-1", "sha1"
	}

	switch lang {
	case LangPython:
		rem.Fix = fmt.Sprintf("Replace hashlib.%s() with hashlib.sha256()", short)
		rem.CodeExample = `# Replace MD5/SHA-1 with SHA-256
import hashlib

# Instead of: hashlib.md5(data) or hashlib.sha1(data)
hash_value = hashlib.sha256(data).hexdigest()

# For maximum quantum safety, use SHA-3:
hash_value = hashlib.sha3_256(data).hexdigest()`

	case LangGo:
		rem.Fix = fmt.Sprintf("Replace %s.Sum(data) with sha256.Sum256(data) from crypto/sha256", short)
		rem.CodeExample = `// Replace MD5/SHA-1 with SHA-256
import "crypto/sha256"

// Instead of: md5.Sum(data) or sha1.Sum(data)
hash := sha256.Sum256(data)

// For maximum quantum safety, use SHA-3:
import "golang.org/x/crypto/sha3"
hash := sha3.Sum256(data)`

	case LangJava:
		rem.Fix = fmt.Sprintf(`Replace MessageDigest.getInstance(%q) with MessageDigest.getInstance("SHA-256")`, digest)
		rem.CodeExample = `// Replace MD5/SHA-1 with SHA-256
import java.security.MessageDigest;

// Instead of: MessageDigest.getInstance("MD5") or ("SHA-1")
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest(data);

// For maximum quantum safety, use SHA-3:
MessageDigest digest = MessageDigest.getInstance("SHA3-256");`

	case LangJavaScript, LangTypeScript:
		rem.Fix = fmt.Sprintf("Replace crypto.createHash('%s') with crypto.createHash('sha256')", short)
		rem.CodeExample = `// Replace MD5/SHA-1 with SHA-256
const crypto = require('crypto');

// Instead of: crypto.createHash('md5') or ('sha1')
const hash = crypto.createHash('sha256').update(data).digest('hex');

// For SHA-3, use a library like 'js-sha3':
// npm install js-sha3
const { sha3_256 } = require('js-sha3');
const hash = sha3_256(data);`
	}

	return rem
}

// weakCipherNames gives each weak cipher's name in the standard API of each
// language, keyed by the pattern Algorithm.
var weakCipherNames = map[string]struct{ java, python, golang, node string }{
	"DES":      {"DES", "DES", "des.NewCipher", "des-cbc"},
	"3DES":     {"DESede", "TripleDES", "des.NewTripleDESCipher", "des-ede3-cbc"},
	"RC4":      {"RC4", "ARC4", "rc4.NewCipher", "rc4"},
	"Blowfish": {"Blowfish", "Blowfish", "blowfish.NewCipher", "bf-cbc"},
}

func (r *RemediationEngine) getSymmetricRemediation(f *types.Finding, lang Language) *Remediation {
	rem := &Remediation{
		Summary:        "Replace weak symmetric cipher with AES-256-GCM",
		Priority:       "CRITICAL",
		Effort:         "Medium",
		NISTReference:  "https://csrc.nist.gov/pubs/sp/800/38/d/final",
		HybridApproach: false,
		MigrationPath:  fmt.Sprintf("%s -> AES-256-GCM (or ChaCha20-Poly1305)", f.Algorithm),
	}

	// A missing entry leaves Fix empty, and Apply falls back to the
	// pattern's remediation sentence.
	names, known := weakCipherNames[f.Algorithm]

	switch lang {
	case LangPython:
		if known {
			rem.Fix = fmt.Sprintf("Replace the %s cipher with AESGCM from cryptography.hazmat.primitives.ciphers.aead and a 32-byte key", names.python)
		}
		rem.Library = "cryptography"
		rem.LibraryInstall = "pip install cryptography"
		rem.CodeExample = `# Replace DES/3DES/RC4 with AES-256-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Generate a 256-bit key
key = os.urandom(32)
nonce = os.urandom(12)

# Encrypt
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

# Decrypt
plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)`

	case LangGo:
		if known {
			rem.Fix = fmt.Sprintf("Replace %s(key) with aes.NewCipher(key) on a 32-byte key, wrapped in cipher.NewGCM", names.golang)
		}
		rem.CodeExample = `// Replace DES/3DES/RC4 with AES-256-GCM
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)

// Create AES-256-GCM cipher
block, _ := aes.NewCipher(key) // 32-byte key for AES-256
gcm, _ := cipher.NewGCM(block)

// Encrypt
nonce := make([]byte, gcm.NonceSize())
rand.Read(nonce)
ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

// Decrypt
plaintext, _ := gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], nil)`

	case LangJava:
		if known {
			rem.Fix = fmt.Sprintf(`Replace the %q transformation in Cipher.getInstance with "AES/GCM/NoPadding" and a 32-byte key`, names.java)
		}
		rem.CodeExample = `// Replace DES/3DES/RC4 with AES-256-GCM
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

SecretKeySpec keySpec = new SecretKeySpec(key, "AES"); // 32-byte key
byte[] iv = new byte[12];
new SecureRandom().nextBytes(iv);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
byte[] ciphertext = cipher.doFinal(plaintext);`

	case LangJavaScript, LangTypeScript:
		if known {
			rem.Fix = fmt.Sprintf("Replace the '%s' cipher in crypto.createCipheriv with 'aes-256-gcm' and a 32-byte key", names.node)
		}
		rem.CodeExample = `// Replace DES/3DES/RC4 with AES-256-GCM
const crypto = require('crypto');

// Encrypt
const key = crypto.randomBytes(32); // 256-bit key
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let ciphertext = cipher.update(plaintext);
ciphertext = Buffer.concat([ciphertext, cipher.final()]);
const authTag = cipher.getAuthTag();

// Decrypt
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTag(authTag);
let plaintext = decipher.update(ciphertext);
plaintext = Buffer.concat([plaintext, decipher.final()]);`
	}

	return rem
}

func (r *RemediationEngine) getKDFRemediation(f *types.Finding, lang Language) *Remediation {
	rem := &Remediation{
		Summary:        "Replace deprecated KDF with Argon2id or PBKDF2",
		Priority:       "HIGH",
		Effort:         "Low",
		NISTReference:  "https://www.rfc-editor.org/rfc/rfc9106.html",
		HybridApproach: false,
		MigrationPath:  "PBKDF1 -> Argon2id (preferred) or PBKDF2 (NIST-approved)",
	}

	switch lang {
	case LangPython:
		rem.Fix = "Replace PBKDF1 with Argon2id through PasswordHasher from argon2-cffi"
		rem.Library = "argon2-cffi"
		rem.LibraryInstall = "pip install argon2-cffi"
		rem.CodeExample = `# Replace PBKDF1 with Argon2id (RFC 9106)
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=4
)

# Hash password
hash = ph.hash(password)

# Verify password
try:
    ph.verify(hash, password)
except argon2.exceptions.VerifyMismatchError:
    print("Invalid password")`

	case LangGo:
		rem.Fix = "Replace PBKDF1 with argon2.IDKey from golang.org/x/crypto/argon2"
		rem.Library = "golang.org/x/crypto/argon2"
		rem.LibraryInstall = "go get golang.org/x/crypto/argon2"
		rem.CodeExample = `// Replace PBKDF1 with Argon2id (RFC 9106)
import "golang.org/x/crypto/argon2"

salt := make([]byte, 16)
rand.Read(salt)

// Argon2id with recommended parameters
hash := argon2.IDKey(
    []byte(password),
    salt,
    3,       // time (iterations)
    64*1024, // memory (64 MB)
    4,       // parallelism
    32,      // key length
)`

	case LangJava:
		rem.Fix = "Replace PBKDF1 with Argon2id through Argon2BytesGenerator from BouncyCastle"
		rem.CodeExample = `// Replace PBKDF1 with Argon2id
// Using BouncyCastle for Argon2
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
    .withSalt(salt)
    .withIterations(3)
    .withMemoryAsKB(65536)
    .withParallelism(4);

Argon2BytesGenerator gen = new Argon2BytesGenerator();
gen.init(builder.build());
byte[] hash = new byte[32];
gen.generateBytes(password.toCharArray(), hash);`

	case LangJavaScript, LangTypeScript:
		rem.Fix = "Replace PBKDF1 with argon2.hash(password, { type: argon2.argon2id }) from the argon2 package"
		rem.Library = "argon2"
		rem.LibraryInstall = "npm install argon2"
		rem.CodeExample = `// Replace PBKDF1 with Argon2id (RFC 9106)
const argon2 = require('argon2');

// Hash password
const hash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,  // 64 MB
    timeCost: 3,
    parallelism: 4
});

// Verify password
const valid = await argon2.verify(hash, password);`
	}

	return rem
}

func (r *RemediationEngine) getGenericRemediation(f *types.Finding, lang Language, status types.MigrationStatus) *Remediation {
	rem := &Remediation{
		Summary:        f.Remediation,
		HybridApproach: false,
	}

	switch status {
	case types.MigrationStatusCritical:
		rem.Priority = "CRITICAL"
		rem.Effort = "Immediate action required"
	case types.MigrationStatusVulnerable:
		rem.Priority = "HIGH"
		rem.Effort = "Medium"
	case types.MigrationStatusPartial:
		rem.Priority = "MEDIUM"
		rem.Effort = "Low"
	case types.MigrationStatusHybrid:
		rem.Priority = "LOW"
		rem.Effort = "Monitoring recommended"
		rem.HybridApproach = true
	default:
		rem.Priority = "INFO"
		rem.Effort = "No action required"
	}

	return rem
}

// GetBulkRemediation provides summary remediation for multiple findings
func (r *RemediationEngine) GetBulkRemediation(findings []types.Finding) map[string]*Remediation {
	remediations := make(map[string]*Remediation)

	for i := range findings {
		f := &findings[i]
		lang := DetectLanguageFromFile(f.File)
		key := f.Algorithm
		if key == "" {
			key = f.Type
		}

		// Only add if not already present (deduplicate)
		if _, exists := remediations[key]; !exists {
			remediations[key] = r.GetRemediation(f, lang)
		}
	}

	return remediations
}
