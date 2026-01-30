// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

//go:build ignore
// +build ignore

// Package cryptosamples contains sample cryptographic code for testing the scanner.
// Run: cryptoscan scan ./crypto-samples to see detection results.
//
// This file demonstrates various cryptographic patterns that the scanner detects,
// organized by category and quantum risk level.
package cryptosamples

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
)

// ============================================================================
// QUANTUM VULNERABLE - Asymmetric Cryptography (HIGH priority for migration)
// These algorithms will be broken by Shor's algorithm on quantum computers
// ============================================================================

// GenerateRSAKey generates an RSA key pair - QUANTUM VULNERABLE
// Remediation: Migrate to ML-KEM (FIPS 203) for key encapsulation
func GenerateRSAKey() (*rsa.PrivateKey, error) {
	// RSA-2048 is quantum vulnerable
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// GenerateWeakRSAKey uses 1024-bit RSA - CRITICAL (weak even classically)
func GenerateWeakRSAKey() (*rsa.PrivateKey, error) {
	// RSA-1024 is weak and should never be used
	return rsa.GenerateKey(rand.Reader, 1024)
}

// GenerateECDSAKey generates an ECDSA key - QUANTUM VULNERABLE
// Remediation: Migrate to ML-DSA (FIPS 204) for signatures
func GenerateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateEd25519Key generates an Ed25519 key pair - QUANTUM VULNERABLE
// Remediation: Migrate to ML-DSA (FIPS 204) for signatures
func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// SignWithEd25519 signs data using Ed25519 - QUANTUM VULNERABLE
func SignWithEd25519(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

// VerifyEd25519 verifies an Ed25519 signature - QUANTUM VULNERABLE
func VerifyEd25519(publicKey ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(publicKey, message, sig)
}

// ============================================================================
// QUANTUM PARTIAL - Symmetric Cryptography (requires larger key sizes)
// These need key size doubling for quantum resistance (Grover's algorithm)
// ============================================================================

// EncryptAES256 encrypts using AES-256-GCM - QUANTUM PARTIAL (acceptable)
// AES-256 provides 128-bit security against quantum attacks
func EncryptAES256(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// EncryptAES128 encrypts using AES-128 - needs upgrade to AES-256
func EncryptAES128(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:16]) // 128-bit key
	if err != nil {
		return nil, err
	}
	_ = block
	return plaintext, nil
}

// EncryptChaCha20 uses ChaCha20-Poly1305 - QUANTUM PARTIAL (acceptable)
func EncryptChaCha20(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// ============================================================================
// BROKEN/WEAK - Should be replaced immediately (not quantum-related)
// ============================================================================

// HashMD5 uses MD5 - BROKEN (collision attacks exist)
// Remediation: Use SHA-256 or SHA-3
func HashMD5(data []byte) []byte {
	hash := md5.Sum(data)
	return hash[:]
}

// HashSHA1 uses SHA-1 - WEAK (collision attacks demonstrated)
// Remediation: Use SHA-256 or SHA-3
func HashSHA1(data []byte) []byte {
	hash := sha1.Sum(data)
	return hash[:]
}

// EncryptDES uses DES - BROKEN (56-bit key is trivially brute-forced)
// Remediation: Use AES-256
func EncryptDES(key, plaintext []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	_ = block
	return plaintext, nil
}

// Encrypt3DES uses Triple-DES - WEAK (deprecated, slow)
// Remediation: Use AES-256
func Encrypt3DES(key, plaintext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	_ = block
	return plaintext, nil
}

// ============================================================================
// QUANTUM SAFE - Hash functions (with sufficient output size)
// ============================================================================

// HashSHA256 uses SHA-256 - QUANTUM SAFE for most uses
func HashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// HashSHA512 uses SHA-512 - QUANTUM SAFE
func HashSHA512(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// HashPassword uses bcrypt - QUANTUM SAFE (password hashing)
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// ============================================================================
// TLS CONFIGURATION - Various security levels
// ============================================================================

// CreateSecureTLSConfig creates a secure TLS 1.3 configuration
func CreateSecureTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
}

// CreateWeakTLSConfig creates an insecure TLS configuration - DO NOT USE
func CreateWeakTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10, // TLS 1.0 is deprecated
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA, // No forward secrecy
		},
	}
}

// ============================================================================
// PATTERNS THAT SHOULD BE FILTERED (false positive examples)
// These demonstrate patterns the scanner correctly ignores
// ============================================================================

// logCryptoOperation logs a message - should be filtered (log statement)
func logCryptoOperation() {
	fmt.Printf("Generated Ed25519 keys for authentication\n")
	fmt.Println("Using RSA-2048 for key exchange")
}

// setCryptoMetadata sets metadata labels - should be filtered (string labels)
func setCryptoMetadata() map[string]string {
	return map[string]string{
		"auth_method":       "ed25519",
		"encryption_type":   "aes-256-gcm",
		"signing_algorithm": "ecdsa-p256",
	}
}

// validateCryptoInput validates input - should be filtered (error messages)
func validateCryptoInput(keyType string) error {
	if keyType == "" {
		return fmt.Errorf("key type must be a valid Ed25519 or RSA key")
	}
	return nil
}

// CryptoDocExample is a docstring example - should be filtered
// This function demonstrates Ed25519 signature verification.
// It uses the standard Go crypto/ed25519 package.
func CryptoDocExample() {
	// This is just documentation, not actual crypto usage
}
