// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"testing"

	"github.com/csnp/cryptoscan/pkg/types"
)

func TestAnalyzeLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		lang        Language
		wantComment bool
		wantImport  bool
	}{
		{"Go comment", "// this is a comment", LangGo, true, false},
		{"Python comment", "# this is a comment", LangPython, true, false},
		{"Go import", `import "crypto/rsa"`, LangGo, false, true},
		{"Python import", "from cryptography import Fernet", LangPython, false, true},
		{"Java import", "import javax.crypto.Cipher;", LangJava, false, true},
		{"JS require", "const crypto = require('crypto');", LangJavaScript, false, true},
		{"Rust use", "use ring::aead;", LangRust, false, true},
		{"Ruby require", "require 'openssl'", LangRuby, false, true},
		{"C# using", "using System.Security.Cryptography;", LangCSharp, false, true},
		{"C include", "#include <openssl/rsa.h>", LangC, false, true},
		{"Go function", "func GenerateKey() {", LangGo, false, false},
		{"Python def", "def encrypt(data):", LangPython, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := AnalyzeLine(tt.line, tt.lang, nil)
			if ctx.IsComment != tt.wantComment {
				t.Errorf("IsComment = %v, want %v", ctx.IsComment, tt.wantComment)
			}
			if ctx.IsImport != tt.wantImport {
				t.Errorf("IsImport = %v, want %v", ctx.IsImport, tt.wantImport)
			}
		})
	}
}

func TestIsCommentLine(t *testing.T) {
	tests := []struct {
		line string
		lang Language
		want bool
	}{
		{"// Go comment", LangGo, true},
		{"/* block comment", LangGo, true},
		{"* continuation", LangJava, true},
		{"# Python comment", LangPython, true},
		{"# Ruby comment", LangRuby, true},
		{"# Shell comment", LangShell, true},
		{"# YAML comment", LangYAML, true},
		{"<!-- HTML comment", LangMarkdown, true},
		{"code line", LangGo, false},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := isCommentLine(tt.line, tt.lang)
			if got != tt.want {
				t.Errorf("isCommentLine(%q, %v) = %v, want %v", tt.line, tt.lang, got, tt.want)
			}
		})
	}
}

func TestIsStringContext(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"@param key The encryption key", true},
		{"@return The decrypted data", true},
		{"@deprecated Use AES instead", true},
		{"TODO: migrate to PQC", true},
		{"FIXME: weak key size", true},
		{"Example: rsa.GenerateKey()", true},
		{"Usage: encrypt(data, key)", true},
		{"e.g. RSA-2048", true},
		{"i.e. post-quantum safe", true},
		{"key, _ := rsa.GenerateKey()", false},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := isStringContext(tt.line)
			if got != tt.want {
				t.Errorf("isStringContext(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

func TestIsImportLine(t *testing.T) {
	tests := []struct {
		line string
		lang Language
		want bool
	}{
		{"import crypto", LangPython, true},
		{"from cryptography.fernet import Fernet", LangPython, true},
		{`import "crypto/rsa"`, LangGo, true},
		{"import javax.crypto.Cipher;", LangJava, true},
		{"import { createCipheriv } from 'crypto';", LangJavaScript, true},
		{"const crypto = require('crypto');", LangJavaScript, true},
		{"use ring::aead;", LangRust, true},
		{"require 'openssl'", LangRuby, true},
		{"using System.Security.Cryptography;", LangCSharp, true},
		{"#include <openssl/rsa.h>", LangC, true},
		{"#include <openssl/aes.h>", LangCPP, true},
		{"key := GenerateKey()", LangGo, false},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := isImportLine(tt.line, tt.lang)
			if got != tt.want {
				t.Errorf("isImportLine(%q, %v) = %v, want %v", tt.line, tt.lang, got, tt.want)
			}
		})
	}
}

func TestIsFunctionDef(t *testing.T) {
	tests := []struct {
		line string
		lang Language
		want bool
	}{
		{"def encrypt(data):", LangPython, true},
		{"async def encrypt(data):", LangPython, true},
		{"func GenerateKey() error {", LangGo, true},
		{"public static void encrypt(byte[] data) {", LangJava, true},
		{"private byte[] decrypt(byte[] data) {", LangJava, true},
		{"function encrypt(data) {", LangJavaScript, true},
		{"const encrypt = (data) => {", LangJavaScript, true},
		{"encrypt: function(data) {", LangJavaScript, true},
		{"fn encrypt(data: &[u8]) -> Vec<u8> {", LangRust, true},
		{"pub fn generate_key() -> Key {", LangRust, true},
		{"def encrypt(data)", LangRuby, true},
		{"key = generateKey()", LangGo, false},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := isFunctionDef(tt.line, tt.lang)
			if got != tt.want {
				t.Errorf("isFunctionDef(%q, %v) = %v, want %v", tt.line, tt.lang, got, tt.want)
			}
		})
	}
}

func TestIsVariableAssignment(t *testing.T) {
	tests := []struct {
		line string
		lang Language
		want bool
	}{
		{"key := GenerateKey()", LangGo, true},
		{"var key = NewKey()", LangGo, true},
		{"key = encrypt(data)", LangPython, true},
		{"cipher = AES.new(key)", LangPython, true},
		{"const key = crypto.randomBytes(32);", LangJavaScript, true},
		{"let iv = new Uint8Array(16);", LangJavaScript, true},
		{"var cipher = crypto.createCipher();", LangJavaScript, true},
		{"Cipher cipher = Cipher.getInstance();", LangJava, true},
		{"let key = generate_key();", LangRust, true},
		{"const KEY_SIZE: usize = 32;", LangRust, true},
		{"if key == nil {", LangGo, false},
		{"if key != expected:", LangPython, false},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := isVariableAssignment(tt.line, tt.lang)
			if got != tt.want {
				t.Errorf("isVariableAssignment(%q, %v) = %v, want %v", tt.line, tt.lang, got, tt.want)
			}
		})
	}
}

func TestDetermineConfidence(t *testing.T) {
	tests := []struct {
		name string
		ctx  *LineContext
		want types.Confidence
	}{
		{"Comment", &LineContext{IsComment: true}, types.ConfidenceLow},
		{"String context", &LineContext{IsString: true}, types.ConfidenceLow},
		{"Import", &LineContext{IsImport: true}, types.ConfidenceHigh},
		{"Function", &LineContext{IsFunction: true}, types.ConfidenceHigh},
		{"Variable", &LineContext{IsVariable: true}, types.ConfidenceMedium},
		{"Other", &LineContext{}, types.ConfidenceMedium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineConfidence(tt.ctx, LangGo)
			if got != tt.want {
				t.Errorf("determineConfidence() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeterminePurpose(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		prevLines []string
		want      string
	}{
		{"Authentication", "token := jwt.Sign(claims)", nil, "authentication"},
		{"Authentication context", "cipher.encrypt(data)", []string{"// authenticate user"}, "authentication"},
		{"Encryption", "ciphertext := encrypt(plaintext)", nil, "encryption"},
		{"Signing", "signature := sign(message)", nil, "signing"},
		{"Hashing", "hash := sha256.Sum256(data)", nil, "hashing"},
		{"TLS", "tls.Dial(\"tcp\", addr, config)", nil, "tls-configuration"},
		{"General", "key := generateKey()", nil, "general"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determinePurpose(tt.line, tt.prevLines, LangGo)
			if got != tt.want {
				t.Errorf("determinePurpose() = %v, want %v", got, tt.want)
			}
		})
	}

	// Additional test for key exchange with proper context
	got := determinePurpose("start key exchange negotiation", nil, LangGo)
	if got != "key-exchange" {
		t.Errorf("determinePurpose() for key exchange = %v, want key-exchange", got)
	}
}

func TestDetectCryptoContext(t *testing.T) {
	tests := []struct {
		line     string
		contains []string
	}{
		{"generateKey()", []string{"key_generation"}},
		{"encrypt(data)", []string{"encryption"}},
		{"decrypt(ciphertext)", []string{"decryption"}},
		{"sign(message)", []string{"signing"}},
		{"verify(signature)", []string{"verification"}},
		{"hash(data)", []string{"hashing"}},
		{"keyExchange()", []string{"key_exchange"}},
		{"password := getPassword()", []string{"password"}},
		{"loadCertificate()", []string{"certificate"}},
		{"randomBytes(32)", []string{"random"}},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			contexts := DetectCryptoContext(tt.line)
			for _, expected := range tt.contains {
				found := false
				for _, ctx := range contexts {
					if ctx == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("DetectCryptoContext(%q) missing %q, got %v", tt.line, expected, contexts)
				}
			}
		})
	}
}
