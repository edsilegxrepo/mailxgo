// Package mailxgo - Cryptographic & TLS Security Module Tests
//
// OBJECTIVES:
// Validate certificate loading, fingerprint computation, normalization, formatting, pinning verification, and secretprotector decryption.
//
// CORE COMPONENTS:
// - TestNormalizeFingerprint: Tests fingerprint hex string normalization (colon removal, case folding).
// - TestFormatFingerprint: Tests fingerprint hex string pretty-printing with colons.
// - TestComputeCertFingerprint: Tests SHA256 fingerprint computation from DER-encoded certificates.
// - TestValidateCertFingerprint: Tests certificate fingerprint pinning verification.
// - TestCreateFingerprintVerifier: Tests TLS VerifyPeerCertificate callback creation.
// - TestLoadCustomCACerts_*: Tests custom CA certificate pool loading from files and directories.
// - TestDecryptSecret*: Tests secretprotector v1:gcm: prefix decryption.
//
// FUNCTIONALITY & DATA FLOW:
// Generated test certificates -> Crypto functions -> Assert computed fingerprint, verification result, decrypted secret.
//
// TEST STRATEGY:
// Self-signed certificate generation in-memory using crypto/rsa and x509.CreateCertificate for deterministic testing.
package mailxgo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase no colons", "aabbccdd", "AABBCCDD"},
		{"uppercase no colons", "AABBCCDD", "AABBCCDD"},
		{"with colons", "AA:BB:CC:DD", "AABBCCDD"},
		{"mixed case with colons", "Aa:Bb:Cc:Dd", "AABBCCDD"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeFingerprint(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeFingerprint(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFormatFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no colons", "AABBCCDD", "AA:BB:CC:DD"},
		{"already has colons", "AA:BB:CC:DD", "AA:BB:CC:DD"},
		{"lowercase", "aabbccdd", "AA:BB:CC:DD"},
		{"odd length", "AABBCCD", "AA:BB:CC:D"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatFingerprint(tt.input)
			if result != tt.expected {
				t.Errorf("FormatFingerprint(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateCertFingerprint(t *testing.T) {
	validSHA256 := "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	validWithColons := "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF"

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid 64 hex chars", validSHA256, false},
		{"valid with colons", validWithColons, false},
		{"valid lowercase", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"too short", "0123456789ABCDEF", true},
		{"too long", validSHA256 + "00", true},
		{"invalid chars", "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEG", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCertFingerprint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCertFingerprint(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestComputeCertFingerprint(t *testing.T) {
	// Create a test certificate
	derCert := []byte("test certificate data")
	fingerprint := ComputeCertFingerprint(derCert)

	// Should be 64 hex chars (SHA256 = 32 bytes = 64 hex)
	if len(fingerprint) != 64 {
		t.Errorf("ComputeCertFingerprint length = %d, want 64", len(fingerprint))
	}

	// Should be uppercase
	if fingerprint != NormalizeFingerprint(fingerprint) {
		t.Errorf("ComputeCertFingerprint should return uppercase hex")
	}

	// Same input should produce same output
	fingerprint2 := ComputeCertFingerprint(derCert)
	if fingerprint != fingerprint2 {
		t.Errorf("ComputeCertFingerprint not deterministic")
	}
}

func TestLoadCustomCACerts_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a self-signed test certificate
	certPEM := generateTestCertPEM(t)
	certFile := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	// Load from single file
	pool, err := loadCustomCACerts(certFile, "")
	if err != nil {
		t.Fatalf("loadCustomCACerts failed: %v", err)
	}
	if pool == nil {
		t.Fatal("loadCustomCACerts returned nil pool")
	}
}

func TestLoadCustomCACerts_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple cert files
	certPEM := generateTestCertPEM(t)
	for _, name := range []string{"ca1.pem", "ca2.crt", "ca3.cer"} {
		if err := os.WriteFile(filepath.Join(tmpDir, name), certPEM, 0o644); err != nil {
			t.Fatalf("Failed to write cert file: %v", err)
		}
	}

	// Create a non-cert file (should be ignored)
	if err := os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("not a cert"), 0o644); err != nil {
		t.Fatalf("Failed to write non-cert file: %v", err)
	}

	// Load from directory
	pool, err := loadCustomCACerts("", tmpDir)
	if err != nil {
		t.Fatalf("loadCustomCACerts from directory failed: %v", err)
	}
	if pool == nil {
		t.Fatal("loadCustomCACerts returned nil pool")
	}
}

func TestLoadCustomCACerts_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Non-existent file
	_, err := loadCustomCACerts(filepath.Join(tmpDir, "nonexistent.pem"), "")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Invalid PEM data
	invalidFile := filepath.Join(tmpDir, "invalid.pem")
	if err := os.WriteFile(invalidFile, []byte("not valid pem data"), 0o644); err != nil {
		t.Fatalf("Failed to write invalid file: %v", err)
	}
	_, err = loadCustomCACerts(invalidFile, "")
	if err == nil {
		t.Error("Expected error for invalid PEM data")
	}
}

func TestLoadCustomCACerts_RelativePath(t *testing.T) {
	// Relative paths should be rejected
	_, err := loadCustomCACerts("relative/path/ca.pem", "")
	if err == nil {
		t.Error("Expected error for relative path")
	}
}

func TestCreateFingerprintVerifier(t *testing.T) {
	// Generate a test certificate
	certDER := generateTestCertDER(t)
	expectedFingerprint := ComputeCertFingerprint(certDER)

	// Create verifier with correct fingerprint
	verifier := createFingerprintVerifier(expectedFingerprint)

	// Should pass for matching cert
	err := verifier([][]byte{certDER}, nil)
	if err != nil {
		t.Errorf("Verifier should pass for matching fingerprint: %v", err)
	}

	// Should fail for different cert
	differentCert := []byte("different certificate data")
	err = verifier([][]byte{differentCert}, nil)
	if err == nil {
		t.Error("Verifier should fail for non-matching fingerprint")
	}

	// Should fail for empty certs
	err = verifier([][]byte{}, nil)
	if err == nil {
		t.Error("Verifier should fail for empty cert list")
	}

	// Test with colon-formatted fingerprint
	colonFingerprint := FormatFingerprint(expectedFingerprint)
	verifier2 := createFingerprintVerifier(colonFingerprint)
	err = verifier2([][]byte{certDER}, nil)
	if err != nil {
		t.Errorf("Verifier should handle colon-formatted fingerprint: %v", err)
	}
}

func TestDecryptSecret_PlainSecret(t *testing.T) {
	// Plain secrets should pass through unchanged
	plain := "myplainpassword"
	result, err := DecryptSecret(plain, "")
	if err != nil {
		t.Errorf("DecryptSecret plain secret error = %v", err)
	}
	if result != plain {
		t.Errorf("DecryptSecret plain secret = %q, want %q", result, plain)
	}
}

func TestDecryptSecret_EmptySecret(t *testing.T) {
	result, err := DecryptSecret("", "")
	if err != nil || result != "" {
		t.Errorf("DecryptSecret empty secret error = %v, result = %q", err, result)
	}
}

func TestDecryptSecret_EncryptedWithoutKey(t *testing.T) {
	// Encrypted secret without master key should fail
	os.Unsetenv("SECRETPROTECTOR_MASTER_KEY")
	encrypted := "v1:gcm:someinvalidbase64data"
	_, err := DecryptSecret(encrypted, "NONEXISTENT_ENV_VAR")
	if err == nil {
		t.Error("DecryptSecret expected error for encrypted secret without master key")
	}
}

// Helper: generate a test certificate PEM
func generateTestCertPEM(t *testing.T) []byte {
	t.Helper()
	der := generateTestCertDER(t)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Helper: generate a test certificate DER
func generateTestCertDER(t *testing.T) []byte {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	return certDER
}
