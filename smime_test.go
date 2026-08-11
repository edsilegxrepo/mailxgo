package mailxgo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
)

// generateTestCert creates an in-memory RSA key and X.509 certificate for testing.
func generateTestCert(t *testing.T, email string, keyUsage x509.KeyUsage, validDays int) (*rsa.PrivateKey, *x509.Certificate, []byte, []byte) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(time.Duration(validDays) * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   email,
			Organization: []string{"mailxgo Test Corp"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}

	if email != "" {
		template.EmailAddresses = []string{email}
		if u, err := url.Parse("mailto:" + email); err == nil {
			template.URIs = []*url.URL{u}
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	return privKey, cert, certPEM, keyPEM
}

func TestEstimateEncryptedSize(t *testing.T) {
	if got := EstimateEncryptedSize(0); got != 0 {
		t.Errorf("EstimateEncryptedSize(0) = %d; want 0", got)
	}
	if got := EstimateEncryptedSize(1000); got != 1370 {
		t.Errorf("EstimateEncryptedSize(1000) = %d; want 1370", got)
	}
}

func TestLoadCertificateAndKey(t *testing.T) {
	tempDir := t.TempDir()
	_, _, certPEM, keyPEM := generateTestCert(t, "test@example.com", x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, 365)

	certPath := filepath.Join(tempDir, "test.pem")
	keyPath := filepath.Join(tempDir, "test.key")

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	cert, err := LoadCertificate(certPath)
	if err != nil {
		t.Fatalf("LoadCertificate failed: %v", err)
	}
	if cert.Subject.CommonName != "test@example.com" {
		t.Errorf("cert CN = %s; want test@example.com", cert.Subject.CommonName)
	}

	key, err := LoadPrivateKey(keyPath, "")
	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}
	if key == nil {
		t.Error("LoadPrivateKey returned nil key")
	}
}

func TestLoadPKCS12(t *testing.T) {
	tempDir := t.TempDir()

	// Test non-existent file
	if _, _, _, err := LoadPKCS12(filepath.Join(tempDir, "nonexistent.pfx"), "pass"); err == nil {
		t.Error("expected error for non-existent PKCS12 file")
	}

	// Test invalid PKCS12 data
	invalidPath := filepath.Join(tempDir, "invalid.pfx")
	if err := os.WriteFile(invalidPath, []byte("NOT_PKCS12_DATA"), 0o600); err != nil {
		t.Fatalf("failed to write invalid file: %v", err)
	}

	if _, _, _, err := LoadPKCS12(invalidPath, "pass"); err == nil {
		t.Error("expected error for invalid PKCS12 content")
	}
}

func TestBuildCertIndexAndResolve(t *testing.T) {
	_, cert1, _, _ := generateTestCert(t, "alice@corp.local", x509.KeyUsageDigitalSignature, 365)
	_, cert2, _, _ := generateTestCert(t, "bob@corp.local", x509.KeyUsageDigitalSignature, 365)

	index := BuildCertIndex([]*x509.Certificate{cert1, cert2})
	if len(index) == 0 {
		t.Fatal("BuildCertIndex returned empty index")
	}

	if resolved := ResolveCertForEmail(index, "alice@corp.local"); resolved == nil {
		t.Error("failed to resolve alice@corp.local")
	} else if resolved.Subject.CommonName != "alice@corp.local" {
		t.Errorf("resolved CN = %s; want alice@corp.local", resolved.Subject.CommonName)
	}

	if resolved := ResolveCertForEmail(index, "ALICE@CORP.LOCAL"); resolved == nil {
		t.Error("failed case-insensitive resolution for ALICE@CORP.LOCAL")
	}

	if resolved := ResolveCertForEmail(index, "nonexistent@corp.local"); resolved != nil {
		t.Error("expected nil for nonexistent email resolution")
	}
}

func TestValidateCertForSigningAndEncryption(t *testing.T) {
	_, validCert, _, _ := generateTestCert(t, "valid@corp.local", x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, 365)
	if err := ValidateCertForSigning(validCert); err != nil {
		t.Errorf("ValidateCertForSigning failed on valid cert: %v", err)
	}
	if err := ValidateCertForEncryption(validCert); err != nil {
		t.Errorf("ValidateCertForEncryption failed on valid cert: %v", err)
	}

	_, expiredCert, _, _ := generateTestCert(t, "expired@corp.local", x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, -10)
	if err := ValidateCertForSigning(expiredCert); err == nil {
		t.Error("expected error for expired signing cert")
	}
	if err := ValidateCertForEncryption(expiredCert); err == nil {
		t.Error("expected error for expired encryption cert")
	}
}

func TestEncryptForRecipients(t *testing.T) {
	_, cert, _, _ := generateTestCert(t, "recipient@corp.local", x509.KeyUsageKeyEncipherment, 365)
	plainText := []byte("Subject: S/MIME Test\r\nContent-Type: text/plain\r\n\r\nHello World!")

	encrypted, err := EncryptForRecipients(plainText, []*x509.Certificate{cert}, "aes-256-gcm")
	if err != nil {
		t.Fatalf("EncryptForRecipients failed: %v", err)
	}
	if len(encrypted) == 0 {
		t.Fatal("encrypted data is empty")
	}
	if bytes.Equal(encrypted, plainText) {
		t.Error("encrypted data matches plaintext")
	}
}

func TestCheckCryptoHygiene(t *testing.T) {
	_, cert, _, _ := generateTestCert(t, "signer@corp.local", x509.KeyUsageDigitalSignature, 15) // < 30 days left
	config := &SMIMEConfig{
		Algorithm:       "3des-cbc",
		DigestAlgorithm: "sha1",
		SignerCert:      cert,
	}

	warnings := CheckCryptoHygiene(config, "")
	if len(warnings) < 3 {
		t.Errorf("expected at least 3 warnings (3des, sha1, cert expiry); got %d: %v", len(warnings), warnings)
	}
}

func TestSMIMEConfigSetupAndPipeline(t *testing.T) {
	tempDir := t.TempDir()
	_, _, certPEM, keyPEM := generateTestCert(t, "sender@corp.local", x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, 365)

	certPath := filepath.Join(tempDir, "sender.pem")
	keyPath := filepath.Join(tempDir, "sender.key")

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	params := EmailParams{
		SMIMESign:           true,
		SMIMEEncrypt:        true,
		SMIMECert:           certPath,
		SMIMEKey:            keyPath,
		SMIMERecipientCerts: []string{certPath},
		To:                  []string{"sender@corp.local"},
	}

	config, err := setupSMIMEConfig(&params)
	if err != nil {
		t.Fatalf("setupSMIMEConfig failed: %v", err)
	}
	if !config.Sign || !config.Encrypt {
		t.Errorf("config sign=%t encrypt=%t; want true, true", config.Sign, config.Encrypt)
	}
	if config.SignerCert == nil || config.SignerKey == nil {
		t.Errorf("signer cert/key is nil")
	}
	if len(config.RecipientCerts) != 1 {
		t.Errorf("len(RecipientCerts) = %d; want 1", len(config.RecipientCerts))
	}

	// Test missing recipient cert error
	paramsMissing := params
	paramsMissing.To = []string{"unresolved@corp.local"}
	if _, err := setupSMIMEConfig(&paramsMissing); err == nil {
		t.Error("expected error when recipient cert resolution fails")
	}
}

func TestPKCS7DecryptionRoundtrip(t *testing.T) {
	privKey, cert, _, _ := generateTestCert(t, "recipient@corp.local", x509.KeyUsageKeyEncipherment, 365)
	originalMessage := []byte("Subject: Confidential Document\r\n\r\nTop secret MFT transfer payload.")

	encrypted, err := EncryptForRecipients(originalMessage, []*x509.Certificate{cert}, "aes-256-gcm")
	if err != nil {
		t.Fatalf("EncryptForRecipients failed: %v", err)
	}

	p7, err := pkcs7.Parse(encrypted)
	if err != nil {
		t.Fatalf("failed to parse PKCS#7 encrypted data: %v", err)
	}

	decrypted, err := p7.Decrypt(cert, privKey)
	if err != nil {
		t.Fatalf("failed to decrypt PKCS#7 data: %v", err)
	}

	if !bytes.Equal(decrypted, originalMessage) {
		t.Errorf("decrypted payload = %q; want %q", string(decrypted), string(originalMessage))
	}
}

func TestMultiRecipientDecryptionRoundtrip(t *testing.T) {
	aliceKey, aliceCert, _, _ := generateTestCert(t, "alice@corp.local", x509.KeyUsageKeyEncipherment, 365)
	bobKey, bobCert, _, _ := generateTestCert(t, "bob@corp.local", x509.KeyUsageKeyEncipherment, 365)
	originalMessage := []byte("Subject: Multi-Recipient Report\r\n\r\nPayroll dataset 2026.")

	encrypted, err := EncryptForRecipients(originalMessage, []*x509.Certificate{aliceCert, bobCert}, "aes-256-gcm")
	if err != nil {
		t.Fatalf("EncryptForRecipients failed for multi-recipients: %v", err)
	}

	// Verify Alice can decrypt
	p7Alice, err := pkcs7.Parse(encrypted)
	if err != nil {
		t.Fatalf("Alice failed to parse PKCS#7 data: %v", err)
	}
	decryptedAlice, err := p7Alice.Decrypt(aliceCert, aliceKey)
	if err != nil {
		t.Fatalf("Alice failed to decrypt PKCS#7 payload: %v", err)
	}
	if !bytes.Equal(decryptedAlice, originalMessage) {
		t.Errorf("Alice decrypted = %q; want %q", string(decryptedAlice), string(originalMessage))
	}

	// Verify Bob can decrypt
	p7Bob, err := pkcs7.Parse(encrypted)
	if err != nil {
		t.Fatalf("Bob failed to parse PKCS#7 data: %v", err)
	}
	decryptedBob, err := p7Bob.Decrypt(bobCert, bobKey)
	if err != nil {
		t.Fatalf("Bob failed to decrypt PKCS#7 payload: %v", err)
	}
	if !bytes.Equal(decryptedBob, originalMessage) {
		t.Errorf("Bob decrypted = %q; want %q", string(decryptedBob), string(originalMessage))
	}
}

func TestLoadCertificatesFromDir(t *testing.T) {
	tempDir := t.TempDir()
	_, _, cert1PEM, _ := generateTestCert(t, "user1@corp.local", x509.KeyUsageKeyEncipherment, 365)
	_, _, cert2PEM, _ := generateTestCert(t, "user2@corp.local", x509.KeyUsageKeyEncipherment, 365)

	if err := os.WriteFile(filepath.Join(tempDir, "user1.pem"), cert1PEM, 0o600); err != nil {
		t.Fatalf("failed to write user1.pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "user2.crt"), cert2PEM, 0o600); err != nil {
		t.Fatalf("failed to write user2.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "ignored.txt"), []byte("not a cert"), 0o600); err != nil {
		t.Fatalf("failed to write ignored.txt: %v", err)
	}

	certs, err := LoadCertificatesFromDir(tempDir)
	if err != nil {
		t.Fatalf("LoadCertificatesFromDir failed: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("len(certs) = %d; want 2", len(certs))
	}
}

func TestFormatBase64MIME(t *testing.T) {
	raw := []byte("The quick brown fox jumps over the lazy dog. 1234567890!@#$%^&*()_+~`|}{[]:;?><,./-=")
	formatted := FormatBase64MIME(raw)

	if !bytes.Contains([]byte(formatted), []byte("\r\n")) {
		t.Error("FormatBase64MIME output missing CRLF line breaks")
	}

	lines := bytes.Split([]byte(formatted), []byte("\r\n"))
	for i, line := range lines {
		if len(line) > 76 {
			t.Errorf("line %d length = %d; want <= 76", i, len(line))
		}
	}

	cleanBase64 := bytes.ReplaceAll([]byte(formatted), []byte("\r\n"), nil)
	decoded, err := base64.StdEncoding.DecodeString(string(cleanBase64))
	if err != nil {
		t.Fatalf("failed to decode base64 MIME output: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Errorf("decoded base64 = %q; want %q", string(decoded), string(raw))
	}
}

func TestEncryptedPrivateKeyLoading(t *testing.T) {
	tempDir := t.TempDir()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	passphrase := "secret123"
	//nolint:staticcheck // SA1019: Testing legacy PEM encryption support required for enterprise compatibility
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privKey), []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("EncryptPEMBlock failed: %v", err)
	}

	keyPath := filepath.Join(tempDir, "encrypted.key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("failed to write encrypted key file: %v", err)
	}

	loadedKey, err := LoadPrivateKey(keyPath, passphrase)
	if err != nil {
		t.Fatalf("LoadPrivateKey with password failed: %v", err)
	}
	if loadedKey == nil {
		t.Error("loaded private key is nil")
	}

	if _, err := LoadPrivateKey(keyPath, "wrongpass"); err == nil {
		t.Error("expected error for wrong private key password")
	}
}

func TestRunSMIMEDiagnostics(t *testing.T) {
	tempDir := t.TempDir()
	_, _, certPEM, keyPEM := generateTestCert(t, "diag@corp.local", x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, 365)

	certPath := filepath.Join(tempDir, "diag.pem")
	keyPath := filepath.Join(tempDir, "diag.key")

	_ = os.WriteFile(certPath, certPEM, 0o600)
	_ = os.WriteFile(keyPath, keyPEM, 0o600)

	params := EmailParams{
		SMIMESign:           true,
		SMIMECert:           certPath,
		SMIMEKey:            keyPath,
		SMIMERecipientCerts: []string{certPath},
	}

	diagInfo := runSMIMEDiagnostics(params)
	if diagInfo == nil {
		t.Fatal("runSMIMEDiagnostics returned nil")
	}
	if diagInfo.SignerCertSubject != "diag@corp.local" {
		t.Errorf("SignerCertSubject = %s; want diag@corp.local", diagInfo.SignerCertSubject)
	}
	if !diagInfo.SignerKeyUsageOK {
		t.Error("SignerKeyUsageOK = false; want true")
	}
	if !diagInfo.SignerKeyDecryptOK {
		t.Error("SignerKeyDecryptOK = false; want true")
	}
}

func TestECDSAKeySigningValidation(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "ecdsa@corp.local",
			Organization: []string{"mailxgo ECDSA Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
		EmailAddresses:        []string{"ecdsa@corp.local"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse ECDSA certificate: %v", err)
	}

	if err := ValidateCertForSigning(cert); err != nil {
		t.Errorf("ValidateCertForSigning failed on ECDSA cert: %v", err)
	}
}

func TestProbeESMTPSize_ConnectionRefused(t *testing.T) {
	// Test against non-existent server - should return error
	_, err := ProbeESMTPSize("127.0.0.1", 59999, "none")
	if err == nil {
		t.Error("expected error for connection refused, got nil")
	}
}

func TestSMIMEDefaultConfigFallback(t *testing.T) {
	tempDir := t.TempDir()
	_, _, certPEM, keyPEM := generateTestCert(t, "default@corp.local", x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, 365)

	certPath := filepath.Join(tempDir, "default.pem")
	keyPath := filepath.Join(tempDir, "default.key")
	_ = os.WriteFile(certPath, certPEM, 0600)
	_ = os.WriteFile(keyPath, keyPEM, 0600)

	// Test that SMIMEDefaultCert/Key are used when SMIMECert/Key are empty
	config := Config{
		SMIMEDefaultCert: certPath,
		SMIMEDefaultKey:  keyPath,
	}

	// Simulate CLI precedence: priorityString([]string{cliValue, configValue, defaultValue})
	// When CLI and config are empty, default should be used
	resolvedCert := priorityString([]string{"", "", config.SMIMEDefaultCert})
	resolvedKey := priorityString([]string{"", "", config.SMIMEDefaultKey})

	if resolvedCert != certPath {
		t.Errorf("SMIMEDefaultCert fallback failed: got %q, want %q", resolvedCert, certPath)
	}
	if resolvedKey != keyPath {
		t.Errorf("SMIMEDefaultKey fallback failed: got %q, want %q", resolvedKey, keyPath)
	}

	// Verify the cert can actually be loaded
	cert, err := LoadCertificate(resolvedCert)
	if err != nil {
		t.Fatalf("LoadCertificate failed on default cert: %v", err)
	}
	if cert.Subject.CommonName != "default@corp.local" {
		t.Errorf("cert CN = %q, want default@corp.local", cert.Subject.CommonName)
	}
}
