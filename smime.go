// Package mailxgo - S/MIME Encryption & Digital Signing Module
//
// OBJECTIVES:
// Provide end-to-end payload encryption and digital signing for email messages per RFC 5751/RFC 8551.
//
// CORE COMPONENTS:
// - SMIMEConfig: Configuration options for S/MIME operations.
// - LoadCertificate / LoadPrivateKey / LoadPKCS12 / LoadCertificatesFromDir: Certificate and key loader functions.
// - BuildCertIndex / ResolveCertForEmail: SAN/EmailAddresses auto-resolution index for recipient certs.
// - ValidateCertForSigning / ValidateCertForEncryption / CheckKeyFilePermissions: Pre-flight certificate and key validation.
// - EncryptForRecipients: PKCS#7 payload encryption wrapper with sync.Pool buffer safety and algorithm override.
// - EstimateEncryptedSize: Calculates pre-dial payload size overhead factor (1.37x).
// - CheckCryptoHygiene: Audits crypto algorithms and key permissions for warning generation.
package mailxgo

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/pkcs12"
)

// SMIMEOverheadFactor represents the estimated payload size expansion multiplier (4/3 Base64 + PKCS#7 envelope headers)
const SMIMEOverheadFactor = 1.37

// pkcs7Mutex protects mutating package-level pkcs7.ContentEncryptionAlgorithm during concurrent encryption calls.
var pkcs7Mutex sync.Mutex

// SMIMEConfig holds configuration settings for S/MIME signing and encryption operations.
type SMIMEConfig struct {
	Sign              bool
	Encrypt           bool
	SignerCert        *x509.Certificate
	SignerKey         crypto.PrivateKey
	IntermediateCerts []*x509.Certificate
	RecipientCerts    []*x509.Certificate
	Algorithm         string // aes-256-gcm (default), aes-128-gcm, aes-256-cbc, aes-128-cbc, 3des-cbc
	DigestAlgorithm   string // sha256 (default), sha384, sha512
}

// EstimateEncryptedSize returns the estimated byte size of a payload after S/MIME encryption and Base64 wrapping.
func EstimateEncryptedSize(rawSize int64) int64 {
	if rawSize <= 0 {
		return 0
	}
	return int64(float64(rawSize) * SMIMEOverheadFactor)
}

// LoadCertificate reads a PEM-encoded X.509 certificate from a file path.
func LoadCertificate(path string) (*x509.Certificate, error) {
	if err := ValidateFilePath(path); err != nil {
		return nil, fmt.Errorf("invalid cert path: %w", err)
	}
	// #nosec G304 -- Path validated via ValidateFilePath above (absolute path, no traversal)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from %s: %w", path, err)
	}
	return cert, nil
}

// LoadPrivateKey reads a PEM-encoded RSA or ECDSA private key from a file path.
// Supports encrypted private keys if password is provided.
func LoadPrivateKey(path, password string) (crypto.PrivateKey, error) {
	if err := ValidateFilePath(path); err != nil {
		return nil, fmt.Errorf("invalid private key path: %w", err)
	}
	// #nosec G304 -- Path validated via ValidateFilePath above (absolute path, no traversal)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", path)
	}

	keyData := block.Bytes
	//nolint:staticcheck // SA1019: Legacy PEM encryption required for enterprise PKCS#1 key compatibility
	if x509.IsEncryptedPEMBlock(block) { // #nosec G501 -- Legacy PEM decryption fallback
		if password == "" {
			return nil, fmt.Errorf("private key in %s is encrypted but no password provided", path)
		}
		var err error
		//nolint:staticcheck // SA1019: Legacy PEM encryption required for enterprise PKCS#1 key compatibility
		keyData, err = x509.DecryptPEMBlock(block, []byte(password)) // #nosec G501
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
	}

	// Parse PKCS#8
	if key, err := x509.ParsePKCS8PrivateKey(keyData); err == nil {
		return key, nil
	}
	// Parse PKCS#1 RSA
	if key, err := x509.ParsePKCS1PrivateKey(keyData); err == nil {
		return key, nil
	}
	// Parse SEC1 EC
	if key, err := x509.ParseECPrivateKey(keyData); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key from %s (unsupported key format)", path)
}

// LoadPKCS12 reads a PKCS#12 bundle (.pfx/.p12) and extracts the certificate, private key, and intermediate CA certs.
func LoadPKCS12(path, password string) (*x509.Certificate, crypto.PrivateKey, []*x509.Certificate, error) {
	if err := ValidateFilePath(path); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid PKCS#12 path: %w", err)
	}
	// #nosec G304 -- Path validated via ValidateFilePath above (absolute path, no traversal)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read PKCS#12 file %s: %w", path, err)
	}

	key, cert, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode PKCS#12 bundle %s: %w", path, err)
	}

	privKey, ok := key.(crypto.PrivateKey)
	if !ok {
		return nil, nil, nil, fmt.Errorf("invalid private key type in PKCS#12 bundle %s", path)
	}

	// Extract additional intermediate CA certs via ToPEM if present.
	// Note: This re-decodes the bundle since golang.org/x/crypto/pkcs12 (frozen package)
	// lacks DecodeChain(). Acceptable for one-time credential loading; not a hot path.
	var caCerts []*x509.Certificate
	if blocks, err := pkcs12.ToPEM(data, password); err == nil {
		for _, block := range blocks {
			if block.Type == "CERTIFICATE" {
				extraCert, err := x509.ParseCertificate(block.Bytes)
				if err == nil && extraCert != nil && !cert.Equal(extraCert) {
					caCerts = append(caCerts, extraCert)
				}
			}
		}
	}

	return cert, privKey, caCerts, nil
}

// LoadCertificatesFromDir loads all PEM X.509 certificates (.pem, .crt, .cer) from a directory.
func LoadCertificatesFromDir(dirPath string) ([]*x509.Certificate, error) {
	if err := ValidateFilePath(dirPath); err != nil {
		return nil, fmt.Errorf("invalid cert directory path: %w", err)
	}
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert directory %s: %w", dirPath, err)
	}

	var certs []*x509.Certificate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".pem" || ext == ".crt" || ext == ".cer" {
			fullPath := filepath.Join(dirPath, entry.Name())
			cert, err := LoadCertificate(fullPath)
			if err == nil && cert != nil {
				certs = append(certs, cert)
			}
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in directory %s", dirPath)
	}
	return certs, nil
}

// BuildCertIndex builds a lower-case email map of certificates indexed by EmailAddresses and mailto: SAN URIs.
func BuildCertIndex(certs []*x509.Certificate) map[string]*x509.Certificate {
	index := make(map[string]*x509.Certificate)
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		// Index by standard EmailAddresses (rfc822Name)
		for _, email := range cert.EmailAddresses {
			if clean := strings.TrimSpace(strings.ToLower(email)); clean != "" {
				index[clean] = cert
			}
		}
		// Index by mailto: URIs (Microsoft AD CS compatibility)
		for _, uri := range cert.URIs {
			if uri != nil && strings.HasPrefix(strings.ToLower(uri.Scheme), "mailto") {
				email := strings.TrimPrefix(uri.String(), "mailto:")
				email = strings.TrimPrefix(email, "MAILTO:")
				if clean := strings.TrimSpace(strings.ToLower(email)); clean != "" {
					index[clean] = cert
				}
			}
		}
	}
	return index
}

// ResolveCertForEmail returns the certificate matching the recipient email address from the certificate index.
func ResolveCertForEmail(index map[string]*x509.Certificate, email string) *x509.Certificate {
	if index == nil {
		return nil
	}
	return index[strings.ToLower(strings.TrimSpace(email))]
}

// ValidateCertForSigning checks if a certificate is valid for signing (not expired, KeyUsageDigitalSignature set).
func ValidateCertForSigning(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("nil certificate provided")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("signer certificate is not yet valid (NotBefore: %v)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("signer certificate has expired (NotAfter: %v)", cert.NotAfter)
	}

	// Check key usage for digital signature if KeyUsage is set
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("signer certificate lacks KeyUsageDigitalSignature flag")
	}

	return nil
}

// ValidateCertForEncryption checks if a certificate is valid for encryption (not expired, KeyUsageKeyEncipherment set).
func ValidateCertForEncryption(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("nil certificate provided")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("recipient certificate is expired or not yet valid")
	}

	// Check key usage for key encipherment if KeyUsage is set
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 && cert.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
		return fmt.Errorf("recipient certificate lacks KeyUsageKeyEncipherment flag")
	}

	return nil
}

// CheckKeyFilePermissions returns an error/warning if the private key file has group or world permissions on Unix.
func CheckKeyFilePermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil // File mode permission checks do not apply to Windows ACLs
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf("private key file %s has insecure permissions %04o (recommended 0600)", path, mode)
	}
	return nil
}

// EncryptForRecipients encrypts raw MIME payload bytes using PKCS#7 for the specified recipient certificates.
// Returns an independent byte slice clone to ensure buffer pool safety.
func EncryptForRecipients(mimeData []byte, recipients []*x509.Certificate, algorithm string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipient certificates provided for S/MIME encryption")
	}
	for i, cert := range recipients {
		if err := ValidateCertForEncryption(cert); err != nil {
			return nil, fmt.Errorf("recipient certificate [%d] invalid: %w", i, err)
		}
	}

	pkcs7Mutex.Lock()
	defer pkcs7Mutex.Unlock()

	// Set ContentEncryptionAlgorithm based on algorithm option
	algoLower := strings.ToLower(strings.TrimSpace(algorithm))
	switch algoLower {
	case "aes-256-gcm", "":
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
	case "aes-128-gcm":
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128GCM
	case "aes-256-cbc":
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
	case "aes-128-cbc":
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
	case "3des-cbc", "des-cbc":
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmDESCBC
	default:
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
	}

	encryptedData, err := pkcs7.Encrypt(mimeData, recipients)
	if err != nil {
		return nil, fmt.Errorf("PKCS#7 encryption failed: %w", err)
	}

	// Ensure buffer safety by returning an independent clone
	return bytes.Clone(encryptedData), nil
}

// FormatBase64MIME encodes binary data into base64 with standard 76-character CRLF line breaks per RFC 2045 / RFC 5751.
func FormatBase64MIME(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	sb.Grow(len(encoded) + (len(encoded)/76)*2 + 2)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteString(encoded[i:end])
		sb.WriteString("\r\n")
	}
	return sb.String()
}

// CheckCryptoHygiene checks S/MIME configuration and certificates for security warnings.
func CheckCryptoHygiene(config *SMIMEConfig, keyPath string) []string {
	var warnings []string
	if config == nil {
		return warnings
	}

	algoLower := strings.ToLower(strings.TrimSpace(config.Algorithm))
	if algoLower == "3des-cbc" || algoLower == "des-cbc" {
		warnings = append(warnings, "WARNING: 3DES-CBC is cryptographically weak/deprecated; use aes-256-gcm")
	}

	digestLower := strings.ToLower(strings.TrimSpace(config.DigestAlgorithm))
	if digestLower == "sha1" || digestLower == "sha-1" {
		warnings = append(warnings, "WARNING: SHA-1 is cryptographically weak/deprecated; use sha256 or higher")
	}

	if keyPath != "" {
		if err := CheckKeyFilePermissions(keyPath); err != nil {
			warnings = append(warnings, err.Error())
		}
	}

	if config.SignerCert != nil {
		daysLeft := int(time.Until(config.SignerCert.NotAfter).Hours() / 24)
		if daysLeft < 30 {
			warnings = append(warnings, fmt.Sprintf("WARNING: Signer certificate expires in %d days", daysLeft))
		}
	}

	for _, cert := range config.RecipientCerts {
		if cert != nil {
			daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
			if daysLeft < 30 {
				name := cert.Subject.CommonName
				if len(cert.EmailAddresses) > 0 {
					name = cert.EmailAddresses[0]
				}
				warnings = append(warnings, fmt.Sprintf("WARNING: Recipient certificate (%s) expires in %d days", name, daysLeft))
			}
		}
	}

	return warnings
}

// ProbeESMTPSize connects to the SMTP server and returns the advertised SIZE limit (0 if not advertised).
// This is a lightweight probe used to check if S/MIME encrypted payloads will exceed server limits.
func ProbeESMTPSize(server string, port int, tlsMode string) (int64, error) {
	addr := net.JoinHostPort(server, fmt.Sprintf("%d", port))

	// For implicit TLS (port 465 or tls-direct mode), use tls.Dial
	if port == 465 || tlsMode == "tls-direct" {
		tlsConfig := &tls.Config{
			ServerName:         server,
			InsecureSkipVerify: tlsMode == "ignore-trust" || tlsMode == "tls-direct", // #nosec G402
			MinVersion:         tls.VersionTLS12,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return 0, fmt.Errorf("TLS dial failed: %w", err)
		}
		defer func() { _ = conn.Close() }()
		return probeESMTPSizeFromConn(conn, server)
	}

	// For STARTTLS or plaintext, use net.Dial
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("TCP dial failed: %w", err)
	}
	defer func() { _ = conn.Close() }()
	return probeESMTPSizeFromConn(conn, server)
}

// probeESMTPSizeFromConn sends EHLO and parses SIZE extension from an established connection.
func probeESMTPSizeFromConn(conn net.Conn, server string) (int64, error) {
	client, err := smtp.NewClient(conn, server)
	if err != nil {
		return 0, fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer func() { _ = client.Quit() }()

	// EHLO to get extensions
	heloDomain := "localhost"
	if host, err := os.Hostname(); err == nil && host != "" {
		heloDomain = host
	}
	if err := client.Hello(heloDomain); err != nil {
		return 0, fmt.Errorf("EHLO failed: %w", err)
	}

	// Check SIZE extension
	if ok, sizeStr := client.Extension("SIZE"); ok && sizeStr != "" {
		if size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64); err == nil {
			return size, nil
		}
	}

	return 0, nil // SIZE not advertised
}
