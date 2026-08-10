// Package mailxgo - Cryptographic & TLS Security Module
//
// OBJECTIVES:
// Provide secure certificate handling, TLS configuration, fingerprint pinning, and secret decryption.
//
// CORE COMPONENTS:
// - loadCustomCACerts: Loads CA certificates from file or directory for custom trust stores.
// - createFingerprintVerifier: Creates SHA256 certificate pinning verifier for self-signed certs.
// - DecryptSecret: Decrypts AES-256-GCM encrypted secrets via secretprotector.
// - NormalizeFingerprint: Normalizes certificate fingerprints for comparison.
// - ComputeCertFingerprint: Computes SHA256 fingerprint of a certificate.
//
// FUNCTIONALITY & DATA FLOW:
// PEM Files -> x509.CertPool -> tls.Config.RootCAs
// Certificate DER -> SHA256 Hash -> Hex Fingerprint -> Pinning Verification
// v1:gcm:base64 -> AES-256-GCM Decrypt -> Plaintext Secret
package mailxgo

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
)

// IsEncryptedSecret checks if a string has the secretprotector encrypted prefix (v1:gcm:).
func IsEncryptedSecret(s string) bool {
	return libsecsecrets.IsEncrypted(s)
}

// DecryptSecret decrypts a secret if it has the v1:gcm: encrypted prefix.
// If the secret is not encrypted, it returns the original value unchanged.
// Uses the master key from environment variable SECRETPROTECTOR_MASTER_KEY or the provided keyEnv.
func DecryptSecret(secret string, keyEnv string) (string, error) {
	if secret == "" {
		return "", nil
	}

	// If not encrypted, return as-is
	if !IsEncryptedSecret(secret) {
		return secret, nil
	}

	// Resolve the master key
	if keyEnv == "" {
		keyEnv = libsecsecrets.DefaultKeyEnv
	}

	key, err := libsecsecrets.ResolveKey(context.Background(), "", keyEnv, "")
	if err != nil {
		return "", fmt.Errorf("failed to resolve master key for decryption: %w", err)
	}
	defer libsecsecrets.ZeroBuffer(key)

	// Decrypt the secret
	decrypted, err := libsecsecrets.Decrypt(context.Background(), secret, key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt secret: %w", err)
	}

	return decrypted, nil
}

// loadCustomCACerts loads CA certificates from a file and/or directory into a cert pool.
// Used for trusting self-signed or internal CA certificates.
func loadCustomCACerts(certFile, certDir string) (*x509.CertPool, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}

	// Load from single file
	if certFile != "" {
		if err := ValidateFilePath(certFile); err != nil {
			return nil, fmt.Errorf("invalid CA cert path: %w", err)
		}
		// #nosec G304 -- Path pre-validated via ValidateFilePath (absolute path, no traversal)
		pemData, err := os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert file %s: %w", certFile, err)
		}
		if !rootCAs.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", certFile)
		}
	}

	// Load from directory
	if certDir != "" {
		if err := ValidateFilePath(certDir); err != nil {
			return nil, fmt.Errorf("invalid CA cert directory path: %w", err)
		}
		entries, err := os.ReadDir(certDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert directory %s: %w", certDir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			// Only process .pem, .crt, .cer files
			name := entry.Name()
			ext := strings.ToLower(filepath.Ext(name))
			if ext != ".pem" && ext != ".crt" && ext != ".cer" {
				continue
			}
			// #nosec G304 -- certDir pre-validated via ValidateFilePath; name from ReadDir (no user input)
			pemData, err := os.ReadFile(filepath.Join(certDir, name))
			if err != nil {
				return nil, fmt.Errorf("failed to read CA cert %s: %w", name, err)
			}
			rootCAs.AppendCertsFromPEM(pemData)
		}
	}

	return rootCAs, nil
}

// NormalizeFingerprint normalizes a certificate fingerprint for comparison.
// Removes colons and converts to uppercase.
func NormalizeFingerprint(fingerprint string) string {
	return strings.ToUpper(strings.ReplaceAll(fingerprint, ":", ""))
}

// ComputeCertFingerprint computes the SHA256 fingerprint of a DER-encoded certificate.
// Returns the fingerprint as an uppercase hex string without colons.
func ComputeCertFingerprint(derCert []byte) string {
	hash := sha256.Sum256(derCert)
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// FormatFingerprint formats a fingerprint with colons for display (AA:BB:CC:...).
func FormatFingerprint(fingerprint string) string {
	normalized := NormalizeFingerprint(fingerprint)
	var parts []string
	for i := 0; i < len(normalized); i += 2 {
		end := i + 2
		if end > len(normalized) {
			end = len(normalized)
		}
		parts = append(parts, normalized[i:end])
	}
	return strings.Join(parts, ":")
}

// createFingerprintVerifier creates a TLS VerifyPeerCertificate function that pins to a specific SHA256 fingerprint.
// The fingerprint can be provided with or without colons (e.g., "AA:BB:CC..." or "AABBCC...").
func createFingerprintVerifier(expectedFingerprint string) func([][]byte, [][]*x509.Certificate) error {
	normalized := NormalizeFingerprint(expectedFingerprint)

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificate presented by server")
		}

		// Compute SHA256 fingerprint of the leaf certificate
		actualFingerprint := ComputeCertFingerprint(rawCerts[0])

		if actualFingerprint != normalized {
			return fmt.Errorf("certificate fingerprint mismatch: expected %s, got %s",
				FormatFingerprint(normalized), FormatFingerprint(actualFingerprint))
		}

		return nil
	}
}

// ValidateCertFingerprint validates that a fingerprint string is a valid SHA256 hex string.
// Returns an error if the fingerprint is not 64 hex characters (with or without colons).
func ValidateCertFingerprint(fingerprint string) error {
	normalized := NormalizeFingerprint(fingerprint)
	if len(normalized) != 64 {
		return fmt.Errorf("invalid SHA256 fingerprint length: expected 64 hex chars, got %d", len(normalized))
	}
	for _, c := range normalized {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("invalid character in fingerprint: %c", c)
		}
	}
	return nil
}

// TLSConfigParams holds parameters for building a TLS configuration.
type TLSConfigParams struct {
	ServerName     string
	TLSMode        string
	TLSCACert      string
	TLSCADir       string
	TLSFingerprint string
}

// BuildTLSConfig creates a tls.Config based on the provided parameters.
// This centralizes TLS configuration to avoid duplication across mailer and diag code.
func BuildTLSConfig(params TLSConfigParams) (*tls.Config, error) {
	// #nosec G402 -- InsecureSkipVerify is user-configurable via ignore-trust mode for internal relays.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: params.TLSMode == "ignore-trust",
		ServerName:         params.ServerName,
		MinVersion:         tls.VersionTLS12,
	}

	// Custom CA certificate or directory
	if params.TLSCACert != "" || params.TLSCADir != "" {
		rootCAs, err := loadCustomCACerts(params.TLSCACert, params.TLSCADir)
		if err != nil {
			return nil, fmt.Errorf("failed to load custom CA certificates: %w", err)
		}
		tlsConfig.RootCAs = rootCAs
		tlsConfig.InsecureSkipVerify = false // Force verification when custom CA is provided
	}

	// Certificate fingerprint pinning
	if params.TLSFingerprint != "" {
		verifier := createFingerprintVerifier(params.TLSFingerprint)
		tlsConfig.VerifyPeerCertificate = verifier
		tlsConfig.InsecureSkipVerify = true // Skip default verification, use fingerprint instead
		// VerifyConnection ensures fingerprint check runs on resumed sessions (G123 mitigation)
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no peer certificates presented")
			}
			return verifier([][]byte{cs.PeerCertificates[0].Raw}, nil)
		}
	}

	return tlsConfig, nil
}
