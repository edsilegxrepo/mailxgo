# S/MIME Encryption Feature Plan

## Overview

Add S/MIME (Secure/Multipurpose Internet Mail Extensions) support to mailxgo for end-to-end message encryption and digital signing per RFC 5751/RFC 8551.

## Use Cases

1. **Message Encryption**: Encrypt email body and attachments so only intended recipients can read them
2. **Digital Signing**: Cryptographically sign messages to prove sender authenticity and message integrity
3. **Sign + Encrypt**: Combined mode for both confidentiality and authenticity

## Proposed CLI Flags

| Flag | Type | Description |
|------|------|-------------|
| `--smime-sign` | Boolean | Sign outgoing message with sender's private key |
| `--smime-encrypt` | Boolean | Encrypt message for recipients using their public certificates |
| `--smime-cert` | String | Path to sender's X.509 certificate (PEM) for signing |
| `--smime-key` | String | Path to sender's private key (PEM) for signing |
| `--smime-key-password` | String | Password for encrypted private key (supports `v1:gcm:` prefix) |
| `--smime-pkcs12` | String | Path to PKCS#12 bundle (.pfx/.p12) containing cert and key |
| `--smime-recipient-cert` | String | Path to recipient certificate(s) for encryption (repeatable or comma-separated) |
| `--smime-recipient-cert-dir` | String | Directory containing recipient certificates (.pem/.crt/.cer) |
| `--smime-algorithm` | String | Encryption algorithm: `aes-256-cbc` (default), `aes-128-cbc`, `3des-cbc` |
| `--smime-digest` | String | Signature digest: `sha256` (default), `sha384`, `sha512` |

## Config File Support

```json
{
  "smime_sign": true,
  "smime_encrypt": true,
  "smime_cert": "/etc/mailxgo/certs/sender.pem",
  "smime_key": "/etc/mailxgo/certs/sender.key",
  "smime_key_password": "v1:gcm:encrypted-password",
  "smime_pkcs12": "/etc/mailxgo/certs/sender.pfx",
  "smime_recipient_certs": [
    "/etc/mailxgo/certs/recipient1.pem",
    "/etc/mailxgo/certs/recipient2.pem"
  ],
  "smime_algorithm": "aes-256-cbc",
  "smime_digest": "sha256"
}
```

## Implementation Approach

### Leveraging Existing Libraries

**Critical Discovery**: `go-mail` (already in use) has **native S/MIME signing support**:
- `Msg.SignWithKeypair(privateKey, certificate, intermediateCerts...)`
- `Msg.SignWithTLSCertificate(tlsCert)`
- Handles MIME canonicalization and PKCS#7 structure internally

This eliminates the need for manual PKCS#7 signing implementation.

### Library Responsibilities

| Library | Purpose | Status |
|---------|---------|--------|
| `github.com/wneessen/go-mail` v0.8.1 | S/MIME signing via `SignWithKeypair()` | Already installed |
| `go.mozilla.org/pkcs7` | S/MIME encryption (EnvelopedData) | To add |
| `golang.org/x/crypto/pkcs12` | PKCS#12 (.pfx/.p12) bundle parsing | To add |

### Recommended Approach
1. **Signing**: Use go-mail's native `Msg.SignWithKeypair()` - handles MIME structure automatically
2. **Encryption**: Use `go.mozilla.org/pkcs7` for `EnvelopedData` creation
3. **PKCS#12**: Use `golang.org/x/crypto/pkcs12` for enterprise certificate bundles
4. **No OpenSSL fallback needed**: Pure Go implementation is sufficient

## Architecture Changes

### New File: `smime.go`

```go
package mailxgo

import (
    "crypto"
    "crypto/x509"
)

type SMIMEConfig struct {
    Sign             bool
    Encrypt          bool
    SignerCert       *x509.Certificate
    SignerKey        crypto.PrivateKey  // RSA or ECDSA
    IntermediateCerts []*x509.Certificate
    RecipientCerts   []*x509.Certificate
    Algorithm        string // aes-256-cbc, aes-128-cbc, 3des-cbc (encryption only)
}

// Certificate/key loading
func LoadCertificate(path string) (*x509.Certificate, error)
func LoadPrivateKey(path, password string) (crypto.PrivateKey, error)
func LoadPKCS12(path, password string) (*x509.Certificate, crypto.PrivateKey, []*x509.Certificate, error)
func LoadCertificatesFromDir(dirPath string) ([]*x509.Certificate, error)

// Pre-flight validation
func ValidateCertForSigning(cert *x509.Certificate) error
func ValidateCertForEncryption(cert *x509.Certificate) error

// Encryption only (signing handled by go-mail natively)
func EncryptForRecipients(mimeData []byte, recipients []*x509.Certificate) ([]byte, error)
```

**Note**: Signing is handled directly by `go-mail`:
```go
// In mailer.go - signing is a single method call
if params.SMIMESign {
    err := msg.SignWithKeypair(smimeConfig.SignerKey, smimeConfig.SignerCert, smimeConfig.IntermediateCerts...)
    if err != nil {
        return nil, fmt.Errorf("S/MIME signing failed: %w", err)
    }
}
```

### Changes to Existing Files

1. **cli.go**: Add S/MIME flag parsing
2. **config.go**: Add S/MIME config fields and JSON parsing
3. **types.go**: Add `SMIMEConfig` to `EmailParams`
4. **mailer.go**: Integrate S/MIME into message composition pipeline

### Message Composition Pipeline

The pipeline leverages go-mail's native S/MIME signing support:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Sign-Only Flow (using go-mail native support)                           │
├─────────────────────────────────────────────────────────────────────────┤
│  mail.NewMsg() ──▶ SetFrom/SetTo/SetSubject ──▶ SetBody/AttachFile     │
│       │                                                                 │
│       ▼                                                                 │
│  msg.SignWithKeypair(key, cert, intermediates...)                       │
│       │                                                                 │
│       ▼   (go-mail handles MIME canonicalization & PKCS#7 internally)  │
│  client.DialAndSend(msg)                                                │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ Encrypt-Only Flow (using pkcs7 library)                                 │
├─────────────────────────────────────────────────────────────────────────┤
│  mail.NewMsg() ──▶ SetFrom/SetTo/SetSubject ──▶ SetBody/AttachFile     │
│       │                                                                 │
│       ▼                                                                 │
│  msg.WriteTo(buf) ──▶ Raw RFC 822 MIME bytes                           │
│       │                                                                 │
│       ▼                                                                 │
│  pkcs7.Encrypt(buf.Bytes(), recipientCerts)                            │
│       │                                                                 │
│       ▼                                                                 │
│  New mail.Msg with application/pkcs7-mime body ──▶ DialAndSend()       │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ Sign + Encrypt Flow (combined)                                          │
├─────────────────────────────────────────────────────────────────────────┤
│  mail.NewMsg() ──▶ Build message ──▶ SignWithKeypair()                 │
│       │                                                                 │
│       ▼                                                                 │
│  signedMsg.WriteTo(buf) ──▶ Signed MIME bytes                          │
│       │                                                                 │
│       ▼                                                                 │
│  pkcs7.Encrypt(buf.Bytes(), recipientCerts)                            │
│       │                                                                 │
│       ▼                                                                 │
│  New mail.Msg with encrypted body ──▶ DialAndSend()                    │
└─────────────────────────────────────────────────────────────────────────┘
```

### Multi-Recipient Encryption

PKCS#7 `EnvelopedData` natively supports multiple recipients in a single message:

1. A random symmetric key (e.g., AES-256-CBC) encrypts the message payload
2. That symmetric key is encrypted once for **each recipient's public key**
3. All encrypted key copies are stored in the `RecipientInfos` structure

```go
// All recipients receive the same encrypted message
// Each can decrypt with their own private key
encryptedData, err := pkcs7.Encrypt(canonicalizedMIME, recipientCerts)
```

This means:
- No need to map email addresses to certificates
- Simply collect all certs from `--smime-recipient-cert` and `--smime-recipient-cert-dir`
- Pass them all to `pkcs7.Encrypt()` as a single slice

## Pre-flight Certificate Validation

Before signing or encrypting, validate certificates to prevent silent failures:

```go
func ValidateCertForSigning(cert *x509.Certificate) error {
    now := time.Now()
    
    // Check expiration
    if now.Before(cert.NotBefore) {
        return fmt.Errorf("certificate not yet valid (NotBefore: %v)", cert.NotBefore)
    }
    if now.After(cert.NotAfter) {
        return fmt.Errorf("certificate expired (NotAfter: %v)", cert.NotAfter)
    }
    
    // Check key usage for signing
    if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
        return fmt.Errorf("certificate lacks KeyUsageDigitalSignature")
    }
    
    // Check extended key usage (if present)
    if len(cert.ExtKeyUsage) > 0 {
        hasEmailProtection := false
        for _, eku := range cert.ExtKeyUsage {
            if eku == x509.ExtKeyUsageEmailProtection || eku == x509.ExtKeyUsageAny {
                hasEmailProtection = true
                break
            }
        }
        if !hasEmailProtection {
            return fmt.Errorf("certificate lacks ExtKeyUsageEmailProtection")
        }
    }
    
    return nil
}

func ValidateCertForEncryption(cert *x509.Certificate) error {
    now := time.Now()
    
    // Check expiration
    if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
        return fmt.Errorf("certificate expired or not yet valid")
    }
    
    // Check key usage for encryption
    if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
        return fmt.Errorf("certificate lacks KeyUsageKeyEncipherment")
    }
    
    return nil
}
```

## Testing Strategy

### Unit Tests (`smime_test.go`)
- Certificate/key loading (PEM and PKCS#12)
- CRLF canonicalization
- Signing with various digest algorithms (SHA-256, SHA-384, SHA-512)
- Encryption with various symmetric algorithms (AES-256-CBC, AES-128-CBC, 3DES)
- Sign + encrypt combined
- Multi-recipient encryption
- Pre-flight validation (expired certs, missing key usage)
- Error cases (invalid certs, wrong passwords, corrupted files)

### Integration Tests
1. **Self-Test**: Sign, verify signature locally using `pkcs7.Parse()` + `Verify()`
2. **Roundtrip**: Sign/encrypt, send to Mailpit, retrieve raw EML, verify/decrypt
3. **Interop**: Generate S/MIME message, verify with OpenSSL CLI:
   ```bash
   openssl smime -verify -in message.eml -CAfile ca.pem
   openssl smime -decrypt -in message.eml -inkey recipient.key
   ```

### Test Certificates
- Generate test CA + end-entity certs in `testdata/smime/`
- Include RSA 2048/4096 and ECDSA P-256 keys
- Include PKCS#12 bundles for enterprise format testing
- Include expired cert for negative testing
- Include cert without EmailProtection EKU for validation testing

## Dependencies

Add to `go.mod`:
```bash
go get go.mozilla.org/pkcs7
go get golang.org/x/crypto/pkcs12
```

**Note**: `github.com/wneessen/go-mail` v0.8.1 is already installed and provides native S/MIME signing.

## Security Considerations

1. **Private Key Protection**: Warn if key file permissions > 0600
2. **Algorithm Deprecation**: Warn if using 3DES (prefer AES-256)
3. **Certificate Validation**: Validate all certs before use:
   - Check expiration dates
   - Verify KeyUsage flags (DigitalSignature for signing, KeyEncipherment for encryption)
   - Verify ExtKeyUsage includes EmailProtection (warn if missing, don't fail)
4. **Key Password**: Support secretprotector `v1:gcm:` prefix for encrypted key passwords
5. **PKCS#12 Security**: Clear decrypted key material from memory after use

## Documentation Updates

1. **README.md**: Add S/MIME section with examples
2. **TESTING.md**: Add S/MIME test cases
3. **ARCHITECTURE.md**: Update message flow diagram

## Estimated Effort

| Component | Hours | Notes |
|-----------|-------|-------|
| smime.go core (encrypt/validate) | 4 | Signing handled by go-mail |
| PKCS#12 support | 2 | Using golang.org/x/crypto/pkcs12 |
| CLI/config integration | 3 | Flag parsing, config struct updates |
| mailer.go integration | 2 | Wire up SignWithKeypair + encryption |
| Unit tests | 4 | Cert loading, validation, encryption |
| Integration tests | 3 | Sign/encrypt/verify with Mailpit |
| Documentation | 2 | README, TESTING, examples |
| **Total** | **20** | Reduced from 30h due to go-mail native signing |

## Example Usage

### Sign Only
```shell
mailxgo \
  --smtp-server smtp.corp.local \
  --smime-sign \
  --smime-cert /path/to/sender.pem \
  --smime-key /path/to/sender.key \
  --from-email sender@corp.local \
  --to-email recipient@corp.local \
  --subject "Signed Message" \
  --body "This message is digitally signed."
```

### Sign with PKCS#12 Bundle
```shell
mailxgo \
  --smtp-server smtp.corp.local \
  --smime-sign \
  --smime-pkcs12 /path/to/sender.pfx \
  --smime-key-password "bundle-password" \
  --from-email sender@corp.local \
  --to-email recipient@corp.local \
  --subject "Signed Message" \
  --body "This message is digitally signed."
```

### Encrypt Only
```shell
mailxgo \
  --smtp-server smtp.corp.local \
  --smime-encrypt \
  --smime-recipient-cert /path/to/recipient.pem \
  --from-email sender@corp.local \
  --to-email recipient@corp.local \
  --subject "Encrypted Message" \
  --body "This message is encrypted."
```

### Encrypt for Multiple Recipients
```shell
mailxgo \
  --smtp-server smtp.corp.local \
  --smime-encrypt \
  --smime-recipient-cert-dir /path/to/recipient-certs/ \
  --from-email sender@corp.local \
  --to-email alice@corp.local,bob@corp.local \
  --subject "Encrypted Message" \
  --body "All recipients can decrypt with their own keys."
```

### Sign + Encrypt
```shell
mailxgo \
  --smtp-server smtp.corp.local \
  --smime-sign --smime-encrypt \
  --smime-cert /path/to/sender.pem \
  --smime-key /path/to/sender.key \
  --smime-recipient-cert /path/to/recipient.pem \
  --from-email sender@corp.local \
  --to-email recipient@corp.local \
  --subject "Signed and Encrypted" \
  --body "Confidential message with verified origin."
```

## Resolved Design Decisions

1. **Multiple Recipients with Different Certs**: PKCS#7 EnvelopedData handles this natively. All recipient certificates are passed to `pkcs7.Encrypt()` which creates a `RecipientInfos` array with the symmetric key encrypted for each recipient's public key. No address-to-cert mapping needed.

2. **Certificate Discovery (LDAP/AD)**: Deferred to Phase 2. Phase 1 requires local certificate files or directory scanning only.

3. **go-mail Integration**: Use 2-stage composition:
   - Stage 1: Build message with go-mail, export to raw bytes via `msg.WriteTo()`
   - Stage 2: Canonicalize, sign/encrypt with pkcs7, wrap in S/MIME MIME structure
   - Stage 3: Create new `mail.Msg` with S/MIME body for dispatch

---

*Created: 2026-08-10*
*Updated: 2026-08-10*
*Status: Planning - Ready for Implementation*
