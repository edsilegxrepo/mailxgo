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
| `--smime-recipient-cert-dir` | String | Directory containing recipient certificates (.pem/.crt/.cer) - auto-indexed by SAN email |
| `--smime-algorithm` | String | Encryption algorithm: `aes-256-gcm` (default), `aes-128-gcm`, `aes-256-cbc`, `aes-128-cbc`, `3des-cbc` |
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
  "smime_recipient_cert_dir": "/etc/mailxgo/certs/recipients/",
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
    "bytes"
    "crypto"
    "crypto/x509"
    "sync"
)

type SMIMEConfig struct {
    Sign              bool
    Encrypt           bool
    SignerCert        *x509.Certificate
    SignerKey         crypto.PrivateKey  // RSA or ECDSA
    IntermediateCerts []*x509.Certificate
    RecipientCerts    []*x509.Certificate
    Algorithm         string // aes-256-gcm (default), aes-128-gcm, aes-256-cbc, aes-128-cbc, 3des-cbc
}

// Buffer pool for large payload processing (reduces GC pressure)
var smimeBufferPool = sync.Pool{
    New: func() interface{} {
        return new(bytes.Buffer)
    },
}

// Certificate/key loading
func LoadCertificate(path string) (*x509.Certificate, error)
func LoadPrivateKey(path, password string) (crypto.PrivateKey, error)
func LoadPKCS12(path, password string) (*x509.Certificate, crypto.PrivateKey, []*x509.Certificate, error)
func LoadCertificatesFromDir(dirPath string) ([]*x509.Certificate, error)

// Auto-resolve recipient certs by email address (SAN/EmailAddresses)
func BuildCertIndex(certs []*x509.Certificate) map[string]*x509.Certificate
func ResolveCertForEmail(index map[string]*x509.Certificate, email string) *x509.Certificate

// Pre-flight validation
func ValidateCertForSigning(cert *x509.Certificate) error
func ValidateCertForEncryption(cert *x509.Certificate) error
func CheckKeyFilePermissions(path string) error  // Warn if > 0600 on Unix

// Encryption (signing handled by go-mail natively)
func EncryptForRecipients(mimeData []byte, recipients []*x509.Certificate, algorithm string) ([]byte, error)

// Size estimation for pre-dial bounds check
func EstimateEncryptedSize(rawSize int64) int64  // Returns rawSize * 1.37 for S/MIME overhead
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
4. **mailer.go**: Integrate S/MIME into message composition pipeline, pre-dial size check with overhead
5. **diag.go**: Add S/MIME certificate diagnostics in `--diag` mode

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

## Optimizations

### 1. Pre-Dial Size Bounds Check with S/MIME Overhead

S/MIME encryption and Base64 wrapping add ~35-40% payload size overhead. Update pre-dial size validation to account for this:

```go
// In mailer.go, before dialing
const smimeOverheadFactor = 1.37  // 4/3 Base64 + PKCS#7 headers

func EstimateEncryptedSize(rawSize int64) int64 {
    return int64(float64(rawSize) * smimeOverheadFactor)
}

// Check against --max-attachment-size AND remote ESMTP SIZE limit
if params.SMIMEEncrypt {
    estimatedSize := EstimateEncryptedSize(totalAttachmentSize)
    if params.MaxAttachmentMB > 0 && estimatedSize > int64(params.MaxAttachmentMB)*1024*1024 {
        return nil, fmt.Errorf("estimated S/MIME payload (%d MB) exceeds --max-attachment-size (%d MB)",
            estimatedSize/(1024*1024), params.MaxAttachmentMB)
    }
}
```

### 2. Auto-Resolve Recipient Certs by Email Address (SAN/Subject)

When `--smime-recipient-cert-dir` is supplied, build an in-memory index by email:

```go
// Index certs by SAN email or cert.EmailAddresses
func BuildCertIndex(certs []*x509.Certificate) map[string]*x509.Certificate {
    index := make(map[string]*x509.Certificate)
    for _, cert := range certs {
        // Index by EmailAddresses field
        for _, email := range cert.EmailAddresses {
            index[strings.ToLower(email)] = cert
        }
        // Also check SAN rfc822Name entries
        for _, san := range cert.URIs {
            if strings.HasPrefix(san.String(), "mailto:") {
                email := strings.TrimPrefix(san.String(), "mailto:")
                index[strings.ToLower(email)] = cert
            }
        }
    }
    return index
}

// Auto-resolve cert for a recipient email
func ResolveCertForEmail(index map[string]*x509.Certificate, email string) *x509.Certificate {
    return index[strings.ToLower(email)]
}
```

**Usage**: When encrypting for `alice@corp.local`, mailxgo automatically finds `alice@corp.local`'s cert from the directory without explicit `--smime-recipient-cert` per recipient.

### 3. S/MIME Diagnostic Probing in `--diag` Mode

Extend `--diag` to audit S/MIME health when S/MIME flags are provided:

```go
// In diag.go, add to DiagReport struct
type SMIMEDiagnostics struct {
    SignerCertValid     bool   `json:"signer_cert_valid,omitempty"`
    SignerCertExpiry    int    `json:"signer_cert_days_until_expiry,omitempty"`
    SignerKeyUsageOK    bool   `json:"signer_key_usage_ok,omitempty"`
    SignerKeyDecryptOK  bool   `json:"signer_key_decrypt_ok,omitempty"`
    RecipientCertsValid []bool `json:"recipient_certs_valid,omitempty"`
    RecipientCertExpiry []int  `json:"recipient_cert_days_until_expiry,omitempty"`
    Warnings            []string `json:"warnings,omitempty"`
}

// Diagnostic checks:
// - Sender/recipient certificate expiration (<30 days = warning)
// - X.509 KeyUsage flags (DigitalSignature, KeyEncipherment)
// - ExtKeyUsage includes EmailProtection
// - Private key decryption test (with v1:gcm: support)
// - Key file permissions check (>0600 = warning on Unix)
```

**Output example**:
```
--- S/MIME Certificate Diagnostics ---
Signer Certificate   : /path/to/sender.pem
  Subject            : CN=sender@corp.local
  Expiration         : 2027-03-15 (217 days remaining)
  KeyUsage           : DigitalSignature ✓
  ExtKeyUsage        : EmailProtection ✓
  Private Key        : Decryption OK ✓

Recipient Certificates:
  [1] alice@corp.local : Valid, expires 2027-05-20 (283 days)
  [2] bob@corp.local   : WARNING: expires in 18 days!

Warnings:
  - Recipient cert bob@corp.local expires in 18 days
```

### 4. Memory Optimization via sync.Pool Buffering

For large MFT payloads (50MB+), use pooled buffers to reduce GC pressure:

```go
var smimeBufferPool = sync.Pool{
    New: func() interface{} {
        return bytes.NewBuffer(make([]byte, 0, 1024*1024)) // 1MB initial capacity
    },
}

func EncryptForRecipients(mimeData []byte, recipients []*x509.Certificate, algorithm string) ([]byte, error) {
    buf := smimeBufferPool.Get().(*bytes.Buffer)
    defer func() {
        buf.Reset()
        smimeBufferPool.Put(buf)
    }()
    
    // Use buf for intermediate processing...
    encrypted, err := pkcs7.Encrypt(mimeData, recipients)
    if err != nil {
        return nil, err
    }
    
    // Base64 encode into pooled buffer
    encoder := base64.NewEncoder(base64.StdEncoding, buf)
    // ... wrap at 76 chars per RFC 2045
    
    return buf.Bytes(), nil
}
```

### 5. Automated Cryptographic Hygiene Warnings

Add runtime security warnings in telemetry outputs (NDJSON/JSON/text):

```go
func checkCryptoHygiene(config *SMIMEConfig, keyPath string) []string {
    var warnings []string
    
    // Warn on weak encryption algorithm
    if config.Algorithm == "3des-cbc" {
        warnings = append(warnings, "WARNING: 3DES-CBC is deprecated; use AES-256-CBC")
    }
    
    // Warn on weak digest (if we ever support sha1)
    if config.DigestAlgorithm == "sha1" {
        warnings = append(warnings, "WARNING: SHA-1 is deprecated; use SHA-256 or higher")
    }
    
    // Warn on loose key file permissions (Unix only)
    if runtime.GOOS != "windows" {
        if err := CheckKeyFilePermissions(keyPath); err != nil {
            warnings = append(warnings, fmt.Sprintf("WARNING: %v", err))
        }
    }
    
    // Warn on near-expiry certs (<30 days)
    if config.SignerCert != nil {
        daysLeft := int(time.Until(config.SignerCert.NotAfter).Hours() / 24)
        if daysLeft < 30 {
            warnings = append(warnings, fmt.Sprintf("WARNING: Signer certificate expires in %d days", daysLeft))
        }
    }
    
    return warnings
}

func CheckKeyFilePermissions(path string) error {
    info, err := os.Stat(path)
    if err != nil {
        return err
    }
    mode := info.Mode().Perm()
    if mode&0077 != 0 {  // Group or world readable/writable
        return fmt.Errorf("private key %s has insecure permissions %04o (should be 0600)", path, mode)
    }
    return nil
}
```

### 6. S/MIME Configuration Profile Presets

Support default S/MIME credentials in config file to simplify CLI commands:

```json
{
  "smime_default_cert": "/etc/mailxgo/certs/sender.pem",
  "smime_default_key": "/etc/mailxgo/certs/sender.key",
  "smime_default_key_password": "v1:gcm:encrypted-password",
  "smime_recipient_cert_dir": "/etc/mailxgo/certs/recipients/"
}
```

**Benefit**: Shortened CLI for automated schedulers:
```shell
# Before: explicit paths every time
mailxgo --smime-sign --smime-cert /path/to/cert.pem --smime-key /path/to/key.pem ...

# After: uses config defaults
mailxgo --smime-sign --smime-encrypt --to alice@corp.local --body "Report"
```

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

## Implementation Notes

### 1. sync.Pool Buffer Safety
When using `smimeBufferPool` in `EncryptForRecipients()`, the buffer is recycled after the function returns. **Must copy the byte payload** before returning:

```go
// WRONG - caller gets corrupted data when buf is recycled
return buf.Bytes(), nil

// CORRECT - return independent copy
return bytes.Clone(buf.Bytes()), nil
// or: return append([]byte(nil), buf.Bytes()...), nil
```

### 2. SAN Email Matching Coverage
Check both `cert.EmailAddresses` and `cert.URIs` with `mailto:` prefix to cover:
- **OpenSSL-generated certs**: Use `cert.EmailAddresses` (standard rfc822Name SAN)
- **Microsoft AD CS certs**: May also use `mailto:` URI in SAN

```go
// Index by EmailAddresses (standard)
for _, email := range cert.EmailAddresses {
    index[strings.ToLower(email)] = cert
}
// Also check URIs for mailto: (AD CS compatibility)
for _, uri := range cert.URIs {
    if strings.HasPrefix(uri.String(), "mailto:") {
        email := strings.TrimPrefix(uri.String(), "mailto:")
        index[strings.ToLower(email)] = cert
    }
}
```

### 3. pkcs7 Cipher Selection
`go.mozilla.org/pkcs7` uses a **global variable** to set the encryption algorithm. Default is DES-CBC (weak!). Must set before calling `Encrypt()`:

```go
// Set cipher based on --smime-algorithm flag
switch algorithm {
case "aes-256-gcm":
    pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
case "aes-128-gcm":
    pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128GCM
case "aes-256-cbc":
    pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
case "aes-128-cbc":
    pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
case "3des-cbc":
    pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmDESCBC
default:
    pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM // secure default
}

encrypted, err := pkcs7.Encrypt(content, recipients)
```

**Note**: The pkcs7 library recommends AES-GCM over AES-CBC for better security (authenticated encryption).

## Testing Strategy

### Unit Tests (`smime_test.go`)
- Certificate/key loading (PEM and PKCS#12)
- Auto-resolve certs by email (SAN/EmailAddresses)
- Signing with various digest algorithms (SHA-256, SHA-384, SHA-512)
- Encryption with various symmetric algorithms (AES-256-GCM, AES-128-GCM, AES-256-CBC, AES-128-CBC, 3DES)
- Sign + encrypt combined
- Multi-recipient encryption
- Pre-flight validation (expired certs, missing key usage)
- Pre-dial size estimation with S/MIME overhead
- Key file permission checks
- Crypto hygiene warnings (3DES, SHA-1, permissions)
- Error cases (invalid certs, wrong passwords, corrupted files)

### Integration Tests
1. **Self-Test**: Sign, verify signature locally using `pkcs7.Parse()` + `Verify()`
2. **Roundtrip**: Sign/encrypt, send to Mailpit, retrieve raw EML, verify/decrypt
3. **Interop**: Generate S/MIME message, verify with OpenSSL CLI:
   ```bash
   openssl smime -verify -in message.eml -CAfile ca.pem
   openssl smime -decrypt -in message.eml -inkey recipient.key
   ```
4. **Diagnostics**: Test `--diag` with S/MIME certs (expiry warnings, key usage checks)
5. **Auto-resolve**: Test cert directory indexing by email address

### Test Certificates
- Generate test CA + end-entity certs in `testdata/smime/`
- Include RSA 2048/4096 and ECDSA P-256 keys
- Include PKCS#12 bundles for enterprise format testing
- Include expired cert for negative testing
- Include cert without EmailProtection EKU for validation testing
- Include certs with various SAN email addresses for auto-resolve testing

## Dependencies

Add to `go.mod`:
```bash
go get go.mozilla.org/pkcs7
go get golang.org/x/crypto/pkcs12
```

**Note**: `github.com/wneessen/go-mail` v0.8.1 is already installed and provides native S/MIME signing.

## Security Considerations

1. **Private Key Protection**: Warn if key file permissions > 0600 (Unix)
2. **Algorithm Deprecation**: Warn if using 3DES or SHA-1 (prefer AES-256, SHA-256+)
3. **Certificate Validation**: Validate all certs before use:
   - Check expiration dates (warn if <30 days)
   - Verify KeyUsage flags (DigitalSignature for signing, KeyEncipherment for encryption)
   - Verify ExtKeyUsage includes EmailProtection (warn if missing, don't fail)
4. **Key Password**: Support secretprotector `v1:gcm:` prefix for encrypted key passwords
5. **PKCS#12 Security**: Clear decrypted key material from memory after use
6. **Size Limits**: Check estimated encrypted size against limits before dialing

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
| Pre-dial size check with S/MIME overhead | 1 | Estimate encrypted size |
| Auto-resolve certs by email (SAN index) | 2 | BuildCertIndex, ResolveCertForEmail |
| S/MIME diagnostics in --diag | 2 | Cert expiry, key usage, key decrypt test |
| Crypto hygiene warnings | 1 | 3DES/SHA-1 warnings, permission checks |
| sync.Pool buffering | 1 | Reduce GC for large payloads |
| Unit tests | 5 | All features + edge cases |
| Integration tests | 4 | Mailpit roundtrip, OpenSSL interop |
| Documentation | 2 | README, TESTING, examples |
| **Total** | **29** | |

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

### Encrypt with Auto-Resolve (Directory Index)
```shell
# Certs in directory are indexed by SAN email
# alice@corp.local.pem, bob@corp.local.pem auto-matched to recipients
mailxgo \
  --smtp-server smtp.corp.local \
  --smime-encrypt \
  --smime-recipient-cert-dir /path/to/recipient-certs/ \
  --from-email sender@corp.local \
  --to-email alice@corp.local,bob@corp.local \
  --subject "Encrypted Message" \
  --body "Certs auto-resolved from directory."
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

### S/MIME Pre-Flight Diagnostics
```shell
mailxgo \
  --diag \
  --smime-cert /path/to/sender.pem \
  --smime-key /path/to/sender.key \
  --smime-recipient-cert-dir /path/to/recipient-certs/ \
  --from-email sender@corp.local
```

### Using Config Defaults
```shell
# With ~/.mailxgo.json containing smime_default_cert, smime_default_key, etc.
mailxgo --smime-sign --smime-encrypt --to alice@corp.local --body "Report"
```

## Resolved Design Decisions

1. **Multiple Recipients with Different Certs**: PKCS#7 EnvelopedData handles this natively. All recipient certificates are passed to `pkcs7.Encrypt()` which creates a `RecipientInfos` array with the symmetric key encrypted for each recipient's public key.

2. **Certificate Discovery**: Auto-resolve from `--smime-recipient-cert-dir` using SAN email / `cert.EmailAddresses` index. LDAP/AD lookup not included (local files/directory only).

3. **go-mail Integration**: Signing uses native `Msg.SignWithKeypair()`. Encryption uses 2-stage composition (build → export → encrypt → wrap).

4. **Pre-Dial Size Validation**: Account for S/MIME overhead (×1.37) when checking against `--max-attachment-size` and remote ESMTP SIZE limit.

5. **S/MIME Diagnostics**: Extended `--diag` mode validates certs, key usage, expiration, and key decryption before network operations.

6. **Memory Efficiency**: `sync.Pool` buffering for large payloads reduces GC pressure in batch MFT scenarios.

---

*Created: 2026-08-10*
*Updated: 2026-08-10*
*Status: Planning - Ready for Implementation*
