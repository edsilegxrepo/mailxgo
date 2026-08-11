# S/MIME Encryption & Digital Signing

## Overview

mailxgo supports S/MIME (Secure/Multipurpose Internet Mail Extensions) for end-to-end message encryption and digital signing per RFC 5751/RFC 8551.

## Use Cases

1. **Message Encryption**: Encrypt email body and attachments so only intended recipients can read them
2. **Digital Signing**: Cryptographically sign messages to prove sender authenticity and message integrity
3. **Sign + Encrypt**: Combined mode for both confidentiality and authenticity

## CLI Flags

| Flag | Type | Description |
|------|------|-------------|
| `--smime-sign` | Boolean | Sign outgoing message with sender's private key |
| `--smime-encrypt` | Boolean | Encrypt message for recipients using their public certificates |
| `--smime-cert` | String | Path to sender's X.509 certificate (PEM) for signing |
| `--smime-key` | String | Path to sender's private key (PEM) for signing |
| `--smime-key-password` | String | Password for encrypted private key (supports `v1:gcm:` prefix) |
| `--smime-pkcs12` | String | Path to PKCS#12 bundle (.pfx/.p12) containing cert and key |
| `--smime-recipient-cert` | String | Path to recipient certificate(s) for encryption (comma-separated) |
| `--smime-recipient-cert-dir` | String | Directory containing recipient certificates (.pem/.crt/.cer) - auto-indexed by SAN email |
| `--smime-algorithm` | String | Encryption algorithm: `aes-256-gcm` (default), `aes-128-gcm`, `aes-256-cbc`, `aes-128-cbc`, `3des-cbc` |
| `--smime-digest` | String | Signature digest: `sha256` (default). Note: go-mail uses SHA-256 internally; this flag is reserved for future use and crypto hygiene warnings. |

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
  "smime_algorithm": "aes-256-gcm",
  "smime_digest": "sha256",

  "smime_default_cert": "/etc/mailxgo/certs/default-sender.pem",
  "smime_default_key": "/etc/mailxgo/certs/default-sender.key",
  "smime_default_key_password": "v1:gcm:encrypted-default-password",
  "smime_default_pkcs12": "/etc/mailxgo/certs/default-sender.pfx"
}
```

### Default Credentials

The `smime_default_*` fields provide fallback credentials when `--smime-sign` or `--smime-encrypt` is used without explicit cert/key paths:

```shell
# With config file containing smime_default_cert/key:
mailxgo --smime-sign --smime-encrypt --to alice@corp.local --body "Report"
# Uses default credentials from config - no need to specify paths each time
```

## Implementation Architecture

### Library Stack

| Library | Purpose |
|---------|---------|
| `github.com/wneessen/go-mail` v0.8.1 | S/MIME signing via native `SignWithKeypair()` |
| `go.mozilla.org/pkcs7` | S/MIME encryption (PKCS#7 EnvelopedData) |
| `golang.org/x/crypto/pkcs12` | PKCS#12 (.pfx/.p12) bundle parsing |

### Core Components (`smime.go`)

| Function | Purpose |
|----------|---------|
| `LoadCertificate(path)` | Load PEM-encoded X.509 certificate |
| `LoadPrivateKey(path, password)` | Load PEM-encoded private key (RSA/ECDSA, encrypted or plain) |
| `LoadPKCS12(path, password)` | Load PKCS#12 bundle, extract cert, key, and intermediate CAs |
| `LoadCertificatesFromDir(dirPath)` | Load all certs from directory (.pem/.crt/.cer) |
| `BuildCertIndex(certs)` | Index certs by EmailAddresses and mailto: URIs |
| `ResolveCertForEmail(index, email)` | Lookup cert by recipient email address |
| `ValidateCertForSigning(cert)` | Pre-flight check: expiration, KeyUsageDigitalSignature |
| `ValidateCertForEncryption(cert)` | Pre-flight check: expiration, KeyUsageKeyEncipherment |
| `CheckKeyFilePermissions(path)` | Warn if key file permissions > 0600 (Unix) |
| `EncryptForRecipients(mimeData, recipients, algorithm)` | PKCS#7 encryption with algorithm selection |
| `EstimateEncryptedSize(rawSize)` | Calculate S/MIME overhead (1.37x factor) |
| `CheckCryptoHygiene(config, keyPath)` | Security warnings (3DES, SHA-1, permissions, expiry) |
| `FormatBase64MIME(data)` | RFC 2045 Base64 encoding with 76-char line wrapping |
| `ProbeESMTPSize(server, port, tlsMode)` | Probe server for ESMTP SIZE extension limit |

### Message Composition Pipeline

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

### Thread Safety

The `pkcs7` library uses a global variable for cipher selection. A `pkcs7Mutex` protects concurrent encryption calls:

```go
var pkcs7Mutex sync.Mutex

func EncryptForRecipients(...) {
    pkcs7Mutex.Lock()
    defer pkcs7Mutex.Unlock()
    pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
    // ...
}
```

### Buffer Safety

`EncryptForRecipients` returns `bytes.Clone()` of the encrypted data to ensure the caller owns the memory:

```go
return bytes.Clone(encryptedData), nil
```

## S/MIME Diagnostics (`--diag`)

When S/MIME flags are provided, `--diag` mode audits certificate health:

```
--- S/MIME Certificate Diagnostics ---
Signer Subject     : sender@corp.local
Signer Expiration  : 2027-03-15T00:00:00Z (217 days remaining)
Signer Key Usage   : DigitalSignature (OK: true)
Signer Key Decrypt : OK (true)
Recipient Certificates:
  [1] alice@corp.local (expires 2027-05-20)
  [2] bob@corp.local (expires 2026-09-01)
Warnings:
  - WARNING: Recipient certificate (bob@corp.local) expires in 21 days
```

## Security Features

### Pre-Flight Validation
- Certificate expiration check (NotBefore/NotAfter)
- KeyUsage flags: `DigitalSignature` for signing, `KeyEncipherment` for encryption
- Key file permission check (warn if > 0600 on Unix)

### Crypto Hygiene Warnings
- 3DES-CBC deprecated warning
- SHA-1 deprecated warning  
- Certificate expiry warning (<30 days)
- Insecure key file permissions warning

### ESMTP SIZE Pre-Check
For S/MIME encrypted payloads larger than 1MB, mailxgo probes the server's ESMTP SIZE extension before sending. If the encrypted message exceeds the server's advertised limit, it fails fast with an error rather than uploading the entire payload only to have it rejected.

### Secure Defaults
- **Default cipher**: AES-256-GCM (not DES-CBC which is pkcs7 library default)
- **Signature digest**: SHA-256 (fixed by go-mail library; `--smime-digest` reserved for future use)

## Multi-Recipient Encryption

PKCS#7 `EnvelopedData` natively supports multiple recipients:
1. A random symmetric key encrypts the message payload
2. That symmetric key is encrypted once for each recipient's public key
3. All encrypted key copies are stored in the `RecipientInfos` structure

All recipients can decrypt with their own private keys from a single encrypted message.

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
# Certificates auto-matched to recipient email addresses
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
  --smtp-server smtp.corp.local \
  --smime-sign \
  --smime-cert /path/to/sender.pem \
  --smime-key /path/to/sender.key \
  --smime-recipient-cert /path/to/recipient.pem \
  --from-email sender@corp.local
```

## Test Coverage

### Unit Tests (`smime_test.go`)
- Certificate/key loading (PEM and PKCS#12)
- Auto-resolve certs by email (SAN/EmailAddresses)
- Encryption roundtrip with decryption verification
- Multi-recipient encryption/decryption
- Pre-flight validation (expired certs, missing key usage)
- Base64 MIME formatting (76-char line wrapping)
- Encrypted private key loading with password
- ECDSA key validation
- Crypto hygiene warnings

### Live E2E Tests (`integration_test.go`)
- `TestLive_SMIMESign`: Digital signing with Mailpit verification
- `TestLive_SMIMEEncrypt`: Encryption with decryption roundtrip
- `TestLive_SMIMESignAndEncrypt`: Combined sign + encrypt
- `TestLive_SMIMERecipientCertDir`: Directory auto-resolution
- `TestLive_SMIMEDiagnostics`: Diagnostic probe validation

## Implementation Notes

### PKCS#12 Double-Decode
The `golang.org/x/crypto/pkcs12` package (frozen) lacks `DecodeChain()`, so `LoadPKCS12` calls both `Decode()` and `ToPEM()` to extract intermediate CA certs. This is acceptable for one-time credential loading (not a hot path).

### Legacy PEM Encryption Support
`LoadPrivateKey` supports legacy RFC 1423 encrypted PEM keys via `x509.IsEncryptedPEMBlock`/`DecryptPEMBlock` (deprecated but required for enterprise PKCS#1 key compatibility).

### Content-Disposition Header
Encrypted messages include `Content-Disposition: attachment; filename="smime.p7m"` per RFC 5751 recommendations.

---

## Appendix: Future Enhancements

### Configurable Signature Digest Algorithm

**Status**: Reserved (flag exists, not yet functional)

The `--smime-digest` flag accepts `sha256`, `sha384`, `sha512` but the underlying `go-mail` library's `SignWithKeypair()` uses SHA-256 internally and does not expose digest algorithm selection. The flag is currently used for:
- Crypto hygiene warnings (detects deprecated SHA-1 in config)
- Forward compatibility when go-mail adds digest selection

**Workaround**: SHA-256 is the current industry standard and provides adequate security for S/MIME signatures.

---

*Version: 1.4.0*
*Status: Implemented*
