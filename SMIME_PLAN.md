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
  "smime_recipient_certs": [
    "/etc/mailxgo/certs/recipient1.pem",
    "/etc/mailxgo/certs/recipient2.pem"
  ],
  "smime_algorithm": "aes-256-cbc",
  "smime_digest": "sha256"
}
```

## Implementation Approach

### Option A: Pure Go (pkcs7 package)
- Use `go.mozilla.org/pkcs7` for PKCS#7 signing/encryption
- Pros: No external dependencies, cross-platform
- Cons: Less mature, may need patches for edge cases

### Option B: OpenSSL via exec
- Shell out to `openssl smime` command
- Pros: Battle-tested, full RFC compliance
- Cons: Requires OpenSSL installed, slower, platform-dependent paths

### Recommended: Option A with OpenSSL fallback
1. Primary: Use pure Go `mozilla/pkcs7` for signing/encryption
2. Fallback: If Go implementation fails, offer `--smime-openssl` flag to use OpenSSL

## Architecture Changes

### New File: `smime.go`

```go
package mailxgo

type SMIMEConfig struct {
    Sign             bool
    Encrypt          bool
    SignerCert       *x509.Certificate
    SignerKey        *rsa.PrivateKey
    RecipientCerts   []*x509.Certificate
    Algorithm        string // aes-256-cbc, aes-128-cbc, 3des-cbc
    DigestAlgorithm  string // sha256, sha384, sha512
}

func (s *SMIMEConfig) SignMessage(data []byte) ([]byte, error)
func (s *SMIMEConfig) EncryptMessage(data []byte) ([]byte, error)
func (s *SMIMEConfig) SignAndEncrypt(data []byte) ([]byte, error)
func LoadCertificate(path string) (*x509.Certificate, error)
func LoadPrivateKey(path, password string) (*rsa.PrivateKey, error)
```

### Changes to Existing Files

1. **cli.go**: Add S/MIME flag parsing
2. **config.go**: Add S/MIME config fields and JSON parsing
3. **types.go**: Add `SMIMEConfig` to `EmailParams`
4. **mailer.go**: Integrate S/MIME into message composition pipeline

### Message Composition Pipeline

```
Original Message
      │
      ▼
┌─────────────────┐
│  Build MIME     │
│  (body, attach) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│  Sign (if       │────▶│  PKCS#7 Signed   │
│  --smime-sign)  │     │  Data            │
└────────┬────────┘     └────────┬─────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌──────────────────┐
│  Encrypt (if    │────▶│  PKCS#7 Envelope │
│  --smime-encrypt│     │  (for recipients)│
└────────┬────────┘     └────────┬─────────┘
         │                       │
         ▼                       ▼
      Final MIME message (application/pkcs7-mime)
```

## Testing Strategy

### Unit Tests (`smime_test.go`)
- Certificate/key loading
- Signing with various digest algorithms
- Encryption with various symmetric algorithms
- Sign + encrypt combined
- Error cases (invalid certs, wrong passwords, expired certs)

### Integration Tests
1. **Self-Test**: Sign, verify signature locally
2. **Roundtrip**: Sign/encrypt, send to Mailpit, retrieve raw EML, verify/decrypt
3. **Interop**: Generate S/MIME message, verify with OpenSSL CLI

### Test Certificates
- Generate test CA + end-entity certs in `testdata/smime/`
- Include RSA 2048/4096 and ECDSA P-256 keys
- Include expired cert for negative testing

## Dependencies

Add to `go.mod`:
```
go.mozilla.org/pkcs7 v0.9.0
```

## Security Considerations

1. **Private Key Protection**: Warn if key file permissions > 0600
2. **Algorithm Deprecation**: Warn if using 3DES (prefer AES-256)
3. **Certificate Validation**: Validate recipient certs before encryption (not expired, valid for email use)
4. **Key Password**: Support secretprotector `v1:gcm:` prefix for encrypted key passwords

## Documentation Updates

1. **README.md**: Add S/MIME section with examples
2. **TESTING.md**: Add S/MIME test cases
3. **ARCHITECTURE.md**: Update message flow diagram

## Estimated Effort

| Component | Hours |
|-----------|-------|
| smime.go core | 8 |
| CLI/config integration | 4 |
| Unit tests | 6 |
| Integration tests | 4 |
| Documentation | 2 |
| **Total** | **24** |

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

## Open Questions

1. **Multiple Recipients with Different Certs**: How to map `--to-email` addresses to specific certificates?
   - Option: Require cert filenames to match email addresses
   - Option: Use `--smime-recipient-cert user@domain.com:/path/to/cert.pem` format

2. **Certificate Discovery**: Should we support LDAP/AD certificate lookup for enterprise environments?

3. **go-mail Integration**: Does `go-mail` have native S/MIME hooks, or do we need to build raw MIME?

---

*Created: 2026-08-10*
*Status: Planning*
