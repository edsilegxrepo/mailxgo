# Changelog

All notable changes to the **mailxgo** project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v1.3.1] - 2026-08-10

### Added
- **Single-Recipient Batch Mode**: Added `--single-recipient` flag to send individual emails per recipient with rate limiting support for high-volume distribution lists.
- **Single-Attachment Batch Mode**: Added `--single-attachment` flag to send separate emails per attachment with `[N/Total]` subject prefix for large file transfers.
- **Max Recipients Guard**: Added `--max-recipients` flag (default 1000) to prevent memory exhaustion from oversized recipient lists.
- **TLS Trust Options**:
  - Added `--tls-ca-cert` flag to load custom CA certificate from PEM file.
  - Added `--tls-ca-dir` flag to load CA certificates from directory (`.pem`, `.crt`, `.cer` files).
  - Added `--tls-fingerprint` flag for SHA256 certificate fingerprint pinning.
  - Added `ignore-trust` TLS mode for self-signed certificates on internal relays.
  - Added `tls-direct` TLS mode for implicit TLS (SMTPS-style) on any port, bypassing STARTTLS negotiation.
- **Secretprotector Integration**: Added AES-256-GCM encrypted credential support via `v1:gcm:` prefix with `SECRETPROTECTOR_MASTER_KEY` environment variable.
- **Live Diagnostics Tests**: Added `TestLive_RunDiagnostics` and `TestLive_OutputDiagReport` E2E tests against Mailpit SMTP server.
- **STARTTLS Live Tests**: Added `TestLive_DiagnosticsSTARTTLS` E2E tests verifying TLS version, cipher suite, certificate info, and handshake latency.
- **Implicit TLS Live Tests**: Added `TestLive_ImplicitTLS_Port465` E2E tests with SSL-only Mailpit container for SMTPS/port 465 behavior.
- **Comprehensive Unit Tests**: Added tests for `BuildTLSConfig`, `noAuthSASL`, `ClassifyError`, and authentication modes (`noauth`, `xoauth2`, `cram-md5`).
- **JSON List Format**: Added `--list-format` flag supporting `text` (default) and `json` formats for `--recipient-list` and `--attachments-list` files.
- **Renamed Flag**: Renamed `--list` to `--recipient-list` for clarity and consistency with `--attachments-list`.
  - Simple JSON array: `["alice@example.com", "bob@example.com"]`
  - Object array with per-recipient vars: `[{"email": "alice@example.com", "vars": {"name": "Alice"}}]`

### Changed
- **Test Coverage**: Increased unit test coverage from 76.6% to 82.5%, integration test coverage to 88.7%.

### Security
- **TLS Session Resumption Security**: Added `VerifyConnection` callback to fingerprint pinning to ensure certificate verification runs on resumed TLS sessions, to avoid a potential TLS session resumption bypass.
- **Directory Permissions**: Changed default directory creation permissions from `0755` to `0750` for improved security on log and EML archive directories.
- Added path validation and sanitization to pre-validate file operations.

---

## [v1.3.0] - 2026-08-08

### Added
- **SASL Authentication Suite**: Added `--auth-type` flag supporting `plain`, `login`, `cram-md5`, `xoauth2`, and `auto` negotiation mechanisms.
- **XOAUTH2 Access Token Support**: Added `--oauth2` mode and `--token` flag with `MAILXGO_OAUTH_TOKEN` environment variable fallback.
- **Corporate & Consumer Mail Provider Presets**: Added `--use` flag with pre-configured settings for `office365`, `googleworkspace`, `aws-ses` (regions: `us-east-1`, `us-west-2`, `eu-west-1`), `sendgrid`, `mailgun`, `postmark`, `fastmail`, `protonmail`, `gmail`, `outlook`, `yahoo`, `gmx`, `zoho`, and `aol`.
- **Advanced Attachment Engine**:
  - Added Attachment List Files (`--attachments-list` / `-lst-af`).
  - Added Directory Attachments (`--attachments-dir` / `-dir-af`).
  - Added Max Attachment Total Size Guard (`--max-attachment-size` / `-max-af`) to calculate and enforce payload limits prior to dialing.
  - Added Inline Image Attachments (`--inline-attachments` / `-ia`).
- **Pre-Flight SMTP Gateway Diagnostics**: Added `--info` / `--diag`, `--print-certs`, `--debug`, latency metrics (TCP Connect RTT, TLS Handshake RTT, EHLO RTT), ESMTP extension probing (`CHUNKING`, `MAXSIZE`, `STARTTLS`, `DSN`), DNS MX preference lookup, domain SPF (`v=spf1`) & DMARC (`v=DMARC1`) checks, and X.509 30-day certificate expiration warnings.
- **Enterprise MFT Features**:
  - Added Carbon Copy (`--cc`) and Blind Carbon Copy (`--bcc`) recipient flags and JSON config fields.
  - Added Friendly Sender Display Name formatting (`--from-name` / `-fn`).
  - Added Custom MIME Headers (`-H` / `--header`) with CRLF injection validation.
  - Added Recipient List File loading (`--recipient-list`).
  - Added Dual ISO-8601 Timestamped Execution Audit Logging (`-log` / `--log-file`).
  - Added Automatic Retries & Timeout Control (`--retries`, `--retry-delay`, `--timeout`).
  - Added Delivery Status Notification requests (`--dsn-notify`, `--dsn-return`).
  - Added Message Priority / Importance (`--importance high|normal|low`).
  - Added Machine-Readable JSON Output (`--json-output` / `-j`).
  - Added Single-Line NDJSON Output (`--ndjson` / `--ndjson-output`) for log aggregators (Splunk, Fluentd, Vector, CloudWatch).
  - Added Environment Variable secret support for passwords (`MAILXGO_SMTP_PASSWORD`) and usernames (`MAILXGO_SMTP_USERNAME`).

### Changed
- **Modern Go Module Architecture**: Refactored core codebase to expose SMTP transmission (`SendEmail`), pre-flight gateway diagnostics (`RunDiagnostics`), configuration decoder (`LoadConfig`), provider presets (`ResolveProviderPreset`), and file utilities directly via root `package mailxgo` (`github.com/edsilegxrepo/mailxgo`) for programmatic consumption in external Go applications.
- **Decoupled CLI Entrypoint**: Isolated CLI flag parsing and execution logic into `cmd/mail2go/main.go` and `cli.go` (`go build ./cmd/mail2go`).

---

## [v1.2.0] - 2026-08-07

### Added
- Added implicit TLS (SMTPS via `mail.WithSSL()`) support for SMTP on port 465.

---

## [v1.1.9] - 2026-06-18

### Fixed
- Fixed `priorityInt` function logic to check for zero values and ensure command line arguments override configuration files.
- Refactored configuration parsing and usage documentation.

---

## [v1.1.8] - 2025-02-14

### Added
- Added Reply-To header support (`--reply-to` / `-r`).
- Added version display flag (`-v` / `--version`).

---

## [v1.1.7] - 2025-02-10

### Added
- Added `--no-auth` / `-na` option for unauthenticated local SMTP relay hosts.

---

## [v1.1.6] - 2024-08-18

### Fixed
- Fixed configuration file search path order and priority resolution.

---

## [v1.1.5] - 2024-05-16

### Changed
- Updated `.gitignore` rules for local build targets.

---

## [v1.1.4] - 2024-05-14

### Added
- Added enhanced TLS modes (`none`, `tls-skip`, `tls`) to support self-signed certificates and unencrypted internal relays.

---

## [v1.1.3] - 2023-12-28

### Changed
- Updated README.md documentation and usage examples.

---

## [v1.1.2] - 2023-12-25

### Changed
- Upgraded SMTP backend library from `gopkg.in/mail.v2` to `wneessen/go-mail` for modern RFC compliance and performance.

---

## [v1.1.0] - 2023-12-23

### Added
- Added JSON configuration file support (`--config` / `-c` and `~/.config/mail2go/config.json`).

---

## [v1.0.0] - 2023-12-21

### Added
- Initial public release of `Mail2Go` lightweight command-line SMTP client.
