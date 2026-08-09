# mailxgo - Enterprise CLI SMTP Client & Gateway Diagnostic Suite

[![License](./LICENSE)](./LICENSE)
[![Go Version](./go.mod)](./go.mod)

`mailxgo` is a command-line Simple Mail Transfer Protocol (SMTP) client and gateway diagnostic utility written in Go. It is designed for enterprise job schedulers, Managed File Transfer (MFT) automation pipelines, system administration workflows, and containerized microservices.

---

## Technical Documentation Links

- [System Architecture Specification (ARCHITECTURE.md)](./ARCHITECTURE.md)
- [Software Design Patterns & Technical Specification (DESIGN.md)](./DESIGN.md)
- [Testing Strategy & Quality Assurance Specification (TESTING.md)](./TESTING.md)

---

## 1. Application Overview & Objectives

### 1.1 Core Objectives
* **Managed File Transfer (MFT) Automation:** Provide a reliable command-line utility for job schedulers (Control-M, Tivoli, ActiveBatch, Cron) to send automated email alerts, reports, and attached data files.
* **Pre-Flight Gateway Diagnostics:** Enable system administrators to probe remote SMTP gateways, evaluate network phase latency (`tcp_connect_ms`, `tls_handshake_ms`, `ehlo_rtt_ms`), inspect ESMTP extension advertisements (`STARTTLS`, `SIZE`, `CHUNKING`, `PIPELINING`, `DSN`), verify DNS records (`MX`, `SPF`, `DMARC`), and audit X.509 TLS certificate expiration status without delivering emails.
* **Structured Observability:** Provide machine-readable single-line NDJSON and indented JSON output formats for integration with log collection infrastructure (Splunk, Fluentd, Logstash, AWS CloudWatch Logs).
* **Programmatic Go Module:** Expose direct programmatic Go APIs via root package `github.com/edsilegxrepo/mailxgo` for integration into custom applications.

### 1.2 Acknowledgements & Inspiration
`mailxgo` builds upon concepts from:
- [mail2go](https://github.com/KeepSec-Technologies/Mail2Go)
- [mailsend-go](https://github.com/muquit/mailsend-go)

---

## 2. Security Assessment

### 2.1 Encryption in Transit
* **TLS Policy Modes (`--tls-mode`):**
  * `tls` (Default): Enforces TLS encryption with full certificate chain verification. Automatically uses implicit SMTPS TLS on port 465 (`mail.WithSSL()`) or explicit STARTTLS on ports 587/25 (`mail.TLSMandatory`).
  * `ignore-trust`: Enforces TLS encryption while ignoring certificate chain of trust validation. Use for internal relays with self-signed or private CA certificates.
  * `none`: Disables TLS encryption (`mail.NoTLS`) for unencrypted internal SMTP relays.

* **Custom Trust Store Options:**
  * `--tls-ca-cert <path>`: Trust a specific CA certificate file (PEM format) for servers using private/internal CAs.
  * `--tls-ca-dir <path>`: Trust all `.pem`, `.crt`, `.cer` files in a directory.
  * `--tls-fingerprint <sha256>`: Pin to a specific certificate SHA256 fingerprint (hex, with or without colons). Use `--diag --print-certs` to retrieve the fingerprint.

### 2.2 Secret Management
* **Environment Variable Ingestion:** Prevents cleartext credentials from appearing in process listing tables (`ps aux` or Task Manager):
  * Passwords: Reads `MAILXGO_SMTP_PASSWORD` $\rightarrow$ `MAIL2GO_SMTP_PASSWORD` $\rightarrow$ `SMTP_USER_PASS`.
  * Usernames: Reads `MAILXGO_SMTP_USERNAME` $\rightarrow$ `MAIL2GO_SMTP_USERNAME` $\rightarrow$ `SMTP_USER`.
  * OAuth Tokens: Reads `MAILXGO_OAUTH_TOKEN` $\rightarrow$ `MAIL2GO_OAUTH_TOKEN` $\rightarrow$ `SMTP_OAUTH_TOKEN`.

* **Encrypted Credential Support (secretprotector):** Passwords and OAuth tokens with `v1:gcm:` prefix are automatically decrypted using AES-256-GCM via the secretprotector library:
  * Set the master key via `SECRETPROTECTOR_MASTER_KEY` environment variable.
  * Encrypted secrets can be used in `--smtp-password`, `--token`, config files, and environment variables.
  * Plain (unencrypted) credentials continue to work without any master key configuration.

### 2.3 Authentication Configuration
* **Supported SASL Mechanisms (`--auth-type`):**
  * `AUTO`: Automatically negotiates supported mechanisms based on remote ESMTP capability advertisement (`EHLO`).
  * `PLAIN`: Implements SASL PLAIN (RFC 4616).
  * `LOGIN`: Implements SASL LOGIN challenge-response format.
  * `CRAM-MD5`: Implements challenge-response authentication (RFC 2195).
  * `XOAUTH2`: Implements OAuth 2.0 access token authentication (RFC 6749) for Microsoft 365 and Google Workspace.
  * `--no-auth`: Bypasses SASL authentication for unauthenticated internal relays.

### 2.4 Unprivileged Execution Context & Library Audit
* **Execution Context:** `mailxgo` operates strictly in user-space (`uid/gid`) and requires no root or elevated system privileges.
* **Dependency Inventory:** Built using native Go Standard Library modules (`net`, `crypto/tls`, `encoding/json`) and `github.com/wneessen/go-mail v0.4.0`. All dependencies are maintained, contain zero indirect third-party modules, and have no known security vulnerabilities.

---

## 3. Code Quality & Architecture Best Practices

* **Granular Exit Codes:** Replaces generic exit codes with granular status codes (`ExitSuccess = 0`, `ExitErrUsage = 2`, `ExitErrConfig = 3`, `ExitErrFileIO = 4`, `ExitErrDNS = 5`, `ExitErrTLS = 6`, `ExitErrAuth = 7`, `ExitErrSend = 8`).
* **Cross-Platform CRLF Compatibility:** Employs `bufio.Scanner` with line trimming across all list file parsers in `util.go`, preventing trailing carriage return (`\r`) file path or email address corruption on Windows environments.
* **MIME Header Injection Mitigation:** Custom MIME header keys and values are sanitized to reject control characters (`\r`, `\n`) in accordance with RFC 5322.
* **Pre-Dial Payload Bounds Protection:** Evaluates total attachment sizes prior to opening network sockets, preventing resource consumption if payloads exceed maximum size thresholds (`--max-attachment-size`).

---

## 4. Command Line Arguments Reference

| Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--smtp-server` | String | `""` | Target SMTP server hostname or IP address |
| `--smtp-port` | Integer | `587` | Target SMTP server port |
| `--smtp-username` | String | `""` | Username for SMTP authentication |
| `--smtp-password` | String | `""` | Password for SMTP authentication (supports v1:gcm: encrypted secrets) |
| `--no-auth` | Boolean | `false` | Disable SMTP authentication |
| `--use` | String | `""` | Mail provider preset (office365, googleworkspace, aws-ses, sendgrid, etc.) |
| `--auth-type` | String | `"auto"` | SASL authentication mechanism (auto, login, plain, cram-md5, xoauth2) |
| `--oauth2` | Boolean | `false` | Enable XOAUTH2 authentication mode |
| `--token` | String | `""` | OAuth2 access token for XOAUTH2 authentication (supports v1:gcm: encrypted secrets) |
| `--charset` | String | `"UTF-8"` | Custom body character set encoding |
| `--tls-mode` | String | `"tls"` | TLS transport policy (tls, ignore-trust, none) |
| `--tls-ca-cert` | String | `""` | Path to CA certificate file (PEM) for custom trust |
| `--tls-ca-dir` | String | `""` | Path to directory containing CA certificates (PEM) |
| `--tls-fingerprint` | String | `""` | SHA256 fingerprint for certificate pinning (hex) |
| `--config` | String | `""` | Path to JSON configuration file |
| `--from-email` | String | `""` | Sender email address |
| `--from-name` | String | `""` | Friendly display name of sender |
| `--to-email` | String | `""` | Recipient email addresses (comma-separated) |
| `--cc` | String | `""` | Carbon Copy (CC) email addresses (comma-separated) |
| `--bcc` | String | `""` | Blind Carbon Copy (BCC) email addresses (comma-separated) |
| `--list` | String | `""` | Path to file containing recipient email addresses (one per line) |
| `--reply-to` | String | `""` | Reply-To email address |
| `--subject` | String | `""` | Email subject line |
| `--body` | String | `""` | Plaintext email body content |
| `--body-file` | String | `""` | Path to file containing HTML email body content |
| `--attachments` | String | `""` | Attachment file paths (comma-separated) |
| `--attachments-list` | String | `""` | Path to file containing attachment file paths (one per line) |
| `--attachments-dir` | String | `""` | Path to directory whose regular file contents will be attached |
| `--max-attachment-size` | Integer | `0` | Maximum combined attachment size limit in MB (0 = disabled) |
| `--inline-attachments` | String | `""` | File paths for inline embedded images (comma-separated) |
| `--header` | String | `""` | Custom MIME header in `Header-Name: Value` format (repeatable) |
| `--log-file` | String | `""` | File path to append execution audit logs |
| `--no-log-recipients` | Boolean | `false` | Redact recipient addresses in log files (GDPR/privacy) |
| `--retries` | Integer | `0` | Retries on network socket dial failure |
| `--retry-delay` | Integer | `5` | Delay in seconds between dial retries |
| `--timeout` | Integer | `30` | Socket connection timeout in seconds |
| `--dsn-notify` | String | `""` | DSN notification options (SUCCESS, FAILURE, DELAY, NEVER) |
| `--dsn-return` | String | `""` | DSN return option (FULL, HDRS) |
| `--importance` | String | `""` | Priority level (high, normal, low) |
| `--json-output` | Boolean | `false` | Output results in formatted JSON |
| `--ndjson-output`, `--ndjson` | Boolean | `false` | Output results in single-line NDJSON format |
| `--diag`, `--info` | Boolean | `false` | Execute pre-flight gateway diagnostics probe and exit |
| `--print-certs` | Boolean | `false` | Display full TLS certificate chain during diagnostics |
| `--debug` | Boolean | `false` | Enable protocol wire debug logging |
| `--version` | Boolean | `false` | Display application version |

### 4.1 Built-in Provider Presets Reference (`--use <preset>`)

| Preset Name | Hostname | Port | TLS Mode |
| :--- | :--- | :--- | :--- |
| `office365`, `m365`, `o365` | `smtp.office365.com` | `587` | `tls` |
| `googleworkspace`, `gsuite` | `smtp.gmail.com` | `587` | `tls` |
| `aws-ses`, `aws-ses-us-east-1` | `email-smtp.us-east-1.amazonaws.com` | `587` | `tls` |
| `aws-ses-us-west-2` | `email-smtp.us-west-2.amazonaws.com` | `587` | `tls` |
| `aws-ses-eu-west-1` | `email-smtp.eu-west-1.amazonaws.com` | `587` | `tls` |
| `sendgrid` | `smtp.sendgrid.net` | `587` | `tls` |
| `mailgun` | `smtp.mailgun.org` | `587` | `tls` |
| `postmark` | `smtp.postmarkapp.com` | `587` | `tls` |
| `fastmail` | `smtp.fastmail.com` | `587` | `tls` |
| `protonmail` | `127.0.0.1` | `1025` | `ignore-trust` |
| `gmail` | `smtp.gmail.com` | `587` | `tls` |
| `outlook` | `smtp.office365.com` | `587` | `tls` |
| `yahoo` | `smtp.mail.yahoo.com` | `587` | `tls` |
| `gmx` | `mail.gmx.com` | `587` | `tls` |
| `zoho` | `smtp.zoho.com` | `587` | `tls` |
| `aol` | `smtp.aol.com` | `587` | `tls` |

---

## 5. Deployment and Operational Usage Examples

### 5.1 Basic Email Dispatch
```shell
mailxgo \
  --smtp-server smtp.office365.com \
  --smtp-port 587 \
  --smtp-username mft-service@company.com \
  --smtp-password "SecretPass123" \
  --from-email mft-service@company.com \
  --to-email administrator@company.com \
  --subject "Batch Processing Completed" \
  --body "Job 84920 completed successfully."
```

#### Output Sample (Human Text):
```text
Email sent successfully to administrator@company.com from mft-service@company.com (attempts: 1)
```

### 5.2 Enterprise Dispatch with Environment Secrets & NDJSON Logging
```shell
export MAILXGO_SMTP_USERNAME="mft-service@company.com"
export MAILXGO_SMTP_PASSWORD="SecretPass123"

mailxgo \
  --use office365 \
  --from-email mft-service@company.com \
  --from-name "MFT System Scheduler" \
  --to-email operator@company.com \
  --list /etc/mailxgo/recipients.txt \
  --subject "Daily Audit Report" \
  --body-file /var/reports/daily_audit.html \
  --attachments /var/reports/summary.pdf \
  --max-attachment-size 25 \
  --ndjson \
  --log-file /var/log/mailxgo/audit.log
```

#### Output Sample (NDJSON to stdout):
```json
{"status":"success","timestamp":"2026-08-08T20:30:00-05:00","smtp_server":"smtp.office365.com","smtp_port":587,"from":"mft-service@company.com","to":["operator@company.com","audit-group@company.com"],"subject":"Daily Audit Report","attempts":1}
```

### 5.3 Pre-Flight Gateway Diagnostic Probe
```shell
mailxgo \
  --smtp-server smtp.gmail.com \
  --smtp-port 587 \
  --info \
  --print-certs \
  --from-email test@company.com
```

#### Output Sample (Diagnostics):
```text
=== mailxgo SMTP Gateway Diagnostics ===
Target Server : smtp.gmail.com:587
Resolved IPs  : 142.250.101.108, 142.250.101.109
MX Records    : gmail-smtp-in.l.google.com (pref 5)
SPF Record    : v=spf1 redirect=_spf.google.com
DMARC Record  : v=DMARC1; p=reject;
TLS Mode      : tls

--- Network & Latency Metrics ---
TCP Connection RTT   : 14.20 ms
TLS Handshake RTT    : 28.50 ms
EHLO Round-Trip RTT  : 11.10 ms
Total Probe Latency  : 53.80 ms

--- ESMTP Gateway Capabilities ---
STARTTLS Extension   : true
CHUNKING (BDAT)      : true (RFC 3030)
MAX MESSAGE SIZE     : 35 MB (36700160 bytes)
AUTH Mechanisms      : PLAIN, LOGIN, XOAUTH2
PIPELINING           : true
8BITMIME             : true
DSN Notifications    : true

--- TLS Certificate & Security Info ---
Subject              : CN=smtp.gmail.com
Issuer               : CN=GTS CA 1C3, O=Google Trust Services LLC, C=US
Validity Period      : 2026-07-01 to 2026-09-23 (46 days remaining)
TLS Protocol         : TLS 1.3
Cipher Suite         : TLS_AES_256_GCM_SHA384
SHA256 Fingerprint   : A1:B2:C3:D4:E5:F6:...:12:34
SAN Names            : smtp.gmail.com

--- Certificate Chain of Trust ---
[0] End-Entity
    Subject     : CN=smtp.gmail.com
    Issuer      : CN=GTS CA 1C3, O=Google Trust Services LLC, C=US
    Expires     : 2026-09-23
    Fingerprint : A1:B2:C3:D4:E5:F6:...:12:34
[1] Intermediate CA
    Subject     : CN=GTS CA 1C3, O=Google Trust Services LLC, C=US
    Issuer      : CN=GTS Root R1, O=Google Trust Services LLC, C=US
    Expires     : 2027-12-15
    Fingerprint : B2:C3:D4:E5:F6:...:23:45

Gateway Probe Complete: SUCCESS
```

### 5.4 Connecting to Internal Relay with Self-Signed Certificate
```shell
# First, get the certificate fingerprint
mailxgo --smtp-server internal-relay.corp.local --diag --tls-mode ignore-trust --print-certs

# Then use fingerprint pinning for secure connection
mailxgo \
  --smtp-server internal-relay.corp.local \
  --smtp-port 587 \
  --tls-fingerprint "C9:AB:9D:79:81:15:99:96:1B:92:55:4B:B8:98:59:3D:8A:05:33:1C:52:45:97:65:04:DB:59:31:5A:1A:DF:CB" \
  --no-auth \
  --from-email alerts@corp.local \
  --to-email admin@corp.local \
  --subject "System Alert" \
  --body "Internal relay test with fingerprint pinning"
```

---

## 6. Programmatic Integration Example

```go
package main

import (
	"fmt"
	"log"

	mailxgo "github.com/edsilegxrepo/mailxgo"
)

func main() {
	params := mailxgo.EmailParams{
		SMTPServer: "smtp.office365.com",
		SMTPPort:   587,
		Username:   "mft@company.com",
		Password:   "Secret123",
		From:       "mft@company.com",
		To:         []string{"admin@company.com"},
		Subject:    "Automated System Notification",
		Body:       "System processing complete.",
		TLSMode:    "tls",
	}

	result, err := mailxgo.SendEmail(params)
	if err != nil {
		log.Fatalf("Email dispatch failed: %v", err)
	}

	fmt.Printf("Status: %s (Attempts: %d)\n", result.Status, result.Attempts)
}
```

---

## 7. License

Distributed under the MIT License. See [LICENSE](./LICENSE) for details.
