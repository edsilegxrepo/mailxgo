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
* **TLS Policy Modes (`--tls-mode` / `-l`):**
  * `tls` (Default): Enforces TLS encryption. Automatically uses implicit SMTPS TLS on port 465 (`mail.WithSSL()`) or explicit STARTTLS on ports 587/25 (`mail.TLSMandatory`).
  * `tls-skip`: Enforces TLS encryption while setting `InsecureSkipVerify: true` for internal test environments utilizing self-signed certificates.
  * `none`: Disables TLS encryption (`mail.NoTLS`) for unencrypted internal SMTP relays.

### 2.2 Secret Management
* **Environment Variable Ingestion:** Prevents cleartext credentials from appearing in process listing tables (`ps aux` or Task Manager):
  * Passwords: Reads `MAILXGO_SMTP_PASSWORD` $\rightarrow$ `MAIL2GO_SMTP_PASSWORD` $\rightarrow$ `SMTP_USER_PASS`.
  * Usernames: Reads `MAILXGO_SMTP_USERNAME` $\rightarrow$ `MAIL2GO_SMTP_USERNAME` $\rightarrow$ `SMTP_USER`.
  * OAuth Tokens: Reads `MAILXGO_OAUTH_TOKEN` $\rightarrow$ `MAIL2GO_OAUTH_TOKEN` $\rightarrow$ `SMTP_OAUTH_TOKEN`.

### 2.3 Authentication Configuration
* **Supported SASL Mechanisms (`--auth-type`):**
  * `AUTO`: Automatically negotiates supported mechanisms based on remote ESMTP capability advertisement (`EHLO`).
  * `PLAIN`: Implements SASL PLAIN (RFC 4616).
  * `LOGIN`: Implements SASL LOGIN challenge-response format.
  * `CRAM-MD5`: Implements challenge-response authentication (RFC 2195).
  * `XOAUTH2`: Implements OAuth 2.0 access token authentication (RFC 6749) for Microsoft 365 and Google Workspace.
  * `--no-auth` (`-na`): Bypasses SASL authentication for unauthenticated internal relays.

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

| Argument (Long) | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--smtp-server` | `-s` | String | `""` | Target SMTP server hostname or IP address |
| `--smtp-port` | `-p` | Integer | `587` | Target SMTP server port |
| `--smtp-username` | `-u` | String | `""` | Username for SMTP authentication |
| `--smtp-password` | `-w` | String | `""` | Password for SMTP authentication |
| `--no-auth` | `-na` | Boolean | `false` | Disable SMTP authentication |
| `--use` | `-use-short` | String | `""` | Mail provider preset (office365, googleworkspace, aws-ses, sendgrid, etc.) |
| `--auth-type` | - | String | `"auto"` | SASL authentication mechanism (auto, login, plain, cram-md5, xoauth2) |
| `--oauth2` | - | Boolean | `false` | Enable XOAUTH2 authentication mode |
| `--token` | - | String | `""` | OAuth2 access token for XOAUTH2 authentication |
| `--charset` | `-cs` | String | `"UTF-8"` | Custom body character set encoding |
| `--tls-mode` | `-l` | String | `"tls"` | TLS transport policy (tls, tls-skip, none) |
| `--config` | `-c` | String | `""` | Path to JSON configuration file |
| `--from-email` | `-f` | String | `""` | Sender email address |
| `--from-name` | `-fn` | String | `""` | Friendly display name of sender |
| `--to-email` | `-t` | String | `""` | Recipient email addresses (comma-separated) |
| `--cc` | `-cc-short` | String | `""` | Carbon Copy (CC) email addresses (comma-separated) |
| `--bcc` | `-bcc-short` | String | `""` | Blind Carbon Copy (BCC) email addresses (comma-separated) |
| `--list` | `-lst` | String | `""` | Path to file containing recipient email addresses (one per line) |
| `--reply-to` | `-r` | String | `""` | Reply-To email address |
| `--subject` | `-h` | String | `""` | Email subject line |
| `--body` | `-b` | String | `""` | Plaintext email body content |
| `--body-file` | `-bf` | String | `""` | Path to file containing HTML email body content |
| `--attachments` | `-af` | String | `""` | Attachment file paths (comma-separated) |
| `--attachments-list` | `-lst-af` | String | `""` | Path to file containing attachment file paths (one per line) |
| `--attachments-dir` | `-dir-af` | String | `""` | Path to directory whose regular file contents will be attached |
| `--max-attachment-size` | `-max-af` | Integer | `0` | Maximum combined attachment size limit in MB (0 = disabled) |
| `--inline-attachments` | `-ia` | String | `""` | File paths for inline embedded images (comma-separated) |
| `--header` | `-H` | String | `""` | Custom MIME header in `Header-Name: Value` format (repeatable) |
| `--log-file` | `-log` | String | `""` | File path to append execution audit logs |
| `--retries` | `-retry` | Integer | `0` | Retries on network socket dial failure |
| `--retry-delay` | - | Integer | `5` | Delay in seconds between dial retries |
| `--timeout` | - | Integer | `30` | Socket connection timeout in seconds |
| `--dsn-notify` | - | String | `""` | DSN notification options (SUCCESS, FAILURE, DELAY, NEVER) |
| `--dsn-return` | - | String | `""` | DSN return option (FULL, HDRS) |
| `--importance` | `-imp` | String | `""` | Priority level (high, normal, low) |
| `--json-output` | `-j` | Boolean | `false` | Output results in formatted JSON |
| `--ndjson-output`, `--ndjson` | `-ndjson-short` | Boolean | `false` | Output results in single-line NDJSON format |
| `--info`, `--diag` | `-info-short` | Boolean | `false` | Execute pre-flight gateway diagnostics probe and exit |
| `--print-certs` | - | Boolean | `false` | Display full TLS certificate chain during diagnostics |
| `--debug` | - | Boolean | `false` | Enable protocol wire debug logging |
| `--version` | `-v` | Boolean | `false` | Display application version |

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
| `protonmail` | `127.0.0.1` | `1025` | `tls-skip` |
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
SAN Names            : smtp.gmail.com

Gateway Probe Complete: SUCCESS
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
