# mailxgo Technical Architecture & Feature Specification

**Document Version:** 1.3.0  
**Release Date:** 2026-08-08  

---

## 1. System Overview & Architectural Purpose

`mailxgo` version 1.3.0 is a high-performance command-line Simple Mail Transfer Protocol (SMTP) client and pre-flight gateway diagnostic engine written in Go. The tool is engineered for Managed File Transfer (MFT) automation pipelines, enterprise job schedulers (Control-M, Tivoli, ActiveBatch), containerized microservices, and system administration.

`mailxgo` combines core email transmission functions with advanced gateway probing, multi-mechanism SASL authentication, structured telemetry output, and payload protection controls.

### 1.1 Programmatic Go Library Architecture
`mailxgo` conforms to modern Go module conventions. The core SMTP transmission, diagnostic probing, configuration decoding, and file utilities are exposed directly via root `package mailxgo` (`github.com/edsilegxrepo/mailxgo`).

External Go applications can import and consume `mailxgo` programmatically:
```go
import mailxgo "github.com/edsilegxrepo/mailxgo"

// Pre-flight probe
report, err := mailxgo.RunDiagnostics(probeParams, printCerts)

// Transmit email
result, err := mailxgo.SendEmail(emailParams)
```

The CLI entry point is isolated in `cmd/mailxgo/main.go`. Compile target: `go build ./cmd/mailxgo`.

### 1.2 Acknowledgements & Heritage
`mailxgo` bridges the heritage of the POSIX standard Unix `mailx` utility with modern Go concurrency and RFC compliance. The project was inspired by and builds upon concepts from:
- [mail2go](https://github.com/KeepSec-Technologies/Mail2Go)
- [mailsend-go](https://github.com/muquit/mailsend-go)

---

## 2. Configuration & Parameter Evaluation Hierarchy

`mailxgo` evaluates runtime parameters through a deterministic six-tier hierarchy. Higher-tier settings override lower-tier settings:

1. **Short Command-Line Flags** (e.g., `-s`, `-p`, `-j`, `-lst-af`)
2. **Long Command-Line Flags** (e.g., `--smtp-server`, `--json-output`, `--attachments-list`)
3. **JSON Configuration File** (specified via `--config` / `-c` or auto-detected at `~/.config/mailxgo/config.json` with `~/.config/mail2go/config.json` fallback)
4. **Environment Variables** (e.g., `MAILXGO_SMTP_PASSWORD`, `MAILXGO_SMTP_USERNAME`, `MAILXGO_OAUTH_TOKEN`)
5. **Provider Presets** (resolved via `--use <preset>`)
6. **Built-in Defaults** (Port `587`, TLS mode `tls`, Timeout `30s`, Charset `UTF-8`, Version `dev`)

---

## 3. Core Email Composition & Transmission Engine

### 3.1 Body Content Rendering
- **Plaintext Body (`-b` / `--body`)**: Inline text body content.
- **HTML Body File (`-bf` / `--body-file`)**: Loads HTML content from a specified file path.
- **Custom Character Set Encoding (`-cs` / `--charset`)**: Sets custom body character sets (e.g., `UTF-8`, `ISO-8859-1`, `Windows-1252`). Default is `UTF-8`.

### 3.2 Recipient Management
- **Primary Recipients (`-t` / `--to-email`)**: Comma-separated list of recipient email addresses.
- **Carbon Copy (`--cc`)**: Comma-separated CC recipient addresses.
- **Blind Carbon Copy (`--bcc`)**: Comma-separated BCC recipient addresses.
- **Recipient List File (`-lst` / `--list`)**: Text file containing email addresses (one per line). Empty lines and comment lines starting with `#` are automatically ignored.

### 3.3 Address & Header Specifications
- **Friendly Sender Name (`-fn` / `--from-name`)**: Formats sender address with display name (`"Name <email@domain.com>"`).
- **Reply-To Address (`-r` / `--reply-to`)**: Sets `Reply-To` header.
- **Custom MIME Headers (`-H` / `--header`)**: Adds arbitrary MIME headers (`"Header-Name: Value"`). Validated to prevent CRLF injection attacks.

### 3.4 TLS Encryption & Transport Security (`-l` / `--tls-mode`)
- **`tls` (Default)**: Enforces TLS encryption. Automatically uses implicit SMTPS TLS (`mail.WithSSL()`) on port 465, or explicit STARTTLS (`mail.TLSMandatory`) on ports 587/25.
- **`tls-skip`**: Enforces TLS encryption while skipping server certificate hostname and chain verification (`InsecureSkipVerify: true`) for internal servers with self-signed certificates.
- **`none`**: Disables TLS encryption entirely (`mail.NoTLS`) for unencrypted internal SMTP relays.

---

## 4. Advanced Attachment Engine

`mailxgo` aggregates email attachments from multiple input vectors:

### 4.1 Input Vectors
1. **Explicit File List (`-af` / `--attachments`)**: Comma-separated file paths.
2. **Attachment List File (`-lst-af` / `--attachments-list`)**: Text file containing file paths, one per line.
3. **Directory Scan (`-dir-af` / `--attachments-dir`)**: Scans specified directory path (`os.ReadDir()`) and attaches all regular non-directory files.
4. **Inline Image Attachments (`-ia` / `--inline-attachments`)**: Embedded MIME parts (`m.EmbedFile()`) for HTML body inline image referencing (`cid:`).

### 4.2 Maximum Total Payload Size Guard (`-max-af` / `--max-attachment-size`)
Before opening an SMTP network socket, `mailxgo` iterates through all resolved attachment files and calculates the cumulative payload byte size (`os.Stat()`).

If total payload size exceeds the configured maximum limit in MB:
$$\sum \text{FileSize}_{bytes} > \text{MaxAttachmentMB} \times 1024 \times 1024$$

`mailxgo` aborts execution prior to network dialing and outputs a descriptive error:
```text
total attachment size (28.50 MB) exceeds configured maximum limit of 25 MB
```

---

## 5. Authentication & Secret Management Engine

### 5.1 SASL Mechanism Support
`mailxgo` supports standard ESMTP authentication mechanisms compliant with RFC 4954 and RFC 4616:

- **`AUTO` (`--auth-type auto`)**: Negotiates authentication mechanism based on server EHLO response. Default fallback is `LOGIN`.
- **`PLAIN` (`--auth-type plain`)**: Implements SASL PLAIN (RFC 4616). Transmits base64-encoded authorization identity, authentication identity, and password over TLS.
- **`LOGIN` (`--auth-type login`)**: Implements SASL LOGIN challenge-response format required by Microsoft Exchange and legacy SMTP relays.
- **`CRAM-MD5` (`--auth-type cram-md5`)**: Implements challenge-response authentication (RFC 2195) preventing cleartext credential transmission.
- **`XOAUTH2` (`--auth-type xoauth2` / `--oauth2`)**: Implements OAuth 2.0 client authentication for cloud providers (Google Workspace, Microsoft 365).

### 5.2 Non-Interactive Secret Ingestion
To eliminate cleartext credentials from process inspection (`ps aux`) and persistent config files, `mailxgo` checks process environment variables:

- Password: `MAILXGO_SMTP_PASSWORD` $\rightarrow$ `MAIL2GO_SMTP_PASSWORD` $\rightarrow$ `SMTP_USER_PASS`
- Username: `MAILXGO_SMTP_USERNAME` $\rightarrow$ `MAIL2GO_SMTP_USERNAME` $\rightarrow$ `SMTP_USER`
- OAuth Token: `MAILXGO_OAUTH_TOKEN` $\rightarrow$ `MAIL2GO_OAUTH_TOKEN` $\rightarrow$ `SMTP_OAUTH_TOKEN`

### 5.3 Unauthenticated SMTP Relays (`-na` / `--no-auth`)
Disables authentication for internal unauthenticated relay servers.

---

## 6. Mail Provider Presets Reference

Specifying `--use <preset>` configures default server hostnames, ports, and TLS modes:

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

## 7. Pre-Flight Gateway Diagnostic & Telemetry Framework

### 7.1 Probe Execution Model (`-info` / `--diag`)
The diagnostic subsystem executes a non-destructive probe against the target SMTP server without issuing `MAIL FROM` or `RCPT TO` commands. The session opens a TCP connection, completes TLS negotiation (if required), issues `EHLO`, records capabilities and latency metrics, and terminates via `QUIT`.

### 7.2 Network Latency Decomposition
Latency is decomposed into discrete phase timings recorded in milliseconds:
- **TCP Connection Latency (`tcp_connect_ms`)**: Duration required to establish TCP socket handshake (`SYN` to `SYN-ACK`).
- **TLS Handshake Latency (`tls_handshake_ms`)**: Duration required to negotiate TLS session, exchange certificates, and establish symmetric cipher keys.
- **EHLO Round-Trip Time (`ehlo_rtt_ms`)**: Round-trip time required to receive the ESMTP capability advertisement.
- **Total Probe RTT (`total_ms`)**: Cumulative duration of connection, handshake, and protocol exchange.

### 7.3 ESMTP Extension Discovery
The probe inspects server capability advertisements:
- **`STARTTLS`**: Explicit TLS upgrade support (RFC 3207).
- **`CHUNKING`**: RFC 3030 `BDAT` chunking support.
- **`SIZE`**: Maximum message payload size advertised by server (`max_size_bytes` and `max_size_mb`).
- **`AUTH`**: Advertised SASL authentication mechanisms.
- **`PIPELINING`**: RFC 2920 command pipelining support.
- **`DSN`**: RFC 3461 Delivery Status Notification support.
- **`8BITMIME` / `BINARYMIME`**: RFC 6152 / RFC 3030 8-bit and binary transport encoding.

### 7.4 DNS Resolution & Security Auditing
- **IP Resolution**: Resolves A/AAAA host records.
- **MX Record Discovery**: Performs DNS MX lookup and orders target hosts by preference priority.
- **SPF Policy Check**: Queries domain TXT records for `v=spf1` validation.
- **DMARC Policy Check**: Queries `_dmarc.<domain>` TXT records for `v=DMARC1` policy enforcement.

### 7.5 X.509 Certificate Chain Inspection (`--print-certs`)
Extracts server TLS connection state:
- Subject and Issuer Distinguished Names (DN).
- Validity start and end timestamps.
- Remaining days until expiration (`days_until_expiration`). Triggers warning if $\le 30$ days.
- TLS Protocol Version (e.g., `TLS 1.3`, `TLS 1.2`).
- Negotiated Cipher Suite (e.g., `TLS_AES_256_GCM_SHA384`).
- Subject Alternative Names (SANs).

---

## 8. MFT Integration & Observability Controls

### 8.1 Indented JSON Output Schema (`--json-output` / `-j`)
Outputs indented JSON to `stdout` for inspection or command-line filtering (`jq`).

### 8.2 Single-Line NDJSON Output Schema (`--ndjson` / `--ndjson-output`)
Outputs un-indented, single-line Newline Delimited JSON (NDJSON) to `stdout` for streaming log aggregators (Splunk, Fluentd, Vector, Logstash, AWS CloudWatch Logs).

#### NDJSON Success Payload Example:
```json
{"status":"success","timestamp":"2026-08-08T18:08:54-05:00","smtp_server":"smtp.office365.com","smtp_port":587,"from":"mft-service@company.com","to":["administrator@company.com"],"subject":"File Transfer Completed","attempts":1}
```

#### NDJSON Error Payload Example:
```json
{"status":"error","timestamp":"2026-08-08T18:08:54-05:00","smtp_server":"127.0.0.1","smtp_port":1025,"from":"mft-service@company.com","to":["administrator@company.com"],"subject":"File Transfer Failed","attempts":4,"error":"error sending email: dial failed: dial tcp 127.0.0.1:1025: connect: connection refused"}
```

### 8.3 Audit File Logging (`-log` / `--log-file`)
Appends ISO-8601 timestamped execution status entries directly to disk:
```text
[2026-08-08T18:08:54-05:00] SUCCESS: Email sent successfully to [administrator@company.com] via smtp.office365.com:587 (attempts: 1)
```

### 8.4 Delivery Resilience & Control Flags
- **Dial Retries (`-retry` / `--retries`)**: Configures retry attempts on dial failure.
- **Retry Delay (`--retry-delay`)**: Configures delay in seconds between retries (default `5s`).
- **Connection Timeout (`--timeout`)**: Configures socket connection timeout in seconds (default `30s`).
- **Delivery Status Notifications (`--dsn-notify`, `--dsn-return`)**: Requests DSN conditions (`SUCCESS`, `FAILURE`, `DELAY`, `NEVER`) and return payload (`FULL`, `HDRS`).
- **Message Priority (`-imp` / `--importance`)**: Sets `Importance` header (`high`, `normal`, `low`).

---

## 9. Complete CLI Command Reference

```text
Usage: mailxgo [options]

  -s, --smtp-server         SMTP server for sending emails
  -p, --smtp-port           SMTP server port (Default: 587)
  -u, --smtp-username       Username for SMTP authentication
  -w, --smtp-password       Password for SMTP authentication
  --use                     Mail provider preset (office365, googleworkspace, aws-ses, sendgrid, mailgun, gmail, etc.)
  --auth-type               SASL Auth mechanism (auto, login, plain, cram-md5, xoauth2)
  --oauth2                  Enable XOAUTH2 authentication mode
  --token                   OAuth2 access token for XOAUTH2 authentication
  -cs, --charset            Custom body character set (Default: UTF-8)

  -c, --config              Path to the SMTP json config file which replaces the above arguments

  -t, --to-email            Email addresses that will receive the email, comma-separated
  --cc                      CC recipient email addresses, comma-separated (optional)
  --bcc                     BCC recipient email addresses, comma-separated (optional)
  -lst, --list              File path containing recipient email addresses, one per line (optional)
  -r, --reply-to            Email address to reply to (optional)
  -h, --subject             Subject of the email
  -b, --body                Body of the email
  -af, --attachments        File paths for attachments, comma-separated (optional)
  -lst-af, --attachments-list File path containing attachment file paths, one per line (optional)
  -dir-af, --attachments-dir Directory path to attach all contained files (optional)
  -max-af, --max-attachment-size Maximum total combined attachment size limit in MB (optional)
  -ia, --inline-attachments File paths for inline attachments, comma-separated (optional)
  -bf, --body-file          File path for HTML email body (replaces the --body argument)
  -H, --header              Custom MIME header in 'Header-Name: Value' format (repeatable)
  -log, --log-file          File path to append execution logs (optional)
  -retry, --retries         Number of retries on SMTP dial failure (Default: 0)
  --retry-delay             Delay in seconds between retries (Default: 5)
  --timeout                 SMTP connection timeout in seconds (Default: 30)
  --dsn-notify              DSN notification options comma-separated (SUCCESS, FAILURE, DELAY, NEVER)
  --dsn-return              DSN return header option (FULL or HDRS)
  -imp, --importance        Email priority/importance (high, normal, low)
  -j, --json-output         Output result in machine-readable JSON format
  --ndjson, --ndjson-output Output result in single-line NDJSON format
  -info, --diag             Run pre-flight SMTP gateway diagnostics and exit
  --print-certs             Print full TLS certificate chain during diagnostics
  --debug                   Enable verbose SMTP protocol wire debug tracing
  -v, --version             Application version
```
