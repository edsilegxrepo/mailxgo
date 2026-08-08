# mailxgo - Enterprise CLI SMTP Client & Gateway Diagnostic Suite

[![License](./LICENSE)](./LICENSE)
[![Go Version](./go.mod)](./go.mod)

`mailxgo` is a high-performance command-line SMTP client and pre-flight gateway diagnostic engine written in Go, designed for Managed File Transfer (MFT) automation, job schedulers, and enterprise email dispatch.

---

## Acknowledgements & Inspiration

`mailxgo` was inspired by and builds upon the work and concepts from:
- [mail2go](https://github.com/KeepSec-Technologies/Mail2Go)
- [mailsend-go](https://github.com/muquit/mailsend-go)

---

## Table of Contents

- [Acknowledgements & Inspiration](#acknowledgements--inspiration)
- [Features](#features)
- [Requirements](#requirements)
- [Building from Source](#building-from-source)
- [Programmatic Go Library](#programmatic-go-library)
- [Usage](#usage)
- [Examples](#examples)
- [License](#license)

---

## Features

- **Send Emails with Ease**: Quickly send emails with subject, body, and multiple recipients (`-t` / `--to-email`).
- **CC and BCC Support**: Carbon copy (`--cc`) and blind carbon copy (`--bcc`) recipients.
- **Friendly Sender Name**: Custom display names for the sender (`-fn` / `--from-name`).
- **Advanced Attachment Engine**:
  - Comma-separated attachments (`-af` / `--attachments`).
  - Attachment List Files (`-lst-af` / `--attachments-list`).
  - Directory Scanning (`-dir-af` / `--attachments-dir`).
  - Max Attachment Total Size Guard (`-max-af` / `--max-attachment-size`).
  - Inline Embedded Images (`-ia` / `--inline-attachments`).
- **Recipient List Files**: Read recipient addresses from a list file (`-lst` / `--list`).
- **Custom MIME Headers**: Specify arbitrary headers like `X-Job-ID` (`-H` / `--header`).
- **Pre-Flight Gateway Diagnostics**: Test SMTP connectivity, latency timing, DNS MX/SPF/DMARC, ESMTP extensions, and X.509 TLS certificate chain inspection (`-info` / `--diag`, `--print-certs`).
- **SASL Authentication Suite**: Support for `PLAIN`, `LOGIN`, `CRAM-MD5`, and `XOAUTH2` authentication (`--auth-type`, `--oauth2`, `--token`).
- **Mail Provider Presets**: Built-in host/port/TLS presets (`--use office365|googleworkspace|aws-ses|sendgrid|mailgun|gmail|outlook`).
- **Observability Output Formats**: Human text, Indented JSON (`-j`), and Single-Line NDJSON (`--ndjson`) for streaming log collectors.
- **Execution Audit Log File**: Append timestamped logs directly to a file (`-log` / `--log-file`).
- **Automatic Retries & Timeouts**: Retries on transient dial failures (`-retry` / `--retries`) with configurable delays (`--retry-delay`) and timeouts (`--timeout`).
- **Environment Variable Secrets**: Automatic credential fallback via `MAILXGO_SMTP_PASSWORD` / `SMTP_USER_PASS` and `MAILXGO_SMTP_USERNAME` / `SMTP_USER`.
- **Delivery Status Notifications (DSN)**: Request delivery status notifications (`--dsn-notify`, `--dsn-return`).
- **Email Priority / Importance**: Set message importance (`-imp` / `--importance high|normal|low`).
- **Automatic Configuration File Detection**: Automatically searches for `~/.config/mailxgo/config.json` (or `~/.config/mail2go/config.json`).

---

## Requirements

- Go 1.22 or higher recommended (for build).
- Access to an SMTP server for sending emails.

---

## Building from Source

1. Clone the repository:
   ```shell
   git clone https://github.com/edsilegxrepo/mailxgo
   cd mailxgo
   ```

2. Build the `mailxgo` CLI binary:
   ```shell
   go build -v -o ./bin/mailxgo ./cmd/mailxgo
   ```

3. Move the binary to `/usr/local/bin/` (Optional):
   ```shell
   sudo mv ./bin/mailxgo /usr/local/bin/mailxgo
   ```

---

## Programmatic Go Library

External Go applications can import `mailxgo` directly:

```go
package main

import (
	"fmt"
	"log"

	mailxgo "github.com/edsilegxrepo/mailxgo"
)

func main() {
	// Pre-Flight Gateway Probe
	probeParams := mailxgo.EmailParams{
		SMTPServer: "smtp.office365.com",
		SMTPPort:   587,
		TLSMode:    "tls",
	}
	report, err := mailxgo.RunDiagnostics(probeParams, true)
	if err != nil {
		log.Fatalf("Probe failed: %v", err)
	}
	fmt.Printf("Gateway Latency: %.2f ms\n", report.Latency.TotalMS)

	// Send Email
	emailParams := mailxgo.EmailParams{
		SMTPServer: "smtp.office365.com",
		SMTPPort:   587,
		Username:   "mft@company.com",
		Password:   "SecretPass123",
		From:       "mft@company.com",
		To:         []string{"admin@company.com"},
		Subject:    "Automated Report",
		Body:       "Transfer complete.",
	}
	result, err := mailxgo.SendEmail(emailParams)
	if err != nil {
		log.Fatalf("Dispatch failed: %v", err)
	}
	fmt.Printf("Status: %s (Attempts: %d)\n", result.Status, result.Attempts)
}
```

---

## Usage

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

---

## Environment Variables

- `MAILXGO_SMTP_PASSWORD` / `MAIL2GO_SMTP_PASSWORD` / `SMTP_USER_PASS`: Password for SMTP authentication.
- `MAILXGO_SMTP_USERNAME` / `MAIL2GO_SMTP_USERNAME` / `SMTP_USER`: Username for SMTP authentication.
- `MAILXGO_OAUTH_TOKEN` / `MAIL2GO_OAUTH_TOKEN` / `SMTP_OAUTH_TOKEN`: OAuth2 access token for XOAUTH2 authentication.

---

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
