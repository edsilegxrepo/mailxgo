// Package main - mailxgo Executable Usage Printer
//
// OBJECTIVES:
// Provide standalone CLI help menu text printing and exit code 1 invocation for package main executions.
//
// CORE COMPONENTS:
// - Usage: Prints CLI option flags reference to os.Stderr and terminates process via osExit(1).
// - osExit: Interceptable exit function variable for unit testing package main.
//
// FUNCTIONALITY & DATA FLOW:
// CLI Invocation (no args) -> Usage() -> Fprintf(os.Stderr) -> osExit(1).
package main

import (
	"fmt"
	"os"
)

var osExit = os.Exit

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  -s, --smtp-server         SMTP server for sending emails")
	fmt.Fprintln(os.Stderr, "  -p, --smtp-port           SMTP server port (Default: 587)")
	fmt.Fprintln(os.Stderr, "  -u, --smtp-username       Username for SMTP authentication")
	fmt.Fprintln(os.Stderr, "  -w, --smtp-password       Password for SMTP authentication")
	fmt.Fprintln(os.Stderr, "  --use                     Mail provider preset (office365, googleworkspace, aws-ses, sendgrid, mailgun, gmail, etc.)")
	fmt.Fprintln(os.Stderr, "  --auth-type               SASL Auth mechanism (auto, login, plain, cram-md5, xoauth2)")
	fmt.Fprintln(os.Stderr, "  --oauth2                  Enable XOAUTH2 authentication mode")
	fmt.Fprintln(os.Stderr, "  --token                   OAuth2 access token for XOAUTH2 authentication")
	fmt.Fprintln(os.Stderr, "  -cs, --charset            Custom body character set (Default: UTF-8)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  -c, --config              Path to the SMTP json config file which replaces the above arguments")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  -t, --to-email            Email addresses that will receive the email, comma-separated")
	fmt.Fprintln(os.Stderr, "  --cc                      CC recipient email addresses, comma-separated (optional)")
	fmt.Fprintln(os.Stderr, "  --bcc                     BCC recipient email addresses, comma-separated (optional)")
	fmt.Fprintln(os.Stderr, "  -lst, --list              File path containing recipient email addresses, one per line (optional)")
	fmt.Fprintln(os.Stderr, "  -r, --reply-to            Email address to reply to (optional)")
	fmt.Fprintln(os.Stderr, "  -h, --subject             Subject of the email")
	fmt.Fprintln(os.Stderr, "  -b, --body                Body of the email")
	fmt.Fprintln(os.Stderr, "  -af, --attachments        File paths for attachments, comma-separated (optional)")
	fmt.Fprintln(os.Stderr, "  -lst-af, --attachments-list File path containing attachment file paths, one per line (optional)")
	fmt.Fprintln(os.Stderr, "  -dir-af, --attachments-dir Directory path to attach all contained files (optional)")
	fmt.Fprintln(os.Stderr, "  -max-af, --max-attachment-size Maximum total combined attachment size limit in MB (optional)")
	fmt.Fprintln(os.Stderr, "  -ia, --inline-attachments File paths for inline attachments, comma-separated (optional)")
	fmt.Fprintln(os.Stderr, "  -bf, --body-file          File path for HTML email body (replaces the --body argument)")
	fmt.Fprintln(os.Stderr, "  -H, --header              Custom MIME header in 'Header-Name: Value' format (repeatable)")
	fmt.Fprintln(os.Stderr, "  -log, --log-file          File path to append execution logs (optional)")
	fmt.Fprintln(os.Stderr, "  -retry, --retries         Number of retries on SMTP dial failure (Default: 0)")
	fmt.Fprintln(os.Stderr, "  --retry-delay             Delay in seconds between retries (Default: 5)")
	fmt.Fprintln(os.Stderr, "  --timeout                 SMTP connection timeout in seconds (Default: 30)")
	fmt.Fprintln(os.Stderr, "  --dsn-notify              DSN notification options comma-separated (SUCCESS, FAILURE, DELAY, NEVER)")
	fmt.Fprintln(os.Stderr, "  --dsn-return              DSN return header option (FULL or HDRS)")
	fmt.Fprintln(os.Stderr, "  -imp, --importance        Email priority/importance (high, normal, low)")
	fmt.Fprintln(os.Stderr, "  -j, --json-output         Output result in machine-readable JSON format")
	fmt.Fprintln(os.Stderr, "  --ndjson, --ndjson-output Output result in single-line NDJSON format")
	fmt.Fprintln(os.Stderr, "  -info, --diag             Run pre-flight SMTP gateway diagnostics and exit")
	fmt.Fprintln(os.Stderr, "  --print-certs             Print full TLS certificate chain during diagnostics")
	fmt.Fprintln(os.Stderr, "  --debug                   Enable verbose SMTP protocol wire debug tracing")
	fmt.Fprintln(os.Stderr, "  -v, --version             Application version")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Ensure all required flags are provided.")
	osExit(1)
}
