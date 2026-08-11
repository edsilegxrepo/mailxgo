// Package mailxgo - CLI Argument Engine & Precedence Evaluator
//
// OBJECTIVES:
// Provide command-line flag definitions, 6-tier parameter precedence resolution, configuration auto-detection, and CLI execution routing.
//
// CORE COMPONENTS:
// - HeaderFlags: Custom flag.Value implementation for parsing repeatable -H "Key: Value" headers with CRLF injection validation.
// - PrintUsage: Help text printer rendering flag reference menu to os.Stderr.
// - RunCLI: Main CLI handler orchestrating argument parsing, configuration loading, environment fallback lookup, parameter priority evaluation, and dispatch routing.
// - priorityString / priorityInt: Precedence evaluation helpers resolving the highest priority parameter across low-to-high ordered slices.
//
// FUNCTIONALITY & DATA FLOW:
// CLI os.Args -> flag.FlagSet parse -> Auto-detect/Load config file -> Read environment variables -> Evaluate 6-tier priority hierarchy -> Construct EmailParams -> Route to RunDiagnostics or SendEmail.
package mailxgo

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	version = "dev" // Application version (set via -ldflags "-X mailxgo.version=x.y.z")
	osExit  = os.Exit
)

// Custom flag.Value implementation for multi-value headers (-H "Key: Value")
// Objectives: Parses repeatable CLI -H flags into a key-value map with CRLF injection sanitization.
type HeaderFlags map[string]string

func (h *HeaderFlags) String() string {
	var sb strings.Builder
	first := true
	for k, v := range *h {
		if !first {
			sb.WriteString(", ")
		}
		sb.WriteString(k)
		sb.WriteByte(':')
		sb.WriteString(v)
		first = false
	}
	return sb.String()
}

// Set validates and stores custom MIME header key-value pairs.
// Security: Rejects header names or values containing \r or \n carriage return/newline control characters (RFC 5322).
func (h *HeaderFlags) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("header must be in 'Header-Name: Value' format")
	}
	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])
	if key == "" {
		return fmt.Errorf("header name cannot be empty")
	}
	if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(val, "\r\n") {
		return fmt.Errorf("header key and value must not contain newline characters")
	}
	if *h == nil {
		*h = make(map[string]string)
	}
	(*h)[key] = val
	return nil
}

// PrintUsage prints the CLI usage help menu text to stderr.
func PrintUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Connection:")
	fmt.Fprintln(os.Stderr, "  --smtp-server             SMTP server for sending emails")
	fmt.Fprintln(os.Stderr, "  --smtp-port               SMTP server port (Default: 587)")
	fmt.Fprintln(os.Stderr, "  --smtp-username           Username for SMTP authentication")
	fmt.Fprintln(os.Stderr, "  --smtp-password           Password for SMTP authentication")
	fmt.Fprintln(os.Stderr, "  --no-auth                 Use unauthenticated SMTP relay")
	fmt.Fprintln(os.Stderr, "  --tls-mode                TLS mode: tls, ignore-trust, none (Default: tls)")
	fmt.Fprintln(os.Stderr, "  --tls-ca-cert             Path to CA certificate file (PEM) for custom trust")
	fmt.Fprintln(os.Stderr, "  --tls-ca-dir              Path to directory containing CA certificates (PEM)")
	fmt.Fprintln(os.Stderr, "  --tls-fingerprint         SHA256 fingerprint for certificate pinning (hex, with or without colons)")
	fmt.Fprintln(os.Stderr, "  --use                     Mail provider preset (office365, googleworkspace, aws-ses, sendgrid, mailgun, gmail)")
	fmt.Fprintln(os.Stderr, "  --auth-type               SASL Auth mechanism: auto, login, plain, cram-md5, xoauth2 (Default: auto)")
	fmt.Fprintln(os.Stderr, "  --oauth2                  Enable XOAUTH2 authentication mode")
	fmt.Fprintln(os.Stderr, "  --token                   OAuth2 access token for XOAUTH2 authentication")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Configuration:")
	fmt.Fprintln(os.Stderr, "  --config                  Path to JSON config file")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Message:")
	fmt.Fprintln(os.Stderr, "  --from-email              Sender email address")
	fmt.Fprintln(os.Stderr, "  --from-name               Sender display name")
	fmt.Fprintln(os.Stderr, "  --to-email                Recipient email addresses, comma-separated")
	fmt.Fprintln(os.Stderr, "  --cc                      CC recipient email addresses, comma-separated")
	fmt.Fprintln(os.Stderr, "  --bcc                     BCC recipient email addresses, comma-separated")
	fmt.Fprintln(os.Stderr, "  --recipient-list          File path containing recipient addresses")
	fmt.Fprintln(os.Stderr, "  --reply-to                Reply-To email address")
	fmt.Fprintln(os.Stderr, "  --subject                 Email subject line")
	fmt.Fprintln(os.Stderr, "  --body                    Email body text")
	fmt.Fprintln(os.Stderr, "  --body-file               File path for HTML email body")
	fmt.Fprintln(os.Stderr, "  --template                Path to Go template file for body")
	fmt.Fprintln(os.Stderr, "  --template-data           Path to JSON file with template variables")
	fmt.Fprintln(os.Stderr, "  --var                     Template variable 'Name: Value' (repeatable)")
	fmt.Fprintln(os.Stderr, "  --charset                 Body character set (Default: UTF-8)")
	fmt.Fprintln(os.Stderr, "  --importance              Email priority: high, normal, low")
	fmt.Fprintln(os.Stderr, "  --header                  Custom MIME header 'Name: Value' (repeatable)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Attachments:")
	fmt.Fprintln(os.Stderr, "  --attachments             File paths for attachments, comma-separated")
	fmt.Fprintln(os.Stderr, "  --attachments-list        File containing attachment paths")
	fmt.Fprintln(os.Stderr, "  --attachments-dir         Directory to attach all files from")
	fmt.Fprintln(os.Stderr, "  --list-format             Format for --recipient-list and --attachments-list: text (default) or json")
	fmt.Fprintln(os.Stderr, "  --inline-attachments      File paths for inline attachments, comma-separated")
	fmt.Fprintln(os.Stderr, "  --max-attachment-size     Maximum total attachment size in MB")
	fmt.Fprintln(os.Stderr, "  --single-attachment       Send one email per attachment with [N/Total] prefix")
	fmt.Fprintln(os.Stderr, "  --route                   Move body file/attachments after send: 'successPath,errorPath'")
	fmt.Fprintln(os.Stderr, "  --delete                  Delete body file/attachments after successful send")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Archiving:")
	fmt.Fprintln(os.Stderr, "  --save-eml                Directory to save .eml archive after successful send")
	fmt.Fprintln(os.Stderr, "  --compress                Compress .eml archive with zstd")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Delivery:")
	fmt.Fprintln(os.Stderr, "  --retries                 Number of retries on SMTP failure (Default: 0)")
	fmt.Fprintln(os.Stderr, "  --retry-delay             Delay between retries in seconds (Default: 5)")
	fmt.Fprintln(os.Stderr, "  --timeout                 Connection timeout in seconds (Default: 30)")
	fmt.Fprintln(os.Stderr, "  --delay                   Delay in seconds before sending")
	fmt.Fprintln(os.Stderr, "  --rate-limit              Max emails per minute (for batch/multi-recipient)")
	fmt.Fprintln(os.Stderr, "  --max-recipients          Maximum recipients per email (Default: 1000)")
	fmt.Fprintln(os.Stderr, "  --single-recipient        Send one email per recipient with rate limiting")
	fmt.Fprintln(os.Stderr, "  --dsn-notify              DSN notification: SUCCESS, FAILURE, DELAY, NEVER")
	fmt.Fprintln(os.Stderr, "  --dsn-return              DSN return: FULL or HDRS")
	fmt.Fprintln(os.Stderr, "  --dry-run                 Validate config and connect but don't send")
	fmt.Fprintln(os.Stderr, "  --read-receipt            Request read receipt (Disposition-Notification-To)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Output:")
	fmt.Fprintln(os.Stderr, "  --json-output             Output result in JSON format")
	fmt.Fprintln(os.Stderr, "  --ndjson-output           Output result in single-line NDJSON format")
	fmt.Fprintln(os.Stderr, "  --log-file                File path to append execution logs")
	fmt.Fprintln(os.Stderr, "  --no-log-recipients       Redact recipient addresses in logs (GDPR/privacy)")
	fmt.Fprintln(os.Stderr, "  --quiet, -q               Suppress output except errors")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Diagnostics:")
	fmt.Fprintln(os.Stderr, "  --diag                    Run pre-flight SMTP gateway diagnostics")
	fmt.Fprintln(os.Stderr, "  --print-certs             Print TLS certificate chain during diagnostics")
	fmt.Fprintln(os.Stderr, "  --debug                   Enable verbose SMTP protocol tracing")
	fmt.Fprintln(os.Stderr, "  --version                 Display application version")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Environment Variables:")
	fmt.Fprintln(os.Stderr, "  MAILXGO_SMTP_PASSWORD     SMTP password (recommended over --smtp-password)")
	fmt.Fprintln(os.Stderr, "  MAILXGO_SMTP_USERNAME     SMTP username")
	fmt.Fprintln(os.Stderr, "  MAILXGO_OAUTH_TOKEN       OAuth2 access token")
}

// RunCLI parses command-line arguments and executes Mail2Go diagnostics or email dispatch.
func RunCLI(args []string) {
	fs := flag.NewFlagSet("mailxgo", flag.ContinueOnError)

	var (
		smtpServer string
		smtpPort   int
		username   string
		password   string

		authType    string
		oauth2Mode  bool
		token       string
		useProvider string
		charset     string

		tlsMode        string
		tlsCACert      string
		tlsCADir       string
		tlsFingerprint string

		configFile string

		fromEmail string
		fromName  string
		toEmail   string
		ccEmail   string
		bccEmail  string
		listFile  string
		replyTo   string

		subject string
		body    string

		attachmentsFiles       string
		inlineAttachmentsFiles string
		attachmentsList        string
		attachmentsDir         string
		maxAttachmentMB        int

		bodyFile        string
		logFile         string
		noLogRecipients bool

		retries    int
		retryDelay int
		timeout    int

		dsnNotify    string
		dsnReturn    string
		importance   string
		jsonOutput   bool
		ndjsonOutput bool

		info       bool
		diag       bool
		printCerts bool
		debug      bool

		headers = make(HeaderFlags)

		showVersion bool
		noAuth      bool
		dryRun      bool
		quiet       bool
		readReceipt bool

		// New features: template, delay, rate limit, archive, attachment routing
		templateFile     string
		templateDataFile string
		templateVars     = make(HeaderFlags) // Reuse HeaderFlags for --var Name=Value
		delay            int
		rateLimit        int
		maxRecipients    int
		saveEMLPath      string
		compressEML      bool
		routePath        string // format: "successPath,errorPath"
		routeDelete      bool
		singleAttachment bool
		singleRecipient  bool
		listFormat       string // "text" (default) or "json"

		// S/MIME flags
		smimeSign             bool
		smimeEncrypt          bool
		smimeCert             string
		smimeKey              string
		smimeKeyPassword      string
		smimePKCS12           string
		smimeRecipientCert    string
		smimeRecipientCertDir string
		smimeAlgorithm        string
		smimeDigest           string
	)

	// Long-form flags
	fs.StringVar(&smtpServer, "smtp-server", "", "SMTP server for sending emails")
	fs.IntVar(&smtpPort, "smtp-port", 0, "SMTP server port (default 587)")
	fs.StringVar(&username, "smtp-username", "", "Username for SMTP authentication")
	fs.StringVar(&password, "smtp-password", "", "Password for SMTP authentication")
	fs.BoolVar(&noAuth, "no-auth", false, "Use unauthenticated SMTP")

	// S/MIME Security Flags
	fs.BoolVar(&smimeSign, "smime-sign", false, "Sign outgoing message with sender's private key")
	fs.BoolVar(&smimeEncrypt, "smime-encrypt", false, "Encrypt message for recipients using their public certificates")
	fs.StringVar(&smimeCert, "smime-cert", "", "Path to sender's X.509 certificate (PEM) for signing")
	fs.StringVar(&smimeKey, "smime-key", "", "Path to sender's private key (PEM) for signing")
	fs.StringVar(&smimeKeyPassword, "smime-key-password", "", "Password for encrypted private key (supports v1:gcm: encrypted secrets)")
	fs.StringVar(&smimePKCS12, "smime-pkcs12", "", "Path to PKCS#12 bundle (.pfx/.p12) containing cert and key")
	fs.StringVar(&smimeRecipientCert, "smime-recipient-cert", "", "Path to recipient certificate(s) for encryption (comma-separated)")
	fs.StringVar(&smimeRecipientCertDir, "smime-recipient-cert-dir", "", "Directory containing recipient certificates (.pem/.crt/.cer)")
	fs.StringVar(&smimeAlgorithm, "smime-algorithm", "aes-256-gcm", "S/MIME encryption algorithm (aes-256-gcm, aes-128-gcm, aes-256-cbc, aes-128-cbc, 3des-cbc)")
	fs.StringVar(&smimeDigest, "smime-digest", "sha256", "S/MIME signature digest algorithm (sha256, sha384, sha512)")

	fs.StringVar(&authType, "auth-type", "auto", "SASL Auth mechanism (auto, login, plain, cram-md5, xoauth2)")
	fs.BoolVar(&oauth2Mode, "oauth2", false, "Enable XOAUTH2 authentication mode")
	fs.StringVar(&token, "token", "", "OAuth2 access token for XOAUTH2 authentication")
	fs.StringVar(&useProvider, "use", "", "Mail provider preset (office365, googleworkspace, aws-ses, sendgrid, mailgun, gmail, etc.)")
	fs.StringVar(&charset, "charset", "", "Custom body character set (default UTF-8)")

	fs.StringVar(&tlsMode, "tls-mode", "", "TLS mode (none, ignore-trust, tls) (default tls)")
	fs.StringVar(&tlsCACert, "tls-ca-cert", "", "Path to CA certificate file (PEM) for custom trust")
	fs.StringVar(&tlsCADir, "tls-ca-dir", "", "Path to directory containing CA certificates (PEM)")
	fs.StringVar(&tlsFingerprint, "tls-fingerprint", "", "SHA256 fingerprint for certificate pinning (hex)")

	fs.StringVar(&configFile, "config", "", "Path to the SMTP config file")

	fs.StringVar(&fromEmail, "from-email", "", "Email address to send from")
	fs.StringVar(&fromName, "from-name", "", "Friendly sender display name")
	fs.StringVar(&toEmail, "to-email", "", "Email addresses that will receive the email, comma-separated")
	fs.StringVar(&ccEmail, "cc", "", "CC recipient email addresses, comma-separated")
	fs.StringVar(&bccEmail, "bcc", "", "BCC recipient email addresses, comma-separated")
	fs.StringVar(&listFile, "recipient-list", "", "File path containing recipient email addresses")
	fs.StringVar(&replyTo, "reply-to", "", "Email address to reply to")

	fs.StringVar(&subject, "subject", "", "Subject of the email")
	fs.StringVar(&body, "body", "", "Body of the email")

	fs.StringVar(&attachmentsFiles, "attachments", "", "File paths for attachments, comma-separated")
	fs.StringVar(&inlineAttachmentsFiles, "inline-attachments", "", "File paths for inline attachments, comma-separated")
	fs.StringVar(&attachmentsList, "attachments-list", "", "File path containing attachment file paths, one per line")
	fs.StringVar(&attachmentsDir, "attachments-dir", "", "Directory path to attach all contained files")
	fs.IntVar(&maxAttachmentMB, "max-attachment-size", 0, "Maximum total attachment size limit in MB")

	fs.StringVar(&bodyFile, "body-file", "", "File path for email body")
	fs.StringVar(&logFile, "log-file", "", "File path to append execution logs")
	fs.BoolVar(&noLogRecipients, "no-log-recipients", false, "Redact recipient addresses in log files (GDPR/privacy)")

	fs.IntVar(&retries, "retries", 0, "Number of retries on SMTP dial failure (default 0)")
	fs.IntVar(&retryDelay, "retry-delay", 5, "Delay in seconds between retries (default 5)")
	fs.IntVar(&timeout, "timeout", 30, "SMTP connection timeout in seconds (default 30)")

	fs.StringVar(&dsnNotify, "dsn-notify", "", "DSN notification options comma-separated (SUCCESS, FAILURE, DELAY, NEVER)")
	fs.StringVar(&dsnReturn, "dsn-return", "", "DSN return header option (FULL or HDRS)")

	fs.StringVar(&importance, "importance", "", "Email priority/importance (high, normal, low)")
	fs.BoolVar(&jsonOutput, "json-output", false, "Output result in machine-readable JSON format")
	fs.BoolVar(&ndjsonOutput, "ndjson-output", false, "Output result in single-line NDJSON format")
	var ndjsonAlias bool
	fs.BoolVar(&ndjsonAlias, "ndjson", false, "Output result in single-line NDJSON format")

	fs.BoolVar(&info, "info", false, "Run pre-flight SMTP gateway diagnostics and exit")
	fs.BoolVar(&diag, "diag", false, "Run pre-flight SMTP gateway diagnostics and exit")
	fs.BoolVar(&printCerts, "print-certs", false, "Print full TLS certificate chain details during diagnostics")
	fs.BoolVar(&debug, "debug", false, "Enable verbose SMTP protocol wire debug tracing")

	fs.Var(&headers, "header", "Custom MIME header in 'Header-Name: Value' format (can be specified multiple times)")

	fs.BoolVar(&dryRun, "dry-run", false, "Validate config and connect but don't send")
	fs.BoolVar(&quiet, "quiet", false, "Suppress output except errors")
	fs.BoolVar(&quiet, "q", false, "Suppress output except errors")
	fs.BoolVar(&readReceipt, "read-receipt", false, "Request read receipt (Disposition-Notification-To)")

	// Template options
	fs.StringVar(&templateFile, "template", "", "Path to Go template file for body")
	fs.StringVar(&templateDataFile, "template-data", "", "Path to JSON file with template variables")
	fs.Var(&templateVars, "var", "Template variable in 'Name: Value' format (repeatable)")

	// Delivery timing
	fs.IntVar(&delay, "delay", 0, "Delay in seconds before sending")
	fs.IntVar(&rateLimit, "rate-limit", 0, "Max emails per minute (for batch/multi-recipient)")
	fs.IntVar(&maxRecipients, "max-recipients", 0, "Maximum recipients per email (default 1000)")
	fs.BoolVar(&singleRecipient, "single-recipient", false, "Send one email per recipient with rate limiting")

	// Archiving
	fs.StringVar(&saveEMLPath, "save-eml", "", "Directory to save .eml archive after successful send")
	fs.BoolVar(&compressEML, "compress", false, "Compress .eml archive with zstd")

	// File routing (body file + attachments)
	fs.StringVar(&routePath, "route", "", "Move body file/attachments after send: 'successPath,errorPath'")
	fs.BoolVar(&routeDelete, "delete", false, "Delete body file/attachments after successful send")
	fs.BoolVar(&singleAttachment, "single-attachment", false, "Send one email per attachment with [N/Total] prefix")

	// List format
	fs.StringVar(&listFormat, "list-format", "text", "Format for --recipient-list and --attachments-list: text (default) or json")

	fs.BoolVar(&showVersion, "version", false, "Display application version")

	if err := fs.Parse(args); err != nil {
		PrintUsage()
		osExit(ExitErrUsage)
		return
	}

	if showVersion {
		fmt.Printf("mailxgo version: %s\n", version)
		osExit(ExitSuccess)
		return
	}

	if configFile == "" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			defaultConfigPath := filepath.Join(homeDir, ".config", "mailxgo", "config.json")
			fallbackConfigPath := filepath.Join(homeDir, ".config", "mail2go", "config.json")
			if _, err := os.Stat(defaultConfigPath); err == nil {
				configFile = defaultConfigPath
			} else if _, err := os.Stat(fallbackConfigPath); err == nil {
				configFile = fallbackConfigPath
			}
		}
	}

	var config Config
	var err error
	if configFile != "" {
		config, err = LoadConfig(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config file %s: %v\n", configFile, err)
			osExit(ExitErrConfig)
			return
		}
	}

	envPass := os.Getenv("MAILXGO_SMTP_PASSWORD")
	envUser := os.Getenv("MAILXGO_SMTP_USERNAME")
	envToken := os.Getenv("MAILXGO_OAUTH_TOKEN")

	// Priority: Config file < Environment variables < CLI flags (last element wins)
	useProvider = priorityString([]string{config.Use, useProvider})
	if useProvider != "" {
		if preset, ok := ResolveProviderPreset(useProvider); ok {
			if smtpServer == "" && config.SMTPServer == "" {
				smtpServer = preset.Host
			}
			if smtpPort == 0 && config.SMTPPort == 0 {
				smtpPort = preset.Port
			}
			if tlsMode == "" && config.TLSMode == "" {
				tlsMode = preset.TLSMode
			}
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Unknown provider preset '%s'\n", useProvider)
		}
	}

	smtpServer = priorityString([]string{config.SMTPServer, smtpServer})
	smtpPort = priorityInt([]int{config.SMTPPort, smtpPort})
	if smtpPort == 0 {
		smtpPort = DefaultSMTPPort
	}

	username = priorityString([]string{config.SMTPUsername, envUser, username})
	password = priorityString([]string{config.SMTPPassword, envPass, password})
	token = priorityString([]string{config.Token, envToken, token})

	// Note: Encrypted secrets (v1:gcm: prefix) are decrypted in SendEmail automatically
	authType = priorityString([]string{config.AuthType, authType})
	oauth2Mode = config.OAuth2 || oauth2Mode
	charset = priorityString([]string{config.Charset, charset})

	noAuth = config.NoAuth || noAuth

	tlsMode = priorityString([]string{config.TLSMode, tlsMode})
	if tlsMode == "" {
		tlsMode = "tls"
	}
	tlsCACert = priorityString([]string{config.TLSCACert, tlsCACert})
	tlsCADir = priorityString([]string{config.TLSCADir, tlsCADir})
	tlsFingerprint = priorityString([]string{config.TLSFingerprint, tlsFingerprint})

	// Validate fingerprint format if provided
	if tlsFingerprint != "" {
		if err := ValidateCertFingerprint(tlsFingerprint); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			osExit(ExitErrUsage)
			return
		}
	}

	fromEmail = priorityString([]string{config.FromEmail, fromEmail})
	fromName = priorityString([]string{config.FromName, fromName})
	// Merge config.To array with config.ToEmail string
	configToEmail := config.ToEmail
	if len(config.To) > 0 {
		configToEmail = strings.Join(config.To, ",")
		if config.ToEmail != "" {
			configToEmail = config.ToEmail + "," + configToEmail
		}
	}
	toEmail = priorityString([]string{configToEmail, toEmail})
	ccEmail = priorityString([]string{strings.Join(config.CC, ","), ccEmail})
	bccEmail = priorityString([]string{strings.Join(config.BCC, ","), bccEmail})

	subject = priorityString([]string{config.Subject, subject})
	body = priorityString([]string{config.Body, body})

	attachmentsList = priorityString([]string{config.AttachmentsList, attachmentsList})
	attachmentsDir = priorityString([]string{config.AttachmentsDir, attachmentsDir})
	maxAttachmentMB = priorityInt([]int{config.MaxAttachmentMB, maxAttachmentMB})

	bodyFile = priorityString([]string{config.BodyFile, bodyFile})
	noLogRecipients = config.NoLogRecipients || noLogRecipients
	logFile = priorityString([]string{config.LogFile, logFile})

	retries = priorityInt([]int{config.Retries, retries})
	retryDelay = priorityInt([]int{config.RetryDelay, retryDelay})
	if retryDelay <= 0 {
		retryDelay = DefaultRetryDelay
	}
	timeout = priorityInt([]int{config.Timeout, timeout})
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	importance = priorityString([]string{config.Importance, importance})
	dsnReturn = priorityString([]string{config.DSNReturn, dsnReturn})
	jsonOutput = config.JSONOutput || jsonOutput
	ndjsonOutput = config.NDJSONOutput || ndjsonOutput || ndjsonAlias
	debug = config.Debug || debug
	info = config.Info || info || diag
	printCerts = config.PrintCerts || printCerts

	var dsnNotifyList []string
	if dsnNotify != "" {
		dsnNotifyList = strings.Split(dsnNotify, ",")
	} else if len(config.DSNNotify) > 0 {
		dsnNotifyList = config.DSNNotify
	}

	if info {
		if smtpServer == "" {
			fmt.Fprintln(os.Stderr, "Error: SMTP server (--smtp-server) is required for diagnostics.")
			PrintUsage()
			osExit(ExitErrUsage)
			return
		}
		diagParams := EmailParams{
			SMTPServer:     smtpServer,
			SMTPPort:       smtpPort,
			From:           fromEmail,
			TLSMode:        tlsMode,
			TLSCACert:      tlsCACert,
			TLSCADir:       tlsCADir,
			TLSFingerprint: tlsFingerprint,
			Timeout:        timeout,
			JSONOutput:     jsonOutput,
			NDJSONOutput:   ndjsonOutput,
		}
		if _, err := RunDiagnostics(diagParams, printCerts); err != nil {
			osExit(ExitErrDNS)
			return
		}
		osExit(ExitSuccess)
		return
	}

	if smtpServer == "" || fromEmail == "" || (toEmail == "" && listFile == "") || subject == "" || (body == "" && bodyFile == "") {
		fmt.Fprintln(os.Stderr, "Error: Missing required arguments for sending email.")
		PrintUsage()
		osExit(ExitErrUsage)
		return
	}

	var attachmentPaths []string
	if attachmentsFiles != "" {
		attachmentPaths = append(attachmentPaths, strings.Split(attachmentsFiles, ",")...)
	}
	if attachmentsList != "" {
		listFileAttachments, _, err := LoadList(attachmentsList, listFormat, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading attachment list file %s: %v\n", attachmentsList, err)
			osExit(ExitErrFileIO)
			return
		}
		attachmentPaths = append(attachmentPaths, listFileAttachments...)
	}
	if attachmentsDir != "" {
		dirFiles, err := ScanAttachmentDir(attachmentsDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning attachment directory %s: %v\n", attachmentsDir, err)
			osExit(ExitErrFileIO)
			return
		}
		attachmentPaths = append(attachmentPaths, dirFiles...)
	}

	var inlineAttachmentPaths []string
	if inlineAttachmentsFiles != "" {
		inlineAttachmentPaths = strings.Split(inlineAttachmentsFiles, ",")
	} else if len(config.InlineAttachments) > 0 {
		inlineAttachmentPaths = config.InlineAttachments
	}

	mergedHeaders := make(map[string]string)
	for k, v := range config.Headers {
		mergedHeaders[k] = v
	}
	for k, v := range headers {
		mergedHeaders[k] = v
	}

	var toEmails []string
	if toEmail != "" {
		toEmails = append(toEmails, strings.Split(toEmail, ",")...)
	}

	if listFile != "" {
		listRecipients, _, err := LoadList(listFile, listFormat, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading recipient list file %s: %v\n", listFile, err)
			osExit(ExitErrFileIO)
			return
		}
		toEmails = append(toEmails, listRecipients...)
	}

	var ccEmails []string
	if ccEmail != "" {
		ccEmails = append(ccEmails, strings.Split(ccEmail, ",")...)
	}

	var bccEmails []string
	if bccEmail != "" {
		bccEmails = append(bccEmails, strings.Split(bccEmail, ",")...)
	}

	// Parse file routing
	var routeSuccessPath, routeErrorPath string
	if routePath != "" {
		parts := strings.SplitN(routePath, ",", 2)
		routeSuccessPath = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			routeErrorPath = strings.TrimSpace(parts[1])
		}
	}

	var recipientCertPaths []string
	if smimeRecipientCert != "" {
		recipientCertPaths = append(recipientCertPaths, strings.Split(smimeRecipientCert, ",")...)
	} else if len(config.SMIMERecipientCerts) > 0 {
		recipientCertPaths = config.SMIMERecipientCerts
	}

	params := EmailParams{
		SMTPServer:        smtpServer,
		SMTPPort:          smtpPort,
		Username:          username,
		Password:          password,
		From:              fromEmail,
		FromName:          fromName,
		To:                toEmails,
		CC:                ccEmails,
		BCC:               bccEmails,
		ReplyTo:           replyTo,
		Subject:           subject,
		Body:              body,
		BodyFile:          bodyFile,
		Attachments:       attachmentPaths,
		InlineAttachments: inlineAttachmentPaths,
		Headers:           mergedHeaders,
		TLSMode:           tlsMode,
		TLSCACert:         tlsCACert,
		TLSCADir:          tlsCADir,
		TLSFingerprint:    tlsFingerprint,
		NoAuth:            noAuth,
		LogFile:           logFile,
		Retries:           retries,
		RetryDelay:        retryDelay,
		Timeout:           timeout,
		DSNNotify:         dsnNotifyList,
		DSNReturn:         dsnReturn,
		Importance:        importance,
		JSONOutput:        jsonOutput,
		Debug:             debug,
		AuthType:          authType,
		OAuth2:            oauth2Mode,
		Token:             token,
		Charset:           charset,
		MaxAttachmentMB:   maxAttachmentMB,
		NDJSONOutput:      ndjsonOutput,
		NoLogRecipients:   noLogRecipients,
		DryRun:            dryRun,
		Quiet:             quiet,
		ReadReceipt:       readReceipt,

		// New features
		TemplateFile:     templateFile,
		TemplateVars:     templateVars,
		TemplateDataFile: templateDataFile,
		Delay:            delay,
		RateLimit:        rateLimit,
		MaxRecipients:    maxRecipients,
		SaveEMLPath:      saveEMLPath,
		CompressEML:      compressEML,
		RouteSuccessPath: routeSuccessPath,
		RouteErrorPath:   routeErrorPath,
		RouteDelete:      routeDelete,
		SingleAttachment: singleAttachment,
		SingleRecipient:  singleRecipient,

		// S/MIME Security Configuration (CLI > config > default fallback)
		SMIMESign:             config.SMIMESign || smimeSign,
		SMIMEEncrypt:          config.SMIMEEncrypt || smimeEncrypt,
		SMIMECert:             priorityString([]string{smimeCert, config.SMIMECert, config.SMIMEDefaultCert}),
		SMIMEKey:              priorityString([]string{smimeKey, config.SMIMEKey, config.SMIMEDefaultKey}),
		SMIMEKeyPassword:      priorityString([]string{smimeKeyPassword, config.SMIMEKeyPassword, config.SMIMEDefaultKeyPassword}),
		SMIMEPKCS12:           priorityString([]string{smimePKCS12, config.SMIMEPKCS12, config.SMIMEDefaultPKCS12}),
		SMIMERecipientCerts:   recipientCertPaths,
		SMIMERecipientCertDir: priorityString([]string{smimeRecipientCertDir, config.SMIMERecipientCertDir}),
		SMIMEAlgorithm:        priorityString([]string{smimeAlgorithm, config.SMIMEAlgorithm}),
		SMIMEDigest:           priorityString([]string{smimeDigest, config.SMIMEDigest}),
	}

	result, err := SendEmail(params)
	if err != nil {
		if !jsonOutput && !ndjsonOutput && !quiet {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		// Use granular exit codes based on error type
		if result != nil {
			switch result.ErrorType {
			case ErrorTypeTLS:
				osExit(ExitErrTLS)
			case ErrorTypeAuth:
				osExit(ExitErrAuth)
			case ErrorTypeConnection:
				osExit(ExitErrConnection)
			default:
				osExit(ExitErrSend)
			}
		} else {
			osExit(ExitErrSend)
		}
		return
	}
}

// priorityString resolves parameter precedence across a slice of strings ordered from lowest to highest priority.
// Functionality: Iterates through the slice and returns the last non-empty string element.
func priorityString(strings []string) string {
	result := ""
	for _, val := range strings {
		if val != "" {
			result = val
		}
	}
	return result
}

// priorityInt resolves parameter precedence across a slice of integers ordered from lowest to highest priority.
// Functionality: Iterates through the slice and returns the last non-zero integer element.
func priorityInt(ints []int) int {
	result := 0
	for _, val := range ints {
		if val != 0 {
			result = val
		}
	}
	return result
}
