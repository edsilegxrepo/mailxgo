package mailxgo

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var Version = "dev" // Application version

// Custom flag.Value implementation for multi-value headers (-H "Key: Value")
type HeaderFlags map[string]string

func (h *HeaderFlags) String() string {
	var parts []string
	for k, v := range *h {
		parts = append(parts, fmt.Sprintf("%s:%s", k, v))
	}
	return strings.Join(parts, ", ")
}

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
}

// RunCLI parses command-line arguments and executes Mail2Go diagnostics or email dispatch.
func RunCLI(args []string) {
	fs := flag.NewFlagSet("mail2go", flag.ExitOnError)

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

		tlsMode string

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

		bodyFile string
		logFile  string

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

		headers HeaderFlags = make(HeaderFlags)

		showVersion bool

		// Short-form flags
		smtpServerShort string
		smtpPortShort   int
		usernameShort   string
		passwordShort   string

		noAuth      bool
		noAuthShort bool

		useProviderShort string
		charsetShort     string

		attachmentsListShort string
		attachmentsDirShort  string
		maxAttachmentMBShort int

		tlsModeShort string

		configFileShort string

		fromEmailShort string
		fromNameShort  string
		toEmailShort   string
		ccEmailShort   string
		bccEmailShort  string
		listFileShort  string
		replyToShort   string

		subjectShort string
		bodyShort    string

		attachmentsFilesShort       string
		inlineAttachmentsFilesShort string
		bodyFileShort               string
		logFileShort                string

		retriesShort      int
		importanceShort   string
		jsonOutputShort   bool
		ndjsonOutputShort bool
		infoShort         bool
		showVersionShort  bool
	)

	// Long-form flags
	fs.StringVar(&smtpServer, "smtp-server", "", "SMTP server for sending emails")
	fs.IntVar(&smtpPort, "smtp-port", 0, "SMTP server port (default 587)")
	fs.StringVar(&username, "smtp-username", "", "Username for SMTP authentication")
	fs.StringVar(&password, "smtp-password", "", "Password for SMTP authentication")
	fs.BoolVar(&noAuth, "no-auth", false, "Use unauthenticated SMTP")

	fs.StringVar(&authType, "auth-type", "auto", "SASL Auth mechanism (auto, login, plain, cram-md5, xoauth2)")
	fs.BoolVar(&oauth2Mode, "oauth2", false, "Enable XOAUTH2 authentication mode")
	fs.StringVar(&token, "token", "", "OAuth2 access token for XOAUTH2 authentication")
	fs.StringVar(&useProvider, "use", "", "Mail provider preset (office365, googleworkspace, aws-ses, sendgrid, mailgun, gmail, etc.)")
	fs.StringVar(&charset, "charset", "", "Custom body character set (default UTF-8)")

	fs.StringVar(&tlsMode, "tls-mode", "", "TLS mode (none, tls-skip, tls) (default tls)")

	fs.StringVar(&configFile, "config", "", "Path to the SMTP config file")

	fs.StringVar(&fromEmail, "from-email", "", "Email address to send from")
	fs.StringVar(&fromName, "from-name", "", "Friendly sender display name")
	fs.StringVar(&toEmail, "to-email", "", "Email addresses that will receive the email, comma-separated")
	fs.StringVar(&ccEmail, "cc", "", "CC recipient email addresses, comma-separated")
	fs.StringVar(&bccEmail, "bcc", "", "BCC recipient email addresses, comma-separated")
	fs.StringVar(&listFile, "list", "", "File path containing recipient email addresses (one per line)")
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

	fs.IntVar(&retries, "retries", 0, "Number of retries on SMTP dial failure (default 0)")
	fs.IntVar(&retryDelay, "retry-delay", 5, "Delay in seconds between retries (default 5)")
	fs.IntVar(&timeout, "timeout", 30, "SMTP connection timeout in seconds (default 30)")

	fs.StringVar(&dsnNotify, "dsn-notify", "", "DSN notification options comma-separated (SUCCESS, FAILURE, DELAY, NEVER)")
	fs.StringVar(&dsnReturn, "dsn-return", "", "DSN return header option (FULL or HDRS)")

	fs.StringVar(&importance, "importance", "", "Email priority/importance (high, normal, low)")
	fs.BoolVar(&jsonOutput, "json-output", false, "Output result in machine-readable JSON format")
	fs.BoolVar(&ndjsonOutput, "ndjson-output", false, "Output result in single-line NDJSON format")
	fs.BoolVar(&ndjsonOutput, "ndjson", false, "Output result in single-line NDJSON format")

	fs.BoolVar(&info, "info", false, "Run pre-flight SMTP gateway diagnostics and exit")
	fs.BoolVar(&diag, "diag", false, "Run pre-flight SMTP gateway diagnostics and exit")
	fs.BoolVar(&printCerts, "print-certs", false, "Print full TLS certificate chain details during diagnostics")
	fs.BoolVar(&debug, "debug", false, "Enable verbose SMTP protocol wire debug tracing")

	fs.Var(&headers, "header", "Custom MIME header in 'Header-Name: Value' format (can be specified multiple times)")

	fs.BoolVar(&showVersion, "version", false, "Display application version")

	// Short-form flags
	fs.StringVar(&smtpServerShort, "s", "", "SMTP server for sending emails (short)")
	fs.IntVar(&smtpPortShort, "p", 0, "SMTP server port (short)")
	fs.StringVar(&usernameShort, "u", "", "Username for SMTP authentication (short)")
	fs.StringVar(&passwordShort, "w", "", "Password for SMTP authentication (short)")
	fs.BoolVar(&noAuthShort, "na", false, "Use unauthenticated SMTP (short)")

	fs.StringVar(&useProviderShort, "use-short", "", "Mail provider preset (short)")
	fs.StringVar(&charsetShort, "cs", "", "Custom body character set (short)")

	fs.StringVar(&attachmentsListShort, "lst-af", "", "File path containing attachment file paths (short)")
	fs.StringVar(&attachmentsDirShort, "dir-af", "", "Directory path to attach all contained files (short)")
	fs.IntVar(&maxAttachmentMBShort, "max-af", 0, "Maximum total attachment size limit in MB (short)")

	fs.StringVar(&tlsModeShort, "l", "", "TLS mode (short)")

	fs.StringVar(&configFileShort, "c", "", "Path to the SMTP config file (short)")

	fs.StringVar(&fromEmailShort, "f", "", "Email address to send from (short)")
	fs.StringVar(&fromNameShort, "fn", "", "Friendly sender display name (short)")
	fs.StringVar(&toEmailShort, "t", "", "Email addresses that will receive the email, comma-separated (short)")
	fs.StringVar(&ccEmailShort, "cc-short", "", "CC recipient email addresses (short)")
	fs.StringVar(&bccEmailShort, "bcc-short", "", "BCC recipient email addresses (short)")
	fs.StringVar(&listFileShort, "lst", "", "File path containing recipient email addresses (short)")
	fs.StringVar(&replyToShort, "r", "", "Email address to reply to (short)")

	fs.StringVar(&subjectShort, "h", "", "Subject of the email (short)")
	fs.StringVar(&bodyShort, "b", "", "Body of the email (short)")

	fs.StringVar(&attachmentsFilesShort, "af", "", "File paths for attachments, comma-separated (short)")
	fs.StringVar(&inlineAttachmentsFilesShort, "ia", "", "File paths for inline attachments, comma-separated (short)")
	fs.StringVar(&bodyFileShort, "bf", "", "File path for email body (short)")
	fs.StringVar(&logFileShort, "log", "", "File path to append execution logs (short)")

	fs.IntVar(&retriesShort, "retry", 0, "Number of retries on SMTP dial failure (short)")
	fs.StringVar(&importanceShort, "imp", "", "Email priority/importance (short)")
	fs.BoolVar(&jsonOutputShort, "j", false, "Output result in machine-readable JSON format (short)")
	fs.BoolVar(&ndjsonOutputShort, "ndjson-short", false, "Output result in single-line NDJSON format (short)")
	fs.BoolVar(&infoShort, "info-short", false, "Run pre-flight SMTP gateway diagnostics and exit")

	fs.Var(&headers, "H", "Custom MIME header in 'Header-Name: Value' format (short)")

	fs.BoolVar(&showVersionShort, "v", false, "Display application version")

	if err := fs.Parse(args); err != nil {
		PrintUsage()
		os.Exit(1)
	}

	if showVersion || showVersionShort {
		fmt.Printf("mailxgo Version: %s\n", Version)
		os.Exit(0)
	}

	configFile = priorityString([]string{configFile, configFileShort})

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
			os.Exit(1)
		}
	}

	envPass := os.Getenv("MAILXGO_SMTP_PASSWORD")
	if envPass == "" {
		envPass = os.Getenv("MAIL2GO_SMTP_PASSWORD")
	}
	if envPass == "" {
		envPass = os.Getenv("SMTP_USER_PASS")
	}

	envUser := os.Getenv("MAILXGO_SMTP_USERNAME")
	if envUser == "" {
		envUser = os.Getenv("MAIL2GO_SMTP_USERNAME")
	}
	if envUser == "" {
		envUser = os.Getenv("SMTP_USER")
	}

	envToken := os.Getenv("MAILXGO_OAUTH_TOKEN")
	if envToken == "" {
		envToken = os.Getenv("MAIL2GO_OAUTH_TOKEN")
	}
	if envToken == "" {
		envToken = os.Getenv("SMTP_OAUTH_TOKEN")
	}

	useProvider = priorityString([]string{config.Use, useProvider, useProviderShort})
	if useProvider != "" {
		if preset, ok := ResolveProviderPreset(useProvider); ok {
			if smtpServer == "" && smtpServerShort == "" && config.SMTPServer == "" {
				smtpServer = preset.Host
			}
			if smtpPort == 0 && smtpPortShort == 0 && config.SMTPPort == 0 {
				smtpPort = preset.Port
			}
			if tlsMode == "" && tlsModeShort == "" && config.TLSMode == "" {
				tlsMode = preset.TLSMode
			}
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Unknown provider preset '%s'\n", useProvider)
		}
	}

	smtpServer = priorityString([]string{config.SMTPServer, smtpServer, smtpServerShort})
	smtpPort = priorityInt([]int{config.SMTPPort, smtpPort, smtpPortShort})
	if smtpPort == 0 {
		smtpPort = 587
	}

	username = priorityString([]string{envUser, config.SMTPUsername, username, usernameShort})
	password = priorityString([]string{envPass, config.SMTPPassword, password, passwordShort})
	token = priorityString([]string{envToken, config.Token, token})
	authType = priorityString([]string{config.AuthType, authType})
	oauth2Mode = config.OAuth2 || oauth2Mode
	charset = priorityString([]string{config.Charset, charset, charsetShort})

	noAuth = config.NoAuth || noAuth || noAuthShort

	tlsMode = priorityString([]string{config.TLSMode, tlsMode, tlsModeShort})
	if tlsMode == "" {
		tlsMode = "tls"
	}

	fromEmail = priorityString([]string{config.FromEmail, fromEmail, fromEmailShort})
	fromName = priorityString([]string{config.FromName, fromName, fromNameShort})
	toEmail = priorityString([]string{config.ToEmail, toEmail, toEmailShort})
	ccEmail = priorityString([]string{strings.Join(config.CC, ","), ccEmail, ccEmailShort})
	bccEmail = priorityString([]string{strings.Join(config.BCC, ","), bccEmail, bccEmailShort})
	listFile = priorityString([]string{listFile, listFileShort})
	replyTo = priorityString([]string{replyTo, replyToShort})

	subject = priorityString([]string{subject, subjectShort})
	body = priorityString([]string{body, bodyShort})

	attachmentsFiles = priorityString([]string{attachmentsFiles, attachmentsFilesShort})
	inlineAttachmentsFiles = priorityString([]string{inlineAttachmentsFiles, inlineAttachmentsFilesShort})
	attachmentsList = priorityString([]string{config.AttachmentsList, attachmentsList, attachmentsListShort})
	attachmentsDir = priorityString([]string{config.AttachmentsDir, attachmentsDir, attachmentsDirShort})
	maxAttachmentMB = priorityInt([]int{config.MaxAttachmentMB, maxAttachmentMB, maxAttachmentMBShort})

	bodyFile = priorityString([]string{bodyFile, bodyFileShort})
	logFile = priorityString([]string{config.LogFile, logFile, logFileShort})

	retries = priorityInt([]int{config.Retries, retries, retriesShort})
	retryDelay = priorityInt([]int{config.RetryDelay, retryDelay})
	if retryDelay <= 0 {
		retryDelay = 5
	}
	timeout = priorityInt([]int{config.Timeout, timeout})
	if timeout <= 0 {
		timeout = 30
	}

	importance = priorityString([]string{config.Importance, importance, importanceShort})
	dsnReturn = priorityString([]string{config.DSNReturn, dsnReturn})
	jsonOutput = config.JSONOutput || jsonOutput || jsonOutputShort
	ndjsonOutput = config.NDJSONOutput || ndjsonOutput || ndjsonOutputShort
	debug = config.Debug || debug
	info = config.Info || info || infoShort || diag
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
			os.Exit(1)
		}
		diagParams := EmailParams{
			SMTPServer:   smtpServer,
			SMTPPort:     smtpPort,
			From:         fromEmail,
			TLSMode:      tlsMode,
			Timeout:      timeout,
			JSONOutput:   jsonOutput,
			NDJSONOutput: ndjsonOutput,
		}
		if _, err := RunDiagnostics(diagParams, printCerts); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if smtpServer == "" || fromEmail == "" || (toEmail == "" && listFile == "") || subject == "" || (body == "" && bodyFile == "") {
		fmt.Fprintln(os.Stderr, "Error: Missing required arguments for sending email.")
		PrintUsage()
		os.Exit(1)
	}

	var attachmentPaths []string
	if attachmentsFiles != "" {
		attachmentPaths = append(attachmentPaths, strings.Split(attachmentsFiles, ",")...)
	}
	if attachmentsList != "" {
		listFileAttachments, err := LoadAttachmentList(attachmentsList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading attachment list file %s: %v\n", attachmentsList, err)
			os.Exit(1)
		}
		attachmentPaths = append(attachmentPaths, listFileAttachments...)
	}
	if attachmentsDir != "" {
		dirFiles, err := ScanAttachmentDir(attachmentsDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning attachment directory %s: %v\n", attachmentsDir, err)
			os.Exit(1)
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
		listRecipients, err := LoadRecipientList(listFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading recipient list file %s: %v\n", listFile, err)
			os.Exit(1)
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
	}

	if _, err := SendEmail(params); err != nil {
		if !jsonOutput && !ndjsonOutput {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		os.Exit(1)
	}
}

func priorityString(strings []string) string {
	var result = ""
	for _, val := range strings {
		if val != "" {
			result = val
		}
	}
	return result
}

func priorityInt(ints []int) int {
	var result = 0
	for _, val := range ints {
		if val != 0 {
			result = val
		}
	}
	return result
}
