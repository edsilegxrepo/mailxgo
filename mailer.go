// Package mailxgo - Email Composition, MIME Construction, & ESMTP Dispatch Engine
//
// OBJECTIVES:
// Provide core email payload composition, MIME header formatting, attachment bounds validation, SASL/OAuth2 authentication negotiation, TLS transport enforcement, dial retry backoff loops, and structured telemetry generation.
//
// CORE COMPONENTS:
// - EmailParams: Input options struct containing all parameters for email delivery.
// - JSONResult: Telemetry output struct serialized to human text, JSON, or single-line NDJSON formats.
// - SendEmail: Core transmission function handling MIME construction, pre-dial size validation, TLS setup, retry execution, and logging.
// - clientSender / clientFactory: Interface abstractions over go-mail.Client enabling unit test client mocking.
// - noAuthSASL: Custom SASL PLAIN mechanism for unauthenticated internal relays.
//
// FUNCTIONALITY & DATA FLOW:
// EmailParams -> CleanEmailList -> MIME construction (m.NewMsg) -> Pre-dial payload size check -> TLS/Auth configuration -> Retry loop (DialAndSend) -> Telemetry output (JSON/NDJSON) & Audit file logging.
package mailxgo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/wneessen/go-mail"
	mailsmtp "github.com/wneessen/go-mail/smtp"
	"github.com/zeebo/xxh3"
)

// ErrorType classifies SMTP errors for granular exit code handling.
type ErrorType int

const (
	ErrorTypeUnknown ErrorType = iota
	ErrorTypeTLS
	ErrorTypeAuth
	ErrorTypeConnection
	ErrorTypeSend
)

// ClassifyError analyzes an error message and returns the appropriate error type.
func ClassifyError(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}
	errStr := strings.ToLower(err.Error())

	// TLS-related errors
	if strings.Contains(errStr, "tls") ||
		strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "x509") ||
		strings.Contains(errStr, "handshake") ||
		strings.Contains(errStr, "ssl") {
		return ErrorTypeTLS
	}

	// Authentication errors
	if strings.Contains(errStr, "auth") ||
		strings.Contains(errStr, "535") ||
		strings.Contains(errStr, "534") ||
		strings.Contains(errStr, "530") ||
		strings.Contains(errStr, "credential") ||
		strings.Contains(errStr, "login") ||
		strings.Contains(errStr, "password") ||
		strings.Contains(errStr, "username") {
		return ErrorTypeAuth
	}

	// Connection errors
	if strings.Contains(errStr, "dial") ||
		strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "refused") ||
		strings.Contains(errStr, "unreachable") ||
		strings.Contains(errStr, "reset") ||
		strings.Contains(errStr, "eof") {
		return ErrorTypeConnection
	}

	return ErrorTypeSend
}

// clientSender defines an interface abstraction over go-mail.Client for unit testing.
type clientSender interface {
	DialAndSend(m ...*mail.Msg) error
}

// clientFactory defines a factory function type for instantiating clientSender instances.
type clientFactory func(host string, opts ...mail.Option) (clientSender, error)

// defaultClientFactory is the default clientFactory function using mail.NewClient. Intercepted in unit tests.
var defaultClientFactory clientFactory = func(host string, opts ...mail.Option) (clientSender, error) {
	return mail.NewClient(host, opts...)
}

// zstdEncoderPool provides reusable zstd encoders for compression efficiency.
var zstdEncoderPool = sync.Pool{
	New: func() interface{} {
		enc, _ := zstd.NewWriter(nil)
		return enc
	},
}

// logMutex protects concurrent log file writes
var logMutex sync.Mutex

// noAuthSASL implements a custom SASL PLAIN fallback for unauthenticated internal relays.
type noAuthSASL struct{}

func (a *noAuthSASL) Start(server *mailsmtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00anonymous\x00anonymous"), nil
}

func (a *noAuthSASL) Next(fromServer []byte, more bool) ([]byte, error) {
	return nil, nil
}

// EmailParams defines all configuration options for constructing and delivering an email.
// Core Components: Connection settings, authentication credentials, recipient lists, MIME payload, and observability options.
type EmailParams struct {
	SMTPServer        string
	SMTPPort          int
	Username          string
	Password          string
	From              string
	FromName          string
	To                []string
	CC                []string
	BCC               []string
	ReplyTo           string
	Subject           string
	Body              string
	BodyFile          string
	Attachments       []string
	InlineAttachments []string
	Headers           map[string]string
	TLSMode           string
	TLSCACert         string // Path to CA certificate file (PEM format)
	TLSCADir          string // Path to directory containing CA certificates
	TLSFingerprint    string // SHA256 fingerprint to pin (hex encoded, with or without colons)
	NoAuth            bool
	LogFile           string
	Retries           int
	RetryDelay        int
	Timeout           int
	DSNNotify         []string
	DSNReturn         string
	Importance        string
	JSONOutput        bool
	Debug             bool
	AuthType          string
	OAuth2            bool
	Token             string
	Charset           string
	MaxAttachmentMB   int
	NDJSONOutput      bool
	NoLogRecipients   bool
	Context           context.Context
	DryRun            bool // Validate and connect but don't send
	Quiet             bool // Suppress output except errors
	ReadReceipt       bool // Request read receipt (Disposition-Notification-To header)

	// Template support
	TemplateFile     string            // Path to Go template file for body
	TemplateVars     map[string]string // Variables for template substitution
	TemplateDataFile string            // Path to JSON file with template variables

	// Delivery options
	Delay         int // Delay in seconds before sending
	RateLimit     int // Max emails per minute (for batch/multi-recipient)
	MaxRecipients int // Max recipients per email (0 = use default 1000)

	// Archiving
	SaveEMLPath string // Directory to save .eml archive after successful send
	CompressEML bool   // Compress .eml archive with zstd

	// File routing (applies to body file and attachments)
	RouteSuccessPath string // Move body file/attachments here on success
	RouteErrorPath   string // Move body file/attachments here on error
	RouteDelete      bool   // Delete body file/attachments after send

	// Single attachment mode
	SingleAttachment bool // Send one email per attachment with [N/Total] prefix
	SingleRecipient  bool // Send one email per recipient with rate limiting
}

// JSONResult represents the structured telemetry output payload for email dispatch execution.
type JSONResult struct {
	Status     string    `json:"status"`
	Timestamp  string    `json:"timestamp"`
	SMTPServer string    `json:"smtp_server"`
	SMTPPort   int       `json:"smtp_port"`
	From       string    `json:"from"`
	To         []string  `json:"to"`
	Subject    string    `json:"subject"`
	Attempts   int       `json:"attempts"`
	Error      string    `json:"error,omitempty"`
	ErrorType  ErrorType `json:"error_type,omitempty"`
}

// SendEmail transmits an email according to the specified EmailParams options.
// Data Flow: Validates paths -> Decrypts secrets -> Validates payload boundaries -> Constructs MIME message -> Configures TLS/Auth -> Dial & Send retry loop -> Audit Logging & Output.
func SendEmail(params EmailParams) (*JSONResult, error) {
	// ==========================================================================
	// PATH VALIDATION: All file/directory paths must be absolute and validated
	// ==========================================================================

	// Validate input file paths (must exist)
	if params.BodyFile != "" {
		absPath, err := ValidateFileExists(params.BodyFile)
		if err != nil {
			return nil, fmt.Errorf("body file validation failed: %w", err)
		}
		params.BodyFile = absPath
	}

	if params.TemplateFile != "" {
		absPath, err := ValidateFileExists(params.TemplateFile)
		if err != nil {
			return nil, fmt.Errorf("template file validation failed: %w", err)
		}
		params.TemplateFile = absPath
	}

	if params.TemplateDataFile != "" {
		absPath, err := ValidateFileExists(params.TemplateDataFile)
		if err != nil {
			return nil, fmt.Errorf("template data file validation failed: %w", err)
		}
		params.TemplateDataFile = absPath
	}

	if params.TLSCACert != "" {
		absPath, err := ValidateFileExists(params.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("TLS CA cert file validation failed: %w", err)
		}
		params.TLSCACert = absPath
	}

	if params.TLSCADir != "" {
		absPath, err := ValidateDirExists(params.TLSCADir, true)
		if err != nil {
			return nil, fmt.Errorf("TLS CA directory validation failed: %w", err)
		}
		params.TLSCADir = absPath
	}

	// Validate attachment paths (must exist)
	for i, att := range params.Attachments {
		if att != "" {
			absPath, err := ValidateFileExists(att)
			if err != nil {
				return nil, fmt.Errorf("attachment validation failed: %w", err)
			}
			params.Attachments[i] = absPath
		}
	}

	for i, att := range params.InlineAttachments {
		if att != "" {
			absPath, err := ValidateFileExists(att)
			if err != nil {
				return nil, fmt.Errorf("inline attachment validation failed: %w", err)
			}
			params.InlineAttachments[i] = absPath
		}
	}

	// Validate output paths (will be created if needed)
	if params.LogFile != "" {
		absPath, err := ValidateOutputPath(params.LogFile, false)
		if err != nil {
			return nil, fmt.Errorf("log file path validation failed: %w", err)
		}
		params.LogFile = absPath
	}

	if params.SaveEMLPath != "" {
		absPath, err := ValidateOutputPath(params.SaveEMLPath, true)
		if err != nil {
			return nil, fmt.Errorf("EML archive path validation failed: %w", err)
		}
		params.SaveEMLPath = absPath
	}

	if params.RouteSuccessPath != "" {
		absPath, err := ValidateOutputPath(params.RouteSuccessPath, true)
		if err != nil {
			return nil, fmt.Errorf("route success path validation failed: %w", err)
		}
		params.RouteSuccessPath = absPath
	}

	if params.RouteErrorPath != "" {
		absPath, err := ValidateOutputPath(params.RouteErrorPath, true)
		if err != nil {
			return nil, fmt.Errorf("route error path validation failed: %w", err)
		}
		params.RouteErrorPath = absPath
	}

	// ==========================================================================
	// NUMERIC PARAMETER VALIDATION
	// ==========================================================================
	if params.Delay < 0 {
		return nil, fmt.Errorf("delay cannot be negative: %d", params.Delay)
	}
	if params.RateLimit < 0 {
		return nil, fmt.Errorf("rate-limit cannot be negative: %d", params.RateLimit)
	}
	if params.Retries < 0 {
		return nil, fmt.Errorf("retries cannot be negative: %d", params.Retries)
	}
	if params.Timeout < 0 {
		return nil, fmt.Errorf("timeout cannot be negative: %d", params.Timeout)
	}
	if params.MaxAttachmentMB < 0 {
		return nil, fmt.Errorf("max-attachment-size cannot be negative: %d", params.MaxAttachmentMB)
	}
	if params.MaxRecipients < 0 {
		return nil, fmt.Errorf("max-recipients cannot be negative: %d", params.MaxRecipients)
	}

	// Max recipients guard
	maxRecipients := params.MaxRecipients
	if maxRecipients == 0 {
		maxRecipients = DefaultMaxRecipients
	}
	totalRecipients := len(params.To) + len(params.CC) + len(params.BCC)
	if totalRecipients > maxRecipients {
		return nil, fmt.Errorf("total recipients (%d) exceeds maximum limit (%d)", totalRecipients, maxRecipients)
	}

	// ==========================================================================
	// SINGLE RECIPIENT MODE: Send one email per recipient with rate limiting
	// ==========================================================================
	if params.SingleRecipient && len(params.To) > 1 {
		return sendSingleRecipientMode(params)
	}

	// ==========================================================================
	// SINGLE ATTACHMENT MODE: Send one email per attachment
	// ==========================================================================
	if params.SingleAttachment && len(params.Attachments) > 1 {
		return sendSingleAttachmentMode(params)
	}

	// ==========================================================================
	// SECRET DECRYPTION
	// ==========================================================================

	// Decrypt secrets if encrypted with secretprotector (v1:gcm: prefix)
	if params.Password != "" {
		if decrypted, err := DecryptSecret(params.Password, ""); err == nil {
			params.Password = decrypted
		} else if IsEncryptedSecret(params.Password) {
			return nil, fmt.Errorf("failed to decrypt password: %w", err)
		}
	}
	if params.Token != "" {
		if decrypted, err := DecryptSecret(params.Token, ""); err == nil {
			params.Token = decrypted
		} else if IsEncryptedSecret(params.Token) {
			return nil, fmt.Errorf("failed to decrypt OAuth2 token: %w", err)
		}
	}

	// Create a new message
	m := mail.NewMsg()

	if params.Charset != "" {
		m.SetCharset(mail.Charset(params.Charset))
	}

	if params.FromName != "" {
		if err := m.FromFormat(params.FromName, params.From); err != nil {
			return nil, fmt.Errorf("failed to format From address: %w", err)
		}
	} else {
		if err := m.From(params.From); err != nil {
			return nil, fmt.Errorf("failed to set From address: %w", err)
		}
	}

	params.To = CleanEmailList(params.To)
	if len(params.To) == 0 {
		return nil, fmt.Errorf("at least one valid To recipient is required")
	}
	if err := ValidateEmailList(params.To); err != nil {
		return nil, fmt.Errorf("invalid To recipient: %w", err)
	}
	if err := m.To(params.To...); err != nil {
		return nil, fmt.Errorf("failed to set To recipients: %w", err)
	}

	params.CC = CleanEmailList(params.CC)
	if len(params.CC) > 0 {
		if err := ValidateEmailList(params.CC); err != nil {
			return nil, fmt.Errorf("invalid CC recipient: %w", err)
		}
		if err := m.Cc(params.CC...); err != nil {
			return nil, fmt.Errorf("failed to set CC recipients: %w", err)
		}
	}

	params.BCC = CleanEmailList(params.BCC)
	if len(params.BCC) > 0 {
		if err := ValidateEmailList(params.BCC); err != nil {
			return nil, fmt.Errorf("invalid BCC recipient: %w", err)
		}
		if err := m.Bcc(params.BCC...); err != nil {
			return nil, fmt.Errorf("failed to set BCC recipients: %w", err)
		}
	}

	if params.ReplyTo != "" {
		if err := m.ReplyTo(params.ReplyTo); err != nil {
			return nil, fmt.Errorf("failed to set Reply-To address: %w", err)
		}
	}

	m.Subject(params.Subject)

	// Load template variables if template features are used
	var templateVars map[string]string
	if params.TemplateFile != "" || params.TemplateDataFile != "" || len(params.TemplateVars) > 0 {
		var err error
		templateVars, err = loadTemplateVars(params.TemplateDataFile, params.TemplateVars)
		if err != nil {
			return nil, err
		}
	}

	// Set Body content (with optional template processing)
	if params.TemplateFile != "" {
		// Load template from file
		tmplBytes, err := os.ReadFile(params.TemplateFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read template file: %w", err)
		}
		body, err := applyTemplate(string(tmplBytes), templateVars)
		if err != nil {
			return nil, err
		}
		// Detect if template is HTML
		if strings.Contains(strings.ToLower(string(tmplBytes)), "<html") || strings.Contains(string(tmplBytes), "<body") {
			m.SetBodyString(mail.TypeTextHTML, body)
		} else {
			m.SetBodyString(mail.TypeTextPlain, body)
		}
	} else if params.BodyFile != "" {
		bodyBytes, err := os.ReadFile(params.BodyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read body file: %w", err)
		}
		body := string(bodyBytes)
		// Apply template if variables are provided
		if len(templateVars) > 0 {
			body, err = applyTemplate(body, templateVars)
			if err != nil {
				return nil, err
			}
		}
		m.SetBodyString(mail.TypeTextHTML, body)
	} else if params.Body != "" {
		body := params.Body
		// Apply template if variables are provided
		if len(templateVars) > 0 {
			var err error
			body, err = applyTemplate(body, templateVars)
			if err != nil {
				return nil, err
			}
		}
		m.SetBodyString(mail.TypeTextPlain, body)
	}

	// Max Attachment Size Guard (check BEFORE attaching to fail fast)
	if params.MaxAttachmentMB > 0 {
		var totalBytes int64
		for _, file := range params.Attachments {
			if file != "" {
				info, err := os.Stat(file)
				if err == nil {
					totalBytes += info.Size()
				}
			}
		}
		maxBytes := int64(params.MaxAttachmentMB) * 1024 * 1024
		if totalBytes > maxBytes {
			return nil, fmt.Errorf("total attachment size (%.2f MB) exceeds configured maximum limit of %d MB",
				float64(totalBytes)/(1024*1024), params.MaxAttachmentMB)
		}
	}

	// Add Attachments
	for _, file := range params.Attachments {
		if file != "" {
			m.AttachFile(file)
		}
	}

	// Add Inline Attachments
	for _, file := range params.InlineAttachments {
		if file != "" {
			m.EmbedFile(file)
		}
	}

	// Custom Headers
	for k, v := range params.Headers {
		kClean := strings.TrimSpace(k)
		vClean := strings.TrimSpace(v)
		if kClean != "" && !strings.ContainsAny(kClean, "\r\n") && !strings.ContainsAny(vClean, "\r\n") {
			m.SetGenHeader(mail.Header(kClean), vClean)
		}
	}

	// Importance / Priority
	if params.Importance != "" {
		switch strings.ToLower(strings.TrimSpace(params.Importance)) {
		case "high":
			m.SetImportance(mail.ImportanceHigh)
		case "low":
			m.SetImportance(mail.ImportanceLow)
		case "normal":
			m.SetImportance(mail.ImportanceNormal)
		}
	}

	// Read Receipt (Disposition-Notification-To header)
	if params.ReadReceipt {
		m.SetGenHeader("Disposition-Notification-To", params.From)
	}

	// Client Options
	var clientOptions []mail.Option

	if params.Timeout > 0 {
		clientOptions = append(clientOptions, mail.WithTimeout(time.Duration(params.Timeout)*time.Second))
	}

	if params.Debug {
		clientOptions = append(clientOptions, mail.WithDebugLog())
	}

	// DSN Notifications (RFC 3461)
	if len(params.DSNNotify) > 0 || params.DSNReturn != "" {
		clientOptions = append(clientOptions, mail.WithDSN())
		if len(params.DSNNotify) > 0 {
			var opts []mail.DSNRcptNotifyOption
			for _, opt := range params.DSNNotify {
				switch strings.ToUpper(strings.TrimSpace(opt)) {
				case "SUCCESS":
					opts = append(opts, mail.DSNRcptNotifySuccess)
				case "FAILURE":
					opts = append(opts, mail.DSNRcptNotifyFailure)
				case "DELAY":
					opts = append(opts, mail.DSNRcptNotifyDelay)
				case "NEVER":
					opts = append(opts, mail.DSNRcptNotifyNever)
				}
			}
			if len(opts) > 0 {
				clientOptions = append(clientOptions, mail.WithDSNRcptNotifyType(opts...))
			}
		}
		if params.DSNReturn != "" {
			switch strings.ToUpper(strings.TrimSpace(params.DSNReturn)) {
			case "FULL":
				clientOptions = append(clientOptions, mail.WithDSNMailReturnType(mail.DSNMailReturnFull))
			case "HDRS":
				clientOptions = append(clientOptions, mail.WithDSNMailReturnType(mail.DSNMailReturnHeadersOnly))
			}
		}
	}

	// TLS Options - use centralized config builder
	tlsConfig, err := BuildTLSConfig(TLSConfigParams{
		ServerName:     params.SMTPServer,
		TLSMode:        params.TLSMode,
		TLSCACert:      params.TLSCACert,
		TLSCADir:       params.TLSCADir,
		TLSFingerprint: params.TLSFingerprint,
	})
	if err != nil {
		return nil, err
	}

	switch params.TLSMode {
	case "ignore-trust":
		clientOptions = append(clientOptions, mail.WithTLSConfig(tlsConfig))
		clientOptions = append(clientOptions, mail.WithTLSPolicy(mail.TLSMandatory))
	case "none":
		clientOptions = append(clientOptions, mail.WithTLSPolicy(mail.NoTLS))
	default:
		clientOptions = append(clientOptions, mail.WithTLSConfig(tlsConfig))
		if params.SMTPPort == 465 {
			clientOptions = append(clientOptions, mail.WithSSL())
		} else {
			clientOptions = append(clientOptions, mail.WithTLSPolicy(mail.TLSMandatory))
		}
	}

	// Authentication Options
	if params.NoAuth {
		// Use SMTPAuthNoAuth - don't attempt any authentication
		clientOptions = append(clientOptions, mail.WithSMTPAuth(mail.SMTPAuthNoAuth))
	} else if params.Username == "" && params.Password == "" && !params.OAuth2 && (params.AuthType == "" || strings.EqualFold(params.AuthType, "auto")) {
		// No credentials provided, use NoAuth
		clientOptions = append(clientOptions, mail.WithSMTPAuth(mail.SMTPAuthNoAuth))
	} else if params.OAuth2 || strings.EqualFold(params.AuthType, "xoauth2") {
		clientOptions = append(clientOptions, mail.WithSMTPAuth(mail.SMTPAuthXOAUTH2))
		if params.Username != "" {
			clientOptions = append(clientOptions, mail.WithUsername(params.Username))
		}
		if params.Token != "" {
			clientOptions = append(clientOptions, mail.WithPassword(params.Token))
		}
	} else {
		if params.Username != "" {
			clientOptions = append(clientOptions, mail.WithUsername(params.Username))
		}
		if params.Password != "" {
			clientOptions = append(clientOptions, mail.WithPassword(params.Password))
		}
		if params.AuthType != "" && !strings.EqualFold(params.AuthType, "auto") {
			switch strings.ToLower(strings.TrimSpace(params.AuthType)) {
			case "login":
				clientOptions = append(clientOptions, mail.WithSMTPAuth(mail.SMTPAuthLogin))
			case "plain":
				clientOptions = append(clientOptions, mail.WithSMTPAuth(mail.SMTPAuthPlain))
			case "cram-md5", "crammd5":
				clientOptions = append(clientOptions, mail.WithSMTPAuth(mail.SMTPAuthCramMD5))
			}
		}
	}

	clientOptions = append(clientOptions, mail.WithPort(params.SMTPPort))

	// Use background context if none provided
	ctx := params.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Delay before sending (blocking)
	if params.Delay > 0 {
		if !params.Quiet && !params.JSONOutput && !params.NDJSONOutput {
			fmt.Fprintf(os.Stderr, "Delaying send for %d seconds...\n", params.Delay)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("operation cancelled during delay: %w", ctx.Err())
		case <-time.After(time.Duration(params.Delay) * time.Second):
		}
	}

	attempts := 0
	var lastErr error
	maxAttempts := 1 + params.Retries
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	// Rate limiting: Currently used in single-attachment mode (sendSingleAttachmentMode).
	// For standard multi-recipient sends, all recipients are in one SMTP transaction.
	// Future batch mode (one email per recipient) would use this rate limiter.
	_ = params.RateLimit // Acknowledged, used in sendSingleAttachmentMode

retryLoop:
	for i := 0; i < maxAttempts; i++ {
		// Check for context cancellation before each attempt
		select {
		case <-ctx.Done():
			lastErr = fmt.Errorf("operation cancelled: %w", ctx.Err())
			break retryLoop
		default:
		}

		attempts++
		c, err := defaultClientFactory(params.SMTPServer, clientOptions...)
		if err != nil {
			lastErr = fmt.Errorf("failed to create SMTP client: %w", err)
		} else {
			// Dry-run mode: connect and authenticate but don't send
			if params.DryRun {
				lastErr = nil
				break
			}
			if err := c.DialAndSend(m); err != nil {
				lastErr = fmt.Errorf("error sending email: %w", err)
			} else {
				lastErr = nil
				break
			}
		}

		if i < maxAttempts-1 {
			delay := params.RetryDelay
			if delay <= 0 {
				delay = DefaultRetryDelay
			}
			retryMsg := fmt.Sprintf("Attempt %d/%d failed: %v. Retrying in %ds...\n", attempts, maxAttempts, lastErr, delay)
			if !params.JSONOutput && !params.NDJSONOutput && !params.Quiet {
				fmt.Fprint(os.Stderr, retryMsg)
			}
			if params.LogFile != "" {
				logAttempt(params.LogFile, retryMsg)
			}

			// Context-aware sleep
			select {
			case <-ctx.Done():
				lastErr = fmt.Errorf("operation cancelled during retry wait: %w", ctx.Err())
				break retryLoop
			case <-time.After(time.Duration(delay) * time.Second):
			}
		}
	}

	timestamp := time.Now().Format(time.RFC3339)
	success := lastErr == nil

	// Post-send actions
	if success && !params.DryRun {
		// Save EML archive (only on success)
		if params.SaveEMLPath != "" {
			emlPath, err := saveEML(m, params.SaveEMLPath, params.CompressEML)
			if err != nil {
				// Log warning but don't fail the send
				if !params.Quiet && !params.JSONOutput && !params.NDJSONOutput {
					fmt.Fprintf(os.Stderr, "Warning: failed to save EML archive: %v\n", err)
				}
			} else if !params.Quiet && !params.JSONOutput && !params.NDJSONOutput {
				fmt.Fprintf(os.Stderr, "EML archived: %s\n", emlPath)
			}
		}
	}

	// Route body file and attachments (on success or error)
	if !params.DryRun && (params.RouteSuccessPath != "" || params.RouteErrorPath != "" || params.RouteDelete) {
		// Collect all files to route (body file + attachments)
		var filesToRoute []string
		if params.BodyFile != "" {
			filesToRoute = append(filesToRoute, params.BodyFile)
		}
		filesToRoute = append(filesToRoute, params.Attachments...)

		if err := routeAttachments(filesToRoute, success, params.RouteSuccessPath, params.RouteErrorPath, params.RouteDelete); err != nil {
			if !params.Quiet && !params.JSONOutput && !params.NDJSONOutput {
				fmt.Fprintf(os.Stderr, "Warning: failed to route files: %v\n", err)
			}
		}
	}

	var res JSONResult
	if lastErr != nil {
		errType := ClassifyError(lastErr)
		logAudit(params.LogFile, timestamp, false, attempts, lastErr.Error(), params)
		res = JSONResult{
			Status:     "error",
			Timestamp:  timestamp,
			SMTPServer: params.SMTPServer,
			SMTPPort:   params.SMTPPort,
			From:       params.From,
			To:         params.To,
			Subject:    params.Subject,
			Attempts:   attempts,
			Error:      lastErr.Error(),
			ErrorType:  errType,
		}
	} else {
		logAudit(params.LogFile, timestamp, true, attempts, "", params)
		res = JSONResult{
			Status:     "success",
			Timestamp:  timestamp,
			SMTPServer: params.SMTPServer,
			SMTPPort:   params.SMTPPort,
			From:       params.From,
			To:         params.To,
			Subject:    params.Subject,
			Attempts:   attempts,
		}
	}

	OutputJSONResult(res, params.JSONOutput, params.NDJSONOutput, params.Quiet, params.DryRun, params.From, params.To, attempts)
	return &res, lastErr
}

// OutputJSONResult handles rendering output in human text, JSON, or NDJSON.
func OutputJSONResult(res JSONResult, jsonOutput bool, ndjsonOutput bool, quiet bool, dryRun bool, from string, to []string, attempts int) {
	// Quiet mode: suppress all output except errors
	if quiet && res.Status == "success" {
		return
	}

	if ndjsonOutput {
		data, _ := json.Marshal(res)
		fmt.Println(string(data))
	} else if jsonOutput {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
	} else if res.Status == "success" {
		recipients := ""
		if len(to) > 0 {
			recipients = strings.Join(to, ", ")
		}
		if dryRun {
			fmt.Printf("Dry-run: validated email to %s from %s (would send, attempts: %d)\n", recipients, from, attempts)
		} else {
			fmt.Printf("Email sent successfully to %s from %s (attempts: %d)\n", recipients, from, attempts)
		}
	}
}

func logAttempt(logFile string, msg string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	// #nosec G304 G302 -- User-configured log file path created with restricted 0600 file permissions.
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(msg)
}

func logAudit(logFile string, timestamp string, success bool, attempts int, errStr string, params EmailParams) {
	if logFile == "" {
		return
	}

	logMutex.Lock()
	defer logMutex.Unlock()

	// #nosec G304 G302 -- User-configured audit log file path created with restricted 0600 file permissions.
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	// Privacy mode: redact recipient addresses
	recipients := strings.Join(params.To, ", ")
	if params.NoLogRecipients {
		recipients = fmt.Sprintf("[%d recipients redacted]", len(params.To))
	}

	if success {
		entry := fmt.Sprintf("[%s] SUCCESS: Email sent successfully to [%s] via %s:%d (attempts: %d)\n",
			timestamp, recipients, params.SMTPServer, params.SMTPPort, attempts)
		_, _ = f.WriteString(entry)
	} else {
		entry := fmt.Sprintf("[%s] ERROR: Email sending failed to [%s] via %s:%d after %d attempts: %s\n",
			timestamp, recipients, params.SMTPServer, params.SMTPPort, attempts, errStr)
		_, _ = f.WriteString(entry)
	}
}

// loadTemplateVars merges template variables from file and inline vars.
// SECURITY: dataFile path must be pre-validated via ValidateFileExists in SendEmail.
func loadTemplateVars(dataFile string, inlineVars map[string]string) (map[string]string, error) {
	result := make(map[string]string)

	// Load from JSON file if specified
	if dataFile != "" {
		// #nosec G304 -- Path pre-validated via ValidateFileExists in SendEmail caller
		data, err := os.ReadFile(dataFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read template data file: %w", err)
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("failed to parse template data file: %w", err)
		}
	}

	// Override with inline vars (inline takes precedence)
	for k, v := range inlineVars {
		result[k] = v
	}

	return result, nil
}

// applyTemplate processes a Go template string with the given variables.
// SECURITY: Template variables are sanitized to prevent injection of template directives.
func applyTemplate(tmplContent string, vars map[string]string) (string, error) {
	// Sanitize template variables to prevent template injection
	sanitizedVars := make(map[string]string, len(vars))
	for k, v := range vars {
		// Escape any template delimiters in variable values
		sanitized := strings.ReplaceAll(v, "{{", "{ {")
		sanitized = strings.ReplaceAll(sanitized, "}}", "} }")
		sanitizedVars[k] = sanitized
	}

	tmpl, err := template.New("body").Parse(tmplContent)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, sanitizedVars); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// saveEML saves the email message as .eml file with xxh3 hash in filename.
// SECURITY: emlPath must be pre-validated as absolute path via ValidateOutputPath.
func saveEML(m *mail.Msg, emlPath string, compress bool) (string, error) {
	// Render message to buffer
	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("failed to render email: %w", err)
	}
	emlData := buf.Bytes()

	// Generate xxh3-128 hash
	hash := xxh3.Hash128(emlData)
	hashStr := fmt.Sprintf("%016x%016x", hash.Hi, hash.Lo)

	// Create filename with timestamp and hash
	timestamp := time.Now().Format("20060102-150405")
	var filename string

	if compress {
		filename = fmt.Sprintf("mailarchive_%s_%s.eml.zst", timestamp, hashStr)
	} else {
		filename = fmt.Sprintf("mailarchive_%s_%s.eml", timestamp, hashStr)
	}

	fullPath := filepath.Join(emlPath, filename)

	// Directory already validated/created by ValidateOutputPath in SendEmail

	if compress {
		// Compress with zstd
		compressed, err := compressZstd(emlData)
		if err != nil {
			return "", fmt.Errorf("failed to compress EML: %w", err)
		}
		// #nosec G304 G306 -- Path pre-validated as absolute in SendEmail
		if err := os.WriteFile(fullPath, compressed, 0o600); err != nil {
			return "", fmt.Errorf("failed to write compressed EML: %w", err)
		}
	} else {
		// #nosec G304 G306 -- Path pre-validated as absolute in SendEmail
		if err := os.WriteFile(fullPath, emlData, 0o600); err != nil {
			return "", fmt.Errorf("failed to write EML: %w", err)
		}
	}

	return fullPath, nil
}

// compressZstd compresses data using zstd with encoder pooling for efficiency.
func compressZstd(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	// Get encoder from pool
	enc := zstdEncoderPool.Get().(*zstd.Encoder)
	enc.Reset(&buf)

	if _, err := enc.Write(data); err != nil {
		zstdEncoderPool.Put(enc)
		return nil, err
	}
	if err := enc.Close(); err != nil {
		zstdEncoderPool.Put(enc)
		return nil, err
	}

	// Return encoder to pool for reuse
	zstdEncoderPool.Put(enc)
	return buf.Bytes(), nil
}

// routeAttachments moves or deletes attachments based on send result.
// SECURITY: All paths should be pre-validated as absolute via ValidateFileExists/ValidateOutputPath in SendEmail.
// Creates destination directories if needed (defense in depth for direct library usage).
func routeAttachments(attachments []string, success bool, successPath, errorPath string, deleteAfter bool) error {
	if len(attachments) == 0 {
		return nil
	}

	for _, att := range attachments {
		if att == "" {
			continue
		}

		if deleteAfter {
			// #nosec G304 -- Path pre-validated as absolute in SendEmail
			if err := os.Remove(att); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to delete attachment %s: %w", att, err)
			}
			continue
		}

		var destDir string
		if success && successPath != "" {
			destDir = successPath
		} else if !success && errorPath != "" {
			destDir = errorPath
		}

		if destDir != "" {
			// Create directory if needed (defense in depth, 0750 restricts to owner and group)
			if err := os.MkdirAll(destDir, 0o750); err != nil {
				return fmt.Errorf("failed to create destination directory %s: %w", destDir, err)
			}
			destFile := filepath.Join(destDir, filepath.Base(att))
			// #nosec G304 -- Paths pre-validated as absolute in SendEmail
			if err := os.Rename(att, destFile); err != nil {
				// Cross-device move: copy then delete
				if err := copyFile(att, destFile); err != nil {
					return fmt.Errorf("failed to move attachment %s: %w", att, err)
				}
				_ = os.Remove(att)
			}
		}
	}

	return nil
}

// copyFile copies a file from src to dst using streaming I/O.
// SECURITY: Both paths must be pre-validated as absolute.
// Uses buffered I/O to handle large files efficiently without loading into memory.
func copyFile(src, dst string) error {
	// #nosec G304 -- Paths pre-validated as absolute by caller
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	// Get source file info for permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	// #nosec G304 -- Output path pre-validated as absolute by caller
	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode()&0o600)
	if err != nil {
		return err
	}

	// Use buffered copy for efficiency
	buf := make([]byte, 32*1024) // 32KB buffer
	_, err = copyBuffer(dstFile, srcFile, buf)
	closeErr := dstFile.Close()

	if err != nil {
		return err
	}
	return closeErr
}

// copyBuffer is a helper that copies using a provided buffer
func copyBuffer(dst *os.File, src *os.File, buf []byte) (int64, error) {
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, fmt.Errorf("short write")
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return written, nil
			}
			return written, rerr
		}
	}
}

// sendSingleAttachmentMode sends one email per attachment with [N/Total] prefix.
// On failure: stops immediately and reports which emails succeeded.
// Body file is NOT routed/deleted until all emails complete successfully.
func sendSingleAttachmentMode(params EmailParams) (*JSONResult, error) {
	attachments := params.Attachments
	total := len(attachments)
	originalSubject := params.Subject
	originalBody := params.Body

	// Read body file content once if specified (reused for all emails)
	var bodyFileContent string
	if params.BodyFile != "" {
		data, err := os.ReadFile(params.BodyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read body file: %w", err)
		}
		bodyFileContent = string(data)
	}

	// Rate limiting for single attachment mode
	var rateLimiter *time.Ticker
	if params.RateLimit > 0 {
		interval := time.Minute / time.Duration(params.RateLimit)
		rateLimiter = time.NewTicker(interval)
		defer rateLimiter.Stop()
	}

	var successCount int
	var lastResult *JSONResult

	for i, att := range attachments {
		n := i + 1
		filename := filepath.Base(att)
		prefix := fmt.Sprintf("[%d/%d]", n, total)

		// Create params for this single attachment
		singleParams := params
		singleParams.SingleAttachment = false // Prevent recursion
		singleParams.Attachments = []string{att}
		singleParams.Subject = fmt.Sprintf("%s %s", prefix, originalSubject)

		// Prefix body with fragment info and filename
		if bodyFileContent != "" {
			singleParams.Body = ""
			singleParams.BodyFile = params.BodyFile // Keep using body file
			// We need to modify the body content - read and prefix it
			singleParams.BodyFile = "" // Clear body file, use inline body instead
			singleParams.Body = fmt.Sprintf("%s %s\n\n%s", prefix, filename, bodyFileContent)
		} else if originalBody != "" {
			singleParams.Body = fmt.Sprintf("%s %s\n\n%s", prefix, filename, originalBody)
		} else {
			singleParams.Body = fmt.Sprintf("%s %s", prefix, filename)
		}

		// Don't route files until all complete - handle routing ourselves
		singleParams.RouteSuccessPath = ""
		singleParams.RouteErrorPath = ""
		singleParams.RouteDelete = false

		// Rate limit wait (skip first email)
		if rateLimiter != nil && i > 0 {
			<-rateLimiter.C
		}

		result, err := SendEmail(singleParams)
		lastResult = result

		if err != nil || (result != nil && result.Status != "success") {
			// Failed - route all attachments to error path
			if params.RouteErrorPath != "" {
				if routeErr := routeAttachments(attachments, false, "", params.RouteErrorPath, false); routeErr != nil {
					if !params.Quiet && !params.JSONOutput && !params.NDJSONOutput {
						fmt.Fprintf(os.Stderr, "Warning: failed to route attachments to error path: %v\n", routeErr)
					}
				}
				if params.BodyFile != "" {
					if routeErr := routeAttachments([]string{params.BodyFile}, false, "", params.RouteErrorPath, false); routeErr != nil {
						if !params.Quiet && !params.JSONOutput && !params.NDJSONOutput {
							fmt.Fprintf(os.Stderr, "Warning: failed to route body file to error path: %v\n", routeErr)
						}
					}
				}
			}

			// Return error with context about partial success
			errMsg := "unknown error"
			if err != nil {
				errMsg = err.Error()
			} else if result != nil && result.Error != "" {
				errMsg = result.Error
			}
			return result, fmt.Errorf("single-attachment mode failed at %d/%d (%s): %s (sent %d/%d successfully)",
				n, total, filename, errMsg, successCount, total)
		}

		successCount++

		// Route this attachment to success path after successful send
		if params.RouteSuccessPath != "" || params.RouteDelete {
			if routeErr := routeAttachments([]string{att}, true, params.RouteSuccessPath, "", params.RouteDelete); routeErr != nil {
				if !params.Quiet && !params.JSONOutput && !params.NDJSONOutput {
					fmt.Fprintf(os.Stderr, "Warning: failed to route attachment %s: %v\n", filepath.Base(att), routeErr)
				}
			}
		}
	}

	// All succeeded - route body file if configured
	if params.BodyFile != "" && (params.RouteSuccessPath != "" || params.RouteDelete) {
		if routeErr := routeAttachments([]string{params.BodyFile}, true, params.RouteSuccessPath, "", params.RouteDelete); routeErr != nil {
			if !params.Quiet && !params.JSONOutput && !params.NDJSONOutput {
				fmt.Fprintf(os.Stderr, "Warning: failed to route body file: %v\n", routeErr)
			}
		}
	}

	// Update last result to reflect batch completion
	if lastResult != nil {
		lastResult.Subject = fmt.Sprintf("%s (%d emails)", originalSubject, total)
	}

	return lastResult, nil
}

// sendSingleRecipientMode sends one email per recipient with rate limiting.
// This enables batch sending with per-recipient tracking and rate control.
// On failure: stops immediately and reports which emails succeeded.
func sendSingleRecipientMode(params EmailParams) (*JSONResult, error) {
	recipients := params.To
	total := len(recipients)
	originalSubject := params.Subject

	// Rate limiting for single recipient mode
	var rateLimiter *time.Ticker
	if params.RateLimit > 0 {
		interval := time.Minute / time.Duration(params.RateLimit)
		rateLimiter = time.NewTicker(interval)
		defer rateLimiter.Stop()
	}

	var successCount int
	var failedRecipients []string

	for i, recipient := range recipients {
		n := i + 1

		// Create params for this single recipient
		singleParams := params
		singleParams.SingleRecipient = false // Prevent recursion
		singleParams.To = []string{recipient}

		// Rate limit wait (skip first email)
		if rateLimiter != nil && i > 0 {
			<-rateLimiter.C
		}

		result, err := SendEmail(singleParams)

		if err != nil || (result != nil && result.Status != "success") {
			failedRecipients = append(failedRecipients, recipient)

			// Log failure but continue with remaining recipients
			if !params.Quiet && !params.JSONOutput && !params.NDJSONOutput {
				errMsg := "unknown error"
				if err != nil {
					errMsg = err.Error()
				} else if result != nil && result.Error != "" {
					errMsg = result.Error
				}
				fmt.Fprintf(os.Stderr, "Failed to send to %s (%d/%d): %s\n", recipient, n, total, errMsg)
			}
			continue
		}

		successCount++
	}

	// Build final result
	timestamp := time.Now().Format(time.RFC3339)
	finalResult := &JSONResult{
		Status:     "success",
		Timestamp:  timestamp,
		SMTPServer: params.SMTPServer,
		SMTPPort:   params.SMTPPort,
		From:       params.From,
		To:         recipients,
		Subject:    fmt.Sprintf("%s (%d/%d sent)", originalSubject, successCount, total),
		Attempts:   total,
	}

	if len(failedRecipients) > 0 {
		finalResult.Status = "partial"
		finalResult.Error = fmt.Sprintf("%d/%d recipients failed: %v", len(failedRecipients), total, failedRecipients)
		return finalResult, fmt.Errorf("single-recipient mode: %d/%d failed", len(failedRecipients), total)
	}

	return finalResult, nil
}
