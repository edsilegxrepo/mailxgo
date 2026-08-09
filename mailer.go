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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/wneessen/go-mail"
	mailsmtp "github.com/wneessen/go-mail/smtp"
)

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
var timeSleep = time.Sleep

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
}

// JSONResult represents the structured telemetry output payload for email dispatch execution.
type JSONResult struct {
	Status     string   `json:"status"`
	Timestamp  string   `json:"timestamp"`
	SMTPServer string   `json:"smtp_server"`
	SMTPPort   int      `json:"smtp_port"`
	From       string   `json:"from"`
	To         []string `json:"to"`
	Subject    string   `json:"subject"`
	Attempts   int      `json:"attempts"`
	Error      string   `json:"error,omitempty"`
}

// SendEmail transmits an email according to the specified EmailParams options.
// Data Flow: Validates payload boundaries -> Constructs MIME message -> Configures TLS/Auth -> Dial & Send retry loop -> Audit Logging & Output.
func SendEmail(params EmailParams) (*JSONResult, error) {
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
	if err := m.To(params.To...); err != nil {
		return nil, fmt.Errorf("failed to set To recipients: %w", err)
	}

	params.CC = CleanEmailList(params.CC)
	if len(params.CC) > 0 {
		if err := m.Cc(params.CC...); err != nil {
			return nil, fmt.Errorf("failed to set CC recipients: %w", err)
		}
	}

	params.BCC = CleanEmailList(params.BCC)
	if len(params.BCC) > 0 {
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

	// Set Body content
	if params.BodyFile != "" {
		bodyBytes, err := os.ReadFile(params.BodyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read body file: %w", err)
		}
		m.SetBodyString(mail.TypeTextHTML, string(bodyBytes))
	} else if params.Body != "" {
		m.SetBodyString(mail.TypeTextPlain, params.Body)
	}

	// Add Attachments
	for _, file := range params.Attachments {
		if file != "" {
			m.AttachFile(file)
		}
	}

	// Max Attachment Size Guard
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
			errStr := fmt.Sprintf("total attachment size (%.2f MB) exceeds configured maximum limit of %d MB",
				float64(totalBytes)/(1024*1024), params.MaxAttachmentMB)
			return nil, fmt.Errorf("%s", errStr)
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

	// TLS Options
	// #nosec G402 -- InsecureSkipVerify is configurable via tls-skip mode for internal relays with self-signed certs.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: params.TLSMode == "tls-skip",
		ServerName:         params.SMTPServer,
		MinVersion:         tls.VersionTLS12,
	}

	switch params.TLSMode {
	case "tls-skip":
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
	if params.NoAuth || (params.Username == "" && params.Password == "" && !params.OAuth2 && (params.AuthType == "" || strings.EqualFold(params.AuthType, "auto"))) {
		clientOptions = append(clientOptions, mail.WithSMTPAuthCustom(&noAuthSASL{}))
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

	attempts := 0
	var lastErr error
	maxAttempts := 1 + params.Retries
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for i := 0; i < maxAttempts; i++ {
		attempts++
		c, err := defaultClientFactory(params.SMTPServer, clientOptions...)
		if err != nil {
			lastErr = fmt.Errorf("failed to create SMTP client: %w", err)
		} else {
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
				delay = 5
			}
			retryMsg := fmt.Sprintf("Attempt %d/%d failed: %v. Retrying in %ds...\n", attempts, maxAttempts, lastErr, delay)
			if !params.JSONOutput && !params.NDJSONOutput {
				fmt.Fprint(os.Stderr, retryMsg)
			}
			if params.LogFile != "" {
				logAttempt(params.LogFile, retryMsg)
			}
			timeSleep(time.Duration(delay) * time.Second)
		}
	}

	timestamp := time.Now().Format(time.RFC3339)

	var res JSONResult
	if lastErr != nil {
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

	OutputJSONResult(res, params.JSONOutput, params.NDJSONOutput, params.From, params.To, attempts)
	return &res, lastErr
}

// OutputJSONResult handles rendering output in human text, JSON, or NDJSON.
func OutputJSONResult(res JSONResult, jsonOutput bool, ndjsonOutput bool, from string, to []string, attempts int) {
	if ndjsonOutput {
		data, _ := json.Marshal(res)
		fmt.Println(string(data))
	} else if jsonOutput {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
	} else if res.Status == "success" {
		fmt.Printf("Email sent successfully to %s from %s (attempts: %d)\n", strings.Join(to, ", "), from, attempts)
	}
}

func logAttempt(logFile string, msg string) {
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
	// #nosec G304 G302 -- User-configured audit log file path created with restricted 0600 file permissions.
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	if success {
		entry := fmt.Sprintf("[%s] SUCCESS: Email sent successfully to [%s] via %s:%d (attempts: %d)\n",
			timestamp, strings.Join(params.To, ", "), params.SMTPServer, params.SMTPPort, attempts)
		_, _ = f.WriteString(entry)
	} else {
		entry := fmt.Sprintf("[%s] ERROR: Email sending failed to [%s] via %s:%d after %d attempts: %s\n",
			timestamp, strings.Join(params.To, ", "), params.SMTPServer, params.SMTPPort, attempts, errStr)
		_, _ = f.WriteString(entry)
	}
}
