package mailxgo

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/wneessen/go-mail"
)

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
		m.SetHeader(mail.Header(k), v)
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
	tlsConfig := &tls.Config{
		ServerName: params.SMTPServer,
	}

	if params.TLSMode == "tls-skip" {
		tlsConfig.InsecureSkipVerify = true
		clientOptions = append(clientOptions, mail.WithTLSConfig(tlsConfig))
		clientOptions = append(clientOptions, mail.WithTLSPolicy(mail.TLSMandatory))
	} else if params.TLSMode == "none" {
		clientOptions = append(clientOptions, mail.WithTLSPolicy(mail.NoTLS))
	} else {
		clientOptions = append(clientOptions, mail.WithTLSConfig(tlsConfig))
		if params.SMTPPort == 465 {
			clientOptions = append(clientOptions, mail.WithSSL())
		} else {
			clientOptions = append(clientOptions, mail.WithTLSPolicy(mail.TLSMandatory))
		}
	}

	// Authentication Options
	if params.NoAuth {
		// Unauthenticated SMTP relay
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
		c, err := mail.NewClient(params.SMTPServer, clientOptions...)
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
			time.Sleep(time.Duration(delay) * time.Second)
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
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(msg)
}

func logAudit(logFile string, timestamp string, success bool, attempts int, errStr string, params EmailParams) {
	if logFile == "" {
		return
	}
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	if success {
		entry := fmt.Sprintf("[%s] SUCCESS: Email sent successfully to [%s] via %s:%d (attempts: %d)\n",
			timestamp, strings.Join(params.To, ", "), params.SMTPServer, params.SMTPPort, attempts)
		f.WriteString(entry)
	} else {
		entry := fmt.Sprintf("[%s] ERROR: Email sending failed to [%s] via %s:%d after %d attempts: %s\n",
			timestamp, strings.Join(params.To, ", "), params.SMTPServer, params.SMTPPort, attempts, errStr)
		f.WriteString(entry)
	}
}
