// Package mailxgo - Mailer Engine Unit Tests
//
// OBJECTIVES:
// Validate email payload composition, MIME header formatting, attachment size limits, retry backoff execution, audit logging, and output telemetry rendering.
//
// CORE COMPONENTS:
// - mockSender / mockFactory: Mock implementations of clientSender and clientFactory for network socket isolation.
// - TestSendEmail_Success: Tests successful email composition and dispatch.
// - TestSendEmail_ValidationErrors: Tests recipient list validation.
// - TestSendEmail_BodyFile: Tests HTML body file ingestion.
// - TestSendEmail_MaxAttachmentMB: Tests pre-dial payload total size guard calculations.
// - TestSendEmail_ClientCreationErrorAndRetries: Tests dial retry loop and audit log output.
// - TestSendEmail_AdvancedOptions: Tests DSN and Importance header settings.
// - TestOutputJSONResult: Tests output formatting in text, JSON, and NDJSON modes.
//
// FUNCTIONALITY & DATA FLOW:
// EmailParams -> SendEmail -> mockSender.DialAndSend -> Assert JSONResult telemetry and error state.
//
// TEST STRATEGY:
// Unit tests isolating network I/O via clientFactory function pointer overriding without external network access.
package mailxgo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wneessen/go-mail"
)

type mockSender struct {
	dialAndSendFunc func(m ...*mail.Msg) error
}

func (m *mockSender) DialAndSend(msg ...*mail.Msg) error {
	if m.dialAndSendFunc != nil {
		return m.dialAndSendFunc(msg...)
	}
	return nil
}

func mockFactory(sender clientSender, factoryErr error) clientFactory {
	return func(host string, opts ...mail.Option) (clientSender, error) {
		if factoryErr != nil {
			return nil, factoryErr
		}
		return sender, nil
	}
}

func TestSendEmail_Success(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{
		dialAndSendFunc: func(m ...*mail.Msg) error {
			return nil
		},
	}
	defaultClientFactory = mockFactory(mock, nil)

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		SMTPPort:   587,
		From:       "sender@example.com",
		FromName:   "Sender",
		To:         []string{" recipient@example.com "},
		CC:         []string{"cc@example.com"},
		BCC:        []string{"bcc@example.com"},
		ReplyTo:    "reply@example.com",
		Subject:    "Test Subject",
		Body:       "Test Body",
		LogFile:    logFile,
		JSONOutput: true,
	}

	res, err := SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail failed unexpectedly: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	logData, err := os.ReadFile(logFile)
	if err != nil || !strings.Contains(string(logData), "SUCCESS") {
		t.Errorf("expected audit log to contain SUCCESS, got: %s (err: %v)", string(logData), err)
	}
}

func TestSendEmail_ValidationErrors(t *testing.T) {
	// Missing recipient
	_, err := SendEmail(EmailParams{From: "sender@example.com"})
	if err == nil || !strings.Contains(err.Error(), "recipient") {
		t.Errorf("expected error for missing recipient, got %v", err)
	}

	// Invalid From format with FromName
	_, err = SendEmail(EmailParams{
		From:     "invalid-email",
		FromName: "Invalid",
		To:       []string{"recipient@example.com"},
	})
	if err == nil {
		t.Errorf("expected error for invalid From format, got nil")
	}

	// Invalid From without FromName
	_, err = SendEmail(EmailParams{
		From: "invalid-email",
		To:   []string{"recipient@example.com"},
	})
	if err == nil {
		t.Errorf("expected error for invalid From address, got nil")
	}
}

func TestSendEmail_BodyFile(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })
	defaultClientFactory = mockFactory(&mockSender{}, nil)

	tmpDir := t.TempDir()
	bodyFile := filepath.Join(tmpDir, "body.html")
	if err := os.WriteFile(bodyFile, []byte("<h1>Hello World</h1>"), 0o644); err != nil {
		t.Fatalf("failed to write body file: %v", err)
	}

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		BodyFile:   bodyFile,
	}

	res, err := SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail with BodyFile failed: %v", err)
	}

	// Non-existent BodyFile error
	params.BodyFile = filepath.Join(tmpDir, "nonexistent.html")
	_, err = SendEmail(params)
	if err == nil {
		t.Errorf("expected error for non-existent body file, got nil")
	}
}

func TestSendEmail_MaxAttachmentMB(t *testing.T) {
	tmpDir := t.TempDir()
	attFile := filepath.Join(tmpDir, "bigfile.dat")

	// Create 2 MB dummy file
	data := make([]byte, 2*1024*1024)
	if err := os.WriteFile(attFile, data, 0o644); err != nil {
		t.Fatalf("failed to create attachment file: %v", err)
	}

	params := EmailParams{
		SMTPServer:      "smtp.example.com",
		From:            "sender@example.com",
		To:              []string{"recipient@example.com"},
		Attachments:     []string{attFile},
		MaxAttachmentMB: 1, // Max limit 1 MB
	}

	_, err := SendEmail(params)
	if err == nil || !strings.Contains(err.Error(), "exceeds configured maximum limit") {
		t.Errorf("expected attachment size error, got %v", err)
	}
}

func TestSendEmail_ClientCreationErrorAndRetries(t *testing.T) {
	origFactory := defaultClientFactory
	origSleep := timeSleep
	timeSleep = func(d time.Duration) {}
	t.Cleanup(func() {
		defaultClientFactory = origFactory
		timeSleep = origSleep
	})

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "retry.log")

	// Factory that always errors
	defaultClientFactory = mockFactory(nil, errors.New("dial timeout"))

	params := EmailParams{
		SMTPServer:   "smtp.example.com",
		From:         "sender@example.com",
		To:           []string{"recipient@example.com"},
		Retries:      1,
		RetryDelay:   -1, // Test fallback to default retry delay
		LogFile:      logFile,
		NDJSONOutput: true,
	}

	res, err := SendEmail(params)
	if err == nil {
		t.Fatalf("expected error from SendEmail, got nil")
	}
	if res.Status != "error" || res.Attempts != 2 {
		t.Errorf("expected status error and 2 attempts, got status=%s, attempts=%d", res.Status, res.Attempts)
	}

	logData, err := os.ReadFile(logFile)
	if err != nil || !strings.Contains(string(logData), "ERROR") {
		t.Errorf("expected audit log to record ERROR, got: %s", string(logData))
	}
}

func TestSendEmail_DialAndSendError(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{
		dialAndSendFunc: func(m ...*mail.Msg) error {
			return errors.New("550 User unknown")
		},
	}
	defaultClientFactory = mockFactory(mock, nil)

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Retries:    0,
	}

	res, err := SendEmail(params)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if res.Status != "error" || res.Attempts != 1 {
		t.Errorf("expected 1 attempt error result, got attempts=%d status=%s", res.Attempts, res.Status)
	}
}

func TestSendEmail_AdvancedOptions(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error { return nil }}
	defaultClientFactory = mockFactory(mock, nil)

	tmpDir := t.TempDir()
	attFile := filepath.Join(tmpDir, "att.txt")
	inlineFile := filepath.Join(tmpDir, "img.png")
	_ = os.WriteFile(attFile, []byte("attachment"), 0o644)
	_ = os.WriteFile(inlineFile, []byte("image"), 0o644)

	params := EmailParams{
		SMTPServer:        "smtp.example.com",
		SMTPPort:          465,
		From:              "sender@example.com",
		To:                []string{"to@example.com"},
		Attachments:       []string{attFile},
		InlineAttachments: []string{inlineFile},
		Headers:           map[string]string{"X-Custom-Header": "TestValue"},
		Importance:        "high",
		TLSMode:           "ignore-trust",
		Timeout:           10,
		Debug:             true,
		AuthType:          "login",
		Username:          "user",
		Password:          "pass",
		Charset:           "UTF-8",
		DSNNotify:         []string{"SUCCESS", "FAILURE", "DELAY", "NEVER"},
		DSNReturn:         "FULL",
	}

	res, err := SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail with advanced options failed: %v", err)
	}

	// Test auth mode XOAUTH2 / OAuth2
	params.OAuth2 = true
	params.Token = "oauth-token"
	params.Importance = "low"
	params.TLSMode = "none"
	params.DSNReturn = "HDRS"
	res, err = SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail with XOAUTH2 options failed: %v", err)
	}

	// Test importance normal
	params.Importance = "normal"
	params.AuthType = "plain"
	res, err = SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail with normal importance failed: %v", err)
	}

	// Test CRAM-MD5 auth type
	params.AuthType = "cram-md5"
	res, err = SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail with cram-md5 auth failed: %v", err)
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected ErrorType
	}{
		{"nil error", "", ErrorTypeUnknown},
		{"TLS error", "tls: handshake failure", ErrorTypeTLS},
		{"certificate error", "x509: certificate signed by unknown authority", ErrorTypeTLS},
		{"auth 535 error", "535 5.7.8 Authentication credentials invalid", ErrorTypeAuth},
		{"auth 534 error", "534 5.7.9 Application-specific password required", ErrorTypeAuth},
		{"login error", "login failed: bad credentials", ErrorTypeAuth},
		{"dial error", "dial tcp: connection refused", ErrorTypeConnection},
		{"timeout error", "i/o timeout", ErrorTypeConnection},
		{"connection reset", "read: connection reset by peer", ErrorTypeConnection},
		{"generic send error", "SMTP error 550", ErrorTypeSend},
		{"unknown error", "some random error", ErrorTypeSend},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errMsg != "" {
				err = errors.New(tt.errMsg)
			}
			result := ClassifyError(err)
			if result != tt.expected {
				t.Errorf("ClassifyError(%q) = %v, want %v", tt.errMsg, result, tt.expected)
			}
		})
	}
}

func TestSendEmail_NoLogRecipients(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{
		dialAndSendFunc: func(m ...*mail.Msg) error {
			return nil
		},
	}
	defaultClientFactory = mockFactory(mock, nil)

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "privacy_audit.log")

	params := EmailParams{
		SMTPServer:      "smtp.example.com",
		SMTPPort:        587,
		From:            "sender@example.com",
		To:              []string{"recipient1@example.com", "recipient2@example.com"},
		Subject:         "Privacy Test",
		Body:            "Test Body",
		LogFile:         logFile,
		NoLogRecipients: true,
	}

	_, err := SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail failed unexpectedly: %v", err)
	}

	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logStr := string(logData)
	// Should contain redacted count, not actual emails
	if !strings.Contains(logStr, "[2 recipients redacted]") {
		t.Errorf("expected log to contain redacted recipients, got: %s", logStr)
	}
	if strings.Contains(logStr, "recipient1@example.com") {
		t.Errorf("log should NOT contain actual recipient email, got: %s", logStr)
	}
}

func TestOutputJSONResult(t *testing.T) {
	res := JSONResult{
		Status:     "success",
		Timestamp:  "2026-08-08T00:00:00Z",
		SMTPServer: "smtp.example.com",
		SMTPPort:   587,
		From:       "from@example.com",
		To:         []string{"to@example.com"},
		Subject:    "Test",
		Attempts:   1,
	}

	// Just invoke OutputJSONResult for text, JSON, and NDJSON modes to ensure no panics
	OutputJSONResult(res, false, false, "from@example.com", []string{"to@example.com"}, 1)
	OutputJSONResult(res, true, false, "from@example.com", []string{"to@example.com"}, 1)
	OutputJSONResult(res, false, true, "from@example.com", []string{"to@example.com"}, 1)
}
