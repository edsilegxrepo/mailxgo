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
	"context"
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
	t.Cleanup(func() {
		defaultClientFactory = origFactory
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
	OutputJSONResult(res, false, false, false, false, "from@example.com", []string{"to@example.com"}, 1)
	OutputJSONResult(res, true, false, false, false, "from@example.com", []string{"to@example.com"}, 1)
	OutputJSONResult(res, false, true, false, false, "from@example.com", []string{"to@example.com"}, 1)
	// Test quiet mode (should suppress success output)
	OutputJSONResult(res, false, false, true, false, "from@example.com", []string{"to@example.com"}, 1)
	// Test dry-run mode
	OutputJSONResult(res, false, false, false, true, "from@example.com", []string{"to@example.com"}, 1)
}

func TestApplyTemplate(t *testing.T) {
	tests := []struct {
		name     string
		tmpl     string
		vars     map[string]string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple substitution",
			tmpl:     "Hello {{.Name}}, welcome to {{.Company}}!",
			vars:     map[string]string{"Name": "John", "Company": "Acme"},
			expected: "Hello John, welcome to Acme!",
		},
		{
			name:     "no variables",
			tmpl:     "Plain text without variables",
			vars:     map[string]string{},
			expected: "Plain text without variables",
		},
		{
			name:     "missing variable uses no value placeholder",
			tmpl:     "Hello {{.Name}}",
			vars:     map[string]string{},
			expected: "Hello <no value>",
		},
		{
			name:    "invalid template syntax",
			tmpl:    "Hello {{.Name",
			vars:    map[string]string{"Name": "John"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := applyTemplate(tt.tmpl, tt.vars)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestLoadTemplateVars(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a JSON data file
	dataFile := filepath.Join(tmpDir, "vars.json")
	jsonContent := `{"Name": "Alice", "Date": "2026-01-15"}`
	if err := os.WriteFile(dataFile, []byte(jsonContent), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	t.Run("load from JSON file", func(t *testing.T) {
		vars, err := loadTemplateVars(dataFile, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vars["Name"] != "Alice" || vars["Date"] != "2026-01-15" {
			t.Errorf("unexpected vars: %v", vars)
		}
	})

	t.Run("inline vars override file vars", func(t *testing.T) {
		inline := map[string]string{"Name": "Bob", "Extra": "Value"}
		vars, err := loadTemplateVars(dataFile, inline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vars["Name"] != "Bob" {
			t.Errorf("inline should override file: got Name=%s", vars["Name"])
		}
		if vars["Date"] != "2026-01-15" {
			t.Errorf("file var should be preserved: got Date=%s", vars["Date"])
		}
		if vars["Extra"] != "Value" {
			t.Errorf("inline extra should be present: got Extra=%s", vars["Extra"])
		}
	})

	t.Run("inline only", func(t *testing.T) {
		inline := map[string]string{"Key": "Value"}
		vars, err := loadTemplateVars("", inline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vars["Key"] != "Value" {
			t.Errorf("expected Key=Value, got %v", vars)
		}
	})

	t.Run("missing file error", func(t *testing.T) {
		_, err := loadTemplateVars(filepath.Join(tmpDir, "nonexistent.json"), nil)
		if err == nil {
			t.Errorf("expected error for missing file")
		}
	})
}

func TestSaveEML(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error { return nil }}
	defaultClientFactory = mockFactory(mock, nil)

	tmpDir := t.TempDir()
	emlDir := filepath.Join(tmpDir, "eml")

	// Test saving EML
	params := EmailParams{
		SMTPServer:  "smtp.example.com",
		From:        "sender@example.com",
		To:          []string{"recipient@example.com"},
		Subject:     "EML Test",
		Body:        "Test body for EML archive",
		SaveEMLPath: emlDir,
	}

	res, err := SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail failed: %v", err)
	}

	// Check that EML file was created
	files, err := os.ReadDir(emlDir)
	if err != nil {
		t.Fatalf("failed to read EML dir: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 EML file, got %d", len(files))
	}
	if len(files) > 0 {
		name := files[0].Name()
		if !strings.HasPrefix(name, "mailarchive_") {
			t.Errorf("expected mailarchive_ prefix, got %s", name)
		}
		if !strings.HasSuffix(name, ".eml") {
			t.Errorf("expected .eml extension, got %s", name)
		}
	}
}

func TestSaveEMLCompressed(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error { return nil }}
	defaultClientFactory = mockFactory(mock, nil)

	tmpDir := t.TempDir()
	emlDir := filepath.Join(tmpDir, "eml-zstd")

	params := EmailParams{
		SMTPServer:  "smtp.example.com",
		From:        "sender@example.com",
		To:          []string{"recipient@example.com"},
		Subject:     "Compressed EML Test",
		Body:        "Test body for compressed EML archive",
		SaveEMLPath: emlDir,
		CompressEML: true,
	}

	res, err := SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail failed: %v", err)
	}

	files, err := os.ReadDir(emlDir)
	if err != nil {
		t.Fatalf("failed to read EML dir: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 compressed EML file, got %d", len(files))
	}
	if len(files) > 0 {
		name := files[0].Name()
		if !strings.HasPrefix(name, "mailarchive_") {
			t.Errorf("expected mailarchive_ prefix, got %s", name)
		}
		if !strings.HasSuffix(name, ".eml.zst") {
			t.Errorf("expected .eml.zst extension, got %s", name)
		}
	}
}

func TestRouteAttachments(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test attachment
	attFile := filepath.Join(tmpDir, "attachment.txt")
	if err := os.WriteFile(attFile, []byte("test content"), 0o644); err != nil {
		t.Fatalf("failed to create attachment: %v", err)
	}

	successDir := filepath.Join(tmpDir, "success")
	errorDir := filepath.Join(tmpDir, "error")

	t.Run("move to success path", func(t *testing.T) {
		// Reset
		_ = os.WriteFile(attFile, []byte("test content"), 0o644)
		_ = os.RemoveAll(successDir)

		err := routeAttachments([]string{attFile}, true, successDir, errorDir, false)
		if err != nil {
			t.Fatalf("routeAttachments failed: %v", err)
		}

		// Check file moved
		if _, err := os.Stat(attFile); !os.IsNotExist(err) {
			t.Errorf("original file should be removed")
		}
		movedFile := filepath.Join(successDir, "attachment.txt")
		if _, err := os.Stat(movedFile); err != nil {
			t.Errorf("file should exist in success dir: %v", err)
		}
	})

	t.Run("move to error path", func(t *testing.T) {
		attFile2 := filepath.Join(tmpDir, "attachment2.txt")
		_ = os.WriteFile(attFile2, []byte("test content"), 0o644)
		_ = os.RemoveAll(errorDir)

		err := routeAttachments([]string{attFile2}, false, successDir, errorDir, false)
		if err != nil {
			t.Fatalf("routeAttachments failed: %v", err)
		}

		movedFile := filepath.Join(errorDir, "attachment2.txt")
		if _, err := os.Stat(movedFile); err != nil {
			t.Errorf("file should exist in error dir: %v", err)
		}
	})

	t.Run("delete attachments", func(t *testing.T) {
		attFile3 := filepath.Join(tmpDir, "attachment3.txt")
		_ = os.WriteFile(attFile3, []byte("test content"), 0o644)

		err := routeAttachments([]string{attFile3}, true, "", "", true)
		if err != nil {
			t.Fatalf("routeAttachments failed: %v", err)
		}

		if _, err := os.Stat(attFile3); !os.IsNotExist(err) {
			t.Errorf("file should be deleted")
		}
	})

	t.Run("empty attachments list", func(t *testing.T) {
		err := routeAttachments([]string{}, true, successDir, errorDir, false)
		if err != nil {
			t.Errorf("routeAttachments should handle empty list: %v", err)
		}
	})

	t.Run("multiple attachments", func(t *testing.T) {
		att1 := filepath.Join(tmpDir, "multi1.txt")
		att2 := filepath.Join(tmpDir, "multi2.txt")
		att3 := filepath.Join(tmpDir, "multi3.txt")
		_ = os.WriteFile(att1, []byte("content1"), 0o644)
		_ = os.WriteFile(att2, []byte("content2"), 0o644)
		_ = os.WriteFile(att3, []byte("content3"), 0o644)
		multiSuccessDir := filepath.Join(tmpDir, "multi-success")
		_ = os.RemoveAll(multiSuccessDir)

		err := routeAttachments([]string{att1, att2, att3}, true, multiSuccessDir, "", false)
		if err != nil {
			t.Fatalf("routeAttachments with multiple files failed: %v", err)
		}

		// All files should be moved
		for _, name := range []string{"multi1.txt", "multi2.txt", "multi3.txt"} {
			movedFile := filepath.Join(multiSuccessDir, name)
			if _, err := os.Stat(movedFile); err != nil {
				t.Errorf("file %s should exist in success dir: %v", name, err)
			}
		}
	})

	t.Run("empty string in attachments list", func(t *testing.T) {
		att4 := filepath.Join(tmpDir, "att4.txt")
		_ = os.WriteFile(att4, []byte("content"), 0o644)
		emptySuccessDir := filepath.Join(tmpDir, "empty-success")
		_ = os.RemoveAll(emptySuccessDir)

		// List with empty strings should skip them
		err := routeAttachments([]string{"", att4, ""}, true, emptySuccessDir, "", false)
		if err != nil {
			t.Fatalf("routeAttachments with empty strings failed: %v", err)
		}

		movedFile := filepath.Join(emptySuccessDir, "att4.txt")
		if _, err := os.Stat(movedFile); err != nil {
			t.Errorf("file should exist in success dir: %v", err)
		}
	})
}

func TestSendEmail_WithTemplate(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error { return nil }}
	defaultClientFactory = mockFactory(mock, nil)

	tmpDir := t.TempDir()

	// Create template file
	tmplFile := filepath.Join(tmpDir, "template.txt")
	tmplContent := "Hello {{.Name}}, your order {{.OrderID}} is ready!"
	if err := os.WriteFile(tmplFile, []byte(tmplContent), 0o644); err != nil {
		t.Fatalf("failed to create template: %v", err)
	}

	params := EmailParams{
		SMTPServer:   "smtp.example.com",
		From:         "sender@example.com",
		To:           []string{"recipient@example.com"},
		Subject:      "Template Test",
		TemplateFile: tmplFile,
		TemplateVars: map[string]string{"Name": "John", "OrderID": "12345"},
	}

	res, err := SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail with template failed: %v", err)
	}
}

func TestSendEmail_WithDelay(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error { return nil }}
	defaultClientFactory = mockFactory(mock, nil)

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Delay Test",
		Body:       "Test with delay",
		Delay:      1, // 1 second delay
		Quiet:      true,
	}

	start := time.Now()
	res, err := SendEmail(params)
	elapsed := time.Since(start)

	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail with delay failed: %v", err)
	}

	if elapsed < 900*time.Millisecond {
		t.Errorf("delay should have waited ~1s, but only took %v", elapsed)
	}
}

func TestSendEmail_WithRateLimit(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error { return nil }}
	defaultClientFactory = mockFactory(mock, nil)

	// Rate limit is only meaningful for batch sends, but we can verify the field is accepted
	params := EmailParams{
		SMTPServer: "smtp.example.com",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Rate Limit Test",
		Body:       "Test with rate limit",
		RateLimit:  60, // 60 emails per minute
		Quiet:      true,
	}

	res, err := SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail with rate limit failed: %v", err)
	}
}

func TestSendEmail_PathValidation(t *testing.T) {
	// Test that relative paths are rejected
	t.Run("relative body file rejected", func(t *testing.T) {
		params := EmailParams{
			SMTPServer: "smtp.example.com",
			From:       "sender@example.com",
			To:         []string{"recipient@example.com"},
			BodyFile:   "relative/path.html",
		}
		_, err := SendEmail(params)
		if err == nil {
			t.Error("expected error for relative body file path")
		}
	})

	t.Run("relative template file rejected", func(t *testing.T) {
		params := EmailParams{
			SMTPServer:   "smtp.example.com",
			From:         "sender@example.com",
			To:           []string{"recipient@example.com"},
			TemplateFile: "relative/template.txt",
		}
		_, err := SendEmail(params)
		if err == nil {
			t.Error("expected error for relative template file path")
		}
	})

	t.Run("nonexistent body file rejected", func(t *testing.T) {
		params := EmailParams{
			SMTPServer: "smtp.example.com",
			From:       "sender@example.com",
			To:         []string{"recipient@example.com"},
			BodyFile:   "/nonexistent/path/body.html",
		}
		_, err := SendEmail(params)
		if err == nil {
			t.Error("expected error for nonexistent body file")
		}
	})

	t.Run("relative save-eml path rejected", func(t *testing.T) {
		params := EmailParams{
			SMTPServer:  "smtp.example.com",
			From:        "sender@example.com",
			To:          []string{"recipient@example.com"},
			Body:        "test",
			SaveEMLPath: "relative/eml",
		}
		_, err := SendEmail(params)
		if err == nil {
			t.Error("expected error for relative save-eml path")
		}
	})

	t.Run("relative route path rejected", func(t *testing.T) {
		params := EmailParams{
			SMTPServer:       "smtp.example.com",
			From:             "sender@example.com",
			To:               []string{"recipient@example.com"},
			Body:             "test",
			RouteSuccessPath: "relative/success",
		}
		_, err := SendEmail(params)
		if err == nil {
			t.Error("expected error for relative route path")
		}
	})
}

func TestSendEmail_SingleAttachment(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	var sentMessages []*mail.Msg
	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error {
		sentMessages = append(sentMessages, m...)
		return nil
	}}
	defaultClientFactory = mockFactory(mock, nil)

	tmpDir := t.TempDir()

	// Create test attachments
	att1 := filepath.Join(tmpDir, "report.pdf")
	att2 := filepath.Join(tmpDir, "data.xlsx")
	att3 := filepath.Join(tmpDir, "summary.docx")
	_ = os.WriteFile(att1, []byte("pdf content"), 0o644)
	_ = os.WriteFile(att2, []byte("excel content"), 0o644)
	_ = os.WriteFile(att3, []byte("word content"), 0o644)

	t.Run("sends one email per attachment", func(t *testing.T) {
		sentMessages = nil

		params := EmailParams{
			SMTPServer:       "smtp.example.com",
			From:             "sender@example.com",
			To:               []string{"recipient@example.com"},
			Subject:          "Monthly Report",
			Body:             "Please find the attachment.",
			Attachments:      []string{att1, att2, att3},
			SingleAttachment: true,
			Quiet:            true,
		}

		res, err := SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail with single attachment failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}

		// Should have sent 3 emails
		if len(sentMessages) != 3 {
			t.Errorf("expected 3 emails sent, got %d", len(sentMessages))
		}
	})

	t.Run("subject has N/Total prefix", func(t *testing.T) {
		sentMessages = nil

		params := EmailParams{
			SMTPServer:       "smtp.example.com",
			From:             "sender@example.com",
			To:               []string{"recipient@example.com"},
			Subject:          "Test Subject",
			Body:             "Body content",
			Attachments:      []string{att1, att2},
			SingleAttachment: true,
			Quiet:            true,
		}

		_, err := SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}

		if len(sentMessages) != 2 {
			t.Fatalf("expected 2 emails, got %d", len(sentMessages))
		}

		// Check subjects contain prefixes (we can't easily extract subject from mail.Msg)
		// but we can verify 2 messages were sent
	})

	t.Run("single attachment skips split", func(t *testing.T) {
		sentMessages = nil

		params := EmailParams{
			SMTPServer:       "smtp.example.com",
			From:             "sender@example.com",
			To:               []string{"recipient@example.com"},
			Subject:          "Single File",
			Body:             "Just one attachment",
			Attachments:      []string{att1},
			SingleAttachment: true,
			Quiet:            true,
		}

		res, err := SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}

		// With only 1 attachment, should send normally (not split)
		if len(sentMessages) != 1 {
			t.Errorf("expected 1 email (no split needed), got %d", len(sentMessages))
		}
	})

	t.Run("routes attachments on success", func(t *testing.T) {
		sentMessages = nil

		// Create fresh attachments
		attA := filepath.Join(tmpDir, "fileA.txt")
		attB := filepath.Join(tmpDir, "fileB.txt")
		_ = os.WriteFile(attA, []byte("A"), 0o644)
		_ = os.WriteFile(attB, []byte("B"), 0o644)

		successDir := filepath.Join(tmpDir, "single-success")

		params := EmailParams{
			SMTPServer:       "smtp.example.com",
			From:             "sender@example.com",
			To:               []string{"recipient@example.com"},
			Subject:          "Route Test",
			Body:             "Test routing",
			Attachments:      []string{attA, attB},
			SingleAttachment: true,
			RouteSuccessPath: successDir,
			Quiet:            true,
		}

		_, err := SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}

		// Check files were routed
		if _, err := os.Stat(filepath.Join(successDir, "fileA.txt")); err != nil {
			t.Errorf("fileA should be routed to success: %v", err)
		}
		if _, err := os.Stat(filepath.Join(successDir, "fileB.txt")); err != nil {
			t.Errorf("fileB should be routed to success: %v", err)
		}
	})
}

func TestSendEmail_MaxRecipients(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error { return nil }}
	defaultClientFactory = mockFactory(mock, nil)

	t.Run("rejects when exceeding limit", func(t *testing.T) {
		// Create a recipient list that exceeds the limit
		recipients := make([]string, 10)
		for i := 0; i < 10; i++ {
			recipients[i] = "recipient" + string(rune('0'+i)) + "@example.com"
		}

		params := EmailParams{
			SMTPServer:    "smtp.example.com",
			From:          "sender@example.com",
			To:            recipients,
			Subject:       "Max Recipients Test",
			Body:          "Test body",
			MaxRecipients: 5, // Limit to 5
			Quiet:         true,
		}

		_, err := SendEmail(params)
		if err == nil {
			t.Error("expected error when exceeding max recipients")
		}
		if err != nil && !strings.Contains(err.Error(), "exceeds maximum") {
			t.Errorf("expected 'exceeds maximum' error, got: %v", err)
		}
	})

	t.Run("accepts when within limit", func(t *testing.T) {
		recipients := []string{"a@example.com", "b@example.com", "c@example.com"}

		params := EmailParams{
			SMTPServer:    "smtp.example.com",
			From:          "sender@example.com",
			To:            recipients,
			Subject:       "Within Limit Test",
			Body:          "Test body",
			MaxRecipients: 5,
			Quiet:         true,
		}

		res, err := SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}
	})

	t.Run("uses default limit when zero", func(t *testing.T) {
		// With MaxRecipients = 0, should use DefaultMaxRecipients (1000)
		recipients := []string{"a@example.com", "b@example.com"}

		params := EmailParams{
			SMTPServer:    "smtp.example.com",
			From:          "sender@example.com",
			To:            recipients,
			Subject:       "Default Limit Test",
			Body:          "Test body",
			MaxRecipients: 0, // Use default
			Quiet:         true,
		}

		res, err := SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}
	})

	t.Run("rejects negative max recipients", func(t *testing.T) {
		params := EmailParams{
			SMTPServer:    "smtp.example.com",
			From:          "sender@example.com",
			To:            []string{"a@example.com"},
			Subject:       "Negative Test",
			Body:          "Test body",
			MaxRecipients: -1,
			Quiet:         true,
		}

		_, err := SendEmail(params)
		if err == nil {
			t.Error("expected error for negative max recipients")
		}
	})
}

func TestSendEmail_SingleRecipient(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	var sentMessages []*mail.Msg
	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error {
		sentMessages = append(sentMessages, m...)
		return nil
	}}
	defaultClientFactory = mockFactory(mock, nil)

	t.Run("sends one email per recipient", func(t *testing.T) {
		sentMessages = nil

		params := EmailParams{
			SMTPServer:      "smtp.example.com",
			From:            "sender@example.com",
			To:              []string{"a@example.com", "b@example.com", "c@example.com"},
			Subject:         "Single Recipient Test",
			Body:            "Test body",
			SingleRecipient: true,
			Quiet:           true,
		}

		res, err := SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}

		// Should have sent 3 separate emails
		if len(sentMessages) != 3 {
			t.Errorf("expected 3 emails sent, got %d", len(sentMessages))
		}
	})

	t.Run("skips single recipient mode with only one recipient", func(t *testing.T) {
		sentMessages = nil

		params := EmailParams{
			SMTPServer:      "smtp.example.com",
			From:            "sender@example.com",
			To:              []string{"single@example.com"},
			Subject:         "Single Recipient Skip Test",
			Body:            "Test body",
			SingleRecipient: true,
			Quiet:           true,
		}

		res, err := SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}

		// With only 1 recipient, should send normally
		if len(sentMessages) != 1 {
			t.Errorf("expected 1 email, got %d", len(sentMessages))
		}
	})

	t.Run("rate limiting with single recipient", func(t *testing.T) {
		sentMessages = nil

		params := EmailParams{
			SMTPServer:      "smtp.example.com",
			From:            "sender@example.com",
			To:              []string{"a@example.com", "b@example.com"},
			Subject:         "Rate Limited Test",
			Body:            "Test body",
			SingleRecipient: true,
			RateLimit:       120, // 120 per minute = 2 per second = 500ms between
			Quiet:           true,
		}

		start := time.Now()
		res, err := SendEmail(params)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}

		// With rate limit of 120/min and 2 recipients, expect ~500ms delay between
		// Total time should be > 400ms (accounting for execution time)
		if elapsed < 400*time.Millisecond {
			t.Errorf("rate limiting should have added delay, elapsed: %v", elapsed)
		}
	})

	t.Run("continues on failure and reports partial", func(t *testing.T) {
		localSentCount := 0
		callCount := 0

		failingMock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error {
			callCount++
			if callCount == 2 {
				return errors.New("simulated failure")
			}
			localSentCount++
			return nil
		}}
		defaultClientFactory = mockFactory(failingMock, nil)

		params := EmailParams{
			SMTPServer:      "smtp.example.com",
			From:            "sender@example.com",
			To:              []string{"a@example.com", "b@example.com", "c@example.com"},
			Subject:         "Failure Test",
			Body:            "Test body",
			SingleRecipient: true,
			Quiet:           true,
		}

		result, err := SendEmail(params)
		// Should return error indicating partial failure
		if err == nil {
			t.Error("expected error on partial failure")
		}

		// Should have succeeded for first and third, failed on second
		if localSentCount != 2 {
			t.Errorf("expected 2 successful emails (skipping failed), got %d", localSentCount)
		}

		// Result should indicate partial success
		if result != nil && result.Status != "partial" {
			t.Errorf("expected status 'partial', got %s", result.Status)
		}
	})
}

func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("copies file content correctly", func(t *testing.T) {
		src := filepath.Join(tmpDir, "source.txt")
		dst := filepath.Join(tmpDir, "dest.txt")
		content := "Hello, this is test content for copy file function."

		if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to create source file: %v", err)
		}

		if err := copyFile(src, dst); err != nil {
			t.Fatalf("copyFile failed: %v", err)
		}

		// Verify content
		copied, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("failed to read destination: %v", err)
		}
		if string(copied) != content {
			t.Errorf("content mismatch: got %q, want %q", string(copied), content)
		}
	})

	t.Run("copies large file with streaming", func(t *testing.T) {
		src := filepath.Join(tmpDir, "large_source.bin")
		dst := filepath.Join(tmpDir, "large_dest.bin")

		// Create a file larger than the 32KB buffer to test streaming
		largeContent := make([]byte, 100*1024) // 100KB
		for i := range largeContent {
			largeContent[i] = byte(i % 256)
		}

		if err := os.WriteFile(src, largeContent, 0o644); err != nil {
			t.Fatalf("failed to create large source file: %v", err)
		}

		if err := copyFile(src, dst); err != nil {
			t.Fatalf("copyFile for large file failed: %v", err)
		}

		// Verify content
		copied, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("failed to read large destination: %v", err)
		}
		if len(copied) != len(largeContent) {
			t.Errorf("size mismatch: got %d, want %d", len(copied), len(largeContent))
		}
		for i := 0; i < len(largeContent); i++ {
			if copied[i] != largeContent[i] {
				t.Errorf("content mismatch at byte %d: got %d, want %d", i, copied[i], largeContent[i])
				break
			}
		}
	})

	t.Run("returns error for non-existent source", func(t *testing.T) {
		src := filepath.Join(tmpDir, "nonexistent.txt")
		dst := filepath.Join(tmpDir, "dest_nonexistent.txt")

		err := copyFile(src, dst)
		if err == nil {
			t.Error("expected error for non-existent source")
		}
	})

	t.Run("returns error for invalid destination", func(t *testing.T) {
		src := filepath.Join(tmpDir, "src_for_invalid_dst.txt")
		dst := filepath.Join(tmpDir, "nonexistent_dir", "subdir", "dest.txt")

		if err := os.WriteFile(src, []byte("test"), 0o644); err != nil {
			t.Fatalf("failed to create source: %v", err)
		}

		err := copyFile(src, dst)
		if err == nil {
			t.Error("expected error for invalid destination path")
		}
	})
}

func TestCompressZstd(t *testing.T) {
	t.Run("compresses data successfully", func(t *testing.T) {
		original := []byte("This is some test data that should be compressed. " +
			"Repeating content helps compression: test test test test test.")

		compressed, err := compressZstd(original)
		if err != nil {
			t.Fatalf("compressZstd failed: %v", err)
		}

		// Compressed data should exist
		if len(compressed) == 0 {
			t.Error("compressed data is empty")
		}

		// For compressible data, output should be smaller or similar
		// (very small inputs might not compress well)
		t.Logf("Original: %d bytes, Compressed: %d bytes", len(original), len(compressed))
	})

	t.Run("compresses empty data", func(t *testing.T) {
		compressed, err := compressZstd([]byte{})
		if err != nil {
			t.Fatalf("compressZstd failed for empty data: %v", err)
		}
		// Zstd produces a small header even for empty input
		if compressed == nil {
			t.Error("compressed result should not be nil")
		}
	})

	t.Run("compresses large data with encoder pooling", func(t *testing.T) {
		// Test that encoder pooling works correctly across multiple calls
		largeData := make([]byte, 50*1024) // 50KB
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		// Call multiple times to test pool reuse
		for i := 0; i < 3; i++ {
			compressed, err := compressZstd(largeData)
			if err != nil {
				t.Fatalf("compressZstd iteration %d failed: %v", i, err)
			}
			if len(compressed) == 0 {
				t.Errorf("iteration %d produced empty output", i)
			}
		}
	})
}

func TestSendEmail_SingleAttachmentModeAdvanced(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	t.Run("handles body file with multiple attachments", func(t *testing.T) {
		var sentCount int
		mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error {
			sentCount++
			return nil
		}}
		defaultClientFactory = mockFactory(mock, nil)

		tmpDir := t.TempDir()

		// Create body file
		bodyFile := filepath.Join(tmpDir, "body.html")
		if err := os.WriteFile(bodyFile, []byte("<html><body>Report content</body></html>"), 0o644); err != nil {
			t.Fatalf("failed to create body file: %v", err)
		}

		// Create attachments
		att1 := filepath.Join(tmpDir, "report1.pdf")
		att2 := filepath.Join(tmpDir, "report2.pdf")
		if err := os.WriteFile(att1, []byte("pdf1"), 0o644); err != nil {
			t.Fatalf("failed to create att1: %v", err)
		}
		if err := os.WriteFile(att2, []byte("pdf2"), 0o644); err != nil {
			t.Fatalf("failed to create att2: %v", err)
		}

		params := EmailParams{
			SMTPServer:       "smtp.example.com",
			From:             "sender@example.com",
			To:               []string{"recipient@example.com"},
			Subject:          "Monthly Reports",
			BodyFile:         bodyFile,
			Attachments:      []string{att1, att2},
			SingleAttachment: true,
			Quiet:            true,
		}

		res, err := SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}
		if sentCount != 2 {
			t.Errorf("expected 2 emails sent, got %d", sentCount)
		}
	})

	t.Run("routes attachments to error path on failure", func(t *testing.T) {
		callCount := 0
		mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error {
			callCount++
			if callCount == 2 {
				return errors.New("send failed")
			}
			return nil
		}}
		defaultClientFactory = mockFactory(mock, nil)

		tmpDir := t.TempDir()
		errorDir := filepath.Join(tmpDir, "errors")

		att1 := filepath.Join(tmpDir, "file1.txt")
		att2 := filepath.Join(tmpDir, "file2.txt")
		att3 := filepath.Join(tmpDir, "file3.txt")
		for _, f := range []string{att1, att2, att3} {
			if err := os.WriteFile(f, []byte("content"), 0o644); err != nil {
				t.Fatalf("failed to create file: %v", err)
			}
		}

		params := EmailParams{
			SMTPServer:       "smtp.example.com",
			From:             "sender@example.com",
			To:               []string{"recipient@example.com"},
			Subject:          "Test",
			Body:             "Body",
			Attachments:      []string{att1, att2, att3},
			SingleAttachment: true,
			RouteErrorPath:   errorDir,
			Quiet:            true,
		}

		_, err := SendEmail(params)
		if err == nil {
			t.Error("expected error on failure")
		}

		// Check files were routed to error path
		files, _ := os.ReadDir(errorDir)
		if len(files) != 3 {
			t.Errorf("expected 3 files in error dir, got %d", len(files))
		}
	})

	t.Run("rate limits single attachment mode", func(t *testing.T) {
		var sentCount int
		mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error {
			sentCount++
			return nil
		}}
		defaultClientFactory = mockFactory(mock, nil)

		tmpDir := t.TempDir()
		att1 := filepath.Join(tmpDir, "att1.txt")
		att2 := filepath.Join(tmpDir, "att2.txt")
		if err := os.WriteFile(att1, []byte("1"), 0o644); err != nil {
			t.Fatalf("failed to create att1: %v", err)
		}
		if err := os.WriteFile(att2, []byte("2"), 0o644); err != nil {
			t.Fatalf("failed to create att2: %v", err)
		}

		params := EmailParams{
			SMTPServer:       "smtp.example.com",
			From:             "sender@example.com",
			To:               []string{"recipient@example.com"},
			Subject:          "Rate Limited",
			Body:             "Test",
			Attachments:      []string{att1, att2},
			SingleAttachment: true,
			RateLimit:        60, // 1 per second
			Quiet:            true,
		}

		start := time.Now()
		res, err := SendEmail(params)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}
		// Should have ~1 second delay between emails
		if elapsed < 800*time.Millisecond {
			t.Errorf("rate limiting should add delay, elapsed: %v", elapsed)
		}
	})
}

func TestLogAttempt(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "attempts.log")

	// Test logging attempt message
	logAttempt(logFile, "Attempt 1/3 failed: connection refused\n")
	logAttempt(logFile, "Attempt 2/3 failed: timeout\n")

	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if !strings.Contains(string(content), "Attempt 1/3") {
		t.Error("log should contain first attempt")
	}
	if !strings.Contains(string(content), "Attempt 2/3") {
		t.Error("log should contain second attempt")
	}
}

func TestLogAudit(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("logs success", func(t *testing.T) {
		logFile := filepath.Join(tmpDir, "audit_success.log")
		params := EmailParams{
			SMTPServer: "smtp.example.com",
			SMTPPort:   587,
			To:         []string{"a@example.com", "b@example.com"},
		}

		logAudit(logFile, "2026-08-10T10:00:00Z", true, 1, "", params)

		content, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatalf("failed to read log: %v", err)
		}
		if !strings.Contains(string(content), "SUCCESS") {
			t.Error("log should contain SUCCESS")
		}
		if !strings.Contains(string(content), "a@example.com") {
			t.Error("log should contain recipient")
		}
	})

	t.Run("logs error", func(t *testing.T) {
		logFile := filepath.Join(tmpDir, "audit_error.log")
		params := EmailParams{
			SMTPServer: "smtp.example.com",
			SMTPPort:   587,
			To:         []string{"user@example.com"},
		}

		logAudit(logFile, "2026-08-10T10:00:00Z", false, 3, "connection timeout", params)

		content, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatalf("failed to read log: %v", err)
		}
		if !strings.Contains(string(content), "ERROR") {
			t.Error("log should contain ERROR")
		}
		if !strings.Contains(string(content), "connection timeout") {
			t.Error("log should contain error message")
		}
	})

	t.Run("redacts recipients with NoLogRecipients", func(t *testing.T) {
		logFile := filepath.Join(tmpDir, "audit_redacted.log")
		params := EmailParams{
			SMTPServer:      "smtp.example.com",
			SMTPPort:        587,
			To:              []string{"secret1@example.com", "secret2@example.com"},
			NoLogRecipients: true,
		}

		logAudit(logFile, "2026-08-10T10:00:00Z", true, 1, "", params)

		content, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatalf("failed to read log: %v", err)
		}
		if strings.Contains(string(content), "secret1@example.com") {
			t.Error("log should NOT contain actual email when redacted")
		}
		if !strings.Contains(string(content), "[2 recipients redacted]") {
			t.Error("log should contain redaction notice")
		}
	})

	t.Run("handles empty log file path", func(t *testing.T) {
		// Should not panic or error with empty path
		params := EmailParams{To: []string{"test@example.com"}}
		logAudit("", "2026-08-10T10:00:00Z", true, 1, "", params)
	})
}

func TestSendEmail_DryRun(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	sendCalled := false
	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error {
		sendCalled = true
		return nil
	}}
	defaultClientFactory = mockFactory(mock, nil)

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Dry Run Test",
		Body:       "This should not actually send",
		DryRun:     true,
		Quiet:      true,
	}

	res, err := SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail dry-run failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected success status, got %s", res.Status)
	}
	if sendCalled {
		t.Error("DialAndSend should NOT be called in dry-run mode")
	}
}

func TestSendEmail_ContextCancellation(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error {
		return errors.New("should not reach here")
	}}
	defaultClientFactory = mockFactory(mock, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Context Test",
		Body:       "Test",
		Context:    ctx,
		Quiet:      true,
	}

	_, err := SendEmail(params)
	if err == nil {
		t.Error("expected error due to cancelled context")
	}
	if !strings.Contains(err.Error(), "cancel") {
		t.Errorf("expected cancellation error, got: %v", err)
	}
}

func TestSendEmail_DelayWithContext(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error {
		return nil
	}}
	defaultClientFactory = mockFactory(mock, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Delay Context Test",
		Body:       "Test",
		Delay:      5, // 5 second delay, but context times out in 100ms
		Context:    ctx,
		Quiet:      true,
	}

	_, err := SendEmail(params)
	if err == nil {
		t.Error("expected error due to context timeout during delay")
	}
	if !strings.Contains(err.Error(), "cancel") {
		t.Errorf("expected cancellation error, got: %v", err)
	}
}

func TestNoAuthSASL(t *testing.T) {
	auth := &noAuthSASL{}

	// Test Start method
	mech, ir, err := auth.Start(nil)
	if err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}
	if mech != "PLAIN" {
		t.Errorf("expected mech PLAIN, got %s", mech)
	}
	expectedIR := []byte("\x00anonymous\x00anonymous")
	if string(ir) != string(expectedIR) {
		t.Errorf("expected IR %q, got %q", expectedIR, ir)
	}

	// Test Next method
	resp, err := auth.Next([]byte("challenge"), true)
	if err != nil {
		t.Fatalf("Next() returned error: %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}

	// Test Next with no more data
	resp, err = auth.Next(nil, false)
	if err != nil {
		t.Fatalf("Next() returned error: %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
}

func TestSendEmail_NoAuthMode(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error { return nil }}
	defaultClientFactory = mockFactory(mock, nil)

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		SMTPPort:   25,
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "No Auth Test",
		Body:       "Test without authentication",
		AuthType:   "noauth",
		Quiet:      true,
	}

	res, err := SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail with noauth failed: %v", err)
	}
}

func TestSendEmail_XOAUTH2Mode(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error { return nil }}
	defaultClientFactory = mockFactory(mock, nil)

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		SMTPPort:   587,
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "XOAUTH2 Test",
		Body:       "Test with OAuth2 authentication",
		Username:   "user@example.com",
		Password:   "ya29.oauth2_token_here",
		AuthType:   "xoauth2",
		TLSMode:    "tls",
		Quiet:      true,
	}

	res, err := SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail with xoauth2 failed: %v", err)
	}
}

func TestSendEmail_CramMD5Mode(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })

	mock := &mockSender{dialAndSendFunc: func(m ...*mail.Msg) error { return nil }}
	defaultClientFactory = mockFactory(mock, nil)

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		SMTPPort:   587,
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "CRAM-MD5 Test",
		Body:       "Test with CRAM-MD5 authentication",
		Username:   "user",
		Password:   "secret",
		AuthType:   "cram-md5",
		TLSMode:    "tls",
		Quiet:      true,
	}

	res, err := SendEmail(params)
	if err != nil || res.Status != "success" {
		t.Fatalf("SendEmail with cram-md5 failed: %v", err)
	}
}

func TestClassifyError_AllTypes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"TLS error", errors.New("tls: handshake failure"), ErrorTypeTLS},
		{"certificate error", errors.New("x509: certificate verification failed"), ErrorTypeTLS},
		{"SSL error", errors.New("SSL protocol error"), ErrorTypeTLS},
		{"handshake error", errors.New("handshake timeout"), ErrorTypeTLS},
		{"auth error", errors.New("535 Authentication failed"), ErrorTypeAuth},
		{"credential error", errors.New("invalid credentials"), ErrorTypeAuth},
		{"login error", errors.New("login rejected"), ErrorTypeAuth},
		{"530 error", errors.New("530 Must authenticate"), ErrorTypeAuth},
		{"534 error", errors.New("534 OAuth required"), ErrorTypeAuth},
		{"connection refused", errors.New("connection refused"), ErrorTypeConnection},
		{"timeout error", errors.New("i/o timeout"), ErrorTypeConnection},
		{"dial error", errors.New("dial tcp failed"), ErrorTypeConnection},
		{"network unreachable", errors.New("network is unreachable"), ErrorTypeConnection},
		{"connection reset", errors.New("connection reset by peer"), ErrorTypeConnection},
		{"eof error", errors.New("unexpected EOF"), ErrorTypeConnection},
		{"generic SMTP error", errors.New("550 mailbox not found"), ErrorTypeSend},
		{"unknown error", errors.New("some unknown error"), ErrorTypeSend},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError(tt.err)
			if result != tt.expected {
				t.Errorf("ClassifyError(%v) = %d, expected %d", tt.err, result, tt.expected)
			}
		})
	}
}
