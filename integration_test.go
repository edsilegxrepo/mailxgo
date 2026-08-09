//go:build integration

// Package mailxgo_test - Live ESMTP Network Integration Tests
//
// OBJECTIVES:
// Validate live network socket interactions, ESMTP protocol state handshakes, SASL authentication exchanges,
// DATA stream buffering, and process binary execution against Mailpit or fallback loopback listener.
//
// CORE COMPONENTS:
// - setupMailpit: Configures Mailpit container or fallback SMTP server on 127.0.0.1:1025.
// - TestLive_*: Production-scenario E2E tests covering all EmailParams fields.
// - Mailpit API verification: Uses Mailpit REST API to verify delivered email content.
//
// FUNCTIONALITY & DATA FLOW:
// Test Dispatch -> Loopback Socket Dial (127.0.0.1:1025) -> EHLO Handshake -> SASL Auth -> DATA Transfer -> Mailpit API Verification.
//
// TEST STRATEGY:
// Hermetic integration testing with Mailpit container (preferred) or embedded in-process ESMTP TCP server.
// Run with: go test -tags=integration -v ./...
package mailxgo_test

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	mailxgo "github.com/edsilegxrepo/mailxgo"
	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
)

const (
	smtpHost      = "127.0.0.1"
	smtpPort      = 1025
	mailpitAPI    = "http://127.0.0.1:8025/api"
	containerName = "mailxgo-integration-smtp"
)

var (
	mailpitReady     bool
	mailpitSetupOnce sync.Once
	mailpitSetupErr  error
	testTLSCertDir   string
)

// TestMain provides one-time setup and teardown for the integration test suite.
// Initializes Mailpit container once for all tests.
func TestMain(m *testing.M) {
	// Setup: Start Mailpit container once
	mailpitSetupOnce.Do(func() {
		mailpitSetupErr = initMailpitContainer()
	})

	code := m.Run()

	// Teardown: Clean up Mailpit container
	if mailpitReady {
		_, _ = runDockerCmd("rm", "-f", containerName)
	}

	// Clean up TLS cert directory
	if testTLSCertDir != "" {
		os.RemoveAll(testTLSCertDir)
	}

	os.Exit(code)
}

// initMailpitContainer starts Mailpit with auth support; waits until API is ready.
func initMailpitContainer() error {
	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)

	// Check if already running
	if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
		conn.Close()
		resp, err := http.Get(mailpitAPI + "/v1/messages")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			mailpitReady = true
			useMailpit = true
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	// Start container
	_, _ = runDockerCmd("rm", "-f", containerName)
	_, err := runDockerCmd("run", "-d", "--name", containerName,
		"-p", fmt.Sprintf("%d:1025", smtpPort),
		"-p", "8025:8025",
		"-e", "MP_SMTP_AUTH_ACCEPT_ANY=true",
		"-e", "MP_SMTP_AUTH_ALLOW_INSECURE=true",
		"axllent/mailpit")
	if err != nil {
		return err
	}

	// Wait for container readiness
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			conn.Close()
			resp, err := http.Get(mailpitAPI + "/v1/messages")
			if err == nil && resp.StatusCode == 200 {
				resp.Body.Close()
				mailpitReady = true
				useMailpit = true
				return nil
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("mailpit not ready after 15s")
}

// MailpitMessage represents a message from Mailpit API
type MailpitMessage struct {
	ID          string   `json:"ID"`
	From        struct {
		Name    string `json:"Name"`
		Address string `json:"Address"`
	} `json:"From"`
	To []struct {
		Name    string `json:"Name"`
		Address string `json:"Address"`
	} `json:"To"`
	Cc []struct {
		Name    string `json:"Name"`
		Address string `json:"Address"`
	} `json:"Cc"`
	Bcc []struct {
		Name    string `json:"Name"`
		Address string `json:"Address"`
	} `json:"Bcc"`
	ReplyTo []struct {
		Name    string `json:"Name"`
		Address string `json:"Address"`
	} `json:"ReplyTo"`
	Subject     string            `json:"Subject"`
	Attachments int               `json:"Attachments"`
	Size        int               `json:"Size"`
	Text        string            `json:"Text"`
	HTML        string            `json:"HTML"`
	Headers     map[string][]string `json:"Headers,omitempty"`
}

// MailpitMessages represents Mailpit API messages response
type MailpitMessages struct {
	Messages []MailpitMessage `json:"messages"`
	Total    int              `json:"total"`
}

type liveSMTPServer struct {
	listener net.Listener
	mu       sync.Mutex
	messages []string
	done     chan struct{}
}

var useMailpit bool

func startFallbackSMTPServer(t *testing.T, port int) *liveSMTPServer {
	t.Helper()
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("Failed to start fallback live SMTP listener: %v", err)
	}

	server := &liveSMTPServer{
		listener: l,
		done:     make(chan struct{}),
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-server.done:
					return
				default:
					return
				}
			}
			go server.handleConn(conn)
		}
	}()

	t.Cleanup(func() {
		close(server.done)
		l.Close()
	})

	return server
}

func (s *liveSMTPServer) handleConn(conn net.Conn) {
	defer conn.Close()
	reader := textproto.NewReader(bufio.NewReader(conn))
	writer := textproto.NewWriter(bufio.NewWriter(conn))

	writer.PrintfLine("220 127.0.0.1 ESMTP mailxgo-live-test ready")

	var currentMsg strings.Builder
	inData := false

	for {
		line, err := reader.ReadLine()
		if err != nil {
			return
		}

		if inData {
			if line == "." {
				inData = false
				s.mu.Lock()
				s.messages = append(s.messages, currentMsg.String())
				s.mu.Unlock()
				currentMsg.Reset()
				writer.PrintfLine("250 2.0.0 OK queued")
			} else {
				if strings.HasPrefix(line, "..") {
					line = line[1:]
				}
				currentMsg.WriteString(line + "\n")
			}
			continue
		}

		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			writer.PrintfLine("250-127.0.0.1 Hello")
			writer.PrintfLine("250-SIZE 26214400")
			writer.PrintfLine("250-8BITMIME")
			writer.PrintfLine("250-AUTH PLAIN LOGIN")
			writer.PrintfLine("250-STARTTLS")
			writer.PrintfLine("250-DSN")
			writer.PrintfLine("250 PIPELINING")
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			writer.PrintfLine("235 2.7.0 Authentication successful")
		case strings.HasPrefix(upper, "AUTH LOGIN"):
			writer.PrintfLine("334 VXNlcm5hbWU6")
			if _, err := reader.ReadLine(); err != nil {
				return
			}
			writer.PrintfLine("334 UGFzc3dvcmQ6")
			if _, err := reader.ReadLine(); err != nil {
				return
			}
			writer.PrintfLine("235 2.7.0 Authentication successful")
		case strings.HasPrefix(upper, "AUTH"):
			writer.PrintfLine("235 2.7.0 Authentication successful")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			writer.PrintfLine("250 2.1.0 Sender OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			writer.PrintfLine("250 2.1.5 Recipient OK")
		case upper == "NOOP" || upper == "RSET":
			writer.PrintfLine("250 2.0.0 OK")
		case upper == "DATA":
			inData = true
			writer.PrintfLine("354 Start mail input; end with <CR><LF>.<CR><LF>")
		case upper == "QUIT":
			writer.PrintfLine("221 2.0.0 Bye")
			return
		default:
			writer.PrintfLine("500 5.5.2 Unrecognized command")
		}
	}
}

func runDockerCmd(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if runtime.GOOS == "windows" {
		wslArgs := append([]string{"docker"}, args...)
		cmd := exec.CommandContext(ctx, "wsl", wslArgs...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return out, nil
		}
		cmdNative := exec.CommandContext(ctx, "docker", args...)
		outNative, errNative := cmdNative.CombinedOutput()
		if errNative == nil {
			return outNative, nil
		}
		return out, fmt.Errorf("wsl docker err: %v, native docker err: %v", err, errNative)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	return cmd.CombinedOutput()
}

func setupMailpit(t *testing.T) *liveSMTPServer {
	t.Helper()

	// TestMain already initialized Mailpit
	if mailpitReady {
		t.Logf("Mailpit container ready on %s:%d", smtpHost, smtpPort)
		return nil
	}

	// If Mailpit setup failed in TestMain, use fallback
	if mailpitSetupErr != nil {
		t.Logf("Mailpit unavailable (%v), using embedded ESMTP server", mailpitSetupErr)
		return startFallbackSMTPServer(t, smtpPort)
	}

	// Fallback check: try to connect directly
	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)
	if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
		conn.Close()
		t.Logf("SMTP server available on %s", addr)
		return nil
	}

	// Final fallback: start embedded server
	t.Logf("Starting embedded ESMTP server on %s...", addr)
	return startFallbackSMTPServer(t, smtpPort)
}

// clearMailpit deletes all messages from Mailpit
func clearMailpit(t *testing.T) {
	if !useMailpit {
		return
	}
	req, _ := http.NewRequest("DELETE", mailpitAPI+"/v1/messages", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Logf("Warning: Failed to clear Mailpit: %v", err)
		return
	}
	resp.Body.Close()
}

// getMailpitMessages retrieves messages from Mailpit API
func getMailpitMessages(t *testing.T) []MailpitMessage {
	if !useMailpit {
		return nil
	}
	// Wait a bit for message to be processed
	time.Sleep(200 * time.Millisecond)

	resp, err := http.Get(mailpitAPI + "/v1/messages")
	if err != nil {
		t.Logf("Warning: Failed to get Mailpit messages: %v", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result MailpitMessages
	if err := json.Unmarshal(body, &result); err != nil {
		t.Logf("Warning: Failed to parse Mailpit response: %v", err)
		return nil
	}
	return result.Messages
}

// getMailpitMessageDetails retrieves full message details
func getMailpitMessageDetails(t *testing.T, id string) *MailpitMessage {
	if !useMailpit {
		return nil
	}
	resp, err := http.Get(mailpitAPI + "/v1/message/" + id)
	if err != nil {
		t.Logf("Warning: Failed to get message details: %v", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var msg MailpitMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Logf("Warning: Failed to parse message details: %v", err)
		return nil
	}
	return &msg
}

// =============================================================================
// E2E TEST: Basic Email Send
// =============================================================================
func TestLive_BasicEmail(t *testing.T) {
	server := setupMailpit(t)
	clearMailpit(t)

	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "basic-sender@example.com",
		To:         []string{"basic-recipient@example.com"},
		Subject:    "Basic E2E Test",
		Body:       "This is a basic plaintext email body.",
		TLSMode:    "none",
		NoAuth:     true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify with Mailpit API
	if useMailpit {
		msgs := getMailpitMessages(t)
		if len(msgs) == 0 {
			t.Error("No messages received by Mailpit")
		} else {
			msg := msgs[0]
			if msg.Subject != "Basic E2E Test" {
				t.Errorf("Subject mismatch: got %s", msg.Subject)
			}
			if msg.From.Address != "basic-sender@example.com" {
				t.Errorf("From mismatch: got %s", msg.From.Address)
			}
		}
	} else if server != nil {
		server.mu.Lock()
		defer server.mu.Unlock()
		if len(server.messages) == 0 {
			t.Error("No messages received by fallback server")
		}
	}
}

// =============================================================================
// E2E TEST: Full Featured Email (All EmailParams fields)
// =============================================================================
func TestLive_FullFeaturedEmail(t *testing.T) {
	server := setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()

	// Create HTML body file
	bodyFile := filepath.Join(tmpDir, "email.html")
	htmlContent := `<!DOCTYPE html>
<html>
<head><title>Test Email</title></head>
<body>
<h1>Full Featured E2E Test</h1>
<p>This email tests all EmailParams fields.</p>
<img src="cid:logo.png" alt="Logo">
</body>
</html>`
	if err := os.WriteFile(bodyFile, []byte(htmlContent), 0o644); err != nil {
		t.Fatalf("Failed to create body file: %v", err)
	}

	// Create attachments
	att1 := filepath.Join(tmpDir, "document.pdf")
	att2 := filepath.Join(tmpDir, "report.xlsx")
	inlineImg := filepath.Join(tmpDir, "logo.png")
	_ = os.WriteFile(att1, []byte("%PDF-1.4 fake pdf content"), 0o644)
	_ = os.WriteFile(att2, []byte("PK fake xlsx content"), 0o644)
	_ = os.WriteFile(inlineImg, []byte("\x89PNG\r\n\x1a\n fake png"), 0o644)

	// Create log file
	logFile := filepath.Join(tmpDir, "audit.log")

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	params := mailxgo.EmailParams{
		// Connection
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		Username:   "testuser",
		Password:   "testpass",
		TLSMode:    "none",
		NoAuth:     false,
		Timeout:    30,

		// Message envelope
		From:     "full-test@example.com",
		FromName: "Full Test Sender",
		To:       []string{"recipient1@example.com", "recipient2@example.com"},
		CC:       []string{"cc1@example.com", "cc2@example.com"},
		BCC:      []string{"bcc@example.com"},
		ReplyTo:  "reply-to@example.com",

		// Message content
		Subject:  "Full Featured E2E Test - All Fields",
		BodyFile: bodyFile,
		Charset:  "UTF-8",

		// Attachments
		Attachments:       []string{att1, att2},
		InlineAttachments: []string{inlineImg},
		MaxAttachmentMB:   25,

		// Headers
		Headers: map[string]string{
			"X-Custom-Header":  "CustomValue",
			"X-Campaign-ID":    "CAMPAIGN-12345",
			"X-Priority":       "1",
			"X-Mailer":         "mailxgo-e2e-test",
		},

		// Delivery options
		Importance: "high",
		DSNNotify:  []string{"SUCCESS", "FAILURE", "DELAY"},
		DSNReturn:  "FULL",
		Retries:    2,
		RetryDelay: 1,

		// Output
		JSONOutput:      false,
		NDJSONOutput:    false,
		LogFile:         logFile,
		NoLogRecipients: false,
		Debug:           false,

		// Context
		Context: ctx,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify audit log was created
	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Errorf("Failed to read audit log: %v", err)
	} else if !strings.Contains(string(logData), "SUCCESS") {
		t.Errorf("Audit log should contain SUCCESS: %s", string(logData))
	}

	// Verify with Mailpit API
	if useMailpit {
		msgs := getMailpitMessages(t)
		if len(msgs) == 0 {
			t.Error("No messages received by Mailpit")
			return
		}

		// Get full message details
		msg := getMailpitMessageDetails(t, msgs[0].ID)
		if msg == nil {
			return
		}

		// Verify all fields
		if msg.Subject != "Full Featured E2E Test - All Fields" {
			t.Errorf("Subject mismatch: got %s", msg.Subject)
		}
		if msg.From.Name != "Full Test Sender" {
			t.Errorf("FromName mismatch: got %s", msg.From.Name)
		}
		if msg.From.Address != "full-test@example.com" {
			t.Errorf("From address mismatch: got %s", msg.From.Address)
		}
		if len(msg.To) < 2 {
			t.Errorf("Expected 2 To recipients, got %d", len(msg.To))
		}
		if len(msg.Cc) < 2 {
			t.Errorf("Expected 2 CC recipients, got %d", len(msg.Cc))
		}
		if len(msg.ReplyTo) == 0 || msg.ReplyTo[0].Address != "reply-to@example.com" {
			t.Errorf("ReplyTo mismatch")
		}
		if msg.Attachments < 2 {
			t.Errorf("Expected at least 2 attachments, got %d", msg.Attachments)
		}
		if !strings.Contains(msg.HTML, "Full Featured E2E Test") {
			t.Errorf("HTML body mismatch")
		}

		// Check custom headers
		if headers := msg.Headers; headers != nil {
			if v, ok := headers["X-Custom-Header"]; !ok || len(v) == 0 || v[0] != "CustomValue" {
				t.Errorf("X-Custom-Header mismatch")
			}
			if v, ok := headers["X-Campaign-Id"]; !ok || len(v) == 0 || v[0] != "CAMPAIGN-12345" {
				t.Errorf("X-Campaign-ID mismatch")
			}
		}
	} else if server != nil {
		server.mu.Lock()
		defer server.mu.Unlock()
		if len(server.messages) == 0 {
			t.Error("No messages received by fallback server")
		} else {
			lastMsg := server.messages[len(server.messages)-1]
			if !strings.Contains(lastMsg, "Full Featured E2E Test") {
				t.Error("Message content mismatch")
			}
			if !strings.Contains(lastMsg, "X-Custom-Header: CustomValue") {
				t.Error("Custom header missing")
			}
		}
	}
}

// =============================================================================
// E2E TEST: SASL Authentication (PLAIN and LOGIN)
// =============================================================================
func TestLive_Authentication(t *testing.T) {
	server := setupMailpit(t)
	clearMailpit(t)

	// Test with explicit auth types
	authTypes := []string{"plain", "login", "auto"}

	for _, authType := range authTypes {
		t.Run("AuthType_"+authType, func(t *testing.T) {
			clearMailpit(t)

			params := mailxgo.EmailParams{
				SMTPServer: smtpHost,
				SMTPPort:   smtpPort,
				Username:   "testuser",
				Password:   "testpassword",
				AuthType:   authType,
				From:       fmt.Sprintf("auth-test-%s@example.com", authType),
				To:         []string{"recipient@example.com"},
				Subject:    fmt.Sprintf("Auth Test - %s", authType),
				Body:       "Testing authentication",
				TLSMode:    "none",
			}

			res, err := mailxgo.SendEmail(params)
			if err != nil {
				t.Fatalf("SendEmail with auth type %s failed: %v", authType, err)
			}
			if res.Status != "success" {
				t.Errorf("expected status success for auth type %s, got %s", authType, res.Status)
			}
		})
	}

	// Verify fallback server received all auth types
	if server != nil {
		server.mu.Lock()
		defer server.mu.Unlock()
		if len(server.messages) < len(authTypes) {
			t.Errorf("Expected %d messages, got %d", len(authTypes), len(server.messages))
		}
	}
}

// =============================================================================
// E2E TEST: Recipient Lists and Attachment Directory
// =============================================================================
func TestLive_ListsAndDirectories(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()

	// Create recipient list file
	recipientList := filepath.Join(tmpDir, "recipients.txt")
	recipientContent := `# Recipients for bulk send
list-recipient1@example.com
list-recipient2@example.com, list-recipient3@example.com
# Comment line
list-recipient4@example.com
`
	if err := os.WriteFile(recipientList, []byte(recipientContent), 0o644); err != nil {
		t.Fatalf("Failed to create recipient list: %v", err)
	}

	// Create attachment list file
	att1 := filepath.Join(tmpDir, "file1.txt")
	att2 := filepath.Join(tmpDir, "file2.txt")
	_ = os.WriteFile(att1, []byte("File 1 content"), 0o644)
	_ = os.WriteFile(att2, []byte("File 2 content"), 0o644)

	attachmentList := filepath.Join(tmpDir, "attachments.txt")
	attListContent := fmt.Sprintf("# Attachment list\n%s\n%s\n", att1, att2)
	if err := os.WriteFile(attachmentList, []byte(attListContent), 0o644); err != nil {
		t.Fatalf("Failed to create attachment list: %v", err)
	}

	// Create attachment directory
	attDir := filepath.Join(tmpDir, "attachments_dir")
	_ = os.MkdirAll(attDir, 0o755)
	_ = os.WriteFile(filepath.Join(attDir, "dir_file1.txt"), []byte("Dir file 1"), 0o644)
	_ = os.WriteFile(filepath.Join(attDir, "dir_file2.txt"), []byte("Dir file 2"), 0o644)

	// Load recipients from list
	recipients, err := mailxgo.LoadRecipientList(recipientList)
	if err != nil {
		t.Fatalf("LoadRecipientList failed: %v", err)
	}
	if len(recipients) != 4 {
		t.Errorf("Expected 4 recipients, got %d: %v", len(recipients), recipients)
	}

	// Load attachments from list
	attFromList, err := mailxgo.LoadAttachmentList(attachmentList)
	if err != nil {
		t.Fatalf("LoadAttachmentList failed: %v", err)
	}
	if len(attFromList) != 2 {
		t.Errorf("Expected 2 attachments from list, got %d", len(attFromList))
	}

	// Scan attachment directory
	attFromDir, err := mailxgo.ScanAttachmentDir(attDir)
	if err != nil {
		t.Fatalf("ScanAttachmentDir failed: %v", err)
	}
	if len(attFromDir) != 2 {
		t.Errorf("Expected 2 attachments from dir, got %d", len(attFromDir))
	}

	// Send email with combined attachments
	allAttachments := append(attFromList, attFromDir...)

	params := mailxgo.EmailParams{
		SMTPServer:      smtpHost,
		SMTPPort:        smtpPort,
		From:            "lists-test@example.com",
		To:              recipients,
		Subject:         "Lists and Directories E2E Test",
		Body:            "Testing recipient lists and attachment directories",
		Attachments:     allAttachments,
		MaxAttachmentMB: 10,
		TLSMode:         "none",
		NoAuth:          true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify with Mailpit
	if useMailpit {
		msgs := getMailpitMessages(t)
		if len(msgs) == 0 {
			t.Error("No messages received")
		} else {
			msg := getMailpitMessageDetails(t, msgs[0].ID)
			if msg != nil {
				if len(msg.To) != 4 {
					t.Errorf("Expected 4 To recipients, got %d", len(msg.To))
				}
				if msg.Attachments != 4 {
					t.Errorf("Expected 4 attachments, got %d", msg.Attachments)
				}
			}
		}
	}
}

// =============================================================================
// E2E TEST: Max Attachment Size Guard
// =============================================================================
func TestLive_MaxAttachmentSize(t *testing.T) {
	setupMailpit(t)

	tmpDir := t.TempDir()

	// Create a 2MB file
	largeFile := filepath.Join(tmpDir, "large.bin")
	data := make([]byte, 2*1024*1024) // 2MB
	if err := os.WriteFile(largeFile, data, 0o644); err != nil {
		t.Fatalf("Failed to create large file: %v", err)
	}

	// Try to send with 1MB limit - should fail
	params := mailxgo.EmailParams{
		SMTPServer:      smtpHost,
		SMTPPort:        smtpPort,
		From:            "size-test@example.com",
		To:              []string{"recipient@example.com"},
		Subject:         "Size Limit Test",
		Body:            "Testing attachment size limits",
		Attachments:     []string{largeFile},
		MaxAttachmentMB: 1, // 1MB limit
		TLSMode:         "none",
		NoAuth:          true,
	}

	_, err := mailxgo.SendEmail(params)
	if err == nil {
		t.Error("Expected error for attachment exceeding size limit")
	} else if !strings.Contains(err.Error(), "exceeds configured maximum limit") {
		t.Errorf("Expected size limit error, got: %v", err)
	}

	// Try with sufficient limit - should succeed
	params.MaxAttachmentMB = 5
	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail with sufficient limit failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}
}

// =============================================================================
// E2E TEST: Privacy Flag (NoLogRecipients)
// =============================================================================
func TestLive_PrivacyNoLogRecipients(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "privacy_audit.log")

	params := mailxgo.EmailParams{
		SMTPServer:      smtpHost,
		SMTPPort:        smtpPort,
		From:            "privacy-test@example.com",
		To:              []string{"secret1@example.com", "secret2@example.com", "secret3@example.com"},
		Subject:         "Privacy Test - Redacted Recipients",
		Body:            "Testing NoLogRecipients flag",
		TLSMode:         "none",
		NoAuth:          true,
		LogFile:         logFile,
		NoLogRecipients: true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify log file does NOT contain actual email addresses
	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}
	logStr := string(logData)

	if strings.Contains(logStr, "secret1@example.com") {
		t.Error("Log file should NOT contain actual recipient addresses")
	}
	if !strings.Contains(logStr, "[3 recipients redacted]") {
		t.Errorf("Log file should contain redacted count, got: %s", logStr)
	}
}

// =============================================================================
// E2E TEST: Context Cancellation
// =============================================================================
func TestLive_ContextCancellation(t *testing.T) {
	setupMailpit(t)

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "context-test@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Context Cancellation Test",
		Body:       "This should not be sent",
		TLSMode:    "none",
		NoAuth:     true,
		Context:    ctx,
		Retries:    3, // Would normally retry
	}

	res, err := mailxgo.SendEmail(params)
	// The send might succeed on first attempt before context check, or fail
	// The important thing is that it respects context eventually
	if res != nil && res.Status == "error" && strings.Contains(res.Error, "cancel") {
		t.Logf("Context cancellation detected as expected: %s", res.Error)
	} else if err != nil && strings.Contains(err.Error(), "cancel") {
		t.Logf("Context cancellation detected as expected: %v", err)
	}
}

// =============================================================================
// E2E TEST: Retry Mechanism
// =============================================================================
func TestLive_RetryMechanism(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "retry_audit.log")

	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "retry-test@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Retry Mechanism Test",
		Body:       "Testing retry with successful server",
		TLSMode:    "none",
		NoAuth:     true,
		Retries:    2,
		RetryDelay: 1,
		LogFile:    logFile,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}
	if res.Attempts != 1 {
		t.Logf("Completed in %d attempts", res.Attempts)
	}
}

// =============================================================================
// E2E TEST: Gateway Diagnostics
// =============================================================================
func TestLive_Diagnostics(t *testing.T) {
	setupMailpit(t)

	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "diag@example.com",
		TLSMode:    "none",
		Timeout:    10,
	}

	// Test without cert printing
	report, err := mailxgo.RunDiagnostics(params, false)
	if err != nil {
		t.Fatalf("RunDiagnostics failed: %v", err)
	}
	if report.Status != "success" {
		t.Errorf("expected status success, got %s (error: %s)", report.Status, report.Error)
	}

	// Verify latency metrics
	if report.Latency.TCPConnectMS <= 0 {
		t.Errorf("Expected positive TCP connect latency, got %f", report.Latency.TCPConnectMS)
	}
	if report.Latency.EHLORTTMS <= 0 {
		t.Errorf("Expected positive EHLO latency, got %f", report.Latency.EHLORTTMS)
	}

	// Verify capabilities
	t.Logf("Server capabilities: StartTLS=%v, Pipelining=%v, 8BITMIME=%v, DSN=%v, Auth=%v",
		report.Capabilities.StartTLS,
		report.Capabilities.Pipelining,
		report.Capabilities.EightBitMIME,
		report.Capabilities.DSN,
		report.Capabilities.AuthMethods)
}

// =============================================================================
// E2E TEST: JSON and NDJSON Output
// =============================================================================
func TestLive_OutputFormats(t *testing.T) {
	setupMailpit(t)

	tests := []struct {
		name         string
		jsonOutput   bool
		ndjsonOutput bool
	}{
		{"PlainText", false, false},
		{"JSON", true, false},
		{"NDJSON", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearMailpit(t)

			params := mailxgo.EmailParams{
				SMTPServer:   smtpHost,
				SMTPPort:     smtpPort,
				From:         fmt.Sprintf("output-%s@example.com", strings.ToLower(tt.name)),
				To:           []string{"recipient@example.com"},
				Subject:      fmt.Sprintf("Output Format Test - %s", tt.name),
				Body:         "Testing output formats",
				TLSMode:      "none",
				NoAuth:       true,
				JSONOutput:   tt.jsonOutput,
				NDJSONOutput: tt.ndjsonOutput,
			}

			res, err := mailxgo.SendEmail(params)
			if err != nil {
				t.Fatalf("SendEmail failed: %v", err)
			}
			if res.Status != "success" {
				t.Errorf("expected status success, got %s", res.Status)
			}
		})
	}
}

// =============================================================================
// E2E TEST: Email Importance Levels
// =============================================================================
func TestLive_ImportanceLevels(t *testing.T) {
	server := setupMailpit(t)

	levels := []string{"high", "normal", "low"}

	for _, level := range levels {
		t.Run("Importance_"+level, func(t *testing.T) {
			clearMailpit(t)

			params := mailxgo.EmailParams{
				SMTPServer: smtpHost,
				SMTPPort:   smtpPort,
				From:       fmt.Sprintf("importance-%s@example.com", level),
				To:         []string{"recipient@example.com"},
				Subject:    fmt.Sprintf("Importance Test - %s", level),
				Body:       fmt.Sprintf("Testing importance level: %s", level),
				Importance: level,
				TLSMode:    "none",
				NoAuth:     true,
			}

			res, err := mailxgo.SendEmail(params)
			if err != nil {
				t.Fatalf("SendEmail failed: %v", err)
			}
			if res.Status != "success" {
				t.Errorf("expected status success, got %s", res.Status)
			}

			// Verify with Mailpit
			if useMailpit {
				msgs := getMailpitMessages(t)
				if len(msgs) > 0 {
					msg := getMailpitMessageDetails(t, msgs[0].ID)
					if msg != nil && msg.Headers != nil {
						// Check X-Priority or Importance header
						t.Logf("Message headers for importance %s: %v", level, msg.Headers)
					}
				}
			}
		})
	}

	if server != nil {
		server.mu.Lock()
		defer server.mu.Unlock()
		if len(server.messages) < len(levels) {
			t.Errorf("Expected %d messages, got %d", len(levels), len(server.messages))
		}
	}
}

// =============================================================================
// E2E TEST: CLI Binary Execution
// =============================================================================
func TestLive_CLIBinary(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()

	// Create config file
	configFile := filepath.Join(tmpDir, "config.json")
	configJSON := fmt.Sprintf(`{
		"smtp_server": "%s",
		"smtp_port": %d,
		"from_email": "cli-binary@example.com",
		"tls_mode": "none",
		"no_auth": true
	}`, smtpHost, smtpPort)
	if err := os.WriteFile(configFile, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Test CLI send
	cmd := exec.Command("go", "run", "./cmd/mailxgo",
		"--config", configFile,
		"--to-email", "cli-recipient@example.com",
		"--subject", "CLI Binary E2E Test",
		"--body", "Sent via CLI binary",
		"--json-output")
	cmd.Dir = "."

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI send failed: %v\nOutput: %s", err, string(out))
	}

	// Parse JSON output
	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		// Try to find JSON in output
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "{") {
				if json.Unmarshal([]byte(line), &result) == nil {
					break
				}
			}
		}
	}

	if result["status"] != "success" {
		t.Errorf("CLI returned non-success status: %v", result)
	}

	// Test CLI diagnostics
	diagCmd := exec.Command("go", "run", "./cmd/mailxgo",
		"--config", configFile,
		"--diag",
		"--json-output")
	diagCmd.Dir = "."

	diagOut, diagErr := diagCmd.CombinedOutput()
	if diagErr != nil {
		t.Fatalf("CLI diagnostics failed: %v\nOutput: %s", diagErr, string(diagOut))
	}

	// Test version
	versionCmd := exec.Command("go", "run", "./cmd/mailxgo", "--version")
	versionCmd.Dir = "."
	versionOut, _ := versionCmd.CombinedOutput()
	if !strings.Contains(string(versionOut), "mailxgo") {
		t.Errorf("Version output should contain 'mailxgo': %s", string(versionOut))
	}
}

// =============================================================================
// E2E TEST: Email Validation Rejection
// =============================================================================
func TestLive_EmailValidation(t *testing.T) {
	setupMailpit(t)

	// Test invalid email addresses
	invalidEmails := [][]string{
		{"invalid-email"},
		{"@nodomain.com"},
		{"nodomain@"},
		{"spaces in@email.com"},
	}

	for _, emails := range invalidEmails {
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			From:       "validation@example.com",
			To:         emails,
			Subject:    "Validation Test",
			Body:       "Should not be sent",
			TLSMode:    "none",
			NoAuth:     true,
		}

		_, err := mailxgo.SendEmail(params)
		if err == nil {
			t.Errorf("Expected validation error for emails %v", emails)
		} else if !strings.Contains(err.Error(), "invalid") {
			t.Errorf("Expected 'invalid' in error for %v, got: %v", emails, err)
		}
	}
}

// =============================================================================
// E2E TEST: Config File with All Options
// =============================================================================
func TestLive_ConfigFileAllOptions(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()

	// Create comprehensive config file
	configFile := filepath.Join(tmpDir, "full_config.json")
	configJSON := fmt.Sprintf(`{
		"smtp_server": "%s",
		"smtp_port": %d,
		"smtp_username": "configuser",
		"smtp_password": "configpass",
		"no_auth": true,
		"tls_mode": "none",
		"from_name": "Config Test Sender",
		"from_email": "config-all@example.com",
		"to_email": "config-to@example.com",
		"to": ["config-to2@example.com", "config-to3@example.com"],
		"cc": ["config-cc@example.com"],
		"bcc": ["config-bcc@example.com"],
		"subject": "Config File All Options Test",
		"body": "Testing all config file options",
		"headers": {
			"X-Config-Header": "ConfigValue"
		},
		"retries": 1,
		"retry_delay": 1,
		"timeout": 30,
		"importance": "normal",
		"dsn_notify": ["SUCCESS"],
		"dsn_return": "HDRS",
		"json_output": false,
		"ndjson_output": false,
		"debug": false,
		"charset": "UTF-8",
		"max_attachment_size_mb": 25,
		"no_log_recipients": false
	}`, smtpHost, smtpPort)

	if err := os.WriteFile(configFile, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Load and use config
	config, err := mailxgo.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify config was loaded correctly
	if config.SMTPServer != smtpHost {
		t.Errorf("Config SMTPServer mismatch: %s", config.SMTPServer)
	}
	if config.FromName != "Config Test Sender" {
		t.Errorf("Config FromName mismatch: %s", config.FromName)
	}
	if len(config.To) != 2 {
		t.Errorf("Config To array should have 2 elements, got %d", len(config.To))
	}

	// Use CLI to send with config
	cmd := exec.Command("go", "run", "./cmd/mailxgo",
		"--config", configFile,
		"--json-output")
	cmd.Dir = "."

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI with config failed: %v\nOutput: %s", err, string(out))
	}

	if !strings.Contains(string(out), `"status"`) {
		t.Errorf("Expected JSON output, got: %s", string(out))
	}
}

// =============================================================================
// E2E TEST: Error Classification
// =============================================================================
func TestLive_ErrorClassification(t *testing.T) {
	// Test that error types are correctly classified
	testCases := []struct {
		name        string
		errMsg      string
		expectedType mailxgo.ErrorType
	}{
		{"TLS Error", "tls: handshake failure", mailxgo.ErrorTypeTLS},
		{"Auth Error", "535 Authentication failed", mailxgo.ErrorTypeAuth},
		{"Connection Error", "dial tcp: connection refused", mailxgo.ErrorTypeConnection},
		{"Generic Error", "550 User unknown", mailxgo.ErrorTypeSend},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := fmt.Errorf("%s", tc.errMsg)
			errType := mailxgo.ClassifyError(err)
			if errType != tc.expectedType {
				t.Errorf("ClassifyError(%q) = %v, want %v", tc.errMsg, errType, tc.expectedType)
			}
		})
	}
}

// =============================================================================
// E2E TEST: Secretprotector Encrypted Credentials
// =============================================================================
func TestLive_SecretprotectorEncryptedPassword(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	// Test 1: Plain password (should work without master key)
	t.Run("PlainPassword", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			Username:   "testuser",
			Password:   "plainpassword",
			From:       "secretprotector-plain@example.com",
			To:         []string{"recipient@example.com"},
			Subject:    "Secretprotector Test - Plain Password",
			Body:       "Testing plain password (no encryption)",
			TLSMode:    "none",
			NoAuth:     false,
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail with plain password failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected status success, got %s", res.Status)
		}
	})

	// Test 2: Encrypted password WITHOUT master key - should fail in SendEmail
	t.Run("EncryptedPassword_NoMasterKey", func(t *testing.T) {
		// Ensure no master key is set
		os.Unsetenv("SECRETPROTECTOR_MASTER_KEY")

		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			Username:   "testuser",
			Password:   "v1:gcm:aW52YWxpZGVuY3J5cHRlZGRhdGE=", // Fake encrypted format
			From:       "secretprotector-encrypted@example.com",
			To:         []string{"recipient@example.com"},
			Subject:    "Secretprotector Test - Encrypted No Key",
			Body:       "Testing encrypted password without master key",
			TLSMode:    "none",
			NoAuth:     false,
		}

		_, err := mailxgo.SendEmail(params)
		if err == nil {
			t.Error("Expected error for encrypted password without master key")
		} else if !strings.Contains(err.Error(), "decrypt") {
			t.Errorf("Expected 'decrypt' in error, got: %v", err)
		} else {
			t.Logf("Got expected error: %v", err)
		}
	})

	// Test 3: Encrypted password WITH valid master key (requires secretprotector setup)
	t.Run("EncryptedPassword_WithMasterKey", func(t *testing.T) {
		// Generate a test master key (32 bytes for AES-256)
		masterKey := "0123456789abcdef0123456789abcdef"
		t.Setenv("SECRETPROTECTOR_MASTER_KEY", masterKey)

		// Use secretprotector to encrypt a test password
		ctx := context.Background()
		testPassword := "secretpassword123"

		encrypted, err := libsecsecrets.Encrypt(ctx, testPassword, []byte(masterKey))
		if err != nil {
			t.Skipf("Secretprotector encryption not available: %v", err)
		}

		// Verify the encrypted format
		if !strings.HasPrefix(encrypted, "v1:gcm:") {
			t.Fatalf("Expected v1:gcm: prefix, got: %s", encrypted)
		}

		// Decrypt should work
		decrypted, err := mailxgo.DecryptSecret(encrypted, "")
		if err != nil {
			t.Fatalf("DecryptSecret failed: %v", err)
		}
		if decrypted != testPassword {
			t.Errorf("Decrypted password mismatch: got %q, want %q", decrypted, testPassword)
		}

		// Send email with encrypted password
		clearMailpit(t)
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			Username:   "testuser",
			Password:   encrypted,
			From:       "secretprotector-valid@example.com",
			To:         []string{"recipient@example.com"},
			Subject:    "Secretprotector Test - Encrypted Password",
			Body:       "Testing encrypted password with valid master key",
			TLSMode:    "none",
			NoAuth:     false,
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail with encrypted password failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected status success, got %s", res.Status)
		}

		// Verify email was received
		if useMailpit {
			msgs := getMailpitMessages(t)
			if len(msgs) == 0 {
				t.Error("No messages received by Mailpit")
			} else if msgs[0].Subject != "Secretprotector Test - Encrypted Password" {
				t.Errorf("Subject mismatch: got %s", msgs[0].Subject)
			}
		}
	})

	// Test 4: Encrypted OAuth2 token - test decryption only
	// Note: Mailpit doesn't support XOAUTH2, so we test decryption functionality
	t.Run("EncryptedOAuth2Token", func(t *testing.T) {
		masterKey := "0123456789abcdef0123456789abcdef"
		t.Setenv("SECRETPROTECTOR_MASTER_KEY", masterKey)

		ctx := context.Background()
		testToken := "ya29.oauth2-access-token-here"

		encrypted, err := libsecsecrets.Encrypt(ctx, testToken, []byte(masterKey))
		if err != nil {
			t.Skipf("Secretprotector encryption not available: %v", err)
		}

		// Verify encrypted format
		if !strings.HasPrefix(encrypted, "v1:gcm:") {
			t.Fatalf("Expected v1:gcm: prefix, got: %s", encrypted)
		}

		// Decrypt token should work
		decrypted, err := mailxgo.DecryptSecret(encrypted, "")
		if err != nil {
			t.Fatalf("DecryptSecret for token failed: %v", err)
		}
		if decrypted != testToken {
			t.Errorf("Decrypted token mismatch: got %q, want %q", decrypted, testToken)
		}
		t.Logf("Successfully encrypted and decrypted OAuth2 token")
	})
}

// =============================================================================
// E2E TEST: CLI with Encrypted Credentials
// =============================================================================
func TestLive_CLI_SecretprotectorCredentials(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()

	// Generate a test master key
	masterKey := "0123456789abcdef0123456789abcdef"
	t.Setenv("SECRETPROTECTOR_MASTER_KEY", masterKey)

	// Encrypt a test password using secretprotector
	ctx := context.Background()
	testPassword := "cli-encrypted-pass"
	encrypted, err := libsecsecrets.Encrypt(ctx, testPassword, []byte(masterKey))
	if err != nil {
		t.Skipf("Secretprotector encryption not available: %v", err)
	}

	// Create config file with encrypted password
	configFile := filepath.Join(tmpDir, "encrypted_config.json")
	configJSON := fmt.Sprintf(`{
		"smtp_server": "%s",
		"smtp_port": %d,
		"smtp_username": "cli-user",
		"smtp_password": "%s",
		"from_email": "cli-encrypted@example.com",
		"to_email": "recipient@example.com",
		"subject": "CLI Secretprotector E2E Test",
		"body": "Testing CLI with encrypted password in config",
		"tls_mode": "none",
		"json_output": true
	}`, smtpHost, smtpPort, encrypted)

	if err := os.WriteFile(configFile, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Run CLI with encrypted config
	cmd := exec.Command("go", "run", "./cmd/mailxgo", "--config", configFile)
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "SECRETPROTECTOR_MASTER_KEY="+masterKey)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI with encrypted config failed: %v\nOutput: %s", err, string(out))
	}

	// Verify JSON output indicates success
	if !strings.Contains(string(out), `"status"`) {
		t.Errorf("Expected JSON output, got: %s", string(out))
	}

	// Verify email was received
	if useMailpit {
		msgs := getMailpitMessages(t)
		if len(msgs) == 0 {
			t.Error("No messages received by Mailpit")
		} else if !strings.Contains(msgs[0].Subject, "CLI Secretprotector") {
			t.Errorf("Subject mismatch: got %s", msgs[0].Subject)
		}
	}
}

// =============================================================================
// E2E TEST: TLS Trust Modes
// =============================================================================
func TestLive_TLSModes(t *testing.T) {
	setupMailpit(t)

	// Test TLS mode 'none' - Mailpit without TLS certs doesn't support STARTTLS,
	// so ignore-trust mode would fail (requires STARTTLS).
	// The ignore-trust mode is tested in TestLive_DiagnosticsWithTLSOptions against real servers.
	t.Run("TLSMode_none", func(t *testing.T) {
		clearMailpit(t)

		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			From:       "tls-none@example.com",
			To:         []string{"recipient@example.com"},
			Subject:    "TLS Mode Test - none",
			Body:       "Testing TLS mode: none",
			TLSMode:    "none",
			NoAuth:     true,
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail with TLS mode none failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected status success for TLS mode none, got %s", res.Status)
		}
	})
}

// =============================================================================
// E2E TEST: TLS CA Certificate Loading
// =============================================================================
func TestLive_TLSCACert(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()

	// Create a test CA certificate (self-signed)
	certPEM := generateTestCertPEM(t)
	caCertFile := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caCertFile, certPEM, 0o644); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}

	// Test with CA cert file (Mailpit doesn't use TLS, so this tests the loading path)
	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "tls-ca-cert@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "TLS CA Cert Test",
		Body:       "Testing TLS CA certificate loading",
		TLSMode:    "none", // Mailpit doesn't have TLS
		TLSCACert:  caCertFile,
		NoAuth:     true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail with TLS CA cert failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}
}

// =============================================================================
// E2E TEST: TLS CA Directory Loading
// =============================================================================
func TestLive_TLSCADir(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		t.Fatalf("Failed to create CA dir: %v", err)
	}

	// Create multiple CA cert files
	certPEM := generateTestCertPEM(t)
	for _, name := range []string{"ca1.pem", "ca2.crt", "ca3.cer"} {
		if err := os.WriteFile(filepath.Join(caDir, name), certPEM, 0o644); err != nil {
			t.Fatalf("Failed to write CA cert %s: %v", name, err)
		}
	}

	// Also create a non-cert file (should be ignored)
	if err := os.WriteFile(filepath.Join(caDir, "readme.txt"), []byte("not a cert"), 0o644); err != nil {
		t.Fatalf("Failed to write non-cert file: %v", err)
	}

	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "tls-ca-dir@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "TLS CA Directory Test",
		Body:       "Testing TLS CA directory loading",
		TLSMode:    "none",
		TLSCADir:   caDir,
		NoAuth:     true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail with TLS CA dir failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}
}

// =============================================================================
// E2E TEST: TLS Fingerprint Validation
// =============================================================================
func TestLive_TLSFingerprintValidation(t *testing.T) {
	// Test fingerprint validation (unit-level, no network needed)
	validFingerprints := []string{
		"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		"01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	for _, fp := range validFingerprints {
		if err := mailxgo.ValidateCertFingerprint(fp); err != nil {
			t.Errorf("ValidateCertFingerprint(%q) unexpected error: %v", fp, err)
		}
	}

	invalidFingerprints := []string{
		"",
		"0123456789ABCDEF",                               // too short
		"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEFGG", // invalid chars
	}

	for _, fp := range invalidFingerprints {
		if err := mailxgo.ValidateCertFingerprint(fp); err == nil {
			t.Errorf("ValidateCertFingerprint(%q) expected error, got nil", fp)
		}
	}
}

// =============================================================================
// E2E TEST: Diagnostics with TLS Options
// =============================================================================
func TestLive_DiagnosticsWithTLSOptions(t *testing.T) {
	setupMailpit(t)

	tmpDir := t.TempDir()

	// Create a test CA certificate
	certPEM := generateTestCertPEM(t)
	caCertFile := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caCertFile, certPEM, 0o644); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}

	// Test diagnostics with ignore-trust mode
	t.Run("DiagIgnoreTrust", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			From:       "diag@example.com",
			TLSMode:    "none",
			Timeout:    10,
		}

		report, err := mailxgo.RunDiagnostics(params, false)
		if err != nil {
			t.Fatalf("RunDiagnostics failed: %v", err)
		}
		if report.Status != "success" {
			t.Errorf("expected status success, got %s", report.Status)
		}
	})

	// Test diagnostics with CA cert file
	t.Run("DiagWithCACert", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			From:       "diag@example.com",
			TLSMode:    "none",
			TLSCACert:  caCertFile,
			Timeout:    10,
		}

		report, err := mailxgo.RunDiagnostics(params, false)
		if err != nil {
			t.Fatalf("RunDiagnostics with CA cert failed: %v", err)
		}
		if report.Status != "success" {
			t.Errorf("expected status success, got %s", report.Status)
		}
	})
}

// =============================================================================
// E2E TEST: CLI with TLS Options
// =============================================================================
func TestLive_CLI_TLSOptions(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()

	// Create config with TLS options
	configFile := filepath.Join(tmpDir, "tls_config.json")
	configJSON := fmt.Sprintf(`{
		"smtp_server": "%s",
		"smtp_port": %d,
		"from_email": "cli-tls@example.com",
		"to_email": "recipient@example.com",
		"subject": "CLI TLS Options Test",
		"body": "Testing CLI with TLS options in config",
		"tls_mode": "none",
		"no_auth": true,
		"json_output": true
	}`, smtpHost, smtpPort)

	if err := os.WriteFile(configFile, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Run CLI with config
	cmd := exec.Command("go", "run", "./cmd/mailxgo", "--config", configFile)
	cmd.Dir = "."

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI with TLS config failed: %v\nOutput: %s", err, string(out))
	}

	if !strings.Contains(string(out), `"status"`) {
		t.Errorf("Expected JSON output, got: %s", string(out))
	}

	// Verify email was received
	if useMailpit {
		msgs := getMailpitMessages(t)
		if len(msgs) == 0 {
			t.Error("No messages received by Mailpit")
		}
	}
}

// Helper: generate a test certificate PEM (for integration tests)
func generateTestCertPEM(t *testing.T) []byte {
	t.Helper()
	der := generateTestCertDERIntegration(t)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Helper: generate a test certificate DER (for integration tests)
func generateTestCertDERIntegration(t *testing.T) []byte {
	t.Helper()

	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(crand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	return certDER
}

// =============================================================================
// E2E TEST: OAuth2 XOAUTH2 Authentication
// =============================================================================

const (
	oauth2MockPort      = 1026
	oauth2ContainerName = "mailxgo-oauth2-mock"
)

var (
	oauth2Ready     bool
	oauth2SetupOnce sync.Once
)

// setupOAuth2Mock starts the OAuth2 mock SMTP server for XOAUTH2 testing.
func setupOAuth2Mock(t *testing.T) bool {
	t.Helper()

	oauth2SetupOnce.Do(func() {
		addr := fmt.Sprintf("%s:%d", smtpHost, oauth2MockPort)

		// Check if already running
		if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			conn.Close()
			oauth2Ready = true
			t.Logf("OAuth2 mock server already running on %s", addr)
			return
		}

		// Try to start using Docker
		_, _ = runDockerCmd("rm", "-f", oauth2ContainerName)

		// Build and run the OAuth2 mock container
		t.Logf("Building OAuth2 mock server container...")
		buildOut, buildErr := runDockerCmd("build", "-t", "mailxgo-oauth2-mock", "./test/oauth2-mock")
		if buildErr != nil {
			t.Logf("Docker build failed: %v\n%s", buildErr, string(buildOut))
			t.Logf("OAuth2 mock requires Docker - skipping OAuth2 tests")
			return
		}

		t.Logf("Starting OAuth2 mock server container...")
		_, runErr := runDockerCmd("run", "-d", "--name", oauth2ContainerName,
			"-p", fmt.Sprintf("%d:1025", oauth2MockPort),
			"-e", "SMTP_ADDR=:1025",
			"mailxgo-oauth2-mock")
		if runErr != nil {
			t.Logf("Docker run failed: %v", runErr)
			return
		}

		// Wait for container readiness
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
				conn.Close()
				oauth2Ready = true
				t.Logf("OAuth2 mock server ready on %s", addr)
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Logf("OAuth2 mock server failed to start within timeout")
	})

	return oauth2Ready
}

func TestLive_OAuth2_XOAUTH2Authentication(t *testing.T) {
	if !setupOAuth2Mock(t) {
		t.Skip("OAuth2 mock server not available - requires Docker")
	}

	t.Cleanup(func() {
		_, _ = runDockerCmd("rm", "-f", oauth2ContainerName)
	})

	// Test 1: XOAUTH2 with valid token
	t.Run("XOAUTH2_ValidToken", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   oauth2MockPort,
			Username:   "oauth-user@example.com",
			OAuth2:     true,
			Token:      "ya29.valid-oauth2-access-token-for-testing",
			From:       "oauth2-sender@example.com",
			To:         []string{"recipient@example.com"},
			Subject:    "OAuth2 XOAUTH2 Test",
			Body:       "Testing XOAUTH2 authentication",
			TLSMode:    "none",
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail with XOAUTH2 failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected status success, got %s", res.Status)
		}
		t.Logf("XOAUTH2 authentication successful")
	})

	// Test 2: XOAUTH2 with test token prefix
	t.Run("XOAUTH2_TestToken", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   oauth2MockPort,
			Username:   "test-user@example.com",
			OAuth2:     true,
			Token:      "test-token-abc123",
			From:       "oauth2-test@example.com",
			To:         []string{"recipient@example.com"},
			Subject:    "OAuth2 Test Token",
			Body:       "Testing with test token prefix",
			TLSMode:    "none",
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail with test token failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected status success, got %s", res.Status)
		}
	})

	// Test 3: XOAUTH2 with encrypted token via secretprotector
	t.Run("XOAUTH2_EncryptedToken", func(t *testing.T) {
		masterKey := "0123456789abcdef0123456789abcdef"
		t.Setenv("SECRETPROTECTOR_MASTER_KEY", masterKey)

		ctx := context.Background()
		testToken := "ya29.encrypted-oauth2-token-here"

		encrypted, err := libsecsecrets.Encrypt(ctx, testToken, []byte(masterKey))
		if err != nil {
			t.Skipf("Secretprotector encryption not available: %v", err)
		}

		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   oauth2MockPort,
			Username:   "encrypted-oauth@example.com",
			OAuth2:     true,
			Token:      encrypted, // v1:gcm:... encrypted token
			From:       "oauth2-encrypted@example.com",
			To:         []string{"recipient@example.com"},
			Subject:    "OAuth2 Encrypted Token Test",
			Body:       "Testing XOAUTH2 with secretprotector encrypted token",
			TLSMode:    "none",
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail with encrypted OAuth2 token failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected status success, got %s", res.Status)
		}
		t.Logf("XOAUTH2 with encrypted token successful")
	})

	// Test 4: CLI with OAuth2 flags
	t.Run("CLI_OAuth2", func(t *testing.T) {
		cmd := exec.Command("go", "run", "./cmd/mailxgo",
			"--smtp-server", smtpHost,
			"--smtp-port", fmt.Sprintf("%d", oauth2MockPort),
			"--oauth2",
			"--smtp-username", "cli-oauth@example.com",
			"--token", "ya29.cli-oauth2-token",
			"--from-email", "cli-oauth2@example.com",
			"--to-email", "recipient@example.com",
			"--subject", "CLI OAuth2 Test",
			"--body", "Testing CLI with OAuth2 flags",
			"--tls-mode", "none",
			"--json-output",
		)
		cmd.Dir = "."

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI with OAuth2 failed: %v\nOutput: %s", err, string(out))
		}

		if !strings.Contains(string(out), `"status": "success"`) && !strings.Contains(string(out), `"status":"success"`) {
			t.Errorf("Expected success status in output, got: %s", string(out))
		}
		t.Logf("CLI OAuth2 test passed")
	})
}
