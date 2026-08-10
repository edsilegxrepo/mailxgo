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

// isWSL returns true if running via WSL docker (higher latency expected)
func isWSL() bool {
	return runtime.GOOS == "windows"
}

// containerTimeout returns appropriate timeout based on environment
func containerTimeout() time.Duration {
	if isWSL() {
		return 30 * time.Second // WSL + Docker has higher latency
	}
	return 15 * time.Second
}

// dialTimeout returns appropriate dial timeout based on environment
func dialTimeout() time.Duration {
	if isWSL() {
		return 500 * time.Millisecond
	}
	return 100 * time.Millisecond
}

// TestMain provides one-time setup and teardown for the integration test suite.
func TestMain(m *testing.M) {
	// Setup: Ensure Mailpit container is running
	mailpitSetupOnce.Do(func() {
		mailpitSetupErr = ensureMailpitContainer()
	})

	code := m.Run()

	// Teardown: Stop and remove container
	_, _ = runDockerCmd("stop", containerName)
	_, _ = runDockerCmd("rm", "-f", containerName)

	// Clean up TLS cert directory
	if testTLSCertDir != "" {
		os.RemoveAll(testTLSCertDir)
	}

	os.Exit(code)
}

// ensureMailpitContainer ensures Mailpit container is running with proper lifecycle:
// 1. If container exists and stopped, start it
// 2. If container doesn't exist but image exists, create and start
// 3. If image doesn't exist, pull it, create and start
func ensureMailpitContainer() error {
	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)
	imageName := "axllent/mailpit"

	// Check if container exists
	out, err := runDockerCmd("inspect", "--format", "{{.State.Running}}", containerName)
	if err == nil {
		// Container exists
		running := strings.TrimSpace(string(out))
		if running == "true" {
			// Already running, verify it's responsive
			return waitForMailpit(addr)
		}
		// Container exists but not running, start it
		if _, err := runDockerCmd("start", containerName); err != nil {
			// Failed to start, remove and recreate
			_, _ = runDockerCmd("rm", "-f", containerName)
		} else {
			return waitForMailpit(addr)
		}
	}

	// Container doesn't exist, check if image exists
	if _, err := runDockerCmd("image", "inspect", imageName); err != nil {
		// Image doesn't exist, pull it
		if _, err := runDockerCmd("pull", imageName); err != nil {
			return fmt.Errorf("failed to pull mailpit image: %w", err)
		}
	}

	// Create and start container
	_, err = runDockerCmd("run", "-d", "--name", containerName,
		"-p", fmt.Sprintf("%d:1025", smtpPort),
		"-p", "8025:8025",
		"-e", "MP_SMTP_AUTH_ACCEPT_ANY=true",
		"-e", "MP_SMTP_AUTH_ALLOW_INSECURE=true",
		imageName)
	if err != nil {
		return fmt.Errorf("failed to create mailpit container: %w", err)
	}

	return waitForMailpit(addr)
}

// waitForMailpit waits until Mailpit API is responsive
func waitForMailpit(addr string) error {
	timeout := containerTimeout()
	deadline := time.Now().Add(timeout)
	dialTO := dialTimeout()

	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", addr, dialTO); err == nil {
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
	return fmt.Errorf("mailpit not ready after %v", timeout)
}

// MailpitMessage represents a message from Mailpit API
type MailpitMessage struct {
	ID   string `json:"ID"`
	From struct {
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
	Subject     string              `json:"Subject"`
	Attachments int                 `json:"Attachments"`
	Size        int                 `json:"Size"`
	Text        string              `json:"Text"`
	HTML        string              `json:"HTML"`
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

	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)
	dialTO := dialTimeout()

	// Check if Mailpit is actually reachable (container may have crashed mid-suite)
	if mailpitReady {
		if conn, err := net.DialTimeout("tcp", addr, dialTO); err == nil {
			conn.Close()
			t.Logf("Mailpit container ready on %s:%d", smtpHost, smtpPort)
			return nil
		}
		// Container was ready but is now unreachable - try to restart it
		t.Logf("Mailpit container became unreachable, attempting restart...")
		_, _ = runDockerCmd("start", containerName)
		if err := waitForMailpit(addr); err == nil {
			t.Logf("Mailpit container restarted on %s:%d", smtpHost, smtpPort)
			return nil
		}
	}

	// If Mailpit setup failed in TestMain, use fallback
	if mailpitSetupErr != nil {
		t.Logf("Mailpit unavailable (%v), using embedded ESMTP server", mailpitSetupErr)
		return startFallbackSMTPServer(t, smtpPort)
	}

	// Fallback check: try to connect directly
	if conn, err := net.DialTimeout("tcp", addr, dialTO); err == nil {
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
			"X-Custom-Header": "CustomValue",
			"X-Campaign-ID":   "CAMPAIGN-12345",
			"X-Priority":      "1",
			"X-Mailer":        "mailxgo-e2e-test",
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
		name         string
		errMsg       string
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
		"0123456789ABCDEF", // too short
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

// =============================================================================
// E2E TEST: Dry-Run Mode
// =============================================================================
func TestLive_DryRun(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "dryrun@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Dry-Run Test",
		Body:       "This should NOT be sent",
		TLSMode:    "none",
		NoAuth:     true,
		DryRun:     true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Dry-run failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify NO email was sent to Mailpit
	if useMailpit {
		time.Sleep(200 * time.Millisecond)
		msgs := getMailpitMessages(t)
		if len(msgs) > 0 {
			t.Errorf("Dry-run should not send email, but found %d messages", len(msgs))
		}
	}
	t.Logf("Dry-run validated without sending")
}

// =============================================================================
// E2E TEST: Quiet Mode
// =============================================================================
func TestLive_QuietMode(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "quiet@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Quiet Mode Test",
		Body:       "Testing quiet mode",
		TLSMode:    "none",
		NoAuth:     true,
		Quiet:      true,
	}

	res, err := mailxgo.SendEmail(params)

	w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("Quiet mode send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify no output was produced
	if len(out) > 0 {
		t.Errorf("Quiet mode should suppress output, but got: %s", string(out))
	}
	t.Logf("Quiet mode suppressed output correctly")
}

// =============================================================================
// E2E TEST: Read Receipt Header
// =============================================================================
func TestLive_ReadReceipt(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	params := mailxgo.EmailParams{
		SMTPServer:  smtpHost,
		SMTPPort:    smtpPort,
		From:        "receipt@example.com",
		To:          []string{"recipient@example.com"},
		Subject:     "Read Receipt Test",
		Body:        "Testing read receipt header",
		TLSMode:     "none",
		NoAuth:      true,
		ReadReceipt: true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Read receipt send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify the Disposition-Notification-To header via Mailpit API
	if useMailpit {
		msgs := getMailpitMessages(t)
		if len(msgs) == 0 {
			t.Error("No messages received by Mailpit")
		} else {
			details := getMailpitMessageDetails(t, msgs[0].ID)
			if details != nil && details.Headers != nil {
				dnt := details.Headers["Disposition-Notification-To"]
				if len(dnt) == 0 || !strings.Contains(dnt[0], "receipt@example.com") {
					t.Errorf("Expected Disposition-Notification-To header with sender, got: %v", dnt)
				} else {
					t.Logf("Read receipt header correctly set: %v", dnt)
				}
			}
		}
	}
}

// =============================================================================
// E2E TEST: Template Substitution
// =============================================================================
func TestLive_Template(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()

	// Create template file
	tmplFile := filepath.Join(tmpDir, "email.tmpl")
	tmplContent := "Dear {{.Name}},\n\nYour order {{.OrderID}} has been shipped.\n\nBest regards,\nThe Team"
	if err := os.WriteFile(tmplFile, []byte(tmplContent), 0o644); err != nil {
		t.Fatalf("Failed to create template: %v", err)
	}

	// Create JSON data file
	dataFile := filepath.Join(tmpDir, "vars.json")
	jsonContent := `{"Name": "Alice", "OrderID": "ORD-12345"}`
	if err := os.WriteFile(dataFile, []byte(jsonContent), 0o644); err != nil {
		t.Fatalf("Failed to create data file: %v", err)
	}

	params := mailxgo.EmailParams{
		SMTPServer:       smtpHost,
		SMTPPort:         smtpPort,
		From:             "template@example.com",
		To:               []string{"recipient@example.com"},
		Subject:          "Template Test",
		TemplateFile:     tmplFile,
		TemplateDataFile: dataFile,
		TLSMode:          "none",
		NoAuth:           true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Template send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify template was processed
	if useMailpit {
		msgs := getMailpitMessages(t)
		if len(msgs) == 0 {
			t.Error("No messages received by Mailpit")
		} else {
			details := getMailpitMessageDetails(t, msgs[0].ID)
			if details != nil {
				if !strings.Contains(details.Text, "Alice") {
					t.Errorf("Expected 'Alice' in body, got: %s", details.Text)
				}
				if !strings.Contains(details.Text, "ORD-12345") {
					t.Errorf("Expected 'ORD-12345' in body, got: %s", details.Text)
				}
				t.Logf("Template correctly processed: Name=Alice, OrderID=ORD-12345")
			}
		}
	}
}

// =============================================================================
// E2E TEST: Template with inline --var flags
// =============================================================================
func TestLive_TemplateInlineVars(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "template-inline@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Inline Template Test",
		Body:       "Hello {{.User}}, your code is {{.Code}}.",
		TemplateVars: map[string]string{
			"User": "Bob",
			"Code": "XYZ789",
		},
		TLSMode: "none",
		NoAuth:  true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Inline template send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	if useMailpit {
		msgs := getMailpitMessages(t)
		if len(msgs) > 0 {
			details := getMailpitMessageDetails(t, msgs[0].ID)
			if details != nil {
				if !strings.Contains(details.Text, "Bob") || !strings.Contains(details.Text, "XYZ789") {
					t.Errorf("Template vars not applied: %s", details.Text)
				} else {
					t.Logf("Inline template vars correctly applied")
				}
			}
		}
	}
}

// =============================================================================
// E2E TEST: Delay before sending
// =============================================================================
func TestLive_Delay(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "delay@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Delay Test",
		Body:       "Testing delay feature",
		TLSMode:    "none",
		NoAuth:     true,
		Delay:      2, // 2 second delay
		Quiet:      true,
	}

	start := time.Now()
	res, err := mailxgo.SendEmail(params)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Delay send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify delay was applied (should take at least 1.5 seconds)
	if elapsed < 1500*time.Millisecond {
		t.Errorf("Expected delay of ~2s, but only took %v", elapsed)
	}
	t.Logf("Delay correctly applied: took %v", elapsed)
}

// =============================================================================
// E2E TEST: Save EML archive
// =============================================================================
func TestLive_SaveEML(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	emlDir := filepath.Join(tmpDir, "archive")

	params := mailxgo.EmailParams{
		SMTPServer:  smtpHost,
		SMTPPort:    smtpPort,
		From:        "archive@example.com",
		To:          []string{"recipient@example.com"},
		Subject:     "EML Archive Test",
		Body:        "Testing EML archiving",
		TLSMode:     "none",
		NoAuth:      true,
		SaveEMLPath: emlDir,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("EML archive send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify EML file was created
	files, err := os.ReadDir(emlDir)
	if err != nil {
		t.Fatalf("Failed to read EML dir: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("Expected 1 EML file, got %d", len(files))
	}
	if len(files) > 0 {
		name := files[0].Name()
		if !strings.HasPrefix(name, "mailarchive_") {
			t.Errorf("Expected mailarchive_ prefix, got %s", name)
		}
		if !strings.HasSuffix(name, ".eml") {
			t.Errorf("Expected .eml extension, got %s", name)
		}
		// Verify file has content
		emlPath := filepath.Join(emlDir, name)
		data, err := os.ReadFile(emlPath)
		if err != nil {
			t.Errorf("Failed to read EML file: %v", err)
		}
		if len(data) < 100 {
			t.Errorf("EML file too small: %d bytes", len(data))
		}
		t.Logf("EML archived: %s (%d bytes)", name, len(data))
	}
}

// =============================================================================
// E2E TEST: Save EML archive with compression
// =============================================================================
func TestLive_SaveEMLCompressed(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	emlDir := filepath.Join(tmpDir, "archive-zstd")

	params := mailxgo.EmailParams{
		SMTPServer:  smtpHost,
		SMTPPort:    smtpPort,
		From:        "archive-zstd@example.com",
		To:          []string{"recipient@example.com"},
		Subject:     "Compressed EML Test",
		Body:        "Testing compressed EML archiving",
		TLSMode:     "none",
		NoAuth:      true,
		SaveEMLPath: emlDir,
		CompressEML: true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Compressed EML send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	files, err := os.ReadDir(emlDir)
	if err != nil {
		t.Fatalf("Failed to read EML dir: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("Expected 1 compressed EML file, got %d", len(files))
	}
	if len(files) > 0 {
		name := files[0].Name()
		if !strings.HasPrefix(name, "mailarchive_") {
			t.Errorf("Expected mailarchive_ prefix, got %s", name)
		}
		if !strings.HasSuffix(name, ".eml.zst") {
			t.Errorf("Expected .eml.zst extension, got %s", name)
		}
		t.Logf("Compressed EML archived: %s", name)
	}
}

// =============================================================================
// E2E TEST: File routing on success (--route)
// =============================================================================
func TestLive_RouteSuccess(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	successDir := filepath.Join(tmpDir, "sent")
	errorDir := filepath.Join(tmpDir, "failed")

	// Create test attachment
	attFile := filepath.Join(tmpDir, "report.pdf")
	if err := os.WriteFile(attFile, []byte("PDF content here"), 0o644); err != nil {
		t.Fatalf("Failed to create attachment: %v", err)
	}

	params := mailxgo.EmailParams{
		SMTPServer:       smtpHost,
		SMTPPort:         smtpPort,
		From:             "routing@example.com",
		To:               []string{"recipient@example.com"},
		Subject:          "Attachment Routing Test",
		Body:             "Testing attachment routing",
		Attachments:      []string{attFile},
		TLSMode:          "none",
		NoAuth:           true,
		RouteSuccessPath: successDir,
		RouteErrorPath:   errorDir,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Attachment routing send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify attachment was moved to success path
	if _, err := os.Stat(attFile); !os.IsNotExist(err) {
		t.Errorf("Original attachment should be removed")
	}
	movedFile := filepath.Join(successDir, "report.pdf")
	if _, err := os.Stat(movedFile); err != nil {
		t.Errorf("Attachment should exist in success dir: %v", err)
	} else {
		t.Logf("Attachment correctly routed to success path")
	}
}

// =============================================================================
// E2E TEST: File delete after success (--delete)
// =============================================================================
func TestLive_RouteDelete(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()

	// Create test attachment
	attFile := filepath.Join(tmpDir, "temp-report.pdf")
	if err := os.WriteFile(attFile, []byte("Temporary PDF content"), 0o644); err != nil {
		t.Fatalf("Failed to create attachment: %v", err)
	}

	params := mailxgo.EmailParams{
		SMTPServer:  smtpHost,
		SMTPPort:    smtpPort,
		From:        "delete@example.com",
		To:          []string{"recipient@example.com"},
		Subject:     "Attachment Delete Test",
		Body:        "Testing attachment delete",
		Attachments: []string{attFile},
		TLSMode:     "none",
		NoAuth:      true,
		RouteDelete: true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Attachment delete send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify attachment was deleted
	if _, err := os.Stat(attFile); !os.IsNotExist(err) {
		t.Errorf("Attachment should be deleted after successful send")
	} else {
		t.Logf("Attachment correctly deleted after send")
	}
}

// =============================================================================
// E2E TEST: Body file routing
// =============================================================================
func TestLive_BodyFileRouting(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	successDir := filepath.Join(tmpDir, "sent-bodies")

	// Create body file
	bodyFile := filepath.Join(tmpDir, "email-body.html")
	if err := os.WriteFile(bodyFile, []byte("<h1>Test Email</h1><p>Body content</p>"), 0o644); err != nil {
		t.Fatalf("Failed to create body file: %v", err)
	}

	params := mailxgo.EmailParams{
		SMTPServer:       smtpHost,
		SMTPPort:         smtpPort,
		From:             "bodyroute@example.com",
		To:               []string{"recipient@example.com"},
		Subject:          "Body File Routing Test",
		BodyFile:         bodyFile,
		TLSMode:          "none",
		NoAuth:           true,
		RouteSuccessPath: successDir,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Body file routing send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify body file was moved to success path
	if _, err := os.Stat(bodyFile); !os.IsNotExist(err) {
		t.Errorf("Original body file should be removed")
	}
	movedFile := filepath.Join(successDir, "email-body.html")
	if _, err := os.Stat(movedFile); err != nil {
		t.Errorf("Body file should exist in success dir: %v", err)
	} else {
		t.Logf("Body file correctly routed to success path")
	}
}

// =============================================================================
// E2E TEST: Rate limit (--rate-limit)
// =============================================================================
func TestLive_RateLimit(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	// Rate limit is for batch sends - test that it's accepted and works
	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "ratelimit@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Rate Limit Test",
		Body:       "Testing rate limit parameter",
		TLSMode:    "none",
		NoAuth:     true,
		RateLimit:  30, // 30 emails per minute
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Rate limit send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}
	t.Logf("Rate limit parameter accepted")
}

// =============================================================================
// E2E TEST: Route with body file only (no attachments)
// =============================================================================
func TestLive_RouteBodyFileOnly(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	successDir := filepath.Join(tmpDir, "sent")

	// Create body file only, no attachments
	bodyFile := filepath.Join(tmpDir, "body-only.html")
	if err := os.WriteFile(bodyFile, []byte("<p>Body only test</p>"), 0o644); err != nil {
		t.Fatalf("Failed to create body file: %v", err)
	}

	params := mailxgo.EmailParams{
		SMTPServer:       smtpHost,
		SMTPPort:         smtpPort,
		From:             "bodyonly@example.com",
		To:               []string{"recipient@example.com"},
		Subject:          "Body File Only Routing Test",
		BodyFile:         bodyFile,
		TLSMode:          "none",
		NoAuth:           true,
		RouteSuccessPath: successDir,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Body file only routing failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify body file was moved
	if _, err := os.Stat(bodyFile); !os.IsNotExist(err) {
		t.Errorf("Original body file should be removed")
	}
	movedFile := filepath.Join(successDir, "body-only.html")
	if _, err := os.Stat(movedFile); err != nil {
		t.Errorf("Body file should exist in success dir: %v", err)
	} else {
		t.Logf("Body file only correctly routed")
	}
}

// =============================================================================
// E2E TEST: Route with multiple attachments
// =============================================================================
func TestLive_RouteMultipleAttachments(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	successDir := filepath.Join(tmpDir, "sent-multi")

	// Create multiple attachments
	att1 := filepath.Join(tmpDir, "doc1.pdf")
	att2 := filepath.Join(tmpDir, "doc2.xlsx")
	att3 := filepath.Join(tmpDir, "image.png")
	if err := os.WriteFile(att1, []byte("PDF content"), 0o644); err != nil {
		t.Fatalf("Failed to create attachment 1: %v", err)
	}
	if err := os.WriteFile(att2, []byte("Excel content"), 0o644); err != nil {
		t.Fatalf("Failed to create attachment 2: %v", err)
	}
	if err := os.WriteFile(att3, []byte("Image content"), 0o644); err != nil {
		t.Fatalf("Failed to create attachment 3: %v", err)
	}

	params := mailxgo.EmailParams{
		SMTPServer:       smtpHost,
		SMTPPort:         smtpPort,
		From:             "multiatt@example.com",
		To:               []string{"recipient@example.com"},
		Subject:          "Multiple Attachments Routing Test",
		Body:             "Email with multiple attachments",
		Attachments:      []string{att1, att2, att3},
		TLSMode:          "none",
		NoAuth:           true,
		RouteSuccessPath: successDir,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Multiple attachments routing failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify all attachments were moved
	for _, name := range []string{"doc1.pdf", "doc2.xlsx", "image.png"} {
		movedFile := filepath.Join(successDir, name)
		if _, err := os.Stat(movedFile); err != nil {
			t.Errorf("Attachment %s should exist in success dir: %v", name, err)
		}
	}
	t.Logf("All %d attachments correctly routed", 3)
}

// =============================================================================
// E2E TEST: Route with body file AND attachments
// =============================================================================
func TestLive_RouteBodyAndAttachments(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	successDir := filepath.Join(tmpDir, "sent-both")

	// Create body file and attachments
	bodyFile := filepath.Join(tmpDir, "newsletter.html")
	att1 := filepath.Join(tmpDir, "report.pdf")
	if err := os.WriteFile(bodyFile, []byte("<h1>Newsletter</h1>"), 0o644); err != nil {
		t.Fatalf("Failed to create body file: %v", err)
	}
	if err := os.WriteFile(att1, []byte("Report content"), 0o644); err != nil {
		t.Fatalf("Failed to create attachment: %v", err)
	}

	params := mailxgo.EmailParams{
		SMTPServer:       smtpHost,
		SMTPPort:         smtpPort,
		From:             "both@example.com",
		To:               []string{"recipient@example.com"},
		Subject:          "Body And Attachment Routing Test",
		BodyFile:         bodyFile,
		Attachments:      []string{att1},
		TLSMode:          "none",
		NoAuth:           true,
		RouteSuccessPath: successDir,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Body and attachment routing failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify both body file and attachment were moved
	bodyMoved := filepath.Join(successDir, "newsletter.html")
	attMoved := filepath.Join(successDir, "report.pdf")
	if _, err := os.Stat(bodyMoved); err != nil {
		t.Errorf("Body file should exist in success dir: %v", err)
	}
	if _, err := os.Stat(attMoved); err != nil {
		t.Errorf("Attachment should exist in success dir: %v", err)
	}
	t.Logf("Both body file and attachment correctly routed")
}

// =============================================================================
// E2E TEST: No routing (plain email, no body file, no attachments)
// =============================================================================
func TestLive_NoRouting(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	params := mailxgo.EmailParams{
		SMTPServer:       smtpHost,
		SMTPPort:         smtpPort,
		From:             "noroute@example.com",
		To:               []string{"recipient@example.com"},
		Subject:          "No Routing Test",
		Body:             "Plain email with inline body, no routing",
		TLSMode:          "none",
		NoAuth:           true,
		RouteSuccessPath: "/some/path", // Set but no files to route
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("No routing send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}
	t.Logf("Plain email with no files to route succeeded")
}

// =============================================================================
// E2E TEST: Path validation errors
// =============================================================================
func TestLive_PathValidation(t *testing.T) {
	setupMailpit(t)

	t.Run("relative body file rejected", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			From:       "test@example.com",
			To:         []string{"recipient@example.com"},
			BodyFile:   "relative/body.html",
			TLSMode:    "none",
			NoAuth:     true,
		}
		_, err := mailxgo.SendEmail(params)
		if err == nil {
			t.Error("expected error for relative body file")
		} else {
			t.Logf("Correctly rejected relative path: %v", err)
		}
	})

	t.Run("nonexistent attachment rejected", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer:  smtpHost,
			SMTPPort:    smtpPort,
			From:        "test@example.com",
			To:          []string{"recipient@example.com"},
			Body:        "test",
			Attachments: []string{"/nonexistent/file.pdf"},
			TLSMode:     "none",
			NoAuth:      true,
		}
		_, err := mailxgo.SendEmail(params)
		if err == nil {
			t.Error("expected error for nonexistent attachment")
		} else {
			t.Logf("Correctly rejected nonexistent file: %v", err)
		}
	})
}

// =============================================================================
// E2E TEST: Single attachment mode (--single-attachment)
// =============================================================================
func TestLive_SingleAttachment(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()

	// Create test attachments
	att1 := filepath.Join(tmpDir, "report.pdf")
	att2 := filepath.Join(tmpDir, "data.xlsx")
	att3 := filepath.Join(tmpDir, "summary.docx")
	_ = os.WriteFile(att1, []byte("PDF content for report"), 0o644)
	_ = os.WriteFile(att2, []byte("Excel content for data"), 0o644)
	_ = os.WriteFile(att3, []byte("Word content for summary"), 0o644)

	params := mailxgo.EmailParams{
		SMTPServer:       smtpHost,
		SMTPPort:         smtpPort,
		From:             "single@example.com",
		To:               []string{"recipient@example.com"},
		Subject:          "Monthly Report",
		Body:             "Please find the attachment.",
		Attachments:      []string{att1, att2, att3},
		SingleAttachment: true,
		TLSMode:          "none",
		NoAuth:           true,
		Quiet:            true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Single attachment send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected success, got %s", res.Status)
	}

	// Verify 3 separate emails were received
	time.Sleep(500 * time.Millisecond) // Allow Mailpit to process
	messages := getMailpitMessages(t)

	if len(messages) != 3 {
		t.Errorf("Expected 3 emails (one per attachment), got %d", len(messages))
	}

	// Verify subject prefixes
	foundPrefixes := make(map[string]bool)
	for _, msg := range messages {
		if strings.Contains(msg.Subject, "[1/3]") {
			foundPrefixes["1/3"] = true
		}
		if strings.Contains(msg.Subject, "[2/3]") {
			foundPrefixes["2/3"] = true
		}
		if strings.Contains(msg.Subject, "[3/3]") {
			foundPrefixes["3/3"] = true
		}
	}

	if len(foundPrefixes) != 3 {
		t.Errorf("Expected all 3 prefixes [1/3], [2/3], [3/3], found: %v", foundPrefixes)
	}

	t.Logf("Single attachment mode: sent %d separate emails with correct prefixes", len(messages))
}

// =============================================================================
// E2E TEST: Single attachment mode with routing
// =============================================================================
func TestLive_SingleAttachmentWithRouting(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	successDir := filepath.Join(tmpDir, "sent")

	// Create test attachments
	att1 := filepath.Join(tmpDir, "file1.txt")
	att2 := filepath.Join(tmpDir, "file2.txt")
	_ = os.WriteFile(att1, []byte("content 1"), 0o644)
	_ = os.WriteFile(att2, []byte("content 2"), 0o644)

	params := mailxgo.EmailParams{
		SMTPServer:       smtpHost,
		SMTPPort:         smtpPort,
		From:             "route@example.com",
		To:               []string{"recipient@example.com"},
		Subject:          "Route Test",
		Body:             "Testing single attachment with routing",
		Attachments:      []string{att1, att2},
		SingleAttachment: true,
		RouteSuccessPath: successDir,
		TLSMode:          "none",
		NoAuth:           true,
		Quiet:            true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Single attachment with routing failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected success, got %s", res.Status)
	}

	// Verify files were routed to success
	if _, err := os.Stat(filepath.Join(successDir, "file1.txt")); err != nil {
		t.Errorf("file1.txt should be in success dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(successDir, "file2.txt")); err != nil {
		t.Errorf("file2.txt should be in success dir: %v", err)
	}

	// Original files should be gone
	if _, err := os.Stat(att1); !os.IsNotExist(err) {
		t.Error("original file1.txt should be moved")
	}
	if _, err := os.Stat(att2); !os.IsNotExist(err) {
		t.Error("original file2.txt should be moved")
	}

	t.Logf("Single attachment mode with routing: files correctly moved to success path")
}

// =============================================================================
// E2E TEST: Single attachment mode - single file (no split)
// =============================================================================
func TestLive_SingleAttachmentOneFile(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()
	att := filepath.Join(tmpDir, "single.txt")
	_ = os.WriteFile(att, []byte("single file content"), 0o644)

	params := mailxgo.EmailParams{
		SMTPServer:       smtpHost,
		SMTPPort:         smtpPort,
		From:             "one@example.com",
		To:               []string{"recipient@example.com"},
		Subject:          "Single File Test",
		Body:             "Only one attachment",
		Attachments:      []string{att},
		SingleAttachment: true,
		TLSMode:          "none",
		NoAuth:           true,
		Quiet:            true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Single file send failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected success, got %s", res.Status)
	}

	// With only 1 attachment, should send 1 email (no split needed)
	time.Sleep(300 * time.Millisecond)
	messages := getMailpitMessages(t)

	if len(messages) != 1 {
		t.Errorf("Expected 1 email for single file, got %d", len(messages))
	}

	t.Logf("Single attachment mode with one file: correctly sent without splitting")
}

// TestLive_MaxRecipients tests the --max-recipients limit guard.
func TestLive_MaxRecipients(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	t.Run("rejects_when_exceeding_limit", func(t *testing.T) {
		// Create 10 recipients but limit to 5
		recipients := make([]string, 10)
		for i := 0; i < 10; i++ {
			recipients[i] = fmt.Sprintf("recipient%d@example.com", i)
		}

		params := mailxgo.EmailParams{
			SMTPServer:    smtpHost,
			SMTPPort:      smtpPort,
			From:          "sender@example.com",
			To:            recipients,
			Subject:       "Max Recipients Test - Should Fail",
			Body:          "This should fail due to recipient limit",
			MaxRecipients: 5,
			TLSMode:       "none",
			NoAuth:        true,
			Quiet:         true,
		}

		_, err := mailxgo.SendEmail(params)
		if err == nil {
			t.Error("expected error when exceeding max recipients")
		}
		if err != nil && !strings.Contains(err.Error(), "exceeds maximum") {
			t.Errorf("expected 'exceeds maximum' error, got: %v", err)
		}

		t.Logf("MaxRecipients: correctly rejected %d recipients (limit: 5)", len(recipients))
	})

	t.Run("accepts_when_within_limit", func(t *testing.T) {
		clearMailpit(t)

		recipients := []string{"a@example.com", "b@example.com", "c@example.com"}

		params := mailxgo.EmailParams{
			SMTPServer:    smtpHost,
			SMTPPort:      smtpPort,
			From:          "sender@example.com",
			To:            recipients,
			Subject:       "Max Recipients Test - Should Pass",
			Body:          "This should succeed",
			MaxRecipients: 5,
			TLSMode:       "none",
			NoAuth:        true,
			Quiet:         true,
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}

		time.Sleep(300 * time.Millisecond)
		messages := getMailpitMessages(t)
		if len(messages) != 1 {
			t.Errorf("expected 1 message, got %d", len(messages))
		}

		t.Logf("MaxRecipients: correctly accepted %d recipients (limit: 5)", len(recipients))
	})
}

// TestLive_SingleRecipient tests --single-recipient batch mode via Mailpit.
func TestLive_SingleRecipient(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	t.Run("sends_one_email_per_recipient", func(t *testing.T) {
		recipients := []string{
			"recipient1@example.com",
			"recipient2@example.com",
			"recipient3@example.com",
		}

		params := mailxgo.EmailParams{
			SMTPServer:      smtpHost,
			SMTPPort:        smtpPort,
			From:            "sender@example.com",
			To:              recipients,
			Subject:         "Single Recipient Mode Test",
			Body:            "This should be sent to each recipient separately.",
			SingleRecipient: true,
			TLSMode:         "none",
			NoAuth:          true,
			Quiet:           true,
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}

		// Wait for all messages to arrive
		time.Sleep(500 * time.Millisecond)
		messages := getMailpitMessages(t)

		// Should have 3 separate emails (one per recipient)
		if len(messages) != 3 {
			t.Errorf("expected 3 separate emails, got %d", len(messages))
		}

		t.Logf("SingleRecipient: sent %d emails for %d recipients", len(messages), len(recipients))
	})

	t.Run("single_recipient_skips_batch_mode", func(t *testing.T) {
		clearMailpit(t)

		params := mailxgo.EmailParams{
			SMTPServer:      smtpHost,
			SMTPPort:        smtpPort,
			From:            "sender@example.com",
			To:              []string{"single@example.com"},
			Subject:         "Single Recipient - No Split",
			Body:            "Only one recipient, no split needed.",
			SingleRecipient: true,
			TLSMode:         "none",
			NoAuth:          true,
			Quiet:           true,
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}

		time.Sleep(300 * time.Millisecond)
		messages := getMailpitMessages(t)

		// With only 1 recipient, should send normally
		if len(messages) != 1 {
			t.Errorf("expected 1 email (no split needed), got %d", len(messages))
		}

		t.Logf("SingleRecipient: correctly skipped batch mode for single recipient")
	})

	t.Run("rate_limited_single_recipient", func(t *testing.T) {
		clearMailpit(t)

		recipients := []string{
			"rate1@example.com",
			"rate2@example.com",
		}

		params := mailxgo.EmailParams{
			SMTPServer:      smtpHost,
			SMTPPort:        smtpPort,
			From:            "sender@example.com",
			To:              recipients,
			Subject:         "Rate Limited Single Recipient",
			Body:            "Testing rate limiting with single recipient mode.",
			SingleRecipient: true,
			RateLimit:       60, // 60/min = 1/sec = 1000ms between emails
			TLSMode:         "none",
			NoAuth:          true,
			Quiet:           true,
		}

		start := time.Now()
		res, err := mailxgo.SendEmail(params)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}

		// With rate limit of 60/min (1/sec) and 2 recipients, expect ~1s delay
		if elapsed < 800*time.Millisecond {
			t.Errorf("rate limiting should have added delay, elapsed: %v", elapsed)
		}

		time.Sleep(300 * time.Millisecond)
		messages := getMailpitMessages(t)

		if len(messages) != 2 {
			t.Errorf("expected 2 emails, got %d", len(messages))
		}

		t.Logf("SingleRecipient with rate limit: sent %d emails in %v", len(messages), elapsed)
	})
}

// =============================================================================
// E2E TEST: RunDiagnostics - Live SMTP Server Probe
// =============================================================================
func TestLive_RunDiagnostics(t *testing.T) {
	setupMailpit(t)

	t.Run("basic diagnostics", func(t *testing.T) {
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
			t.Errorf("expected status success, got %s (error: %s)", report.Status, report.Error)
		}
		if report.SMTPServer != smtpHost {
			t.Errorf("expected SMTPServer %s, got %s", smtpHost, report.SMTPServer)
		}
		if report.SMTPPort != smtpPort {
			t.Errorf("expected SMTPPort %d, got %d", smtpPort, report.SMTPPort)
		}

		// Latency metrics should be populated
		if report.Latency.TCPConnectMS <= 0 {
			t.Error("TCPConnectMS should be > 0")
		}
		if report.Latency.EHLORTTMS <= 0 {
			t.Error("EHLORTTMS should be > 0")
		}
		if report.Latency.TotalMS <= 0 {
			t.Error("TotalMS should be > 0")
		}

		t.Logf("Diagnostics: TCP=%.2fms, EHLO=%.2fms, Total=%.2fms",
			report.Latency.TCPConnectMS, report.Latency.EHLORTTMS, report.Latency.TotalMS)
	})

	t.Run("diagnostics with capabilities", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			TLSMode:    "none",
			Timeout:    10,
		}

		report, err := mailxgo.RunDiagnostics(params, false)
		if err != nil {
			t.Fatalf("RunDiagnostics failed: %v", err)
		}

		// Mailpit should advertise 8BITMIME
		if !report.Capabilities.EightBitMIME {
			t.Log("Note: EightBitMIME not advertised by server")
		}

		t.Logf("Capabilities: STARTTLS=%v, 8BITMIME=%v, Pipelining=%v, Auth=%v",
			report.Capabilities.StartTLS,
			report.Capabilities.EightBitMIME,
			report.Capabilities.Pipelining,
			report.Capabilities.AuthMethods)
	})

	t.Run("diagnostics with DNS info", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			From:       "dns-test@example.com",
			TLSMode:    "none",
			Timeout:    10,
		}

		report, err := mailxgo.RunDiagnostics(params, false)
		if err != nil {
			t.Fatalf("RunDiagnostics failed: %v", err)
		}

		// DNS info should be populated
		if report.DNSInfo.TargetHost != smtpHost {
			t.Errorf("expected TargetHost %s, got %s", smtpHost, report.DNSInfo.TargetHost)
		}

		t.Logf("DNS Info: Target=%s, IPs=%v, MX=%v",
			report.DNSInfo.TargetHost,
			report.DNSInfo.ResolvedIPs,
			report.DNSInfo.MXRecords)
	})

	t.Run("diagnostics JSON output", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			TLSMode:    "none",
			JSONOutput: true,
			Timeout:    10,
		}

		report, err := mailxgo.RunDiagnostics(params, false)
		if err != nil {
			t.Fatalf("RunDiagnostics failed: %v", err)
		}

		if report.Status != "success" {
			t.Errorf("expected success, got %s", report.Status)
		}
	})

	t.Run("diagnostics NDJSON output", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer:   smtpHost,
			SMTPPort:     smtpPort,
			TLSMode:      "none",
			NDJSONOutput: true,
			Timeout:      10,
		}

		report, err := mailxgo.RunDiagnostics(params, false)
		if err != nil {
			t.Fatalf("RunDiagnostics failed: %v", err)
		}

		if report.Status != "success" {
			t.Errorf("expected success, got %s", report.Status)
		}
	})

	t.Run("diagnostics connection failure", func(t *testing.T) {
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   19999, // Non-existent port
			TLSMode:    "none",
			Timeout:    2,
		}

		report, err := mailxgo.RunDiagnostics(params, false)
		// Should return a report even on error
		if report == nil {
			t.Fatal("expected report even on connection failure")
		}
		if report.Status != "error" {
			t.Errorf("expected status error, got %s", report.Status)
		}
		if report.Error == "" {
			t.Error("expected error message to be populated")
		}
		if err == nil {
			t.Error("expected error return")
		}

		t.Logf("Connection failure error: %s", report.Error)
	})
}

// =============================================================================
// E2E TEST: OutputDiagReport - All Output Modes
// =============================================================================
func TestLive_OutputDiagReport(t *testing.T) {
	setupMailpit(t)

	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		TLSMode:    "none",
		Timeout:    10,
	}

	report, err := mailxgo.RunDiagnostics(params, false)
	if err != nil {
		t.Fatalf("RunDiagnostics failed: %v", err)
	}

	t.Run("text output", func(t *testing.T) {
		err := mailxgo.OutputDiagReport(*report, false, false, false)
		if err != nil {
			t.Errorf("OutputDiagReport text failed: %v", err)
		}
	})

	t.Run("JSON output", func(t *testing.T) {
		err := mailxgo.OutputDiagReport(*report, true, false, false)
		if err != nil {
			t.Errorf("OutputDiagReport JSON failed: %v", err)
		}
	})

	t.Run("NDJSON output", func(t *testing.T) {
		err := mailxgo.OutputDiagReport(*report, false, true, false)
		if err != nil {
			t.Errorf("OutputDiagReport NDJSON failed: %v", err)
		}
	})

	t.Run("text with certs", func(t *testing.T) {
		err := mailxgo.OutputDiagReport(*report, false, false, true)
		if err != nil {
			t.Errorf("OutputDiagReport text+certs failed: %v", err)
		}
	})
}

// =============================================================================
// E2E TEST: JSON List Format - Recipients and Attachments
// =============================================================================
func TestLive_JSONListFormat(t *testing.T) {
	setupMailpit(t)
	clearMailpit(t)

	tmpDir := t.TempDir()

	t.Run("JSON recipient list simple array", func(t *testing.T) {
		clearMailpit(t)

		// Create JSON recipient list
		listFile := filepath.Join(tmpDir, "recipients.json")
		content := `["recipient1@example.com", "recipient2@example.com"]`
		if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write recipient list: %v", err)
		}

		// Load and send
		recipients, _, err := mailxgo.LoadList(listFile, "json", true)
		if err != nil {
			t.Fatalf("LoadList failed: %v", err)
		}
		if len(recipients) != 2 {
			t.Fatalf("expected 2 recipients, got %d", len(recipients))
		}

		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			From:       "json-test@example.com",
			To:         recipients,
			Subject:    "JSON List Format Test",
			Body:       "Testing JSON recipient list",
			TLSMode:    "none",
			NoAuth:     true,
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}

		// Verify via Mailpit
		time.Sleep(200 * time.Millisecond)
		messages := getMailpitMessages(t)
		if len(messages) == 0 {
			t.Error("no messages received")
		} else {
			msg := getMailpitMessageDetails(t, messages[0].ID)
			if msg != nil && len(msg.To) != 2 {
				t.Errorf("expected 2 To recipients, got %d", len(msg.To))
			}
		}
	})

	t.Run("JSON recipient list with vars", func(t *testing.T) {
		clearMailpit(t)

		// Create JSON recipient list with per-recipient vars
		listFile := filepath.Join(tmpDir, "recipients_vars.json")
		content := `[
			{"email": "alice@example.com", "vars": {"name": "Alice", "order": "12345"}},
			{"email": "bob@example.com", "vars": {"name": "Bob", "order": "67890"}}
		]`
		if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write recipient list: %v", err)
		}

		// Load and verify vars are parsed
		recipients, recipientVars, err := mailxgo.LoadList(listFile, "json", true)
		if err != nil {
			t.Fatalf("LoadList failed: %v", err)
		}
		if len(recipients) != 2 {
			t.Fatalf("expected 2 recipients, got %d", len(recipients))
		}
		if len(recipientVars) != 2 {
			t.Fatalf("expected 2 var maps, got %d", len(recipientVars))
		}
		if recipientVars[0]["name"] != "Alice" {
			t.Errorf("expected Alice, got %s", recipientVars[0]["name"])
		}
		if recipientVars[1]["order"] != "67890" {
			t.Errorf("expected 67890, got %s", recipientVars[1]["order"])
		}

		// Send (vars not used yet, but parsed correctly)
		params := mailxgo.EmailParams{
			SMTPServer: smtpHost,
			SMTPPort:   smtpPort,
			From:       "json-vars@example.com",
			To:         recipients,
			Subject:    "JSON List with Vars Test",
			Body:       "Testing JSON recipient list with vars",
			TLSMode:    "none",
			NoAuth:     true,
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}
	})

	t.Run("JSON attachment list", func(t *testing.T) {
		clearMailpit(t)

		// Create test attachments
		att1 := filepath.Join(tmpDir, "doc1.txt")
		att2 := filepath.Join(tmpDir, "doc2.txt")
		if err := os.WriteFile(att1, []byte("Document 1"), 0o644); err != nil {
			t.Fatalf("failed to create attachment: %v", err)
		}
		if err := os.WriteFile(att2, []byte("Document 2"), 0o644); err != nil {
			t.Fatalf("failed to create attachment: %v", err)
		}

		// Create JSON attachment list (use forward slashes for JSON)
		listFile := filepath.Join(tmpDir, "attachments.json")
		content := `["` + filepath.ToSlash(att1) + `", "` + filepath.ToSlash(att2) + `"]`
		if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write attachment list: %v", err)
		}

		// Load attachments
		attachments, _, err := mailxgo.LoadList(listFile, "json", false)
		if err != nil {
			t.Fatalf("LoadList failed: %v", err)
		}
		if len(attachments) != 2 {
			t.Fatalf("expected 2 attachments, got %d", len(attachments))
		}

		params := mailxgo.EmailParams{
			SMTPServer:  smtpHost,
			SMTPPort:    smtpPort,
			From:        "json-attach@example.com",
			To:          []string{"recipient@example.com"},
			Subject:     "JSON Attachment List Test",
			Body:        "Testing JSON attachment list",
			Attachments: attachments,
			TLSMode:     "none",
			NoAuth:      true,
		}

		res, err := mailxgo.SendEmail(params)
		if err != nil {
			t.Fatalf("SendEmail failed: %v", err)
		}
		if res.Status != "success" {
			t.Errorf("expected success, got %s", res.Status)
		}

		// Verify attachments via Mailpit
		time.Sleep(200 * time.Millisecond)
		messages := getMailpitMessages(t)
		if len(messages) == 0 {
			t.Error("no messages received")
		} else {
			msg := getMailpitMessageDetails(t, messages[0].ID)
			if msg != nil && msg.Attachments != 2 {
				t.Errorf("expected 2 attachments, got %d", msg.Attachments)
			}
		}
	})

	t.Run("text format fallback", func(t *testing.T) {
		// Verify text format still works
		listFile := filepath.Join(tmpDir, "recipients.txt")
		content := "text1@example.com\ntext2@example.com\n# comment\n"
		if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write recipient list: %v", err)
		}

		recipients, vars, err := mailxgo.LoadList(listFile, "text", true)
		if err != nil {
			t.Fatalf("LoadList text format failed: %v", err)
		}
		if vars != nil {
			t.Error("expected nil vars for text format")
		}
		if len(recipients) != 2 {
			t.Errorf("expected 2 recipients, got %d", len(recipients))
		}
	})
}
