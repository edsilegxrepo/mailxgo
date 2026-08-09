//go:build integration

// Package mailxgo_test - Live ESMTP Network Integration Tests
//
// OBJECTIVES:
// Validate live network socket interactions, ESMTP protocol state handshakes, SASL authentication exchanges, DATA stream buffering, and process binary execution against a local loopback listener.
//
// CORE COMPONENTS:
// - startFallbackSMTPServer: Spawns an in-process stateful ESMTP TCP listener on 127.0.0.1:1025 handling EHLO, AUTH PLAIN/LOGIN, MAIL FROM, RCPT TO, DATA, and QUIT.
// - TestIntegration_LiveSMTPServer: Performs live email dispatch against loopback server and asserts 250 OK queue response and received message content.
// - TestIntegration_CLIBinary: Compiles the mailxgo CLI binary and executes end-to-end process dispatch tests against the live listener.
//
// FUNCTIONALITY & DATA FLOW:
// Test Dispatch -> Loopback Socket Dial (127.0.0.1:1025) -> EHLO Handshake -> SASL Auth -> DATA Transfer -> 250 OK Queue Acknowledgment.
//
// TEST STRATEGY:
// Hermetic integration testing with an embedded in-process ESMTP TCP server requiring zero external dependencies or internet access.
package mailxgo_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
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
)

const (
	smtpHost      = "127.0.0.1"
	smtpPort      = 1025
	containerName = "mailxgo-integration-smtp"
)

type liveSMTPServer struct {
	listener net.Listener
	mu       sync.Mutex
	messages []string
	done     chan struct{}
}

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
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
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

func setupLiveSMTP(t *testing.T) *liveSMTPServer {
	t.Helper()

	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)
	conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Logf("Live SMTP server already listening on %s", addr)
		return nil
	}

	if os.Getenv("USE_DOCKER_CONTAINER") == "1" {
		t.Logf("Attempting to start live SMTP container (%s)...", containerName)
		_, _ = runDockerCmd("rm", "-f", containerName)
		out, err := runDockerCmd("run", "-d", "--name", containerName, "-p", fmt.Sprintf("%d:1025", smtpPort), "axllent/mailpit")
		if err == nil {
			t.Cleanup(func() {
				_, _ = runDockerCmd("rm", "-f", containerName)
			})
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
					conn.Close()
					t.Logf("Docker SMTP container ready on %s", addr)
					return nil
				}
				time.Sleep(200 * time.Millisecond)
			}
		} else {
			t.Logf("Docker container start skipped/failed (%v: %s). Falling back to live ESMTP server listener.", err, string(out))
		}
	}

	// Fallback to real live in-process ESMTP listener
	t.Logf("Starting live ESMTP server on %s...", addr)
	return startFallbackSMTPServer(t, smtpPort)
}

func TestLive_SMTP_SendEmail_E2E(t *testing.T) {
	server := setupLiveSMTP(t)

	tmpDir := t.TempDir()
	attFile := filepath.Join(tmpDir, "report.txt")
	if err := os.WriteFile(attFile, []byte("Integration Test Report Attachment Data"), 0o644); err != nil {
		t.Fatalf("failed to create attachment file: %v", err)
	}

	logFile := filepath.Join(tmpDir, "integration_audit.log")

	params := mailxgo.EmailParams{
		SMTPServer:  smtpHost,
		SMTPPort:    smtpPort,
		From:        "integration-sender@example.com",
		FromName:    "Integration Sender",
		To:          []string{"integration-to@example.com"},
		CC:          []string{"integration-cc@example.com"},
		Subject:     "Live Integration Test Email",
		Body:        "Hello from Mail2Go Live Integration E2E Test Workflow!",
		Attachments: []string{attFile},
		Headers:     map[string]string{"X-Integration-Suite": "Mail2Go"},
		TLSMode:     "none",
		NoAuth:      true,
		LogFile:     logFile,
		JSONOutput:  true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Live SendEmail failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	// Verify audit log
	logData, err := os.ReadFile(logFile)
	if err != nil || !strings.Contains(string(logData), "SUCCESS") {
		t.Errorf("expected log file to contain SUCCESS, got: %s", string(logData))
	}

	// If fallback server was used, verify received message content
	if server != nil {
		server.mu.Lock()
		defer server.mu.Unlock()
		if len(server.messages) == 0 {
			t.Errorf("expected server to receive 1 message, got 0")
		} else {
			lastMsg := server.messages[len(server.messages)-1]
			if !strings.Contains(lastMsg, "Live Integration Test Email") {
				t.Errorf("expected received message to contain subject, got: %s", lastMsg)
			}
		}
	}
}

func TestLive_Diagnostics_E2E(t *testing.T) {
	setupLiveSMTP(t)

	params := mailxgo.EmailParams{
		SMTPServer: smtpHost,
		SMTPPort:   smtpPort,
		From:       "diag-test@example.com",
		TLSMode:    "none",
		Timeout:    10,
	}

	report, err := mailxgo.RunDiagnostics(params, false)
	if err != nil {
		t.Fatalf("Live RunDiagnostics failed: %v", err)
	}
	if report.Status != "success" {
		t.Errorf("expected status success, got %s", report.Status)
	}

	if report.Latency.TCPConnectMS < 0 {
		t.Errorf("expected non-negative TCP connect latency, got %f", report.Latency.TCPConnectMS)
	}
	if report.Latency.EHLORTTMS < 0 {
		t.Errorf("expected non-negative EHLO latency, got %f", report.Latency.EHLORTTMS)
	}
}

func TestLive_SMTP_SendEmail_AdvancedE2E(t *testing.T) {
	server := setupLiveSMTP(t)

	tmpDir := t.TempDir()
	bodyFile := filepath.Join(tmpDir, "email_body.html")
	if err := os.WriteFile(bodyFile, []byte("<h1>Advanced HTML Email</h1><p>Live E2E HTML Content</p>"), 0o644); err != nil {
		t.Fatalf("failed to write body file: %v", err)
	}

	inlineAtt := filepath.Join(tmpDir, "logo.png")
	if err := os.WriteFile(inlineAtt, []byte("fake-image-bytes"), 0o644); err != nil {
		t.Fatalf("failed to write inline attachment: %v", err)
	}

	logFile := filepath.Join(tmpDir, "advanced_audit.log")

	params := mailxgo.EmailParams{
		SMTPServer:        smtpHost,
		SMTPPort:          smtpPort,
		From:              "adv-sender@example.com",
		FromName:          "Advanced Sender",
		To:                []string{"adv-to@example.com"},
		CC:                []string{"adv-cc@example.com"},
		BCC:               []string{"adv-bcc@example.com"},
		ReplyTo:           "reply@example.com",
		Subject:           "Advanced E2E Test Email",
		BodyFile:          bodyFile,
		InlineAttachments: []string{inlineAtt},
		Headers:           map[string]string{"X-Campaign-ID": "E2E-12345"},
		Importance:        "high",
		DSNNotify:         []string{"SUCCESS", "FAILURE"},
		DSNReturn:         "FULL",
		TLSMode:           "none",
		NoAuth:            true,
		Retries:           1,
		RetryDelay:        1,
		LogFile:           logFile,
		NDJSONOutput:      true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("Advanced SendEmail failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}

	if server != nil {
		server.mu.Lock()
		defer server.mu.Unlock()
		if len(server.messages) == 0 {
			t.Errorf("expected server to receive message, got 0")
		} else {
			lastMsg := server.messages[len(server.messages)-1]
			if !strings.Contains(lastMsg, "X-Campaign-ID: E2E-12345") {
				t.Errorf("expected received message to contain custom header")
			}
		}
	}
}

func TestLive_SMTP_ListsAndDirAttachments_E2E(t *testing.T) {
	setupLiveSMTP(t)

	tmpDir := t.TempDir()
	listFile := filepath.Join(tmpDir, "recipients.txt")
	if err := os.WriteFile(listFile, []byte("list-to1@example.com\nlist-to2@example.com\n"), 0o644); err != nil {
		t.Fatalf("failed to write recipient list file: %v", err)
	}

	att1 := filepath.Join(tmpDir, "att1.pdf")
	att2 := filepath.Join(tmpDir, "att2.docx")
	_ = os.WriteFile(att1, []byte("PDF Data"), 0o644)
	_ = os.WriteFile(att2, []byte("DOCX Data"), 0o644)

	attListFile := filepath.Join(tmpDir, "attachments_list.txt")
	if err := os.WriteFile(attListFile, []byte(att1+"\n"+att2+"\n"), 0o644); err != nil {
		t.Fatalf("failed to write attachment list file: %v", err)
	}

	attDir := filepath.Join(tmpDir, "extra_files")
	_ = os.MkdirAll(attDir, 0o755)
	_ = os.WriteFile(filepath.Join(attDir, "extra1.txt"), []byte("Extra 1 Data"), 0o644)
	_ = os.WriteFile(filepath.Join(attDir, "extra2.txt"), []byte("Extra 2 Data"), 0o644)

	recipients, err := mailxgo.LoadRecipientList(listFile)
	if err != nil {
		t.Fatalf("LoadRecipientList failed: %v", err)
	}

	attFromList, err := mailxgo.LoadAttachmentList(attListFile)
	if err != nil {
		t.Fatalf("LoadAttachmentList failed: %v", err)
	}

	attFromDir, err := mailxgo.ScanAttachmentDir(attDir)
	if err != nil {
		t.Fatalf("ScanAttachmentDir failed: %v", err)
	}

	allAttachments := append(attFromList, attFromDir...)

	params := mailxgo.EmailParams{
		SMTPServer:      smtpHost,
		SMTPPort:        smtpPort,
		From:            "lists-sender@example.com",
		To:              recipients,
		Attachments:     allAttachments,
		MaxAttachmentMB: 10,
		Subject:         "Lists and Dir Attachments E2E",
		Body:            "Testing list file, attachments list, and attachment dir",
		TLSMode:         "none",
		NoAuth:          true,
	}

	res, err := mailxgo.SendEmail(params)
	if err != nil {
		t.Fatalf("SendEmail with lists/dir failed: %v", err)
	}
	if res.Status != "success" {
		t.Errorf("expected status success, got %s", res.Status)
	}
}

func TestLive_CLI_E2E(t *testing.T) {
	setupLiveSMTP(t)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")
	configJSON := fmt.Sprintf(`{
		"smtp_server": "%s",
		"smtp_port": %d,
		"from_email": "cli-sender@example.com",
		"tls_mode": "none",
		"no_auth": true
	}`, smtpHost, smtpPort)

	if err := os.WriteFile(configFile, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// 1. Test CLI Send Email
	cmd := exec.Command("go", "run", "./cmd/mailxgo", "-c", configFile, "-t", "cli-to@example.com", "-h", "CLI E2E Test Subject", "-b", "CLI Body Content", "-j")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI send email failed: %v, output: %s", err, string(out))
	}
	if !strings.Contains(string(out), `"status": "success"`) && !strings.Contains(string(out), `"status":"success"`) {
		t.Errorf("expected CLI output to contain status success, got: %s", string(out))
	}

	// 2. Test CLI Run Diagnostics
	diagCmd := exec.Command("go", "run", "./cmd/mailxgo", "-c", configFile, "-info", "-j")
	diagOut, diagErr := diagCmd.CombinedOutput()
	if diagErr != nil {
		t.Fatalf("CLI diagnostics failed: %v, output: %s", diagErr, string(diagOut))
	}
	if !strings.Contains(string(diagOut), `"status": "success"`) && !strings.Contains(string(diagOut), `"status":"success"`) {
		t.Errorf("expected CLI diagnostic output to contain status success, got: %s", string(diagOut))
	}
}
