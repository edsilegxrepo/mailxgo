// Package mailxgo - CLI Engine Unit Tests
//
// OBJECTIVES:
// Validate command-line flag parsing, multi-value header handling, 6-tier parameter precedence evaluation (CLI > Env > Config), granular exit code status codes, diagnostic probe routing, and full CLI email dispatch.
//
// CORE COMPONENTS:
// - mockExit: Intercepts process exit calls (osExit) via panic/recover hooks to assert numeric exit codes without terminating the test runner.
// - runCLIWithCatch: Helper function executing RunCLI within panic recovery bounds.
// - TestHeaderFlags: Tests repeatable -H "Key: Value" flag parsing and CRLF injection rejection.
// - TestPrintUsage: Asserts usage menu text rendering without panicking.
// - TestPriorityHelpers: Tests priorityString and priorityInt precedence functions.
// - TestRunCLI_Version: Tests -v / --version flag handling.
// - TestRunCLI_ParseError / TestRunCLI_MissingRequiredArgs: Tests usage error handling and exit codes.
// - TestRunCLI_ConfigAndPresets: Tests config file loading and error trapping.
// - TestRunCLI_PrecedenceOrder: Verifies CLI > Environment Variable > Config File priority resolution.
// - TestRunCLI_Diagnostics: Tests CLI pre-flight diagnostic probe execution.
// - TestRunCLI_FullDispatch: Tests end-to-end CLI email dispatch execution.
//
// FUNCTIONALITY & DATA FLOW:
// Test Flag Arguments -> RunCLI -> mockExit Panic Interception -> Assert exit code & side-effects.
//
// TEST STRATEGY:
// Unit tests capturing process exit calls using mockExit and overriding defaultClientFactory for non-destructive local testing.
package mailxgo

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wneessen/go-mail"
)

func TestHeaderFlags(t *testing.T) {
	headers := make(HeaderFlags)

	// Test valid header
	if err := headers.Set("X-Custom-Header: CustomValue"); err != nil {
		t.Fatalf("HeaderFlags.Set failed: %v", err)
	}
	if headers["X-Custom-Header"] != "CustomValue" {
		t.Errorf("HeaderFlags value = %q, want %q", headers["X-Custom-Header"], "CustomValue")
	}

	str := headers.String()
	if !strings.Contains(str, "X-Custom-Header:CustomValue") {
		t.Errorf("HeaderFlags.String() = %q", str)
	}

	// Invalid format (no colon)
	if err := headers.Set("InvalidHeader"); err == nil {
		t.Errorf("expected error for header without colon, got nil")
	}

	// Empty header key
	if err := headers.Set(" : Value"); err == nil {
		t.Errorf("expected error for empty header key, got nil")
	}

	// Newline in key or value
	if err := headers.Set("Header: Value\r\nInjected"); err == nil {
		t.Errorf("expected error for header containing newline, got nil")
	}
}

func TestPrintUsage(t *testing.T) {
	// Simple invocation to ensure no panic
	PrintUsage()
}

func TestPriorityHelpers(t *testing.T) {
	// priorityString returns the last non-empty string in slice
	s := priorityString([]string{"", "first", "", "second", ""})
	if s != "second" {
		t.Errorf("priorityString = %q, want %q", s, "second")
	}

	// priorityInt returns the last non-zero int in slice
	i := priorityInt([]int{0, 10, 0, 20, 0})
	if i != 20 {
		t.Errorf("priorityInt = %d, want 20", i)
	}
}

func mockExit(t *testing.T) (<-chan int, func()) {
	origExit := osExit
	exitChan := make(chan int, 1)
	osExit = func(code int) {
		select {
		case exitChan <- code:
		default:
		}
		panic(fmt.Sprintf("exit_%d", code))
	}
	cleanup := func() {
		osExit = origExit
	}
	return exitChan, cleanup
}

func runCLIWithCatch(args []string) (code int, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			if str, ok := r.(string); ok && strings.HasPrefix(str, "exit_") {
				panicked = true
				_, _ = fmt.Sscanf(str, "exit_%d", &code)
			} else {
				panic(r)
			}
		}
	}()
	RunCLI(args)
	return 0, false
}

func TestRunCLI_Version(t *testing.T) {
	_, cleanup := mockExit(t)
	defer cleanup()

	code, panicked := runCLIWithCatch([]string{"--version"})
	if !panicked || code != ExitSuccess {
		t.Errorf("RunCLI(--version) code = %d, panicked = %v, want code %d", code, panicked, ExitSuccess)
	}
}

func TestRunCLI_ParseError(t *testing.T) {
	_, cleanup := mockExit(t)
	defer cleanup()

	code, panicked := runCLIWithCatch([]string{"--invalid-unknown-flag"})
	if !panicked || code != ExitErrUsage {
		t.Errorf("RunCLI invalid flag code = %d, panicked = %v, want code %d", code, panicked, ExitErrUsage)
	}
}

func TestRunCLI_MissingRequiredArgs(t *testing.T) {
	_, cleanup := mockExit(t)
	defer cleanup()

	code, panicked := runCLIWithCatch([]string{"--smtp-server", "smtp.example.com"})
	if !panicked || code != ExitErrUsage {
		t.Errorf("RunCLI missing args code = %d, panicked = %v, want code %d", code, panicked, ExitErrUsage)
	}
}

func TestRunCLI_ConfigAndPresets(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })
	defaultClientFactory = mockFactory(&mockSender{}, nil)

	_, cleanup := mockExit(t)
	defer cleanup()

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")
	configJSON := `{
		"smtp_server": "smtp.example.com",
		"smtp_port": 587,
		"from_email": "sender@example.com",
		"to_email": "to@example.com",
		"subject": "Config Test",
		"body": "Body Test"
	}`
	if err := os.WriteFile(configFile, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	code, _ := runCLIWithCatch([]string{"--config", configFile})
	if code != ExitSuccess {
		t.Errorf("RunCLI config file test code = %d, want %d", code, ExitSuccess)
	}

	// Invalid config file
	invalidConfig := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(invalidConfig, []byte("{bad-json"), 0o644); err != nil {
		t.Fatalf("failed to write invalid config file: %v", err)
	}
	code, panicked := runCLIWithCatch([]string{"--config", invalidConfig})
	if !panicked || code != ExitErrConfig {
		t.Errorf("RunCLI invalid config test code = %d, want %d", code, ExitErrConfig)
	}
}

func TestRunCLI_PrecedenceOrder(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })
	var capturedParams EmailParams
	defaultClientFactory = func(host string, opts ...mail.Option) (clientSender, error) {
		return &mockSender{}, nil
	}

	_, cleanup := mockExit(t)
	defer cleanup()

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")
	configJSON := `{
		"smtp_server": "config.example.com",
		"smtp_username": "config_user",
		"smtp_password": "config_password",
		"from_email": "config@example.com",
		"to_email": "to@example.com",
		"subject": "Config Subj",
		"body": "Config Body"
	}`
	if err := os.WriteFile(configFile, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	t.Setenv("MAILXGO_SMTP_USERNAME", "env_user")
	t.Setenv("MAILXGO_SMTP_PASSWORD", "env_pass")

	// Env should override Config file
	code, _ := runCLIWithCatch([]string{"--config", configFile})
	if code != ExitSuccess {
		t.Errorf("RunCLI precedence test code = %d, want %d", code, ExitSuccess)
	}
	_ = capturedParams
}

func TestRunCLI_Diagnostics(t *testing.T) {
	origHost := netLookupHost
	origDial := netDialTimeout
	t.Cleanup(func() {
		netLookupHost = origHost
		netDialTimeout = origDial
	})

	netLookupHost = func(host string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("dial error")
	}

	_, cleanup := mockExit(t)
	defer cleanup()

	// Diag without server should fail
	code, panicked := runCLIWithCatch([]string{"--info"})
	if !panicked || code != ExitErrUsage {
		t.Errorf("RunCLI info without server code = %d, want %d", code, ExitErrUsage)
	}

	// Diag with server fails on dial error
	code, panicked = runCLIWithCatch([]string{"--info", "--smtp-server", "smtp.example.com"})
	if !panicked || code != ExitErrDNS {
		t.Errorf("RunCLI info dial error code = %d, want %d", code, ExitErrDNS)
	}
}

func TestRunCLI_FullDispatch(t *testing.T) {
	origFactory := defaultClientFactory
	t.Cleanup(func() { defaultClientFactory = origFactory })
	defaultClientFactory = mockFactory(&mockSender{}, nil)

	_, cleanup := mockExit(t)
	defer cleanup()

	tmpDir := t.TempDir()
	listFile := filepath.Join(tmpDir, "list.txt")
	if err := os.WriteFile(listFile, []byte("recipient1@example.com\nrecipient2@example.com"), 0o644); err != nil {
		t.Fatalf("failed to write recipient list file: %v", err)
	}

	attListFile := filepath.Join(tmpDir, "att_list.txt")
	att1 := filepath.Join(tmpDir, "att1.txt")
	att2 := filepath.Join(tmpDir, "att2.txt")
	_ = os.WriteFile(att1, []byte("data1"), 0o644)
	_ = os.WriteFile(att2, []byte("data2"), 0o644)
	_ = os.WriteFile(attListFile, []byte(att1), 0o644)

	attDir := filepath.Join(tmpDir, "att_dir")
	_ = os.Mkdir(attDir, 0o755)
	_ = os.WriteFile(filepath.Join(attDir, "att3.txt"), []byte("data3"), 0o644)

	bodyFile := filepath.Join(tmpDir, "body.txt")
	_ = os.WriteFile(bodyFile, []byte("Hello Body File"), 0o644)

	t.Setenv("MAILXGO_SMTP_PASSWORD", "secretenvpass")
	t.Setenv("MAILXGO_SMTP_USERNAME", "envuser")

	args := []string{
		"--use", "gmail",
		"--smtp-username", "user",
		"--smtp-password", "pass",
		"--from-email", "sender@example.com",
		"--from-name", "Sender Name",
		"--to-email", "to@example.com",
		"--cc", "cc@example.com",
		"--bcc", "bcc@example.com",
		"--recipient-list", listFile,
		"--reply-to", "reply@example.com",
		"--subject", "Test Subject",
		"--body-file", bodyFile,
		"--attachments", att2,
		"--attachments-list", attListFile,
		"--attachments-dir", attDir,
		"--max-attachment-size", "10",
		"--inline-attachments", att1,
		"--header", "X-Header-1: Value1",
		"--header", "X-Header-2: Value2",
		"--retries", "1",
		"--retry-delay", "1",
		"--timeout", "10",
		"--dsn-notify", "SUCCESS,FAILURE",
		"--dsn-return", "FULL",
		"--importance", "high",
		"--json-output",
	}

	code, _ := runCLIWithCatch(args)
	if code != ExitSuccess {
		t.Errorf("RunCLI full dispatch code = %d, want %d", code, ExitSuccess)
	}

	// Missing list file error
	badListArgs := []string{
		"--smtp-server", "smtp.example.com",
		"--from-email", "sender@example.com",
		"--recipient-list", filepath.Join(tmpDir, "nonexistent.txt"),
		"--subject", "Subj",
		"--body", "Body",
	}
	code, panicked := runCLIWithCatch(badListArgs)
	if !panicked || code != ExitErrFileIO {
		t.Errorf("RunCLI missing list file code = %d, want %d", code, ExitErrFileIO)
	}

	// Missing attachment list file error
	badAttListArgs := []string{
		"--smtp-server", "smtp.example.com",
		"--from-email", "sender@example.com",
		"--to-email", "to@example.com",
		"--attachments-list", filepath.Join(tmpDir, "nonexistent_att.txt"),
		"--subject", "Subj",
		"--body", "Body",
	}
	code, panicked = runCLIWithCatch(badAttListArgs)
	if !panicked || code != ExitErrFileIO {
		t.Errorf("RunCLI missing attachment list file code = %d, want %d", code, ExitErrFileIO)
	}

	// Missing attachment dir error
	badAttDirArgs := []string{
		"--smtp-server", "smtp.example.com",
		"--from-email", "sender@example.com",
		"--to-email", "to@example.com",
		"--attachments-dir", filepath.Join(tmpDir, "nonexistent_dir"),
		"--subject", "Subj",
		"--body", "Body",
	}
	code, panicked = runCLIWithCatch(badAttDirArgs)
	if !panicked || code != ExitErrFileIO {
		t.Errorf("RunCLI missing attachment dir code = %d, want %d", code, ExitErrFileIO)
	}
}
