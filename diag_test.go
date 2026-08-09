// Package mailxgo - Gateway Diagnostics Engine Unit Tests
//
// OBJECTIVES:
// Validate pre-flight gateway diagnostic probe execution, latency decomposition metrics, TLS protocol string mapping, cipher suite identification, and diagnostic report formatting.
//
// CORE COMPONENTS:
// - mockConn: Mock net.Conn implementation for socket isolation.
// - TestGetTLSVersionAndCipherSuiteStrings: Tests TLS version and cipher suite string mapping functions.
// - TestRunDiagnostics_TCPDialError: Tests probe handling when target TCP dial fails.
// - TestRunDiagnostics_OutputModes: Tests rendering of diagnostic reports in text, JSON, and NDJSON modes.
// - TestRunDiagnostics_Port465_HandshakeFailure: Tests SMTPS port 465 implicit TLS handshake failure handling.
// - TestRunDiagnostics_SMTPClientInitFailure: Tests ESMTP banner parsing and initial EHLO probe error handling.
//
// FUNCTIONALITY & DATA FLOW:
// EmailParams -> RunDiagnostics -> Mock Network Function Pointers -> Assert DiagReport fields & Output formatting.
//
// TEST STRATEGY:
// Unit tests overriding netLookupHost, netLookupMX, netLookupTXT, and netDialTimeout function pointers for deterministic socket-free testing.
package mailxgo

import (
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"testing"
	"time"
)

func TestGetTLSVersionAndCipherSuiteStrings(t *testing.T) {
	versions := []uint16{
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
		tls.VersionTLS13,
		0x9999,
	}

	for _, v := range versions {
		str := getTLSVersionString(v)
		if str == "" {
			t.Errorf("getTLSVersionString(%d) returned empty string", v)
		}
	}

	// Cipher suite lookup
	csStr := getCipherSuiteString(tls.TLS_AES_128_GCM_SHA256)
	if csStr == "" {
		t.Errorf("getCipherSuiteString returned empty string")
	}

	// Unknown cipher suite
	unknownCs := getCipherSuiteString(0xffff)
	if unknownCs != "0xffff" {
		t.Errorf("expected 0xffff, got %s", unknownCs)
	}
}

func TestRunDiagnostics_TCPDialError(t *testing.T) {
	origHost := netLookupHost
	origMX := netLookupMX
	origTXT := netLookupTXT
	origDial := netDialTimeout
	t.Cleanup(func() {
		netLookupHost = origHost
		netLookupMX = origMX
		netLookupTXT = origTXT
		netDialTimeout = origDial
	})

	netLookupHost = func(host string) ([]string, error) { return []string{"192.0.2.1"}, nil }
	netLookupMX = func(host string) ([]*net.MX, error) { return []*net.MX{{Host: "mx.example.com", Pref: 10}}, nil }
	netLookupTXT = func(name string) ([]string, error) {
		if name == "_dmarc.example.com" {
			return []string{"v=DMARC1; p=none"}, nil
		}
		return []string{"v=spf1 include:_spf.example.com ~all"}, nil
	}
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		SMTPPort:   25,
		From:       "sender@example.com",
		TLSMode:    "tls",
	}

	report, err := RunDiagnostics(params, false)
	if err == nil {
		t.Fatalf("expected error on TCP dial failure, got nil")
	}
	if report.Status != "error" {
		t.Errorf("expected status error, got %s", report.Status)
	}
	if report.DNSInfo.SPFRecord == "" || report.DNSInfo.DMARCRecord == "" {
		t.Errorf("expected SPF and DMARC records to be populated, got SPF=%q DMARC=%q", report.DNSInfo.SPFRecord, report.DNSInfo.DMARCRecord)
	}
}

func TestRunDiagnostics_OutputModes(t *testing.T) {
	report := DiagReport{
		Status:     "success",
		Timestamp:  time.Now().Format(time.RFC3339),
		SMTPServer: "smtp.example.com",
		SMTPPort:   587,
		TLSMode:    "tls",
		DNSInfo: DNSDiagInfo{
			TargetHost:  "smtp.example.com",
			ResolvedIPs: []string{"192.0.2.1"},
			MXRecords:   []string{"mx.example.com (pref 10)"},
			SPFRecord:   "v=spf1 ~all",
			DMARCRecord: "v=DMARC1; p=none",
		},
		Latency: LatencyMetrics{
			TCPConnectMS:   10.5,
			TLSHandshakeMS: 20.1,
			EHLORTTMS:      5.2,
			TotalMS:        35.8,
		},
		Capabilities: ESMTPCapabilities{
			StartTLS:     true,
			Chunking:     true,
			MaxSizeMB:    25,
			MaxSizeBytes: 26214400,
			AuthMethods:  []string{"PLAIN", "LOGIN"},
			Pipelining:   true,
			EightBitMIME: true,
			DSN:          true,
		},
		TLSInfo: &TLSCertInfo{
			Subject:             "CN=smtp.example.com",
			Issuer:              "CN=Example CA",
			NotBefore:           "2026-01-01",
			NotAfter:            "2026-12-31",
			DaysUntilExpiration: 200,
			DNSNames:            []string{"smtp.example.com"},
			Version:             "TLS 1.3",
			CipherSuite:         "TLS_AES_128_GCM_SHA256",
			ExpirationWarning:   false,
		},
	}

	// Test text output
	if err := OutputDiagReport(report, false, false, true); err != nil {
		t.Errorf("OutputDiagReport text mode error: %v", err)
	}

	// Test JSON output
	if err := OutputDiagReport(report, true, false, false); err != nil {
		t.Errorf("OutputDiagReport JSON mode error: %v", err)
	}

	// Test NDJSON output
	if err := OutputDiagReport(report, false, true, false); err != nil {
		t.Errorf("OutputDiagReport NDJSON mode error: %v", err)
	}

	// Test error status output mode
	errReport := report
	errReport.Status = "error"
	errReport.Error = "SMTP negotiation error"
	if err := OutputDiagReport(errReport, true, false, false); err == nil {
		t.Errorf("expected error from OutputDiagReport when status=error in JSON mode")
	}
	if err := OutputDiagReport(errReport, false, true, false); err == nil {
		t.Errorf("expected error from OutputDiagReport when status=error in NDJSON mode")
	}
	if err := OutputDiagReport(errReport, false, false, false); err == nil {
		t.Errorf("expected error from OutputDiagReport when status=error in text mode")
	}
}

func TestRunDiagnostics_Port465_HandshakeFailure(t *testing.T) {
	origHost := netLookupHost
	origDial := netDialTimeout
	t.Cleanup(func() {
		netLookupHost = origHost
		netDialTimeout = origDial
	})

	netLookupHost = func(host string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			time.Sleep(10 * time.Millisecond)
			_ = c2.Close()
		}()
		return c1, nil
	}

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		SMTPPort:   465,
		TLSMode:    "tls",
	}

	report, err := RunDiagnostics(params, false)
	if err == nil {
		t.Fatalf("expected error when TLS handshake fails on port 465, got nil")
	}
	if report.Status != "error" {
		t.Errorf("expected status error, got %s", report.Status)
	}
}

func TestRunDiagnostics_SMTPClientInitFailure(t *testing.T) {
	origHost := netLookupHost
	origDial := netDialTimeout
	origSMTPInit := smtpClientInit
	t.Cleanup(func() {
		netLookupHost = origHost
		netDialTimeout = origDial
		smtpClientInit = origSMTPInit
	})

	netLookupHost = func(host string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			time.Sleep(10 * time.Millisecond)
			_ = c2.Close()
		}()
		return c1, nil
	}
	smtpClientInit = func(c net.Conn, host string) (*smtp.Client, error) {
		return nil, errors.New("500 Bad SMTP banner")
	}

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		SMTPPort:   587,
		TLSMode:    "tls",
	}

	report, err := RunDiagnostics(params, false)
	if err == nil {
		t.Fatalf("expected error when SMTP client init fails, got nil")
	}
	if report.Status != "error" {
		t.Errorf("expected status error, got %s", report.Status)
	}
}
