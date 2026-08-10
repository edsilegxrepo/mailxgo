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

func TestRunDiagnostics_DNSLookupFailures(t *testing.T) {
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

	// All DNS lookups fail
	netLookupHost = func(host string) ([]string, error) { return nil, errors.New("DNS lookup failed") }
	netLookupMX = func(host string) ([]*net.MX, error) { return nil, errors.New("MX lookup failed") }
	netLookupTXT = func(name string) ([]string, error) { return nil, errors.New("TXT lookup failed") }
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		SMTPPort:   587,
		From:       "test@example.com",
		TLSMode:    "tls",
	}

	report, _ := RunDiagnostics(params, false)

	// Should still return a report even with DNS failures
	if report == nil {
		t.Fatal("expected report even with DNS failures")
	}
	// DNS info should be empty due to failures
	if len(report.DNSInfo.ResolvedIPs) != 0 {
		t.Errorf("expected no resolved IPs, got %v", report.DNSInfo.ResolvedIPs)
	}
	if len(report.DNSInfo.MXRecords) != 0 {
		t.Errorf("expected no MX records, got %v", report.DNSInfo.MXRecords)
	}
}

func TestRunDiagnostics_TLSModeNone(t *testing.T) {
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
		return nil, errors.New("connection closed")
	}

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		SMTPPort:   25,
		TLSMode:    "none", // No TLS
	}

	report, _ := RunDiagnostics(params, false)
	if report == nil {
		t.Fatal("expected report")
	}
	if report.TLSMode != "none" {
		t.Errorf("expected TLS mode 'none', got %s", report.TLSMode)
	}
}

func TestRunDiagnostics_DefaultTimeout(t *testing.T) {
	origHost := netLookupHost
	origDial := netDialTimeout
	t.Cleanup(func() {
		netLookupHost = origHost
		netDialTimeout = origDial
	})

	netLookupHost = func(host string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		// Verify default timeout is 30 seconds
		if timeout != 30*time.Second {
			t.Errorf("expected default timeout 30s, got %v", timeout)
		}
		return nil, errors.New("connection refused")
	}

	params := EmailParams{
		SMTPServer: "smtp.example.com",
		SMTPPort:   587,
		Timeout:    0, // Should default to 30
	}

	_, _ = RunDiagnostics(params, false)
}

func TestOutputDiagReport_WithCertChain(t *testing.T) {
	report := DiagReport{
		Status:     "success",
		Timestamp:  "2026-08-10T10:00:00Z",
		SMTPServer: "smtp.example.com",
		SMTPPort:   587,
		TLSMode:    "tls",
		DNSInfo: DNSDiagInfo{
			TargetHost:  "smtp.example.com",
			ResolvedIPs: []string{"192.0.2.1"},
		},
		Latency: LatencyMetrics{
			TCPConnectMS:   10.0,
			TLSHandshakeMS: 20.0,
			EHLORTTMS:      5.0,
			TotalMS:        35.0,
		},
		Capabilities: ESMTPCapabilities{
			StartTLS:     true,
			EightBitMIME: true,
		},
		TLSInfo: &TLSCertInfo{
			Subject:             "CN=smtp.example.com",
			Issuer:              "CN=Example CA",
			NotBefore:           "2026-01-01",
			NotAfter:            "2026-12-31",
			DaysUntilExpiration: 143,
			Version:             "TLS 1.3",
			CipherSuite:         "TLS_AES_128_GCM_SHA256",
			ExpirationWarning:   false,
			ChainOfTrust: []CertChainEntry{
				{
					Subject:     "CN=smtp.example.com",
					Issuer:      "CN=Example CA",
					Fingerprint: "AA:BB:CC:DD",
					NotAfter:    "2026-12-31",
					IsCA:        false,
				},
				{
					Subject:     "CN=Example CA",
					Issuer:      "CN=Root CA",
					Fingerprint: "EE:FF:00:11",
					NotAfter:    "2030-12-31",
					IsCA:        true,
				},
			},
		},
	}

	// Test with printCerts=true to cover cert chain output
	err := OutputDiagReport(report, false, false, true)
	if err != nil {
		t.Errorf("OutputDiagReport with cert chain failed: %v", err)
	}
}

func TestOutputDiagReport_SelfSignedCert(t *testing.T) {
	report := DiagReport{
		Status:     "success",
		Timestamp:  "2026-08-10T10:00:00Z",
		SMTPServer: "internal.local",
		SMTPPort:   587,
		TLSMode:    "ignore-trust",
		DNSInfo:    DNSDiagInfo{TargetHost: "internal.local"},
		Latency:    LatencyMetrics{TCPConnectMS: 1.0, EHLORTTMS: 1.0, TotalMS: 2.0},
		TLSInfo: &TLSCertInfo{
			Subject:             "CN=internal.local",
			Issuer:              "CN=internal.local", // Self-signed: same subject and issuer
			DaysUntilExpiration: 365,
			Version:             "TLS 1.2",
			CipherSuite:         "TLS_RSA_WITH_AES_256_CBC_SHA",
			ChainOfTrust: []CertChainEntry{
				{
					Subject:     "CN=internal.local",
					Issuer:      "CN=internal.local",
					Fingerprint: "AB:CD:EF:01",
					NotAfter:    "2027-08-10",
					IsCA:        true,
				},
			},
		},
	}

	// Test self-signed cert detection (single cert where subject == issuer)
	err := OutputDiagReport(report, false, false, true)
	if err != nil {
		t.Errorf("OutputDiagReport with self-signed cert failed: %v", err)
	}
}

func TestOutputDiagReport_ExpirationWarning(t *testing.T) {
	report := DiagReport{
		Status:     "success",
		Timestamp:  "2026-08-10T10:00:00Z",
		SMTPServer: "smtp.example.com",
		SMTPPort:   587,
		TLSMode:    "tls",
		DNSInfo:    DNSDiagInfo{TargetHost: "smtp.example.com"},
		Latency:    LatencyMetrics{TCPConnectMS: 10.0, EHLORTTMS: 5.0, TotalMS: 15.0},
		TLSInfo: &TLSCertInfo{
			Subject:             "CN=smtp.example.com",
			Issuer:              "CN=CA",
			DaysUntilExpiration: 15, // Less than 30 days
			ExpirationWarning:   true,
			Version:             "TLS 1.3",
			CipherSuite:         "TLS_AES_256_GCM_SHA384",
		},
	}

	// Expiration warning should trigger cert output even without printCerts
	err := OutputDiagReport(report, false, false, false)
	if err != nil {
		t.Errorf("OutputDiagReport with expiration warning failed: %v", err)
	}
}
