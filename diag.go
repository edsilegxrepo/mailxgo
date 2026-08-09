// Package mailxgo - Gateway Diagnostics & Telemetry Probe Engine
//
// OBJECTIVES:
// Execute non-destructive pre-flight probes against remote SMTP gateways to audit DNS host resolutions, MX records, SPF/DMARC policies, TCP dial RTT, TLS handshake/cert expiration, and ESMTP capability advertisements without delivering emails.
//
// CORE COMPONENTS:
// - LatencyMetrics: Records decomposed phase round-trip times (tcp_connect_ms, tls_handshake_ms, ehlo_rtt_ms, total_ms).
// - ESMTPCapabilities: Stores advertised server capability flags (STARTTLS, CHUNKING, PIPELINING, DSN, 8BITMIME, SIZE).
// - TLSCertInfo: Stores X.509 certificate chain details, expiration warnings, TLS protocol version, and cipher suite names.
// - DNSDiagInfo: Stores host A/AAAA resolutions, MX priority lists, and SPF/DMARC policy strings.
// - DiagReport: Aggregates complete diagnostic probe findings.
// - RunDiagnostics: Core probe function orchestrating DNS lookup -> TCP dial -> TLS handshake -> EHLO capability check.
//
// FUNCTIONALITY & DATA FLOW:
// EmailParams -> DNS Resolution (A/AAAA/MX/SPF/DMARC) -> TCP Dial RTT measurement -> TLS Handshake & Cert audit -> EHLO Capability Probe -> DiagReport -> OutputJSON/Text.
package mailxgo

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Network function pointers intercepted during unit testing.
var (
	netLookupHost  = net.LookupHost
	netLookupMX    = net.LookupMX
	netLookupTXT   = net.LookupTXT
	netDialTimeout = net.DialTimeout
	osHostname     = os.Hostname
	smtpClientInit = smtp.NewClient
)

// LatencyMetrics records decomposed phase round-trip times in milliseconds.
type LatencyMetrics struct {
	TCPConnectMS   float64 `json:"tcp_connect_ms"`
	TLSHandshakeMS float64 `json:"tls_handshake_ms,omitempty"`
	EHLORTTMS      float64 `json:"ehlo_rtt_ms"`
	TotalMS        float64 `json:"total_ms"`
}

// ESMTPCapabilities stores ESMTP extension capability flags extracted during EHLO probe.
type ESMTPCapabilities struct {
	StartTLS      bool     `json:"starttls"`
	Chunking      bool     `json:"chunking"`
	MaxSizeMB     int      `json:"max_size_mb,omitempty"`
	MaxSizeBytes  int64    `json:"max_size_bytes,omitempty"`
	AuthMethods   []string `json:"auth_methods,omitempty"`
	Pipelining    bool     `json:"pipelining"`
	DSN           bool     `json:"dsn"`
	EightBitMIME  bool     `json:"eight_bit_mime"`
	BinaryMIME    bool     `json:"binary_mime"`
	RawExtensions []string `json:"raw_extensions,omitempty"`
}

// TLSCertInfo stores X.509 certificate chain details extracted during TLS handshake.
type TLSCertInfo struct {
	Subject             string           `json:"subject"`
	Issuer              string           `json:"issuer"`
	NotBefore           string           `json:"not_before"`
	NotAfter            string           `json:"not_after"`
	DaysUntilExpiration int              `json:"days_until_expiration"`
	DNSNames            []string         `json:"dns_names,omitempty"`
	Fingerprint         string           `json:"fingerprint_sha256"`
	Version             string           `json:"tls_version"`
	CipherSuite         string           `json:"cipher_suite"`
	ExpirationWarning   bool             `json:"expiration_warning"`
	ChainOfTrust        []CertChainEntry `json:"chain_of_trust,omitempty"`
}

// CertChainEntry represents a certificate in the chain of trust.
type CertChainEntry struct {
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	Fingerprint string `json:"fingerprint_sha256"`
	NotAfter    string `json:"not_after"`
	IsCA        bool   `json:"is_ca"`
}

// DNSDiagInfo stores DNS host IP resolutions, MX priority lists, and SPF/DMARC record policies.
type DNSDiagInfo struct {
	TargetHost  string   `json:"target_host"`
	ResolvedIPs []string `json:"resolved_ips"`
	MXRecords   []string `json:"mx_records,omitempty"`
	SPFRecord   string   `json:"spf_record,omitempty"`
	DMARCRecord string   `json:"dmarc_record,omitempty"`
}

// DiagReport aggregates complete diagnostic probe findings for telemetry rendering.
type DiagReport struct {
	Status       string            `json:"status"`
	Timestamp    string            `json:"timestamp"`
	SMTPServer   string            `json:"smtp_server"`
	SMTPPort     int               `json:"smtp_port"`
	TLSMode      string            `json:"tls_mode"`
	DNSInfo      DNSDiagInfo       `json:"dns_info"`
	Latency      LatencyMetrics    `json:"latency"`
	Capabilities ESMTPCapabilities `json:"capabilities"`
	TLSInfo      *TLSCertInfo      `json:"tls_info,omitempty"`
	Error        string            `json:"error,omitempty"`
}

// getTLSVersionString maps uint16 TLS protocol versions to human-readable strings.
func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0 (Deprecated)"
	case tls.VersionTLS11:
		return "TLS 1.1 (Deprecated)"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// getCipherSuiteString maps uint16 cipher suite IDs to human-readable names.
func getCipherSuiteString(id uint16) string {
	for _, cs := range tls.CipherSuites() {
		if cs.ID == id {
			return cs.Name
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		if cs.ID == id {
			return cs.Name + " (Insecure)"
		}
	}
	return fmt.Sprintf("0x%04x", id)
}

// RunDiagnostics performs non-destructive pre-flight gateway probing against target SMTP servers.
// Data Flow: Resolves DNS (A/AAAA/MX/SPF/DMARC) -> Measures TCP connect RTT -> Performs TLS handshake & Cert extraction -> Issues EHLO & measures extension capability RTT -> Renders diagnostic report.
func RunDiagnostics(params EmailParams, printCerts bool) (*DiagReport, error) {
	timestamp := time.Now().Format(time.RFC3339)
	report := DiagReport{
		Status:     "success",
		Timestamp:  timestamp,
		SMTPServer: params.SMTPServer,
		SMTPPort:   params.SMTPPort,
		TLSMode:    params.TLSMode,
		DNSInfo: DNSDiagInfo{
			TargetHost: params.SMTPServer,
		},
	}

	timeoutSec := params.Timeout
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	dialTimeout := time.Duration(timeoutSec) * time.Second

	// 1. DNS Resolution & MX Lookup
	ips, err := netLookupHost(params.SMTPServer)
	if err == nil {
		report.DNSInfo.ResolvedIPs = ips
	}

	mxRecords, err := netLookupMX(params.SMTPServer)
	if err == nil && len(mxRecords) > 0 {
		sort.Slice(mxRecords, func(i, j int) bool {
			return mxRecords[i].Pref < mxRecords[j].Pref
		})
		for _, mx := range mxRecords {
			report.DNSInfo.MXRecords = append(report.DNSInfo.MXRecords, fmt.Sprintf("%s (pref %d)", mx.Host, mx.Pref))
		}
	}

	// Domain SPF / DMARC check if domain in From address
	if params.From != "" {
		parts := strings.Split(params.From, "@")
		if len(parts) == 2 {
			domain := parts[1]
			txts, _ := netLookupTXT(domain)
			for _, txt := range txts {
				if strings.HasPrefix(txt, "v=spf1") {
					report.DNSInfo.SPFRecord = txt
					break
				}
			}
			dmarcTxts, _ := netLookupTXT("_dmarc." + domain)
			for _, txt := range dmarcTxts {
				if strings.HasPrefix(txt, "v=DMARC1") {
					report.DNSInfo.DMARCRecord = txt
					break
				}
			}
		}
	}

	addr := fmt.Sprintf("%s:%d", params.SMTPServer, params.SMTPPort)

	// 2. TCP Connection Latency
	t0 := time.Now()
	conn, err := netDialTimeout("tcp", addr, dialTimeout)
	tcpLatency := time.Since(t0).Seconds() * 1000
	report.Latency.TCPConnectMS = tcpLatency

	if err != nil {
		report.Status = "error"
		report.Error = fmt.Sprintf("TCP dial failed: %v", err)
		return &report, OutputDiagReport(report, params.JSONOutput, params.NDJSONOutput, printCerts)
	}
	defer func() { _ = conn.Close() }()

	// Handle Port 465 SSL/TLS or STARTTLS
	var client *smtp.Client
	var tlsState *tls.ConnectionState

	if params.SMTPPort == 465 || params.TLSMode == "tls-direct" {
		// #nosec G402 -- InsecureSkipVerify is user-configurable via ignore-trust mode for internal relays.
		tlsConfig := &tls.Config{
			InsecureSkipVerify: params.TLSMode == "ignore-trust",
			ServerName:         params.SMTPServer,
			MinVersion:         tls.VersionTLS12,
		}

		// Custom CA certificates
		if params.TLSCACert != "" || params.TLSCADir != "" {
			rootCAs, err := loadCustomCACerts(params.TLSCACert, params.TLSCADir)
			if err != nil {
				report.Status = "error"
				report.Error = fmt.Sprintf("Failed to load custom CA certificates: %v", err)
				return &report, OutputDiagReport(report, params.JSONOutput, params.NDJSONOutput, printCerts)
			}
			tlsConfig.RootCAs = rootCAs
			tlsConfig.InsecureSkipVerify = false
		}

		// Certificate fingerprint pinning
		if params.TLSFingerprint != "" {
			tlsConfig.VerifyPeerCertificate = createFingerprintVerifier(params.TLSFingerprint)
			tlsConfig.InsecureSkipVerify = true
		}

		tTLS0 := time.Now()
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			report.Status = "error"
			report.Error = fmt.Sprintf("TLS handshake failed on port %d: %v", params.SMTPPort, err)
			return &report, OutputDiagReport(report, params.JSONOutput, params.NDJSONOutput, printCerts)
		}
		tlsLatency := time.Since(tTLS0).Seconds() * 1000
		report.Latency.TLSHandshakeMS = tlsLatency

		state := tlsConn.ConnectionState()
		tlsState = &state

		c, err := smtpClientInit(tlsConn, params.SMTPServer)
		if err != nil {
			report.Status = "error"
			report.Error = fmt.Sprintf("SMTP client init failed: %v", err)
			return &report, OutputDiagReport(report, params.JSONOutput, params.NDJSONOutput, printCerts)
		}
		client = c
	} else {
		c, err := smtpClientInit(conn, params.SMTPServer)
		if err != nil {
			report.Status = "error"
			report.Error = fmt.Sprintf("SMTP banner/EHLO failed: %v", err)
			return &report, OutputDiagReport(report, params.JSONOutput, params.NDJSONOutput, printCerts)
		}
		client = c
	}

	// 3. EHLO & Capabilities Discovery
	tEHLO0 := time.Now()
	heloDomain := "localhost"
	if host, err := osHostname(); err == nil && host != "" {
		heloDomain = host
	}
	if err := client.Hello(heloDomain); err != nil {
		report.Status = "error"
		report.Error = fmt.Errorf("EHLO negotiation failed: %w", err).Error()
		return &report, OutputDiagReport(report, params.JSONOutput, params.NDJSONOutput, printCerts)
	}
	ehloLatency := time.Since(tEHLO0).Seconds() * 1000
	report.Latency.EHLORTTMS = ehloLatency
	report.Latency.TotalMS = report.Latency.TCPConnectMS + report.Latency.TLSHandshakeMS + report.Latency.EHLORTTMS

	// STARTTLS if supported and required
	if ok, _ := client.Extension("STARTTLS"); ok && (params.TLSMode == "tls" || params.TLSMode == "ignore-trust") && params.SMTPPort != 465 {
		report.Capabilities.StartTLS = true
		// #nosec G402 -- InsecureSkipVerify is user-configurable via ignore-trust mode for internal relays.
		tlsConfig := &tls.Config{
			InsecureSkipVerify: params.TLSMode == "ignore-trust",
			ServerName:         params.SMTPServer,
			MinVersion:         tls.VersionTLS12,
		}

		// Custom CA certificates
		if params.TLSCACert != "" || params.TLSCADir != "" {
			rootCAs, err := loadCustomCACerts(params.TLSCACert, params.TLSCADir)
			if err != nil {
				report.Status = "error"
				report.Error = fmt.Sprintf("Failed to load custom CA certificates: %v", err)
				return &report, OutputDiagReport(report, params.JSONOutput, params.NDJSONOutput, printCerts)
			}
			tlsConfig.RootCAs = rootCAs
			tlsConfig.InsecureSkipVerify = false
		}

		// Certificate fingerprint pinning
		if params.TLSFingerprint != "" {
			tlsConfig.VerifyPeerCertificate = createFingerprintVerifier(params.TLSFingerprint)
			tlsConfig.InsecureSkipVerify = true
		}

		tTLS0 := time.Now()
		if err := client.StartTLS(tlsConfig); err != nil {
			report.Status = "error"
			report.Error = fmt.Sprintf("STARTTLS command failed: %v", err)
			return &report, OutputDiagReport(report, params.JSONOutput, params.NDJSONOutput, printCerts)
		}
		tlsLatency := time.Since(tTLS0).Seconds() * 1000
		report.Latency.TLSHandshakeMS = tlsLatency
		report.Latency.TotalMS += tlsLatency

		// Capture TLS connection state after STARTTLS upgrade
		if state, ok := client.TLSConnectionState(); ok {
			tlsState = &state
		}
	}

	// Discover extensions
	if ok, extParams := client.Extension("SIZE"); ok {
		if extParams != "" {
			if sz, err := strconv.ParseInt(strings.TrimSpace(extParams), 10, 64); err == nil {
				report.Capabilities.MaxSizeBytes = sz
				report.Capabilities.MaxSizeMB = int(sz / (1024 * 1024))
			}
		}
	}

	if ok, _ := client.Extension("CHUNKING"); ok {
		report.Capabilities.Chunking = true
	}
	if ok, authStr := client.Extension("AUTH"); ok {
		report.Capabilities.AuthMethods = strings.Fields(authStr)
	}
	if ok, _ := client.Extension("PIPELINING"); ok {
		report.Capabilities.Pipelining = true
	}
	if ok, _ := client.Extension("DSN"); ok {
		report.Capabilities.DSN = true
	}
	if ok, _ := client.Extension("8BITMIME"); ok {
		report.Capabilities.EightBitMIME = true
	}
	if ok, _ := client.Extension("BINARYMIME"); ok {
		report.Capabilities.BinaryMIME = true
	}

	// Collect TLS Cert info if available
	if tlsState != nil && len(tlsState.PeerCertificates) > 0 {
		leaf := tlsState.PeerCertificates[0]
		now := time.Now()
		daysRemaining := int(leaf.NotAfter.Sub(now).Hours() / 24)

		// Compute SHA256 fingerprint of leaf certificate
		leafFingerprint := FormatFingerprint(ComputeCertFingerprint(leaf.Raw))

		// Build chain of trust
		var chain []CertChainEntry
		for _, cert := range tlsState.PeerCertificates {
			entry := CertChainEntry{
				Subject:     cert.Subject.String(),
				Issuer:      cert.Issuer.String(),
				Fingerprint: FormatFingerprint(ComputeCertFingerprint(cert.Raw)),
				NotAfter:    cert.NotAfter.Format("2006-01-02"),
				IsCA:        cert.IsCA,
			}
			chain = append(chain, entry)
		}

		report.TLSInfo = &TLSCertInfo{
			Subject:             leaf.Subject.String(),
			Issuer:              leaf.Issuer.String(),
			NotBefore:           leaf.NotBefore.Format("2006-01-02"),
			NotAfter:            leaf.NotAfter.Format("2006-01-02"),
			DaysUntilExpiration: daysRemaining,
			DNSNames:            leaf.DNSNames,
			Fingerprint:         leafFingerprint,
			Version:             getTLSVersionString(tlsState.Version),
			CipherSuite:         getCipherSuiteString(tlsState.CipherSuite),
			ExpirationWarning:   daysRemaining <= 30,
			ChainOfTrust:        chain,
		}
	}

	_ = client.Quit()

	err = OutputDiagReport(report, params.JSONOutput, params.NDJSONOutput, printCerts)
	return &report, err
}

func OutputDiagReport(report DiagReport, jsonOutput bool, ndjsonOutput bool, printCerts bool) error {
	if ndjsonOutput {
		data, _ := json.Marshal(report)
		fmt.Println(string(data))
		if report.Status != "success" {
			return errors.New(report.Error)
		}
		return nil
	}
	if jsonOutput {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
		if report.Status != "success" {
			return errors.New(report.Error)
		}
		return nil
	}

	fmt.Println("=== mailxgo SMTP Gateway Diagnostics ===")
	fmt.Printf("Target Server : %s:%d\n", report.SMTPServer, report.SMTPPort)
	if len(report.DNSInfo.ResolvedIPs) > 0 {
		fmt.Printf("Resolved IPs  : %s\n", strings.Join(report.DNSInfo.ResolvedIPs, ", "))
	}
	if len(report.DNSInfo.MXRecords) > 0 {
		fmt.Printf("MX Records    : %s\n", strings.Join(report.DNSInfo.MXRecords, ", "))
	}
	if report.DNSInfo.SPFRecord != "" {
		fmt.Printf("SPF Record    : %s\n", report.DNSInfo.SPFRecord)
	}
	if report.DNSInfo.DMARCRecord != "" {
		fmt.Printf("DMARC Record  : %s\n", report.DNSInfo.DMARCRecord)
	}
	fmt.Printf("TLS Mode      : %s\n", report.TLSMode)

	if report.Status != "success" {
		fmt.Printf("\n[DIAGNOSTIC FAILED]: %s\n", report.Error)
		return errors.New(report.Error)
	}

	fmt.Println("\n--- Network & Latency Metrics ---")
	fmt.Printf("TCP Connection RTT   : %.2f ms\n", report.Latency.TCPConnectMS)
	if report.Latency.TLSHandshakeMS > 0 {
		fmt.Printf("TLS Handshake RTT    : %.2f ms\n", report.Latency.TLSHandshakeMS)
	}
	fmt.Printf("EHLO Round-Trip RTT  : %.2f ms\n", report.Latency.EHLORTTMS)
	fmt.Printf("Total Probe Latency  : %.2f ms\n", report.Latency.TotalMS)

	fmt.Println("\n--- ESMTP Gateway Capabilities ---")
	fmt.Printf("STARTTLS Extension   : %t\n", report.Capabilities.StartTLS)
	fmt.Printf("CHUNKING (BDAT)      : %t (RFC 3030)\n", report.Capabilities.Chunking)
	if report.Capabilities.MaxSizeMB > 0 {
		fmt.Printf("MAX MESSAGE SIZE     : %d MB (%d bytes)\n", report.Capabilities.MaxSizeMB, report.Capabilities.MaxSizeBytes)
	} else {
		fmt.Printf("MAX MESSAGE SIZE     : Unlimited / Not Advertised\n")
	}
	if len(report.Capabilities.AuthMethods) > 0 {
		fmt.Printf("AUTH Mechanisms      : %s\n", strings.Join(report.Capabilities.AuthMethods, ", "))
	}
	fmt.Printf("PIPELINING           : %t\n", report.Capabilities.Pipelining)
	fmt.Printf("8BITMIME             : %t\n", report.Capabilities.EightBitMIME)
	fmt.Printf("DSN Notifications    : %t\n", report.Capabilities.DSN)

	if report.TLSInfo != nil && (printCerts || report.TLSInfo.ExpirationWarning) {
		fmt.Println("\n--- TLS Certificate & Security Info ---")
		fmt.Printf("Subject              : %s\n", report.TLSInfo.Subject)
		fmt.Printf("Issuer               : %s\n", report.TLSInfo.Issuer)
		fmt.Printf("Validity Period      : %s to %s (%d days remaining)\n", report.TLSInfo.NotBefore, report.TLSInfo.NotAfter, report.TLSInfo.DaysUntilExpiration)
		if report.TLSInfo.ExpirationWarning {
			fmt.Printf("WARNING              : Certificate expires in %d days!\n", report.TLSInfo.DaysUntilExpiration)
		}
		fmt.Printf("TLS Protocol         : %s\n", report.TLSInfo.Version)
		fmt.Printf("Cipher Suite         : %s\n", report.TLSInfo.CipherSuite)
		fmt.Printf("SHA256 Fingerprint   : %s\n", report.TLSInfo.Fingerprint)
		if len(report.TLSInfo.DNSNames) > 0 {
			fmt.Printf("SAN Names            : %s\n", strings.Join(report.TLSInfo.DNSNames, ", "))
		}

		// Display chain of trust
		if len(report.TLSInfo.ChainOfTrust) > 0 {
			fmt.Println("\n--- Certificate Chain of Trust ---")
			for i, cert := range report.TLSInfo.ChainOfTrust {
				certType := "End-Entity"
				if cert.IsCA {
					if i == len(report.TLSInfo.ChainOfTrust)-1 {
						certType = "Root CA"
					} else {
						certType = "Intermediate CA"
					}
				}
				fmt.Printf("[%d] %s\n", i, certType)
				fmt.Printf("    Subject     : %s\n", cert.Subject)
				fmt.Printf("    Issuer      : %s\n", cert.Issuer)
				fmt.Printf("    Expires     : %s\n", cert.NotAfter)
				fmt.Printf("    Fingerprint : %s\n", cert.Fingerprint)
			}
			if len(report.TLSInfo.ChainOfTrust) == 1 {
				// Check if self-signed
				chain := report.TLSInfo.ChainOfTrust[0]
				if chain.Subject == chain.Issuer {
					fmt.Println("\n    Note: Self-signed certificate (no CA chain)")
				}
			}
		}
	}

	fmt.Println("\nGateway Probe Complete: SUCCESS")
	return nil
}
