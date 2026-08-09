// Package main - OAuth2 Mock SMTP Server for Integration Testing
//
// OBJECTIVES:
// Provide a lightweight SMTP server that accepts XOAUTH2 and OAUTHBEARER SASL mechanisms
// for testing mailxgo OAuth2 authentication without requiring real provider credentials.
//
// USAGE:
//
//	go run main.go
//	# Or build and run in Docker
//
// SASL MECHANISMS:
// - XOAUTH2: Accepts tokens in format "user=<email>\x01auth=Bearer <token>\x01\x01"
// - PLAIN/LOGIN: Also supported for fallback testing
package main

import (
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// Backend implements smtp.Backend for the mock server.
type Backend struct {
	// ValidTokenPrefix defines tokens that will be accepted (for testing).
	ValidTokenPrefix string
}

// NewSession creates a new session for each connection.
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{backend: b}, nil
}

// Session implements smtp.Session and smtp.AuthSession for handling SMTP transactions.
type Session struct {
	backend  *Backend
	authUser string
	from     string
	to       []string
}

// AuthMechanisms returns the list of supported SASL mechanisms.
func (s *Session) AuthMechanisms() []string {
	return []string{"XOAUTH2", "PLAIN", "LOGIN"}
}

// Auth returns a SASL server for the requested mechanism.
func (s *Session) Auth(mech string) (sasl.Server, error) {
	log.Printf("[AUTH] Requested mechanism: %s", mech)
	return &authServer{session: s, mech: strings.ToUpper(mech)}, nil
}

// authServer implements sasl.Server for handling authentication.
type authServer struct {
	session *Session
	mech    string
	step    int
}

// Next processes SASL authentication steps.
func (a *authServer) Next(response []byte) (challenge []byte, done bool, err error) {
	log.Printf("[AUTH %s] Step %d, response length: %d", a.mech, a.step, len(response))
	a.step++

	switch a.mech {
	case "XOAUTH2":
		return a.handleXOAuth2(response)
	case "PLAIN":
		return a.handlePlain(response)
	case "LOGIN":
		return a.handleLogin(response)
	default:
		return nil, false, &smtp.SMTPError{Code: 504, EnhancedCode: smtp.EnhancedCode{5, 7, 4}, Message: "Unrecognized authentication type"}
	}
}

// handleXOAuth2 processes XOAUTH2 authentication.
// Format: "user=<email>\x01auth=Bearer <token>\x01\x01"
func (a *authServer) handleXOAuth2(response []byte) ([]byte, bool, error) {
	if len(response) == 0 {
		// Initial response empty, send empty challenge
		return nil, false, nil
	}

	payload := string(response)
	log.Printf("[XOAUTH2] Raw payload: %q", payload)

	// Parse XOAUTH2 format
	parts := strings.Split(payload, "\x01")
	var user, token string
	for _, part := range parts {
		if strings.HasPrefix(part, "user=") {
			user = strings.TrimPrefix(part, "user=")
		} else if strings.HasPrefix(part, "auth=Bearer ") {
			token = strings.TrimPrefix(part, "auth=Bearer ")
		}
	}

	if user == "" || token == "" {
		log.Printf("[XOAUTH2] Missing user or token")
		return nil, false, &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Invalid XOAUTH2 format"}
	}

	if !a.session.isValidToken(token) {
		log.Printf("[XOAUTH2] Invalid token")
		return nil, false, &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Authentication credentials invalid"}
	}

	a.session.authUser = user
	log.Printf("[XOAUTH2] Authentication successful for user: %s", user)
	return nil, true, nil
}

// handlePlain processes PLAIN authentication.
// Format: \x00username\x00password
func (a *authServer) handlePlain(response []byte) ([]byte, bool, error) {
	if len(response) == 0 {
		return nil, false, nil
	}

	parts := strings.Split(string(response), "\x00")
	if len(parts) != 3 {
		return nil, false, &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Invalid PLAIN format"}
	}

	a.session.authUser = parts[1]
	log.Printf("[PLAIN] Authentication successful for user: %s", a.session.authUser)
	return nil, true, nil
}

// handleLogin processes LOGIN authentication (multi-step).
func (a *authServer) handleLogin(response []byte) ([]byte, bool, error) {
	switch a.step {
	case 1:
		// Send username challenge
		return []byte("Username:"), false, nil
	case 2:
		// Received username, send password challenge
		a.session.authUser = string(response)
		return []byte("Password:"), false, nil
	case 3:
		// Received password, authentication complete
		log.Printf("[LOGIN] Authentication successful for user: %s", a.session.authUser)
		return nil, true, nil
	default:
		return nil, false, &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Too many LOGIN steps"}
	}
}

// isValidToken checks if the token is valid for testing purposes.
func (s *Session) isValidToken(token string) bool {
	// Accept any token that:
	// 1. Starts with configured valid prefix
	// 2. Starts with "ya29." (Google token format)
	// 3. Starts with "test" (for testing)
	// 4. Is non-empty and at least 10 chars (basic sanity check)
	if s.backend.ValidTokenPrefix != "" && strings.HasPrefix(token, s.backend.ValidTokenPrefix) {
		return true
	}
	if strings.HasPrefix(token, "ya29.") {
		return true
	}
	if strings.HasPrefix(token, "test") {
		return true
	}
	return len(token) >= 10
}

// Mail handles MAIL FROM command.
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	log.Printf("[MAIL FROM] %s", from)
	s.from = from
	return nil
}

// Rcpt handles RCPT TO command.
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	log.Printf("[RCPT TO] %s", to)
	s.to = append(s.to, to)
	return nil
}

// Data handles the DATA command and message body.
func (s *Session) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	log.Printf("[DATA] Received %d bytes from %s to %v", len(data), s.from, s.to)
	return nil
}

// Reset resets the session state.
func (s *Session) Reset() {
	s.from = ""
	s.to = nil
}

// Logout handles session termination.
func (s *Session) Logout() error {
	return nil
}

func main() {
	addr := ":1026" // Use different port to avoid conflict with Mailpit
	if envAddr := os.Getenv("SMTP_ADDR"); envAddr != "" {
		addr = envAddr
	}

	validPrefix := os.Getenv("VALID_TOKEN_PREFIX")

	be := &Backend{
		ValidTokenPrefix: validPrefix,
	}

	s := smtp.NewServer(be)
	s.Addr = addr
	s.Domain = "oauth2-mock.local"
	s.AllowInsecureAuth = true // Allow auth without TLS for testing
	s.ReadTimeout = 30 * time.Second
	s.WriteTimeout = 30 * time.Second
	s.MaxMessageBytes = 10 * 1024 * 1024 // 10MB
	s.MaxRecipients = 50

	log.Printf("Starting OAuth2 Mock SMTP Server on %s", addr)
	log.Printf("Supported SASL mechanisms: XOAUTH2, PLAIN, LOGIN")
	log.Printf("AllowInsecureAuth: %v", s.AllowInsecureAuth)
	if validPrefix != "" {
		log.Printf("Valid token prefix: %s", validPrefix)
	}

	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
