package main

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/wneessen/go-mail"
)

// sendEmail function modified to include the reply-to header
func sendEmail(smtpServer string, smtpPort int, username string, password string, from string, to []string, replyTo string, subject, body, bodyFile string, attachments []string, tlsMode string, noAuth bool) error {
	// Create a new message
	m := mail.NewMsg()
	if err := m.From(from); err != nil {
		return err
	}

	// Set recipient(s)
	if err := m.To(to...); err != nil {
		return err
	}

	// Set the subject
	m.Subject(subject)

	// Set the body
	if bodyFile != "" {
		m.SetBodyString(mail.TypeTextHTML, body)
	} else {
		m.SetBodyString(mail.TypeTextPlain, body)
	}

	// Add attachments
	for _, attachment := range attachments {
		m.AttachFile(attachment)
	}

	// Add the reply-to header if provided
	if replyTo != "" {
		if err := m.ReplyTo(replyTo); err != nil {
			return err
		}
	}

	clientOptions := []mail.Option{
		mail.WithPort(smtpPort),
	}

	// Define client options
	if !noAuth && (username != "" || password != "") {
		clientOptions = append(
			clientOptions,
			mail.WithSMTPAuth(mail.SMTPAuthLogin),
			mail.WithUsername(username),
			mail.WithPassword(password),
		)
	}

	// Conditionally add TLS options based on tlsMode
	switch tlsMode {
	case "none":
		clientOptions = append(clientOptions, mail.WithTLSPolicy(mail.NoTLS))
	case "tls-skip":
		tlsSkipConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         smtpServer,
		}
		clientOptions = append(clientOptions, mail.WithTLSConfig(tlsSkipConfig))
	case "tls":
		clientOptions = append(clientOptions, mail.WithTLSPolicy(mail.TLSMandatory))
	default:
		return fmt.Errorf("invalid tls-mode %q (expected none, tls-skip, or tls)", tlsMode)
	}

	// Create a new client using the options
	c, err := mail.NewClient(smtpServer, clientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}

	// Send the email
	if err := c.DialAndSend(m); err != nil {
		return fmt.Errorf("error sending email: %w", err)
	}

	fmt.Printf("\nEmail sent successfully to %s from %s\n", strings.Join(to, ", "), from)
	return nil
}
