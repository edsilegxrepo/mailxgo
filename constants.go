// Package mailxgo - Application Constants
//
// OBJECTIVES:
// Define centralized configuration constants for default values used throughout the application.
//
// CORE COMPONENTS:
// - DefaultSMTPPort: Default SMTP submission port (587).
// - DefaultRetryDelay: Default delay between retry attempts in seconds.
// - DefaultTimeout: Default SMTP connection timeout in seconds.
// - DefaultCharset: Default character set for email body content.
package mailxgo

const (
	// DefaultSMTPPort is the default SMTP submission port (RFC 6409).
	DefaultSMTPPort = 587

	// DefaultSMTPSPort is the default implicit TLS SMTP port.
	DefaultSMTPSPort = 465

	// DefaultRetryDelay is the default delay between retry attempts in seconds.
	DefaultRetryDelay = 5

	// DefaultTimeout is the default SMTP connection timeout in seconds.
	DefaultTimeout = 30

	// DefaultCharset is the default character set for email body content.
	DefaultCharset = "UTF-8"

	// MaxEmailLength is the maximum allowed email address length per RFC 5321.
	MaxEmailLength = 254
)
