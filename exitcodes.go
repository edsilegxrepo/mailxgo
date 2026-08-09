// Package mailxgo - Enterprise CLI SMTP Client & Gateway Diagnostic Engine
//
// OBJECTIVES:
// Define granular, deterministic process exit code constants for CLI automation and enterprise job schedulers.
//
// CORE COMPONENTS:
// - Exit code constants (ExitSuccess, ExitErrUsage, ExitErrConfig, ExitErrFileIO, ExitErrDNS, ExitErrTLS, ExitErrAuth, ExitErrSend).
// - ExitFunc: Function pointer to os.Exit, allowing unit test execution without terminating the test runner.
//
// FUNCTIONALITY & DATA FLOW:
// Functions in cli.go and mailer.go evaluate error conditions and invoke osExit(ExitErrCode), returning numeric status codes to the parent process.
package mailxgo

import "os"

// Granular exit codes for mailxgo CLI diagnostics and process automation.
// Objectives: Allow enterprise job schedulers (Control-M, Tivoli, Cron) to programmatically handle distinct failure modes.
const (
	ExitSuccess   = 0 // ExitSuccess indicates execution completed cleanly without errors.
	ExitErrUsage  = 2 // ExitErrUsage indicates invalid CLI arguments or missing mandatory parameters.
	ExitErrConfig = 3 // ExitErrConfig indicates JSON configuration file loading or parsing failure.
	ExitErrFileIO = 4 // ExitErrFileIO indicates recipient list or attachment file I/O failure.
	ExitErrDNS    = 5 // ExitErrDNS indicates DNS host resolution, MX query, or gateway probe failure.
	ExitErrTLS    = 6 // ExitErrTLS indicates SMTPS / STARTTLS handshake failure or certificate error.
	ExitErrAuth   = 7 // ExitErrAuth indicates SASL / XOAUTH2 authentication rejection.
	ExitErrSend   = 8 // ExitErrSend indicates SMTP dial or payload transmission error.
)

// ExitFunc points to os.Exit by default; intercepted during unit tests.
var ExitFunc = os.Exit
