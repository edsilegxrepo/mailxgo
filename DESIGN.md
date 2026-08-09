# Technical Design & Software Patterns Specification

## 1. System Overview & Core Design Philosophy

`mailxgo` is designed as a zero-dependency (outside of standard Go libraries and `go-mail`), single-binary executable and modular Go package. The software architecture prioritizes:
- **Predictability & Determinism:** Parameter priority evaluation and system exit codes follow strict deterministic contracts.
- **Resilience:** Defensive validation prevents remote socket dialing when inputs or payload sizes violate bounds.
- **Observability:** Telemetry output is decoupled into human-readable text, structured indented JSON, and single-line NDJSON formats.

---

## 2. Software Design Patterns

### 2.1 Factory Pattern (`clientFactory`)
* **Location:** [mailer.go](./mailer.go#L19-L23)
* **Purpose:** Decouples `mail.NewClient` initialization from `SendEmail` execution logic.
* **Implementation:** `defaultClientFactory` allows unit tests to inject mock SMTP clients (`mockSender`) without establishing remote TCP connections.

```go
type clientSender interface {
	DialAndSend(m ...*mail.Msg) error
}

type clientFactory func(host string, opts ...mail.Option) (clientSender, error)
```

### 2.2 Chain of Responsibility & Precedence Strategy
* **Location:** [cli.go](./cli.go#L360-L435)
* **Purpose:** Evaluates runtime settings across CLI short flags, CLI long flags, JSON configuration files, process environment variables, provider presets, and built-in defaults.
* **Implementation:** `priorityString` and `priorityInt` process low-to-high priority slices:
  $$\text{Priority Slice} = [\text{Config File}, \text{Environment Variables}, \text{CLI Long Flags}, \text{CLI Short Flags}]$$

```go
func priorityString(strings []string) string {
	var result = ""
	for _, val := range strings {
		if val != "" {
			result = val
		}
	}
	return result
}
```

### 2.3 Strategy Pattern for SASL Authentication
* **Location:** [mailer.go](./mailer.go#L260-L288)
* **Purpose:** Dynamically constructs SASL authentication options based on user preference or remote ESMTP capability advertisement (`EHLO`).
* **Supported Strategies:**
  - `noAuthSASL`: Custom unauthenticated SASL fallback (`PLAIN` with `anonymous`).
  - `SMTPAuthPlain`: Standard PLAIN authentication (RFC 4616).
  - `SMTPAuthLogin`: Challenge-response LOGIN authentication.
  - `SMTPAuthCramMD5`: Challenge-response CRAM-MD5 authentication (RFC 2195).
  - `SMTPAuthXOAUTH2`: OAuth 2.0 Access Token bearer authentication (RFC 6749).

---

## 3. Error Handling & Exit Code Matrix

The error handling design guarantees non-zero exit status codes for all abnormal terminations:

| Code Constant | Numeric Code | Failure Scenario |
| :--- | :--- | :--- |
| `ExitSuccess` | `0` | Execution completed without errors. |
| `ExitErrUsage` | `2` | Flag parsing error or missing mandatory arguments. |
| `ExitErrConfig` | `3` | JSON configuration file loading or parsing failure. |
| `ExitErrFileIO` | `4` | Recipient list or attachment file missing or unreadable. |
| `ExitErrDNS` | `5` | DNS host resolution, MX lookup, or diagnostic probe failure. |
| `ExitErrTLS` | `6` | SMTPS / STARTTLS handshake failure or certificate error. |
| `ExitErrAuth` | `7` | SASL / XOAUTH2 authentication rejection. |
| `ExitErrSend` | `8` | SMTP dial or payload transmission error. |

---

## 4. Cross-Platform I/O & Memory Optimization

### 4.1 CRLF Line Normalization
File parsing functions in [util.go](./util.go) process recipient list files and attachment list files using `bufio.Scanner`. This design:
- Automatically strips carriage returns (`\r`) on Windows line endings (`\r\n`).
- Filters `#` comment lines and empty lines.
- Prevents file corruption when crossing operating system boundaries.

### 4.2 Socket Resource & Memory Safety
- All network dials inherit context timeouts (`time.Duration(timeout) * time.Second`).
- File descriptors are closed via `defer file.Close()` immediately following scanner initialization.
