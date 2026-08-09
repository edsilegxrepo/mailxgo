For torture-testing a Go SMTP client against a real server with support for **STARTTLS, Implicit SSL/TLS, and AUTH (PLAIN/LOGIN)**, the best lightweight container depends on whether you are testing **RFC compliance/throughput** or **fault tolerance/error handling**.

Here are the top three containerized recommendations based on test scenarios:

---

### 1. Mailpit (`axllent/mailpit`) – **Best Overall for Standard Integration Tests**

**Mailpit** is a modern, Go-based, lightning-fast replacement for MailHog. It runs as a single lightweight binary in a tiny Docker image (`~15MB`) and handles heavy concurrent loads effortlessly.

* **Why it's great:** Built-in support for STARTTLS, implicit TLS, strict or permissive SMTP Authentication, and a web UI/REST API to assert received emails.
* **Protocols supported:** Plain SMTP, STARTTLS (Port 587), SSL/TLS (Port 465), SASL PLAIN/LOGIN auth.

#### Quickstart with TLS & Auth

Run Mailpit configured to enforce TLS and SMTP Authentication:

```bash
docker run -d \
  --name mailpit \
  -p 1025:1025 \
  -p 10465:465 \
  -p 8025:8025 \
  -e MP_SMTP_AUTH_ACCEPT_ANY=true \
  -e MP_SMTP_REQUIRE_STARTTLS=true \
  -e MP_SMTP_TLS_CERT=/certs/cert.pem \
  -e MP_SMTP_TLS_KEY=/certs/key.pem \
  -v $(pwd)/certs:/certs \
  axllent/mailpit:latest

```

---

### 2. Postfix in Alpine (`catatnight/postfix`) – **Best for Strict Real-World Protocol Conformance**

If you want to torture test your client against a **hardened, battle-tested production server** (to verify edge cases in Go's `net/smtp` buffer parsing, line endings `\r\n`, header sizes, or SASL handshakes), Postfix inside Alpine Linux is the industry standard.

* **Why it's great:** Extremely low memory footprint (`~20MB RAM`), strict RFC implementation, customizable rate-limiting, and max body size/connection limits.
* **Protocols supported:** Full Postfix feature set including SASL (Dovecot/Cyrus), TLS 1.2/1.3, STARTTLS.

#### Example `docker-compose.yml` for Postfix

```yaml
version: '3.8'
services:
  postfix:
    image: catatnight/postfix
    ports:
      - "25:25"
      - "587:587"
    environment:
      maildomain: example.com
      smtp_user: testuser:testpassword

```

---

### 3. Custom Go Fault Injector (`emersion/go-smtp`) – **Best for True "Torture" & Chaos Testing**

If "torture testing" means simulating network failure modes—like **expired/self-signed TLS certs, dropped TCP connections mid-DATA, malformed 4xx/5xx SMTP codes, or forced latency**: mock tools like Mailpit won't intentionally fail.

Building a minimal 50-line Go server using [`emersion/go-smtp`](https://github.com/emersion/go-smtp) compiled into a scratch/distroless container is ideal for chaos testing.

#### Minimal Chaos Server Script (`main.go`)

```go
package main

import (
	"errors"
	"log"
	"time"

	"github.com/emersion/go-smtp"
)

type Backend struct{}

func (bkd *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{}, nil
}

type Session struct{}

func (s *Session) AuthMechanisms() []string {
	return []string{smtp.PlainAuth}
}

func (s *Session) Auth(mech string, stream []byte) error {
	// Simulate bad auth 50% of the time or corrupt auth response
	return errors.New("535 5.7.8 Authentication credentials invalid")
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error { return nil }
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error   { return nil }
func (s *Session) Data(r io.Reader) error                         { return nil }
func (s *Session) Reset()                                         {}
func (s *Session) Logout() error                                  { return nil }

func main() {
	be := &Backend{}
	s := smtp.NewServer(be)
	s.Addr = ":1025"
	s.Domain = "localhost"
	s.ReadTimeout = 2 * time.Second
	s.WriteTimeout = 2 * time.Second

	log.Println("Starting chaos SMTP server on :1025")
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

```

---

### Comparison Summary

| Feature | Mailpit | Postfix (Alpine) | Custom `go-smtp` |
| --- | --- | --- | --- |
| **Primary Use Case** | Fast Integration & Assertions | Strict RFC Compliance | Chaos & Error Injection |
| **Image Size** | `~15 MB` | `~30 MB` | `~10 MB` |
| **STARTTLS & TLS** | Yes | Yes | Yes (customizable) |
| **Auth Support** | Yes (Flexible) | Yes (Strict) | Fully Mockable |
| **Fault/Chaos Testing** | Limited | Minimal | Unlimited |

### Recommendation

* Start with **Mailpit** if you want to verify that your Go client handles real STARTTLS handshakes, implicit TLS connections, authentication flows, and high message throughput without breaking.
* Use **`emersion/go-smtp`** in a scratch container if you specifically need to test how your Go client handles bad TLS certs, dropped connections, and non-standard SMTP server errors.