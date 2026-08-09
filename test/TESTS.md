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

---

Mailpit **does** support standard SASL authentication (SASL `PLAIN` and `LOGIN` over STARTTLS/TLS using `MP_SMTP_AUTH` or `MP_SMTP_AUTH_ACCEPT_ANY=true`).

However, Mailpit does **not** support **OAuth2** (such as `XOAUTH2` or `OAUTHBEARER` SASL mechanisms).

If you need to test custom SASL mechanisms or modern OAuth2 flows with your Go client, here is how to test both:

---

### 1. How to enable standard SASL (PLAIN/LOGIN) in Mailpit

If you ran into `AUTH` errors with Mailpit, it's usually because Mailpit blocks plaintext password mechanisms unless TLS is enabled. You can fix this by either providing TLS certificates or allowing insecure auth for test environments:

```bash
docker run -d \
  --name mailpit \
  -p 1025:1025 \
  -e MP_SMTP_AUTH_ACCEPT_ANY=true \
  -e MP_SMTP_AUTH_ALLOW_INSECURE=true \
  axllent/mailpit:latest

```

* `MP_SMTP_AUTH_ACCEPT_ANY=true`: Accepts any credentials passed during `AUTH PLAIN` or `AUTH LOGIN`.
* `MP_SMTP_AUTH_ALLOW_INSECURE=true`: Allows `AUTH` commands without requiring STARTTLS/TLS first.

---

### 2. For SASL XOAUTH2 / OAUTHBEARER: `docker-mailserver`

To test OAuth2 SASL mechanisms (`XOAUTH2` or `OAUTHBEARER` used by Gmail and Exchange Online), Mailpit is too lightweight. The industry-standard containerized solution is **`docker-mailserver`**, which uses Postfix + Dovecot and natively supports SASL OAuth2.

#### Quick setup with Docker Compose:

```yaml
version: '3.8'
services:
  mailserver:
    image: ghcr.io/docker-mailserver/docker-mailserver:latest
    container_name: mailserver
    hostname: mail
    domainname: example.com
    ports:
      - "587:587"  # STARTTLS + AUTH
      - "465:465"  # Implicit TLS + AUTH
    environment:
      - ENABLE_SASL_AUTH=1
      - SASL_AUTH_MECHANISMS=PLAIN,LOGIN,XOAUTH2,OAUTHBEARER
      - TLS_LEVEL=modern
    volumes:
      - ./docker-data/dms/mail-data/:/var/mail/
      - ./docker-data/dms/mail-state/:/var/mail-state/
      - ./docker-data/dms/config/:/tmp/docker-mailserver/

```

---

### 3. Quick Mock for Go Unit Tests (`emersion/go-smtp`)

If you want to mock `XOAUTH2` or `OAUTHBEARER` SASL handshakes inside a lightweight test suite without spinning up a full mail server, write a tiny Go server using `emersion/go-smtp` (which natively supports custom SASL mechanisms).

#### Go Mock Server Code:

```go
package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

type Backend struct{}

func (bkd *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{}, nil
}

type Session struct{}

// Register XOAUTH2 and OAUTHBEARER alongside PLAIN
func (s *Session) AuthMechanisms() []string {
	return []string{"XOAUTH2", "OAUTHBEARER", sasl.Plain}
}

func (s *Session) Auth(mech string, stream []byte) error {
	log.Printf("Received AUTH mechanism: %s with payload: %s", mech, string(stream))

	switch mech {
	case "XOAUTH2", "OAUTHBEARER":
		// Mock token validation logic for your Go client
		if len(stream) == 0 {
			return errors.New("535 5.7.8 Empty OAuth token")
		}
		return nil // Successfully authenticated
	case sasl.Plain:
		return nil
	default:
		return errors.New("504 5.7.4 Unrecognized authentication type")
	}
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error { return nil }
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error   { return nil }
func (s *Session) Data(r io.Reader) error                         { return nil }
func (s *Session) Reset()                                         {}
func (s *Session) Logout() error                                  { return nil }

func main() {
	s := smtp.NewServer(&Backend{})
	s.Addr = ":1025"
	s.Domain = "localhost"
	s.AllowInsecureAuth = true // For local testing

	fmt.Println("Listening for SASL/OAuth2 SMTP on :1025...")
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

```

### Recommendation

* **Standard SASL (`PLAIN`/`LOGIN`):** Run Mailpit with `MP_SMTP_AUTH_ALLOW_INSECURE=true` and `MP_SMTP_AUTH_ACCEPT_ANY=true`.
* **Real OAuth2 (`XOAUTH2`/`OAUTHBEARER`):** Use **`docker-mailserver`**.
* **Fast In-Memory Go Tests:** Compile the `emersion/go-smtp` snippet above into a minimal Docker image.

---

To provide TLS certificates to Mailpit, you pass the cert and private key files into the container using **Docker volume mounts** and point to them using environment variables.

---

### Step 1: Generate Self-Signed Certificates (Local Testing)

If you don't already have certificates for your local test environment, generate a quick keypair using `openssl`:

```bash
mkdir -p certs

openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 \
  -subj "/CN=localhost"

```

---

### Step 2: Run Mailpit with TLS Enabled

Mount the `./certs` folder into the container (e.g., at `/certs`) and set `MP_SMTP_TLS_CERT` and `MP_SMTP_TLS_KEY`.

#### Using `docker run`:

```bash
docker run -d \
  --name mailpit \
  -p 1025:1025 \
  -p 10465:465 \
  -p 8025:8025 \
  -v $(pwd)/certs:/certs \
  -e MP_SMTP_TLS_CERT=/certs/cert.pem \
  -e MP_SMTP_TLS_KEY=/certs/key.pem \
  -e MP_SMTP_AUTH_ACCEPT_ANY=true \
  axllent/mailpit:latest

```

#### Using `docker-compose.yml`:

```yaml
version: '3.8'

services:
  mailpit:
    image: axllent/mailpit:latest
    container_name: mailpit
    ports:
      - "1025:1025"   # Standard / STARTTLS SMTP
      - "10465:465"   # Implicit TLS / SMTPS
      - "8025:8025"   # Web UI
    environment:
      MP_SMTP_TLS_CERT: /certs/cert.pem
      MP_SMTP_TLS_KEY: /certs/key.pem
      MP_SMTP_AUTH_ACCEPT_ANY: "true"
    volumes:
      - ./certs:/certs

```

---

### Key Environment Variables to Control TLS Behavior

Depending on how strictly you want to torture-test your Go client, configure Mailpit's TLS behavior with these flags:

| Environment Variable | Default | Purpose |
| --- | --- | --- |
| `MP_SMTP_TLS_CERT` | *None* | Path to the TLS certificate file. Enabling this turns on `STARTTLS` on port `1025`. |
| `MP_SMTP_TLS_KEY` | *None* | Path to the TLS private key file. |
| `MP_SMTP_REQUIRE_STARTTLS` | `false` | Set to `true` to force the client to execute `STARTTLS` before allowing commands like `AUTH` or `MAIL FROM`. |
| `MP_SMTP_ALLOW_INSECURE_AUTH` | `false` | Set to `false` (default) to enforce that `AUTH` is only accepted over encrypted TLS connections. |

> **Go Client Note:** Because self-signed certificates will fail standard Go `tls.Config` verification, ensure your Go client either includes the self-signed cert in its `RootCAs` pool or sets `InsecureSkipVerify: true` during local test setup.
