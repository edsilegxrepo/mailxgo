# OAuth2 Mock SMTP Server for mailxgo Integration Testing
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o oauth2-smtp-mock .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/oauth2-smtp-mock .

ENV SMTP_ADDR=:1025
ENV VALID_TOKEN_PREFIX=

EXPOSE 1025

CMD ["./oauth2-smtp-mock"]
