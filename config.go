// Package mailxgo - Configuration & Provider Preset Engine
//
// OBJECTIVES:
// Define the JSON configuration file schema (Config) and provide pre-configured mail provider preset resolutions (ProviderPresets).
//
// CORE COMPONENTS:
// - ProviderPreset: Map entry struct for mail provider presets (Host, Port, TLSMode).
// - ProviderPresets: Pre-configured lookup table for enterprise (office365, aws-ses, sendgrid) and consumer (gmail, outlook, yahoo) mail providers.
// - ResolveProviderPreset: Lookup function performing case-insensitive provider preset matching.
// - Config: Complete JSON configuration file unmarshaling struct.
// - LoadConfig: Stream-decoding function loading JSON config files from disk.
//
// FUNCTIONALITY & DATA FLOW:
// Config File Path -> os.Open -> json.NewDecoder -> Config struct -> Merged with CLI arguments in cli.go via priority evaluation.
package mailxgo

import (
	"encoding/json"
	"os"
	"strings"
)

// ProviderPreset holds standard configuration presets for common mail servers.
// Core Components: Host address, default SMTP port, and TLS transport policy.
type ProviderPreset struct {
	Host    string
	Port    int
	TLSMode string
}

// ProviderPresets holds pre-configured settings for enterprise and consumer mail services.
// Objectives: Allow rapid configuration via simple preset aliases (--use office365|googleworkspace|aws-ses|gmail|outlook).
var ProviderPresets = map[string]ProviderPreset{
	// Corporate / Enterprise Presets
	"office365":         {Host: "smtp.office365.com", Port: 587, TLSMode: "tls"},
	"m365":              {Host: "smtp.office365.com", Port: 587, TLSMode: "tls"},
	"o365":              {Host: "smtp.office365.com", Port: 587, TLSMode: "tls"},
	"googleworkspace":   {Host: "smtp.gmail.com", Port: 587, TLSMode: "tls"},
	"gsuite":            {Host: "smtp.gmail.com", Port: 587, TLSMode: "tls"},
	"aws-ses":           {Host: "email-smtp.us-east-1.amazonaws.com", Port: 587, TLSMode: "tls"},
	"aws-ses-us-east-1": {Host: "email-smtp.us-east-1.amazonaws.com", Port: 587, TLSMode: "tls"},
	"aws-ses-us-west-2": {Host: "email-smtp.us-west-2.amazonaws.com", Port: 587, TLSMode: "tls"},
	"aws-ses-eu-west-1": {Host: "email-smtp.eu-west-1.amazonaws.com", Port: 587, TLSMode: "tls"},
	"sendgrid":          {Host: "smtp.sendgrid.net", Port: 587, TLSMode: "tls"},
	"mailgun":           {Host: "smtp.mailgun.org", Port: 587, TLSMode: "tls"},
	"postmark":          {Host: "smtp.postmarkapp.com", Port: 587, TLSMode: "tls"},
	"fastmail":          {Host: "smtp.fastmail.com", Port: 587, TLSMode: "tls"},
	"protonmail":        {Host: "127.0.0.1", Port: 1025, TLSMode: "tls-skip"},

	// Consumer Presets
	"gmail":   {Host: "smtp.gmail.com", Port: 587, TLSMode: "tls"},
	"outlook": {Host: "smtp.office365.com", Port: 587, TLSMode: "tls"},
	"yahoo":   {Host: "smtp.mail.yahoo.com", Port: 587, TLSMode: "tls"},
	"gmx":     {Host: "mail.gmx.com", Port: 587, TLSMode: "tls"},
	"zoho":    {Host: "smtp.zoho.com", Port: 587, TLSMode: "tls"},
	"aol":     {Host: "smtp.aol.com", Port: 587, TLSMode: "tls"},
}

// ResolveProviderPreset returns the ProviderPreset for a given provider name.
// Functionality: Performs case-insensitive, whitespace-trimmed lookup in ProviderPresets map.
func ResolveProviderPreset(name string) (ProviderPreset, bool) {
	preset, ok := ProviderPresets[strings.ToLower(strings.TrimSpace(name))]
	return preset, ok
}

// Config defines the JSON configuration schema for Mail2Go.
// Data Flow: Unmarshaled from JSON files (~/.config/mailxgo/config.json or explicit -c paths).
type Config struct {
	SMTPServer        string            `json:"smtp_server"`
	SMTPPort          int               `json:"smtp_port"`
	SMTPUsername      string            `json:"smtp_username"`
	SMTPPassword      string            `json:"smtp_password"`
	NoAuth            bool              `json:"no_auth"`
	TLSMode           string            `json:"tls_mode"`
	FromName          string            `json:"from_name"`
	FromEmail         string            `json:"from_email"`
	ToEmail           string            `json:"to_email"`
	To                []string          `json:"to"`
	CC                []string          `json:"cc"`
	BCC               []string          `json:"bcc"`
	Headers           map[string]string `json:"headers"`
	InlineAttachments []string          `json:"inline_attachments"`
	LogFile           string            `json:"log_file"`
	Retries           int               `json:"retries"`
	RetryDelay        int               `json:"retry_delay"`
	Timeout           int               `json:"timeout"`
	DSNNotify         []string          `json:"dsn_notify"`
	DSNReturn         string            `json:"dsn_return"`
	Importance        string            `json:"importance"`
	JSONOutput        bool              `json:"json_output"`
	NDJSONOutput      bool              `json:"ndjson_output"`
	Info              bool              `json:"info"`
	PrintCerts        bool              `json:"print_certs"`
	Debug             bool              `json:"debug"`
	AuthType          string            `json:"auth_type"`
	OAuth2            bool              `json:"oauth2"`
	Token             string            `json:"token"`
	Use               string            `json:"use"`
	Charset           string            `json:"charset"`
	Subject           string            `json:"subject"`
	Body              string            `json:"body"`
	BodyFile          string            `json:"body_file"`
	AttachmentsList   string            `json:"attachments_list"`
	AttachmentsDir    string            `json:"attachments_dir"`
	MaxAttachmentMB   int               `json:"max_attachment_size_mb"`
}

// LoadConfig decodes a JSON configuration file from disk.
// Functionality: Stream decodes specified file path into a Config struct. Returns error if file missing or malformed JSON.
func LoadConfig(filePath string) (Config, error) {
	var config Config

	// #nosec G304
	file, err := os.Open(filePath)
	if err != nil {
		return config, err
	}
	defer func() { _ = file.Close() }()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return config, err
	}

	return config, nil
}
