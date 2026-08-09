// Package mailxgo - Configuration Engine Unit Tests
//
// OBJECTIVES:
// Validate resolution of pre-configured mail provider presets and JSON configuration file decoding from disk.
//
// CORE COMPONENTS:
// - TestResolveProviderPreset: Table-driven test evaluating provider preset alias resolution (office365, GMAIL, aws-ses, protonmail, unknown).
// - TestLoadConfig: File-driven test evaluating valid JSON unmarshaling, corrupt JSON error handling, and missing file error handling.
//
// FUNCTIONALITY & DATA FLOW:
// Test Inputs -> ResolveProviderPreset / LoadConfig -> Assert returned struct fields and error conditions.
//
// TEST STRATEGY:
// Isolated unit tests using t.TempDir() for hermetic JSON file creation without external side effects.
package mailxgo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveProviderPreset(t *testing.T) {
	tests := []struct {
		input        string
		expectedOK   bool
		expectedHost string
		expectedPort int
	}{
		{"office365", true, "smtp.office365.com", 587},
		{"GMAIL", true, "smtp.gmail.com", 587},
		{"  aws-ses  ", true, "email-smtp.us-east-1.amazonaws.com", 587},
		{"protonmail", true, "127.0.0.1", 1025},
		{"unknown-provider", false, "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			preset, ok := ResolveProviderPreset(tt.input)
			if ok != tt.expectedOK {
				t.Errorf("ResolveProviderPreset(%q) ok = %v, want %v", tt.input, ok, tt.expectedOK)
			}
			if ok {
				if preset.Host != tt.expectedHost {
					t.Errorf("ResolveProviderPreset(%q).Host = %q, want %q", tt.input, preset.Host, tt.expectedHost)
				}
				if preset.Port != tt.expectedPort {
					t.Errorf("ResolveProviderPreset(%q).Port = %d, want %d", tt.input, preset.Port, tt.expectedPort)
				}
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")

	validJSON := `{
		"smtp_server": "smtp.example.com",
		"smtp_port": 587,
		"smtp_username": "user",
		"smtp_password": "pass",
		"from_name": "Test Sender",
		"from_email": "sender@example.com",
		"to_email": "recipient@example.com",
		"retries": 3,
		"timeout": 15
	}`

	if err := os.WriteFile(configFile, []byte(validJSON), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.SMTPServer != "smtp.example.com" || config.SMTPPort != 587 {
		t.Errorf("LoadConfig loaded incorrect server/port: %s:%d", config.SMTPServer, config.SMTPPort)
	}
	if config.Retries != 3 || config.Timeout != 15 {
		t.Errorf("LoadConfig loaded incorrect retries/timeout: %d, %d", config.Retries, config.Timeout)
	}

	// Invalid JSON error
	invalidFile := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(invalidFile, []byte("{invalid-json"), 0o644); err != nil {
		t.Fatalf("failed to write invalid config file: %v", err)
	}
	_, err = LoadConfig(invalidFile)
	if err == nil {
		t.Errorf("expected error loading invalid JSON config, got nil")
	}

	// Non-existent file error
	_, err = LoadConfig(filepath.Join(tmpDir, "nonexistent.json"))
	if err == nil {
		t.Errorf("expected error loading non-existent config file, got nil")
	}
}
