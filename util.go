package mailxgo

import (
	"os"
	"path/filepath"
	"strings"
)

// CleanEmailList trims whitespace from email addresses and removes empty elements.
func CleanEmailList(emails []string) []string {
	var cleaned []string
	for _, email := range emails {
		trimmed := strings.TrimSpace(email)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return cleaned
}

// LoadRecipientList reads a text file containing email addresses (one per line or comma-separated).
func LoadRecipientList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var recipients []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, addr := range strings.Split(line, ",") {
			addr = strings.TrimSpace(addr)
			if addr != "" && !strings.HasPrefix(addr, "#") {
				recipients = append(recipients, addr)
			}
		}
	}
	return recipients, nil
}

// LoadAttachmentList reads a text file containing attachment file paths (one per line).
func LoadAttachmentList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var files []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, item := range strings.Split(line, ",") {
			item = strings.TrimSpace(item)
			if item != "" && !strings.HasPrefix(item, "#") {
				files = append(files, item)
			}
		}
	}
	return files, nil
}

// ScanAttachmentDir scans a directory and returns full file paths for all regular non-directory files.
func ScanAttachmentDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	return files, nil
}
