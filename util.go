// Package mailxgo - Utility & File I/O Engine
//
// OBJECTIVES:
// Provide cross-platform streaming file parsers, directory scanners, and string slice normalization helpers.
//
// CORE COMPONENTS:
// - CleanEmailList: Normalizes email address slices by trimming whitespace and removing empty entries.
// - LoadRecipientList: Stream-parses recipient email address text files with CRLF/LF line normalization and comment filtering.
// - LoadAttachmentList: Stream-parses attachment file path text files with CRLF/LF line normalization and comment filtering.
// - ScanAttachmentDir: Scans directories and returns full file paths for all regular non-directory files.
//
// FUNCTIONALITY & DATA FLOW:
// Text files -> os.Open -> bufio.Scanner (buffered line reading) -> strings.TrimSpace (CRLF/LF line trimming) -> comma splitting -> validated string slice.
package mailxgo

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// emailRegex is a simplified RFC 5322 compliant email pattern.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// ValidateEmail checks if an email address has a valid format.
// Returns an error if the email address is invalid.
func ValidateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email address cannot be empty")
	}
	if len(email) > MaxEmailLength {
		return fmt.Errorf("email address exceeds maximum length of %d characters", MaxEmailLength)
	}
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email address format: %s", email)
	}
	return nil
}

// ValidateEmailList validates a slice of email addresses.
// Returns an error if any email address is invalid.
func ValidateEmailList(emails []string) error {
	for _, email := range emails {
		if err := ValidateEmail(email); err != nil {
			return err
		}
	}
	return nil
}

// ValidateFilePath checks if a file path is safe.
// Requires absolute paths only - relative paths are rejected for security.
// Accepts Windows (C:\..., D:/...) and Unix (/...) style absolute paths.
func ValidateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Check for absolute path - handle Windows and Unix styles
	isAbsolute := filepath.IsAbs(path)

	// On Windows, also accept:
	// - Unix-style absolute paths starting with /
	// - Windows paths with forward slashes (D:/path/to/file)
	if !isAbsolute {
		if len(path) > 0 && path[0] == '/' {
			isAbsolute = true
		} else if len(path) >= 2 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' {
			// Windows drive letter with colon (C: or c:) followed by / or \
			isAbsolute = true
		}
	}

	if !isAbsolute {
		return fmt.Errorf("relative path not allowed, use absolute path: %s", path)
	}

	// Clean the path to normalize it
	cleaned := filepath.Clean(path)

	// Check for path traversal attempts (shouldn't happen with absolute paths, but defense in depth)
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("path traversal detected in path: %s", path)
	}

	return nil
}

// CleanEmailList trims whitespace from email addresses and removes empty elements.
// Objectives: Normalize recipient email address slices before MIME envelope construction.
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
// Functionality: Uses bufio.Scanner for line streaming. Trims whitespace (handling Windows CRLF \r\n and Linux \n line endings), ignores empty lines and # comments.
func LoadRecipientList(path string) ([]string, error) {
	// #nosec G304
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var recipients []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return recipients, nil
}

// LoadAttachmentList reads a text file containing attachment file paths (one per line).
// Functionality: Reads file paths line-by-line using bufio.Scanner, trimming trailing \r\n line endings and skipping comment lines starting with #.
// Security: Validates each path to prevent path traversal attacks.
func LoadAttachmentList(path string) ([]string, error) {
	// #nosec G304
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var files []string
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, item := range strings.Split(line, ",") {
			item = strings.TrimSpace(item)
			if item != "" && !strings.HasPrefix(item, "#") {
				if err := ValidateFilePath(item); err != nil {
					return nil, fmt.Errorf("line %d: %w", lineNum, err)
				}
				files = append(files, item)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return files, nil
}

// ScanAttachmentDir scans a directory and returns full file paths for all regular non-directory files.
// Functionality: Enumerates directory entries using os.ReadDir and returns full paths for non-directory regular files.
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
