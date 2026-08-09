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
	"os"
	"path/filepath"
	"strings"
)

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
func LoadAttachmentList(path string) ([]string, error) {
	// #nosec G304
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var files []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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
