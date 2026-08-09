// Package mailxgo - Utility Engine Unit Tests
//
// OBJECTIVES:
// Validate recipient list parsing, attachment list parsing, string slice cleaning, CRLF/LF line trimming, comment filtering, and directory file scanning.
//
// CORE COMPONENTS:
// - TestCleanEmailList: Table-driven test evaluating whitespace trimming and empty element removal.
// - TestLoadRecipientList: File-driven test evaluating streamed recipient list file parsing, line trimming, and comment skipping.
// - TestLoadAttachmentList: File-driven test evaluating streamed attachment list file parsing, line trimming, and comment skipping.
// - TestScanAttachmentDir: Directory-driven test evaluating directory entry scanning and regular file path collection.
//
// FUNCTIONALITY & DATA FLOW:
// Test Files/Directories -> Util Functions -> Assert returned slice contents and error conditions.
//
// TEST STRATEGY:
// Hermetic file I/O unit tests creating temporary files and subdirectories via t.TempDir().
package mailxgo

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCleanEmailList(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty elements and whitespace",
			input:    []string{"  user1@example.com  ", "", "  ", "user2@example.com"},
			expected: []string{"user1@example.com", "user2@example.com"},
		},
		{
			name:     "clean list already",
			input:    []string{"a@b.com", "c@d.com"},
			expected: []string{"a@b.com", "c@d.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CleanEmailList(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("CleanEmailList(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestLoadRecipientList(t *testing.T) {
	tmpDir := t.TempDir()
	listFile := filepath.Join(tmpDir, "recipients.txt")

	content := "# Comment line\nuser1@example.com, user2@example.com\n\n# Another comment\nuser3@example.com\n"
	if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to create temp recipient file: %v", err)
	}

	recipients, err := LoadRecipientList(listFile)
	if err != nil {
		t.Fatalf("LoadRecipientList failed: %v", err)
	}

	expected := []string{"user1@example.com", "user2@example.com", "user3@example.com"}
	if !reflect.DeepEqual(recipients, expected) {
		t.Errorf("LoadRecipientList = %v, want %v", recipients, expected)
	}

	// Non-existent file error
	_, err = LoadRecipientList(filepath.Join(tmpDir, "nonexistent.txt"))
	if err == nil {
		t.Errorf("expected error loading non-existent recipient file, got nil")
	}
}

func TestLoadAttachmentList(t *testing.T) {
	tmpDir := t.TempDir()
	listFile := filepath.Join(tmpDir, "attachments.txt")

	content := "# Attachments\n/path/to/doc1.pdf, /path/to/doc2.pdf\n\n/path/to/img.png\n"
	if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to create temp attachment list file: %v", err)
	}

	files, err := LoadAttachmentList(listFile)
	if err != nil {
		t.Fatalf("LoadAttachmentList failed: %v", err)
	}

	expected := []string{"/path/to/doc1.pdf", "/path/to/doc2.pdf", "/path/to/img.png"}
	if !reflect.DeepEqual(files, expected) {
		t.Errorf("LoadAttachmentList = %v, want %v", files, expected)
	}

	// Non-existent file error
	_, err = LoadAttachmentList(filepath.Join(tmpDir, "nonexistent.txt"))
	if err == nil {
		t.Errorf("expected error loading non-existent attachment list, got nil")
	}
}

func TestScanAttachmentDir(t *testing.T) {
	tmpDir := t.TempDir()

	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.pdf")
	subDir := filepath.Join(tmpDir, "subDir")

	if err := os.WriteFile(file1, []byte("data1"), 0o644); err != nil {
		t.Fatalf("failed to create temp file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte("data2"), 0o644); err != nil {
		t.Fatalf("failed to create temp file2: %v", err)
	}
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatalf("failed to create subDir: %v", err)
	}

	files, err := ScanAttachmentDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanAttachmentDir failed: %v", err)
	}

	if len(files) != 2 {
		t.Errorf("expected 2 files scanned, got %d: %v", len(files), files)
	}

	// Non-existent directory error
	_, err = ScanAttachmentDir(filepath.Join(tmpDir, "nonexistent_dir"))
	if err == nil {
		t.Errorf("expected error scanning non-existent directory, got nil")
	}
}
