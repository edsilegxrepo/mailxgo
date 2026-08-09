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

	// Create actual test files (absolute paths)
	doc1 := filepath.Join(tmpDir, "doc1.pdf")
	doc2 := filepath.Join(tmpDir, "doc2.pdf")
	img := filepath.Join(tmpDir, "img.png")
	_ = os.WriteFile(doc1, []byte("pdf"), 0o644)
	_ = os.WriteFile(doc2, []byte("pdf"), 0o644)
	_ = os.WriteFile(img, []byte("png"), 0o644)

	listFile := filepath.Join(tmpDir, "attachments.txt")
	content := "# Attachments\n" + doc1 + ", " + doc2 + "\n\n" + img + "\n"
	if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to create temp attachment list file: %v", err)
	}

	files, err := LoadAttachmentList(listFile)
	if err != nil {
		t.Fatalf("LoadAttachmentList failed: %v", err)
	}

	expected := []string{doc1, doc2, img}
	if !reflect.DeepEqual(files, expected) {
		t.Errorf("LoadAttachmentList = %v, want %v", files, expected)
	}

	// Non-existent file error
	_, err = LoadAttachmentList(filepath.Join(tmpDir, "nonexistent.txt"))
	if err == nil {
		t.Errorf("expected error loading non-existent attachment list, got nil")
	}

	// Test relative path rejection
	relativeListFile := filepath.Join(tmpDir, "relative_attachments.txt")
	relativeContent := "relative/path/file.txt\n"
	if err := os.WriteFile(relativeListFile, []byte(relativeContent), 0o644); err != nil {
		t.Fatalf("failed to create relative attachment list file: %v", err)
	}
	_, err = LoadAttachmentList(relativeListFile)
	if err == nil {
		t.Errorf("expected error for relative path in attachment list, got nil")
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid email", "user@example.com", false},
		{"valid email with subdomain", "user@mail.example.com", false},
		{"valid email with plus", "user+tag@example.com", false},
		{"empty email", "", true},
		{"no at sign", "userexample.com", true},
		{"no domain", "user@", true},
		{"no local part", "@example.com", true},
		{"invalid characters", "user name@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail(%q) error = %v, wantErr %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEmailList(t *testing.T) {
	// Valid list
	err := ValidateEmailList([]string{"a@b.com", "c@d.com"})
	if err != nil {
		t.Errorf("ValidateEmailList valid list error = %v", err)
	}

	// Invalid list
	err = ValidateEmailList([]string{"a@b.com", "invalid"})
	if err == nil {
		t.Error("ValidateEmailList expected error for invalid email in list")
	}

	// Empty list
	err = ValidateEmailList([]string{})
	if err != nil {
		t.Errorf("ValidateEmailList empty list error = %v", err)
	}
}

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid absolute unix path", "/home/user/file.txt", false},
		{"valid absolute windows backslash", "C:\\Users\\file.txt", false},
		{"valid absolute windows forward slash", "D:/data/file.txt", false},
		{"valid lowercase drive letter", "c:/users/file.txt", false},
		{"relative path rejected", "file.txt", true},
		{"path traversal rejected", "../../../etc/passwd", true},
		{"relative path traversal rejected", "subdir/../../../etc/passwd", true},
		{"valid deep absolute path", "/home/user/subdir/file.txt", false},
		{"empty path rejected", "", true},
		{"relative subdir rejected", "subdir/file.txt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestDecryptSecret(t *testing.T) {
	// Test that non-encrypted secrets pass through unchanged
	plainSecret := "myplainpassword"
	result, err := DecryptSecret(plainSecret, "")
	if err != nil {
		t.Errorf("DecryptSecret plain secret error = %v", err)
	}
	if result != plainSecret {
		t.Errorf("DecryptSecret plain secret = %q, want %q", result, plainSecret)
	}

	// Test empty secret
	result, err = DecryptSecret("", "")
	if err != nil || result != "" {
		t.Errorf("DecryptSecret empty secret error = %v, result = %q", err, result)
	}

	// Test encrypted secret without master key (should error)
	encryptedSecret := "v1:gcm:someinvalidbase64data"
	_, err = DecryptSecret(encryptedSecret, "NONEXISTENT_ENV_VAR")
	if err == nil {
		t.Error("DecryptSecret expected error for encrypted secret without master key")
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
