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

func TestValidateFileExists(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	t.Run("valid existing file", func(t *testing.T) {
		absPath, err := ValidateFileExists(testFile)
		if err != nil {
			t.Errorf("ValidateFileExists failed: %v", err)
		}
		if absPath == "" {
			t.Error("expected non-empty absolute path")
		}
		// Should be absolute
		if !filepath.IsAbs(absPath) {
			t.Errorf("expected absolute path, got: %s", absPath)
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := ValidateFileExists(filepath.Join(tmpDir, "nonexistent.txt"))
		if err == nil {
			t.Error("expected error for non-existent file")
		}
	})

	t.Run("empty path", func(t *testing.T) {
		_, err := ValidateFileExists("")
		if err == nil {
			t.Error("expected error for empty path")
		}
	})

	t.Run("directory not file", func(t *testing.T) {
		_, err := ValidateFileExists(tmpDir)
		if err == nil {
			t.Error("expected error when path is a directory")
		}
	})

	t.Run("relative path rejected", func(t *testing.T) {
		_, err := ValidateFileExists("relative/path.txt")
		if err == nil {
			t.Error("expected error for relative path")
		}
	})
}

func TestValidateDirExists(t *testing.T) {
	tmpDir := t.TempDir()
	testSubDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(testSubDir, 0o755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	t.Run("valid existing directory", func(t *testing.T) {
		absPath, err := ValidateDirExists(testSubDir, true)
		if err != nil {
			t.Errorf("ValidateDirExists failed: %v", err)
		}
		if !filepath.IsAbs(absPath) {
			t.Errorf("expected absolute path, got: %s", absPath)
		}
	})

	t.Run("non-existent directory with mustExist", func(t *testing.T) {
		_, err := ValidateDirExists(filepath.Join(tmpDir, "nonexistent"), true)
		if err == nil {
			t.Error("expected error for non-existent directory with mustExist=true")
		}
	})

	t.Run("non-existent directory without mustExist", func(t *testing.T) {
		absPath, err := ValidateDirExists(filepath.Join(tmpDir, "newdir"), false)
		if err != nil {
			t.Errorf("ValidateDirExists with mustExist=false failed: %v", err)
		}
		if absPath == "" {
			t.Error("expected non-empty path")
		}
	})

	t.Run("file not directory", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "file.txt")
		_ = os.WriteFile(testFile, []byte("x"), 0o644)
		_, err := ValidateDirExists(testFile, true)
		if err == nil {
			t.Error("expected error when path is a file not directory")
		}
	})
}

func TestValidateOutputPath(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("new file path creates parent", func(t *testing.T) {
		newPath := filepath.Join(tmpDir, "newsubdir", "output.txt")
		absPath, err := ValidateOutputPath(newPath, false)
		if err != nil {
			t.Errorf("ValidateOutputPath failed: %v", err)
		}
		if !filepath.IsAbs(absPath) {
			t.Errorf("expected absolute path, got: %s", absPath)
		}
		// Parent dir should exist
		parentDir := filepath.Dir(absPath)
		if _, err := os.Stat(parentDir); err != nil {
			t.Errorf("parent directory should exist: %v", err)
		}
	})

	t.Run("new directory path creates it", func(t *testing.T) {
		newDir := filepath.Join(tmpDir, "outputdir")
		absPath, err := ValidateOutputPath(newDir, true)
		if err != nil {
			t.Errorf("ValidateOutputPath failed: %v", err)
		}
		if _, err := os.Stat(absPath); err != nil {
			t.Errorf("directory should exist: %v", err)
		}
	})

	t.Run("empty path rejected", func(t *testing.T) {
		_, err := ValidateOutputPath("", false)
		if err == nil {
			t.Error("expected error for empty path")
		}
	})

	t.Run("relative path rejected", func(t *testing.T) {
		_, err := ValidateOutputPath("relative/output.txt", false)
		if err == nil {
			t.Error("expected error for relative path")
		}
	})
}

func TestLoadRecipientListJSON(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("simple string array", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "recipients_simple.json")
		content := `["alice@example.com", "bob@example.com", "charlie@example.com"]`
		if err := os.WriteFile(jsonFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		recipients, vars, err := LoadRecipientListJSON(jsonFile)
		if err != nil {
			t.Fatalf("LoadRecipientListJSON failed: %v", err)
		}
		if vars != nil {
			t.Error("expected nil vars for simple array")
		}
		if len(recipients) != 3 {
			t.Errorf("expected 3 recipients, got %d", len(recipients))
		}
		expected := []string{"alice@example.com", "bob@example.com", "charlie@example.com"}
		if !reflect.DeepEqual(recipients, expected) {
			t.Errorf("expected %v, got %v", expected, recipients)
		}
	})

	t.Run("object array with vars", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "recipients_objects.json")
		content := `[
			{"email": "alice@example.com", "vars": {"name": "Alice", "order": "12345"}},
			{"email": "bob@example.com", "vars": {"name": "Bob", "order": "67890"}}
		]`
		if err := os.WriteFile(jsonFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		recipients, vars, err := LoadRecipientListJSON(jsonFile)
		if err != nil {
			t.Fatalf("LoadRecipientListJSON failed: %v", err)
		}
		if len(recipients) != 2 {
			t.Errorf("expected 2 recipients, got %d", len(recipients))
		}
		if len(vars) != 2 {
			t.Errorf("expected 2 var maps, got %d", len(vars))
		}
		if vars[0]["name"] != "Alice" || vars[0]["order"] != "12345" {
			t.Errorf("unexpected vars for alice: %v", vars[0])
		}
		if vars[1]["name"] != "Bob" || vars[1]["order"] != "67890" {
			t.Errorf("unexpected vars for bob: %v", vars[1])
		}
	})

	t.Run("empty array", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "recipients_empty.json")
		if err := os.WriteFile(jsonFile, []byte(`[]`), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		recipients, _, err := LoadRecipientListJSON(jsonFile)
		if err != nil {
			t.Fatalf("LoadRecipientListJSON failed: %v", err)
		}
		if len(recipients) != 0 {
			t.Errorf("expected 0 recipients, got %d", len(recipients))
		}
	})

	t.Run("invalid email in array", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "recipients_invalid.json")
		content := `["valid@example.com", "invalid-email"]`
		if err := os.WriteFile(jsonFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, _, err := LoadRecipientListJSON(jsonFile)
		if err == nil {
			t.Error("expected error for invalid email")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "recipients_malformed.json")
		content := `{"not": "an array"}`
		if err := os.WriteFile(jsonFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, _, err := LoadRecipientListJSON(jsonFile)
		if err == nil {
			t.Error("expected error for non-array JSON")
		}
	})

	t.Run("missing email field", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "recipients_missing_email.json")
		content := `[{"vars": {"name": "Alice"}}]`
		if err := os.WriteFile(jsonFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, _, err := LoadRecipientListJSON(jsonFile)
		if err == nil {
			t.Error("expected error for missing email field")
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, _, err := LoadRecipientListJSON(filepath.Join(tmpDir, "nonexistent.json"))
		if err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("whitespace trimming", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "recipients_whitespace.json")
		content := `["  alice@example.com  ", "bob@example.com"]`
		if err := os.WriteFile(jsonFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		recipients, _, err := LoadRecipientListJSON(jsonFile)
		if err != nil {
			t.Fatalf("LoadRecipientListJSON failed: %v", err)
		}
		if recipients[0] != "alice@example.com" {
			t.Errorf("expected trimmed email, got %q", recipients[0])
		}
	})
}

func TestLoadAttachmentListJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test attachment files
	att1 := filepath.Join(tmpDir, "file1.txt")
	att2 := filepath.Join(tmpDir, "file2.pdf")
	if err := os.WriteFile(att1, []byte("content1"), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.WriteFile(att2, []byte("content2"), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	t.Run("valid attachment array", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "attachments.json")
		// Use filepath.ToSlash for JSON compatibility on Windows
		content := `["` + filepath.ToSlash(att1) + `", "` + filepath.ToSlash(att2) + `"]`
		if err := os.WriteFile(jsonFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		files, err := LoadAttachmentListJSON(jsonFile)
		if err != nil {
			t.Fatalf("LoadAttachmentListJSON failed: %v", err)
		}
		if len(files) != 2 {
			t.Errorf("expected 2 files, got %d", len(files))
		}
	})

	t.Run("empty array", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "attachments_empty.json")
		if err := os.WriteFile(jsonFile, []byte(`[]`), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		files, err := LoadAttachmentListJSON(jsonFile)
		if err != nil {
			t.Fatalf("LoadAttachmentListJSON failed: %v", err)
		}
		if len(files) != 0 {
			t.Errorf("expected 0 files, got %d", len(files))
		}
	})

	t.Run("invalid path (relative)", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "attachments_relative.json")
		content := `["relative/path.txt"]`
		if err := os.WriteFile(jsonFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, err := LoadAttachmentListJSON(jsonFile)
		if err == nil {
			t.Error("expected error for relative path")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "attachments_malformed.json")
		content := `not json`
		if err := os.WriteFile(jsonFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, err := LoadAttachmentListJSON(jsonFile)
		if err == nil {
			t.Error("expected error for malformed JSON")
		}
	})

	t.Run("skip empty strings", func(t *testing.T) {
		jsonFile := filepath.Join(tmpDir, "attachments_empty_strings.json")
		content := `["` + filepath.ToSlash(att1) + `", "", "  ", "` + filepath.ToSlash(att2) + `"]`
		if err := os.WriteFile(jsonFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		files, err := LoadAttachmentListJSON(jsonFile)
		if err != nil {
			t.Fatalf("LoadAttachmentListJSON failed: %v", err)
		}
		if len(files) != 2 {
			t.Errorf("expected 2 files (empty strings skipped), got %d", len(files))
		}
	})
}

func TestLoadList(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("text format recipients", func(t *testing.T) {
		listFile := filepath.Join(tmpDir, "recipients.txt")
		content := "alice@example.com\nbob@example.com\n# comment\n"
		if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		recipients, vars, err := LoadList(listFile, "text", true)
		if err != nil {
			t.Fatalf("LoadList failed: %v", err)
		}
		if vars != nil {
			t.Error("expected nil vars for text format")
		}
		if len(recipients) != 2 {
			t.Errorf("expected 2 recipients, got %d", len(recipients))
		}
	})

	t.Run("json format recipients", func(t *testing.T) {
		listFile := filepath.Join(tmpDir, "recipients.json")
		content := `["alice@example.com", "bob@example.com"]`
		if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		recipients, _, err := LoadList(listFile, "json", true)
		if err != nil {
			t.Fatalf("LoadList failed: %v", err)
		}
		if len(recipients) != 2 {
			t.Errorf("expected 2 recipients, got %d", len(recipients))
		}
	})

	t.Run("default format is text", func(t *testing.T) {
		listFile := filepath.Join(tmpDir, "recipients_default.txt")
		content := "alice@example.com\n"
		if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		recipients, _, err := LoadList(listFile, "", true)
		if err != nil {
			t.Fatalf("LoadList with empty format failed: %v", err)
		}
		if len(recipients) != 1 {
			t.Errorf("expected 1 recipient, got %d", len(recipients))
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		listFile := filepath.Join(tmpDir, "recipients_any.txt")
		if err := os.WriteFile(listFile, []byte("test@example.com"), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, _, err := LoadList(listFile, "csv", true)
		if err == nil {
			t.Error("expected error for unsupported format")
		}
	})

	t.Run("text format attachments", func(t *testing.T) {
		att := filepath.Join(tmpDir, "att.txt")
		if err := os.WriteFile(att, []byte("content"), 0o644); err != nil {
			t.Fatalf("failed to create attachment: %v", err)
		}

		listFile := filepath.Join(tmpDir, "attachments.txt")
		content := att + "\n"
		if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		files, vars, err := LoadList(listFile, "text", false)
		if err != nil {
			t.Fatalf("LoadList failed: %v", err)
		}
		if vars != nil {
			t.Error("expected nil vars for attachments")
		}
		if len(files) != 1 {
			t.Errorf("expected 1 file, got %d", len(files))
		}
	})

	t.Run("json format attachments", func(t *testing.T) {
		att := filepath.Join(tmpDir, "att2.txt")
		if err := os.WriteFile(att, []byte("content"), 0o644); err != nil {
			t.Fatalf("failed to create attachment: %v", err)
		}

		listFile := filepath.Join(tmpDir, "attachments2.json")
		content := `["` + filepath.ToSlash(att) + `"]`
		if err := os.WriteFile(listFile, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		files, _, err := LoadList(listFile, "json", false)
		if err != nil {
			t.Fatalf("LoadList failed: %v", err)
		}
		if len(files) != 1 {
			t.Errorf("expected 1 file, got %d", len(files))
		}
	})
}
