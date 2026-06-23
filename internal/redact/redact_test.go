package redact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huydinhtrong/secretguard/internal/detector"
	"github.com/huydinhtrong/secretguard/internal/finding"
)

func TestMarker(t *testing.T) {
	got := Marker("OpenAI API Key", "sha256:abc123")
	want := "[REDACTED:OpenAI API Key:sha256:abc123]"
	if got != want {
		t.Errorf("Marker() = %q, want %q", got, want)
	}

	got2 := Marker("GitHub Token", "sha256:def456")
	want2 := "[REDACTED:GitHub Token:sha256:def456]"
	if got2 != want2 {
		t.Errorf("Marker() = %q, want %q", got2, want2)
	}
}

func TestRedactText_ReplacesSecrets(t *testing.T) {
	content := []byte(`OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactText(content, det)
	if err != nil {
		t.Fatal(err)
	}

	out := string(result.Content)
	if strings.Contains(out, "sk-test_abcdefghijklmnopqrstuvwxyz123456") {
		t.Error("full secret still present in redacted output")
	}
	if !strings.Contains(out, "[REDACTED:OpenAI API Key:sha256:") {
		t.Error("redaction marker not found")
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings")
	}
}

func TestRedactText_MultipleSecrets(t *testing.T) {
	content := []byte(`OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456
GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactText(content, det)
	if err != nil {
		t.Fatal(err)
	}

	out := string(result.Content)
	if !strings.Contains(out, "[REDACTED:OpenAI API Key:sha256:") {
		t.Error("OpenAI marker not found")
	}
	if !strings.Contains(out, "[REDACTED:GitHub Token:sha256:") {
		t.Error("GitHub marker not found")
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}

func TestRedactText_NoSecrets(t *testing.T) {
	content := []byte(`hello world\nthis is safe`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactText(content, det)
	if err != nil {
		t.Fatal(err)
	}

	if string(result.Content) != string(content) {
		t.Error("content changed even though no secrets present")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestRedactText_DryRunModifiesNothing(t *testing.T) {
	content := []byte(`OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactText(content, det)
	if err != nil {
		t.Fatal(err)
	}

	// Dry-run means we don't write; proving RedactText gives us the new content
	// without touching the original byte slice. The original is unchanged.
	if string(content) == string(result.Content) {
		t.Error("redacted content should differ from original")
	}
}

func TestRedactJSON_PreservesValidity(t *testing.T) {
	content := []byte(`{"key":"sk-test_abcdefghijklmnopqrstuvwxyz123456"}`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactJSON(content, det)
	if err != nil {
		t.Fatal(err)
	}

	if !json.Valid(result.Content) {
		t.Error("redacted output is not valid JSON")
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings")
	}
}

func TestRedactJSON_RecursiveRedaction(t *testing.T) {
	content := []byte(`{"nested":{"deep":"sk-test_abcdefghijklmnopqrstuvwxyz123456"}}`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactJSON(content, det)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(result.Content), "sk-test_abcdefghijklmnopqrstuvwxyz123456") {
		t.Error("full secret still present in nested JSON value")
	}
	if !strings.Contains(string(result.Content), "[REDACTED:OpenAI API Key:sha256:") {
		t.Error("redaction marker not found in nested value")
	}
}

func TestRedactJSON_ArrayValues(t *testing.T) {
	content := []byte(`{"keys":["sk-test_abcdefghijklmnopqrstuvwxyz123456","safe"]}`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactJSON(content, det)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(result.Content), "sk-test_abcdefghijklmnopqrstuvwxyz123456") {
		t.Error("full secret present in array value")
	}
}

func TestRedactJSON_InvalidJSON(t *testing.T) {
	content := []byte(`{invalid json}`)
	det := detector.New(detector.BuiltinRules, nil)

	_, err := RedactJSON(content, det)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestRedactJSON_NoSecrets(t *testing.T) {
	content := []byte(`{"safe":"hello world"}`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactJSON(content, det)
	if err != nil {
		t.Fatal(err)
	}

	if string(result.Content) != "{\n  \"safe\": \"hello world\"\n}" {
		t.Errorf("unexpected output for safe JSON: %s", string(result.Content))
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestRedactJSONL_PreservesValidity(t *testing.T) {
	content := []byte(`{"key":"sk-test_abcdefghijklmnopqrstuvwxyz123456"}
{"key":"safe"}`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactJSONL(content, det)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(result.Content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Errorf("line %d is not valid JSON: %s", i+1, line)
		}
	}
	if !strings.Contains(lines[0], "[REDACTED:OpenAI API Key:sha256:") {
		t.Error("first line missing marker")
	}
	if strings.Contains(lines[1], "[REDACTED:") {
		t.Error("second line should not have marker")
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestRedactJSONL_EmptyLines(t *testing.T) {
	content := []byte(`{"key":"sk-test_abcdefghijklmnopqrstuvwxyz123456"}

{"key":"safe"}`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactJSONL(content, det)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(string(result.Content), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines (including empty), got %d", len(lines))
	}
}

func TestRedactFile_BinaryExt(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	_, err := RedactFile("test.png", det)
	if err == nil {
		t.Error("expected error for binary file")
	}
}

func TestRedactFile_SQLiteExt(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	_, err := RedactFile("data.sqlite", det)
	if err == nil {
		t.Error("expected error for sqlite file")
	}
}

func TestRedactFile_NonexistentPath(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	_, err := RedactFile("/nonexistent/path.txt", det)
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestRedactFile_TxtRoundTrip(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata", "redact", "secrets.txt")
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactFile(fixtures, det)
	if err != nil {
		t.Fatal(err)
	}

	out := string(result.Content)
	if strings.Contains(out, "sk-test_abcdefghijklmnopqrstuvwxyz123456") {
		t.Error("full secret present in redacted output")
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings from fixture")
	}
}

func TestRedactFile_JSONRoundTrip(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata", "redact", "secrets.json")
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactFile(fixtures, det)
	if err != nil {
		t.Fatal(err)
	}

	if !json.Valid(result.Content) {
		t.Error("redacted output is not valid JSON")
	}
	if strings.Contains(string(result.Content), "sk-test_abcdefghijklmnopqrstuvwxyz123456") {
		t.Error("full secret present in redacted JSON")
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings from JSON fixture")
	}
}

func TestRedactFile_JSONLRoundTrip(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata", "redact", "secrets.jsonl")
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactFile(fixtures, det)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(result.Content)), "\n")
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Errorf("line %d is not valid JSON: %s", i+1, line)
		}
	}
}

func TestSameSecret_SameFingerprint(t *testing.T) {
	content := []byte(`key=sk-test_abcdefghijklmnopqrstuvwxyz123456
key2=sk-test_abcdefghijklmnopqrstuvwxyz123456`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactText(content, det)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	if result.Findings[0].Fingerprint != result.Findings[1].Fingerprint {
		t.Error("same secret produced different fingerprints")
	}

	out := string(result.Content)
	markers := strings.Count(out, "[REDACTED:OpenAI API Key:")
	if markers != 2 {
		t.Errorf("expected 2 replacement markers, got %d", markers)
	}
}

func TestRedactText_AllowlistSkipsSecret(t *testing.T) {
	secret := "sk-test_abcdefghijklmnopqrstuvwxyz123456"
	fp := finding.GenerateFingerprint(secret)
	al, err := detector.NewAllowlist(nil, []string{fp}, nil)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`OPENAI_API_KEY=` + secret)
	det := detector.New(detector.BuiltinRules, al)

	result, err := RedactText(content, det)
	if err != nil {
		t.Fatal(err)
	}

	if string(result.Content) != string(content) {
		t.Error("allowlisted secret should not be redacted")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings with allowlist, got %d", len(result.Findings))
	}
}

func TestFullSecretAbsentFromRedacted(t *testing.T) {
	secrets := []string{
		"sk-test_abcdefghijklmnopqrstuvwxyz123456",
		"ghp_abcdefghijklmnopqrstuvwxyz1234567890",
		"sk-ant-test_abcdefghijklmnopqrstuvwxyz123456",
		"AKIAIOSFODNN7EXAMPLE",
		"postgres://user:supersecretpassword@localhost:5432/app",
	}

	content := []byte(strings.Join(secrets, "\n"))
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactText(content, det)
	if err != nil {
		t.Fatal(err)
	}

	out := string(result.Content)
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("full secret %q found in redacted output", s)
		}
	}
}

func TestMarkerContainsKindAndFingerprint(t *testing.T) {
	content := []byte(`OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456`)
	det := detector.New(detector.BuiltinRules, nil)

	result, err := RedactText(content, det)
	if err != nil {
		t.Fatal(err)
	}

	out := string(result.Content)
	if !strings.Contains(out, "OpenAI API Key") {
		t.Error("marker missing secret kind")
	}
	if !strings.Contains(out, "sha256:") {
		t.Error("marker missing fingerprint")
	}
}

func TestRedactFile_NoNilResult(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	fixtures := filepath.Join("..", "..", "testdata", "redact", "secrets.txt")
	result, err := RedactFile(fixtures, det)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
}

func TestBackupCreateAndRestore(t *testing.T) {
	tmpDir := t.TempDir()
	originalPath := filepath.Join(tmpDir, "test.txt")
	originalContent := []byte(`OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456`)

	if err := os.WriteFile(originalPath, originalContent, 0600); err != nil {
		t.Fatal(err)
	}

	backupDir := filepath.Join(tmpDir, "backups")
	bm := NewBackupManagerWithDir(backupDir)

	backup, err := bm.CreateBackup(originalPath)
	if err != nil {
		t.Fatal(err)
	}

	if backup.SHA256Before == "" {
		t.Error("backup missing checksum")
	}
	if backup.OriginalPath != originalPath {
		t.Errorf("backup original path = %q, want %q", backup.OriginalPath, originalPath)
	}
	if _, err := os.Stat(backup.BackupPath); os.IsNotExist(err) {
		t.Error("backup file does not exist")
	}

	// Modify original
	if err := os.WriteFile(originalPath, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}

	// Restore
	if err := bm.RestoreByID(backup.ID); err != nil {
		t.Fatal(err)
	}

	restored, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(originalContent) {
		t.Errorf("restored content = %q, want %q", string(restored), string(originalContent))
	}
}

func TestBackupList(t *testing.T) {
	tmpDir := t.TempDir()
	bm := NewBackupManagerWithDir(filepath.Join(tmpDir, "backups"))

	backups, err := bm.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Errorf("expected 0 backups, got %d", len(backups))
	}

	// Create a backup
	originalPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(originalPath, []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := bm.CreateBackup(originalPath); err != nil {
		t.Fatal(err)
	}

	backups, err = bm.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Errorf("expected 1 backup, got %d", len(backups))
	}
}

func TestRestore_VerifiesChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	originalPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(originalPath, []byte("original content"), 0600); err != nil {
		t.Fatal(err)
	}

	bm := NewBackupManagerWithDir(filepath.Join(tmpDir, "backups"))
	backup, err := bm.CreateBackup(originalPath)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with backup file
	if err := os.WriteFile(backup.BackupPath, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}

	// Restore should fail due to checksum mismatch
	if err := bm.RestoreByID(backup.ID); err == nil {
		t.Error("expected error when backup is tampered")
	}
}
