package filesystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huydinhtrong/secretguard/internal/detector"
)

func projectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("project root not found")
		}
		dir = parent
	}
}

func testdataPath(t *testing.T, subpath string) string {
	t.Helper()
	return filepath.Join(projectRoot(), "testdata", "secrets", subpath)
}

func newTestDetector(t *testing.T, allowlistPaths []string) *detector.Detector {
	t.Helper()
	al, err := detector.NewAllowlist(allowlistPaths, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return detector.New(detector.BuiltinRules, al)
}

func TestScanner_FindsSecretsInEnvFile(t *testing.T) {
	s := New(newTestDetector(t, nil))
	findings, err := s.Scan(testdataPath(t, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings in .env file")
	}
}

func TestScanner_FindsSecretsInJSONFile(t *testing.T) {
	s := New(newTestDetector(t, nil))
	findings, err := s.Scan(testdataPath(t, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings in config.json")
	}
}

func TestScanner_FindsSecretsInMDFile(t *testing.T) {
	s := New(newTestDetector(t, nil))
	findings, err := s.Scan(testdataPath(t, "readme.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings in readme.md")
	}
}

func TestScanner_FindsSecretsInSourceFile(t *testing.T) {
	s := New(newTestDetector(t, nil))
	findings, err := s.Scan(testdataPath(t, "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings in main.go")
	}
}

func TestScanner_ReturnsLineNumbers(t *testing.T) {
	s := New(newTestDetector(t, nil))
	findings, err := s.Scan(testdataPath(t, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Location.Line == 0 {
			t.Errorf("finding %s has no line number", f.ID)
		}
		if f.Location.Column == 0 {
			t.Errorf("finding %s has no column number", f.ID)
		}
	}
}

func TestScanner_SkipsBinaryFiles(t *testing.T) {
	s := New(newTestDetector(t, nil))
	findings, err := s.Scan(testdataPath(t, "logo.png"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in binary file, got %d", len(findings))
	}
}

func TestScanner_SkipsIgnoredDirectories(t *testing.T) {
	ignoredPath := testdataPath(t, "node_modules")
	err := os.MkdirAll(ignoredPath, 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(ignoredPath, "leak.txt"),
		[]byte("sk-test_abcdefghijklmnopqrstuvwxyz123456"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(ignoredPath) }()

	s := New(newTestDetector(t, nil))
	findings, err := s.Scan(testdataPath(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if strings.Contains(f.Location.Path, "node_modules") {
			t.Errorf("found secret in ignored directory: %s", f.Location.Path)
		}
	}
}

func TestScanner_RespectsMaxFileSize(t *testing.T) {
	s := New(newTestDetector(t, nil), WithMaxFileSize(1))
	findings, err := s.Scan(testdataPath(t, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings with 1-byte max file size, got %d", len(findings))
	}
}

func TestScanner_ScanRecursively(t *testing.T) {
	s := New(newTestDetector(t, nil))
	findings, err := s.Scan(testdataPath(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings in recursive scan")
	}
}

func TestScanner_NoFullSecretInFindings(t *testing.T) {
	s := New(newTestDetector(t, nil))
	findings, err := s.Scan(testdataPath(t, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if strings.Contains(f.Preview, "sk-test_") && strings.Contains(f.Preview, "abcdefghijklmn") {
			t.Errorf("finding %s contains full secret in preview: %s", f.ID, f.Preview)
		}
	}
}

func TestScanner_RespectsAllowlistedPathsViaDetector(t *testing.T) {
	allowlistPath := filepath.Join(testdataPath(t, "allowlisted_dir"), "**")
	al, err := detector.NewAllowlist([]string{allowlistPath}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	det := detector.New(detector.BuiltinRules, al)
	s := New(det)
	findings, err := s.Scan(testdataPath(t, "allowlisted_dir"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in allowlisted path, got %d", len(findings))
	}
}

func TestScanner_HandlesNonexistentPath(t *testing.T) {
	s := New(newTestDetector(t, nil))
	_, err := s.Scan(testdataPath(t, "nonexistent"))
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestScanner_BinaryDetectionByContent(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"null byte at start", []byte{0x00, 'A', 'B', 'C'}, true},
		{"null byte mid", []byte{'h', 'e', 'l', 'l', 'o', 0x00, 'w'}, true},
		{"plain text", []byte("hello world\nthis is text\n"), false},
		{"empty", []byte{}, false},
		{"null byte at 511", func() []byte {
			b := make([]byte, 512)
			b[511] = 0x00
			return b
		}(), true},
		{"no null byte large", func() []byte {
			b := make([]byte, 1024)
			for i := range b {
				b[i] = 'A'
			}
			return b
		}(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBinary(tt.data)
			if got != tt.want {
				t.Errorf("isBinary(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
