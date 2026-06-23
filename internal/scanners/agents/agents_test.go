package agents

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huydinhtrong/secretguard/internal/detector"
	"github.com/huydinhtrong/secretguard/internal/finding"
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

func testdataPath(t *testing.T, agent, name string) string {
	t.Helper()
	return filepath.Join(projectRoot(), "testdata", "agents", agent, name)
}

func newTestDetector(t *testing.T) *detector.Detector {
	t.Helper()
	al, err := detector.NewAllowlist(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return detector.New(detector.BuiltinRules, al)
}

func withWorkingDir(t *testing.T, dir string) {
	t.Helper()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCodex_ScansJSONLFixture(t *testing.T) {
	d := newTestDetector(t)
	s := CodexScanner{}

	findings, err := s.ScanPath(context.TODO(), testdataPath(t, "codex", "sessions.jsonl"), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from codex fixture")
	}
	for _, f := range findings {
		if f.Source != finding.SourceAgent {
			t.Errorf("finding %s: expected SourceAgent, got %s", f.ID, f.Source)
		}
		if f.Metadata == nil || f.Metadata["agent"] != "codex" {
			t.Errorf("finding %s: expected agent=codex in metadata", f.ID)
		}
		if f.Metadata == nil || f.Metadata["field"] != "content" {
			t.Errorf("finding %s: expected field=content in metadata, got %v", f.ID, f.Metadata)
		}
	}
}

func TestOpenCode_ScansJSONFixture(t *testing.T) {
	d := newTestDetector(t)
	s := OpenCodeScanner{}

	findings, err := s.ScanPath(context.TODO(), testdataPath(t, "opencode", "export.json"), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from opencode fixture")
	}
	for _, f := range findings {
		if f.Source != finding.SourceAgent {
			t.Errorf("finding %s: expected SourceAgent, got %s", f.ID, f.Source)
		}
		if f.Metadata == nil || f.Metadata["agent"] != "opencode" {
			t.Errorf("finding %s: expected agent=opencode in metadata", f.ID)
		}
		if f.Metadata == nil || f.Metadata["field"] != "content" {
			t.Errorf("finding %s: expected field=content in metadata, got %v", f.ID, f.Metadata)
		}
	}
}

func TestCopilot_ScansConfigJSON(t *testing.T) {
	d := newTestDetector(t)
	s := CopilotScanner{}

	findings, err := s.ScanPath(context.TODO(), testdataPath(t, "copilot", "config.json"), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from copilot fixture")
	}
	for _, f := range findings {
		if f.Source != finding.SourceAgent {
			t.Errorf("finding %s: expected SourceAgent, got %s", f.ID, f.Source)
		}
		if f.Metadata == nil || f.Metadata["agent"] != "copilot" {
			t.Errorf("finding %s: expected agent=copilot in metadata", f.ID)
		}
		if f.Metadata == nil || f.Metadata["field"] != "token" {
			t.Errorf("finding %s: expected field=token in metadata, got %v", f.ID, f.Metadata)
		}
	}
}

func TestCopilot_ScansTxtFile(t *testing.T) {
	d := newTestDetector(t)
	s := CopilotScanner{}

	findings, err := s.ScanPath(context.TODO(), testdataPath(t, "copilot", "session.txt"), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from copilot txt fixture")
	}
	for _, f := range findings {
		if f.Source != finding.SourceAgent {
			t.Errorf("finding %s: expected SourceAgent, got %s", f.ID, f.Source)
		}
		if f.Metadata == nil || f.Metadata["agent"] != "copilot" {
			t.Errorf("finding %s: expected agent=copilot in metadata", f.ID)
		}
	}
}

func TestFindings_IncludeAgentDir(t *testing.T) {
	d := newTestDetector(t)
	s := CopilotScanner{}

	findings, err := s.ScanPath(context.TODO(), testdataPath(t, "copilot", ""), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from copilot dir")
	}
	for _, f := range findings {
		if f.Source != finding.SourceAgent {
			t.Errorf("expected SourceAgent, got %s", f.Source)
		}
		if f.Metadata == nil || f.Metadata["agent"] != "copilot" {
			t.Errorf("expected agent=copilot in metadata")
		}
	}
}

func TestDiscoverPaths_MissingDefaults(t *testing.T) {
	s := CodexScanner{}
	paths, err := s.DiscoverPaths(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	_ = paths
}

func TestDiscoverPaths_DoesNotError(t *testing.T) {
	for _, s := range []AgentScanner{CodexScanner{}, OpenCodeScanner{}, CopilotScanner{}} {
		paths, err := s.DiscoverPaths(context.TODO())
		if err != nil {
			t.Errorf("%s DiscoverPaths: %v", s.Name(), err)
		}
		_ = paths
	}
}

func TestDiscoverPaths_ProjectLocalBestEffort(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	project := t.TempDir()
	withWorkingDir(t, project)

	for _, dir := range []string{".codex", ".opencode"} {
		if err := os.MkdirAll(filepath.Join(project, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name    string
		scanner AgentScanner
		want    string
	}{
		{name: "codex", scanner: CodexScanner{}, want: filepath.Join(project, ".codex")},
		{name: "opencode", scanner: OpenCodeScanner{}, want: filepath.Join(project, ".opencode")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want, err := filepath.EvalSymlinks(tc.want)
			if err != nil {
				t.Fatal(err)
			}
			paths, err := tc.scanner.DiscoverPaths(context.TODO())
			if err != nil {
				t.Fatal(err)
			}
			if len(paths) != 1 {
				t.Fatalf("expected 1 path, got %+v", paths)
			}
			got, err := filepath.EvalSymlinks(paths[0].Path)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("expected %q, got %+v", want, paths)
			}
		})
	}
}

func TestCopilotDiscoverPaths_IncludeVSCodeStorage(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := t.TempDir()
	withWorkingDir(t, project)

	copilotHome := filepath.Join(home, ".copilot")
	vscodeStorage := filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "github.copilot")
	for _, dir := range []string{copilotHome, vscodeStorage} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	paths, err := (CopilotScanner{}).DiscoverPaths(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected default copilot path only, got %+v", paths)
	}
	got, err := filepath.EvalSymlinks(paths[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(copilotHome)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("expected default copilot path only, got %+v", paths)
	}

	paths, err = (CopilotScanner{IncludeVSCodeStorage: true}).DiscoverPaths(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %+v", paths)
	}
	gotHome, err := filepath.EvalSymlinks(paths[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if gotHome != want {
		gotHome, err = filepath.EvalSymlinks(paths[1].Path)
		if err != nil {
			t.Fatal(err)
		}
	}
	if gotHome != want {
		t.Fatalf("expected copilot home in %+v", paths)
	}
	wantVSCode, err := filepath.EvalSymlinks(vscodeStorage)
	if err != nil {
		t.Fatal(err)
	}
	gotVSCode, err := filepath.EvalSymlinks(paths[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if gotVSCode != wantVSCode {
		gotVSCode, err = filepath.EvalSymlinks(paths[1].Path)
		if err != nil {
			t.Fatal(err)
		}
	}
	if gotVSCode != wantVSCode {
		t.Fatalf("expected vscode storage in %+v", paths)
	}
}

func TestNoFullSecretInPreview(t *testing.T) {
	d := newTestDetector(t)
	s := CodexScanner{}

	findings, err := s.ScanPath(context.TODO(), testdataPath(t, "codex", "sessions.jsonl"), d)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Preview == "" {
			continue
		}
		if !strings.Contains(f.Preview, "...") && f.Preview != "***" {
			t.Errorf("finding %s: preview may contain full secret: %q", f.ID, f.Preview)
		}
	}
}

func TestFileFormat_OnlySupportedExts(t *testing.T) {
	d := newTestDetector(t)
	s := CodexScanner{}

	tmp := t.TempDir()
	unsupported := filepath.Join(tmp, "data.bin")
	if err := os.WriteFile(unsupported, []byte("sk-test_abcdefghijklmnopqrstuvwxyz123456"), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := s.ScanPath(context.TODO(), tmp, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 0 {
		t.Errorf("expected no findings from unsupported ext, got %d", len(findings))
	}
}

func TestExtractJSONFields(t *testing.T) {
	lines := []string{`{"type": "session", "token": "secret"}`}
	if got := extractJSONField(lines, 1, len(lines[0])); got != "token" {
		t.Fatalf("expected token, got %q", got)
	}
}

func TestScanNonexistentPath(t *testing.T) {
	s := CodexScanner{}
	_, err := s.ScanPath(context.TODO(), "/nonexistent/path", newTestDetector(t))
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}
