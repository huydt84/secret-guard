package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Version != 1 {
		t.Errorf("expected version 1, got %d", cfg.Version)
	}
	if !cfg.Scan.Git.WorkingTree {
		t.Error("expected git working_tree scan enabled by default")
	}
	if cfg.Scan.Docker.Enabled {
		t.Error("expected docker scan disabled by default")
	}
	if cfg.Report.Format != "terminal" {
		t.Errorf("expected report format 'terminal', got %s", cfg.Report.Format)
	}
	if !cfg.Redaction.Backup {
		t.Error("expected redaction backup enabled by default")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secretguard.yml")
	content := []byte("version: 1\nscan:\n  git:\n    working_tree: false\n")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Scan.Git.WorkingTree {
		t.Error("expected git working_tree to be false after override")
	}
}

func TestLoad_NotFound(t *testing.T) {
	_, err := Load("/nonexistent/.secretguard.yml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
