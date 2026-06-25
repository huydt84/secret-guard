package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huydt84/secret-guard/internal/detector"
	"github.com/huydt84/secret-guard/internal/finding"
	fs "github.com/huydt84/secret-guard/internal/scanners/filesystem"
)

func newTestDetector(t *testing.T) *detector.Detector {
	t.Helper()
	al, err := detector.NewAllowlist(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return detector.New(detector.BuiltinRules, al)
}

func gitExec(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %s", args, string(out))
	}
	return string(out)
}

func initTempRepo(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()

	gitExec(t, tmpDir, "init")
	gitExec(t, tmpDir, "config", "user.name", "test")
	gitExec(t, tmpDir, "config", "user.email", "test@test.com")

	return tmpDir
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	err := os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHistory_FindsDeletedSecret(t *testing.T) {
	repo := initTempRepo(t)

	envContent := "OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456"
	writeFile(t, repo, ".env", envContent)
	gitExec(t, repo, "add", ".env")
	gitExec(t, repo, "commit", "-m", "add .env with secret")

	err := os.Remove(filepath.Join(repo, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	gitExec(t, repo, "add", ".env")
	gitExec(t, repo, "commit", "-m", "delete .env")

	det := newTestDetector(t)

	fsScanner := fs.New(det)
	fsFindings, err := fsScanner.Scan(repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fsFindings {
		if strings.Contains(f.Preview, "sk-test") {
			t.Errorf("filesystem scanner found deleted secret: %s", f.Preview)
		}
	}

	gitScanner := New(det)
	historyFindings, err := gitScanner.ScanHistory(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(historyFindings) == 0 {
		t.Fatal("expected history scan to find the deleted secret")
	}

	secretKeyFound := false
	for _, f := range historyFindings {
		if f.DetectorID == "openai-api-key" {
			secretKeyFound = true
		}
		if f.Location.CommitSHA == "" {
			t.Errorf("history finding %s missing commit SHA", f.ID)
		}
		if f.Source != finding.SourceGitHistory {
			t.Errorf("history finding %s has source %s, want git_history", f.ID, f.Source)
		}
	}
	if !secretKeyFound {
		t.Errorf("history scan did not find expected openai-api-key secret")
	}
}

func TestStaged_DetectsNewlyStagedSecret(t *testing.T) {
	repo := initTempRepo(t)

	writeFile(t, repo, "README.md", "# Clean repo\n")
	gitExec(t, repo, "add", "README.md")
	gitExec(t, repo, "commit", "-m", "initial commit")

	det := newTestDetector(t)
	gitScanner := New(det)

	stageFindings, err := gitScanner.ScanStaged(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(stageFindings) != 0 {
		t.Errorf("expected 0 staged findings before staging, got %d", len(stageFindings))
	}

	envContent := "GITHUB_TOKEN=ghp_test_abcdefghijklmnopqrstuvwxyz123456"
	writeFile(t, repo, ".env", envContent)
	gitExec(t, repo, "add", ".env")

	stageFindings, err = gitScanner.ScanStaged(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(stageFindings) == 0 {
		t.Fatal("expected staged scan to find newly staged secret")
	}

	foundGitHub := false
	for _, f := range stageFindings {
		if f.Source != finding.SourceGit {
			t.Errorf("staged finding %s has source %s, want git", f.ID, f.Source)
		}
		if f.DetectorID == "github-token" {
			foundGitHub = true
		}
	}
	if !foundGitHub {
		t.Errorf("staged scan did not find github-token")
	}
}

func TestStaged_DoesNotReportOldUnchangedFiles(t *testing.T) {
	repo := initTempRepo(t)

	writeFile(t, repo, "safe.txt", "hello world")
	gitExec(t, repo, "add", "safe.txt")
	gitExec(t, repo, "commit", "-m", "initial commit")

	writeFile(t, repo, ".env", "OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456")
	gitExec(t, repo, "add", ".env")

	det := newTestDetector(t)
	gitScanner := New(det)
	stageFindings, err := gitScanner.ScanStaged(repo)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range stageFindings {
		if f.Location.Path == "safe.txt" {
			t.Errorf("staged scanner reported unrelated file safe.txt")
		}
	}

	hasEnvFinding := false
	for _, f := range stageFindings {
		if f.Location.Path == ".env" {
			hasEnvFinding = true
			break
		}
	}
	if !hasEnvFinding {
		t.Errorf("staged scanner did not report .env secret")
	}
}

func TestWorkingTree_DetectsTrackedSecrets(t *testing.T) {
	repo := initTempRepo(t)

	envContent := "NPM_TOKEN=npm_trvkrjghpqstuvwxyzklmnopqrstuvwxyz"
	writeFile(t, repo, ".env", envContent)
	gitExec(t, repo, "add", ".env")
	gitExec(t, repo, "commit", "-m", "add .env")

	det := newTestDetector(t)
	gitScanner := New(det)

	findings, err := gitScanner.ScanWorkingTree(repo, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected working tree scan to find npm token")
	}

	foundNPM := false
	for _, f := range findings {
		if f.Source != finding.SourceGit {
			t.Errorf("working tree finding %s has source %s, want git", f.ID, f.Source)
		}
		if f.DetectorID == "npm-token" {
			foundNPM = true
		}
	}
	if !foundNPM {
		t.Errorf("working tree scan did not find npm-token")
	}
}

func TestWorkingTree_IgnoresUntrackedWithoutFlag(t *testing.T) {
	repo := initTempRepo(t)

	writeFile(t, repo, "tracked.txt", "safe")
	gitExec(t, repo, "add", "tracked.txt")
	gitExec(t, repo, "commit", "-m", "initial")

	writeFile(t, repo, "untracked.env", "DATABASE_URL=postgres://user:supersecretpassword@localhost:5432/app")

	det := newTestDetector(t)
	gitScanner := New(det)

	findings, err := gitScanner.ScanWorkingTree(repo, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Location.Path == "untracked.env" {
			t.Errorf("working tree scan found untracked file without --include-untracked")
		}
	}
}

func TestWorkingTree_IncludesUntrackedWithFlag(t *testing.T) {
	repo := initTempRepo(t)

	writeFile(t, repo, "tracked.txt", "safe")
	gitExec(t, repo, "add", "tracked.txt")
	gitExec(t, repo, "commit", "-m", "initial")

	writeFile(t, repo, "untracked.env", "DATABASE_URL=postgres://user:supersecretpassword@localhost:5432/app")

	det := newTestDetector(t)
	gitScanner := New(det)

	findings, err := gitScanner.ScanWorkingTree(repo, true)
	if err != nil {
		t.Fatal(err)
	}

	foundDBURL := false
	for _, f := range findings {
		if f.Location.Path == "untracked.env" {
			foundDBURL = true
			break
		}
	}
	if !foundDBURL {
		t.Errorf("working tree scan with untracked did not find untracked.env secret")
	}
}

func TestStaged_MultipleFilesScanned(t *testing.T) {
	repo := initTempRepo(t)

	writeFile(t, repo, "safe.txt", "hello")
	gitExec(t, repo, "add", "safe.txt")
	gitExec(t, repo, "commit", "-m", "initial")

	writeFile(t, repo, "config.json", `{"api_key": "sk-test_MYAPIKEY12345678901234567890"}`)
	writeFile(t, repo, "key.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----")
	gitExec(t, repo, "add", "config.json")
	gitExec(t, repo, "add", "key.pem")

	det := newTestDetector(t)
	gitScanner := New(det)
	findings, err := gitScanner.ScanStaged(repo)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) == 0 {
		t.Fatal("expected staged scan to find multiple secrets")
	}
}

func TestScanWorkingTree_NotGitRepo(t *testing.T) {
	tmpDir := t.TempDir()
	det := newTestDetector(t)
	gitScanner := New(det)

	_, err := gitScanner.ScanWorkingTree(tmpDir, false)
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
}

func TestScanStaged_NotGitRepo(t *testing.T) {
	tmpDir := t.TempDir()
	det := newTestDetector(t)
	gitScanner := New(det)

	_, err := gitScanner.ScanStaged(tmpDir)
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
}

func TestScanHistory_NotGitRepo(t *testing.T) {
	tmpDir := t.TempDir()
	det := newTestDetector(t)
	gitScanner := New(det)

	_, err := gitScanner.ScanHistory(tmpDir)
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
}

func TestHistory_NoFullSecretInOutput(t *testing.T) {
	repo := initTempRepo(t)

	envContent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	writeFile(t, repo, ".env", envContent)
	gitExec(t, repo, "add", ".env")
	gitExec(t, repo, "commit", "-m", "add secret")

	err := os.Remove(filepath.Join(repo, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	gitExec(t, repo, "add", ".env")
	gitExec(t, repo, "commit", "-m", "remove")

	det := newTestDetector(t)
	gitScanner := New(det)
	findings, err := gitScanner.ScanHistory(repo)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if strings.Contains(f.Preview, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("finding %s contains full secret in preview: %s", f.ID, f.Preview)
		}
	}
}
