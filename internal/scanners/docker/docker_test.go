package docker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huydinhtrong/secretguard/internal/detector"
	"github.com/huydinhtrong/secretguard/internal/finding"
)

func TestDockerfileScanner_FindsENVSecret(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	os.WriteFile(df, []byte(`FROM alpine
ENV OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456
`), 0600)

	fs, err := ScanDockerfile(df, det)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range fs {
		if f.DetectorID == "openai-api-key" {
			found = true
			if f.Metadata["directive"] != "ENV" {
				t.Errorf("expected directive ENV, got %q", f.Metadata["directive"])
			}
			break
		}
	}
	if !found {
		t.Errorf("openai-api-key not found in ENV scan")
	}
}

func TestDockerfileScanner_FindsARGSecret(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	os.WriteFile(df, []byte(`FROM alpine
ARG ANTHROPIC_API_KEY=sk-ant-test_abcdefghijklmnopqrstuvwxyz123456
`), 0600)

	fs, err := ScanDockerfile(df, det)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range fs {
		if f.DetectorID == "anthropic-api-key" {
			found = true
			if f.Metadata["directive"] != "ARG" {
				t.Errorf("expected directive ARG, got %q", f.Metadata["directive"])
			}
			break
		}
	}
	if !found {
		t.Errorf("anthropic-api-key not found in ARG scan")
	}
}

func TestDockerfileScanner_DetectsCOPYEnvRisk(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	os.WriteFile(df, []byte(`FROM alpine
COPY .env /app/.env
`), 0600)

	fs, err := ScanDockerfile(df, det)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range fs {
		if f.DetectorID == "dockerfile-risk" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("dockerfile-risk not detected for COPY .env")
	}
}

func TestDockerfileScanner_DetectsADDEnvRisk(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	os.WriteFile(df, []byte(`FROM alpine
ADD --chown=app:app .env /app/.env
`), 0600)

	fs, err := ScanDockerfile(df, det)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range fs {
		if f.DetectorID == "dockerfile-risk" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("dockerfile-risk not detected for ADD .env")
	}
}

func TestDockerfileScanner_RUNExport(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	os.WriteFile(df, []byte(`FROM alpine
RUN export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE && echo done
`), 0600)

	fs, err := ScanDockerfile(df, det)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range fs {
		if f.DetectorID == "aws-access-key-id" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("aws-access-key-id not found in RUN export")
	}
}

func TestDockerfileScanner_FullFixture(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "docker", "Dockerfile"))
	if err != nil {
		t.Skip("fixture not found:", err)
	}
	os.WriteFile(df, data, 0600)

	fs, err := ScanDockerfile(df, det)
	if err != nil {
		t.Fatal(err)
	}

	if len(fs) == 0 {
		t.Error("expected findings from Dockerfile fixture")
	}

	hasOpenAI := false
	hasAnthropic := false
	hasCopyRisk := false
	hasAWSSec := false
	for _, f := range fs {
		switch f.DetectorID {
		case "openai-api-key":
			hasOpenAI = true
		case "anthropic-api-key":
			hasAnthropic = true
		case "dockerfile-risk":
			hasCopyRisk = true
		case "aws-access-key-id":
			hasAWSSec = true
		}
	}
	if !hasOpenAI {
		t.Error("expected openai-api-key finding")
	}
	if !hasAnthropic {
		t.Error("expected anthropic-api-key finding")
	}
	if !hasCopyRisk {
		t.Error("expected dockerfile-risk finding for COPY/ADD .env")
	}
	if !hasAWSSec {
		t.Error("expected aws-access-key-id finding from RUN export")
	}
}

func TestComposeScanner_DetectsDirectEnvSecret(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	cp := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(cp, []byte(`services:
  web:
    image: nginx
    environment:
      OPENAI_API_KEY: sk-test_abcdefghijklmnopqrstuvwxyz123456
`), 0600)

	fs, err := ScanCompose(cp, det)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range fs {
		if f.DetectorID == "openai-api-key" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("openai-api-key not found in compose environment")
	}
}

func TestComposeScanner_DetectsBuildArgsSecret(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	cp := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(cp, []byte(`services:
  web:
    image: nginx
    build:
      args:
        GITHUB_TOKEN: ghp_abcdefghijklmnopqrstuvwxyz1234567890
`), 0600)

	fs, err := ScanCompose(cp, det)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range fs {
		if f.DetectorID == "github-token" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("github-token not found in compose build.args")
	}
}

func TestComposeScanner_DetectsEnvFileRisk(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	cp := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(cp, []byte(`services:
  web:
    image: nginx
    env_file: .env
`), 0600)

	fs, err := ScanCompose(cp, det)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range fs {
		if f.DetectorID == "compose-risk" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("compose-risk not detected for env_file")
	}
}

func TestComposeScanner_FullFixture(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	cp := filepath.Join(dir, "docker-compose.yml")
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "docker", "docker-compose.yml"))
	if err != nil {
		t.Skip("fixture not found:", err)
	}
	os.WriteFile(cp, data, 0600)

	fs, err := ScanCompose(cp, det)
	if err != nil {
		t.Fatal(err)
	}

	if len(fs) == 0 {
		t.Error("expected findings from compose fixture")
	}
}

func TestComposeScanner_EnvironmentListForm(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	cp := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(cp, []byte(`services:
  web:
    image: nginx
    environment:
      - OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456
`), 0600)

	fs, err := ScanCompose(cp, det)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range fs {
		if f.DetectorID == "openai-api-key" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("openai-api-key not found in compose list-form environment")
	}
}

func TestDockerfileScanner_EmptyDockerfile(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	os.WriteFile(df, []byte("FROM alpine\nCMD [\"sh\"]\n"), 0600)

	fs, err := ScanDockerfile(df, det)
	if err != nil {
		t.Fatal(err)
	}

	if len(fs) != 0 {
		t.Errorf("expected 0 findings for safe Dockerfile, got %d", len(fs))
	}
}

func TestDockerfileScanner_NoFullSecretInPreview(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	os.WriteFile(df, []byte(`FROM alpine
ENV KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456
`), 0600)

	fs, err := ScanDockerfile(df, det)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range fs {
		if strings.Contains(f.Preview, "sk-test_abcdefghijklmnopqrstuvwxyz123456") {
			t.Errorf("preview leaked full secret: %s", f.Preview)
		}
	}
}

func TestScanHistoryOutput(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)

	output := "IMAGE\tCREATED\tCREATED BY\tSIZE\tCOMMENT\n" +
		"sha256:abc\t2 weeks ago\t/bin/sh -c #(nop)  ENV OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456\t0B\t\n" +
		"sha256:def\t2 weeks ago\t/bin/sh -c echo \"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\"\t10MB\t\n" +
		"sha256:ghi\t2 weeks ago\t/bin/sh -c apk add --no-cache curl\t5MB\t\n"

	findings := scanHistoryOutput(output, "test-image", det)
	if len(findings) == 0 {
		t.Fatal("expected findings from history output")
	}

	hasOpenAI := false
	hasGitHub := false
	for _, f := range findings {
		switch f.DetectorID {
		case "openai-api-key":
			hasOpenAI = true
		case "github-token":
			hasGitHub = true
		}
	}
	if !hasOpenAI {
		t.Errorf("expected openai-api-key finding in history")
	}
	if !hasGitHub {
		t.Errorf("expected github-token finding in history")
	}
}

func TestScanHistoryOutput_Empty(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)

	output := "IMAGE\tCREATED\tCREATED BY\tSIZE\tCOMMENT\n" +
		"sha256:abc\t2 weeks ago\t/bin/sh -c apk add --no-cache curl\t5MB\t\n"
	findings := scanHistoryOutput(output, "test-image", det)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe history, got %d", len(findings))
	}
}

func TestComposeScanner_NoSecrets(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	cp := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(cp, []byte(`services:
  web:
    image: nginx
    environment:
      NODE_ENV: production
`), 0600)

	fs, err := ScanCompose(cp, det)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range fs {
		if strings.Contains(f.Preview, "sk-test") || strings.Contains(f.Preview, "ghp_") {
			t.Errorf("full secret leaked in preview: %s", f.Preview)
		}
	}
}

func TestDockerfileScanner_NonexistentFile(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	_, err := ScanDockerfile("/nonexistent/Dockerfile", det)
	if err == nil {
		t.Error("expected error for nonexistent Dockerfile")
	}
}

func TestIsComposeFile(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"docker-compose.yml", true},
		{"docker-compose.yaml", true},
		{"compose.yml", true},
		{"compose.yaml", true},
		{"docker-compose.xml", false},
		{"Dockerfile", false},
	}
	for _, tc := range cases {
		got := IsComposeFile(tc.name)
		if got != tc.want {
			t.Errorf("IsComposeFile(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestContainerScanner_ErrorOnNonexistent(t *testing.T) {
	if os.Getenv("SECRETGUARD_DOCKER_TESTS") == "1" {
		t.Skip("live Docker test; run separately")
	}

	det := detector.New(detector.BuiltinRules, nil)
	scanner := NewContainerScanner("nonexistent-test-container", det)
	_, err := scanner.Scan()
	if err == nil {
		t.Error("expected error for nonexistent container or unavailable Docker")
	}
}

func TestImageScanner_ErrorOnNonexistent(t *testing.T) {
	if os.Getenv("SECRETGUARD_DOCKER_TESTS") == "1" {
		t.Skip("live Docker test; run separately")
	}

	det := detector.New(detector.BuiltinRules, nil)
	scanner := NewImageScanner("nonexistent-test-image", det)
	_, err := scanner.Scan()
	if err == nil {
		t.Error("expected error for nonexistent image or unavailable Docker")
	}
}

func TestScanDocker_BestEffortNoDocker(t *testing.T) {
	if os.Getenv("SECRETGUARD_DOCKER_TESTS") == "1" {
		t.Skip("live Docker test; run separately")
	}

	det := detector.New(detector.BuiltinRules, nil)
	scanner := New(det)
	fs, err := scanner.ScanDocker(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("expected 0 findings with no docker files, got %d", len(fs))
	}
}

func TestComposeScanner_YAMLErrors(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	cp := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(cp, []byte(`invalid: yaml: unclosed
  block
`), 0600)

	_, err := ScanCompose(cp, det)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestDockerfileScanner_SourceKind(t *testing.T) {
	det := detector.New(detector.BuiltinRules, nil)
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	os.WriteFile(df, []byte(`FROM alpine
ENV OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456
`), 0600)

	fs, err := ScanDockerfile(df, det)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range fs {
		if f.Source != finding.SourceDocker {
			t.Errorf("expected SourceDocker, got %v", f.Source)
		}
	}
}


