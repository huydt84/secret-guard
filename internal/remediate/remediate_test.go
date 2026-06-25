package remediate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huydt84/secret-guard/internal/finding"
)

func makeTestFindings() []finding.Finding {
	return []finding.Finding{
		{
			ID:          "sg-finding-git-001",
			Source:      finding.SourceGitHistory,
			DetectorID:  "github-token",
			SecretKind:  "GitHub Token",
			Severity:    finding.SevHigh,
			Confidence:  finding.ConfHigh,
			Location:    finding.Location{Path: "src/config.yml", Line: 10, Column: 1},
			Preview:     "ghp_...7890",
			Fingerprint: "sha256:aabbccddee11",
		},
		{
			ID:          "sg-finding-docker-env-002",
			Source:      finding.SourceDocker,
			DetectorID:  "openai-api-key",
			SecretKind:  "OpenAI API Key",
			Severity:    finding.SevHigh,
			Confidence:  finding.ConfHigh,
			Location:    finding.Location{Path: "Dockerfile", Line: 5, Column: 1},
			Preview:     "sk-t...3456",
			Fingerprint: "sha256:bbccddeeff22",
			Evidence:    finding.Evidence{Context: "ENV OPENAI_API_KEY=sk-test_..."},
		},
		{
			ID:          "sg-finding-docker-arg-003",
			Source:      finding.SourceDocker,
			DetectorID:  "npm-token",
			SecretKind:  "NPM Token",
			Severity:    finding.SevMedium,
			Confidence:  finding.ConfHigh,
			Location:    finding.Location{Path: "Dockerfile", Line: 8, Column: 1},
			Preview:     "npm_...3456",
			Fingerprint: "sha256:ccddeeff33",
			Evidence:    finding.Evidence{Context: "ARG NPM_TOKEN=npm_..."},
		},
		{
			ID:          "sg-finding-docker-compose-004",
			Source:      finding.SourceDocker,
			DetectorID:  "database-url",
			SecretKind:  "Database URL",
			Severity:    finding.SevHigh,
			Confidence:  finding.ConfHigh,
			Location:    finding.Location{Path: "docker-compose.yml", Line: 12, Column: 1},
			Preview:     "postg...rd",
			Fingerprint: "sha256:ddeeff44",
		},
		{
			ID:          "sg-finding-docker-image-005",
			Source:      finding.SourceDocker,
			DetectorID:  "openai-api-key",
			SecretKind:  "OpenAI API Key",
			Severity:    finding.SevHigh,
			Confidence:  finding.ConfHigh,
			Location:    finding.Location{Path: "image:myapp:v1.0", Line: 3, Column: 1},
			Preview:     "sk-t...3456",
			Fingerprint: "sha256:eeff55",
		},
		{
			ID:          "sg-finding-agent-006",
			Source:      finding.SourceAgent,
			DetectorID:  "anthropic-api-key",
			SecretKind:  "Anthropic API Key",
			Severity:    finding.SevHigh,
			Confidence:  finding.ConfHigh,
			Location:    finding.Location{Path: "agent/sessions.jsonl", Line: 42, Column: 1},
			Preview:     "sk-an...3456",
			Fingerprint: "sha256:ff66",
		},
		{
			ID:          "sg-finding-agent-low-007",
			Source:      finding.SourceAgent,
			DetectorID:  "generic-api-key",
			SecretKind:  "API Key",
			Severity:    finding.SevLow,
			Confidence:  finding.ConfLow,
			Location:    finding.Location{Path: "agent/sessions.jsonl", Line: 10, Column: 1},
			Preview:     "abc...xyz",
			Fingerprint: "sha256:aa77",
		},
	}
}

func TestLookupFinding_Found(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "report.json")
	data, err := json.Marshal(makeTestFindings())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	f, err := LookupFinding(reportPath, "sg-finding-git-001")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if f.ID != "sg-finding-git-001" {
		t.Errorf("expected id sg-finding-git-001, got %s", f.ID)
	}
}

func TestLookupFinding_NotFound(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "report.json")
	data, err := json.Marshal(makeTestFindings())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	_, err = LookupFinding(reportPath, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent finding")
	}
}

func TestLookupFinding_InvalidPath(t *testing.T) {
	_, err := LookupFinding("/nonexistent/path.json", "sg-finding-git-001")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestGenerateGitPlan_ContainsSteps(t *testing.T) {
	f := makeTestFindings()[0]
	plan := GenerateGitPlan(f)

	if len(plan.Steps) == 0 {
		t.Fatal("expected at least one step")
	}

	stepTitles := []string{
		"Rotate or revoke the credential immediately",
		"Create a fresh mirror clone",
		"Prepare a replacement text file",
		"Run git filter-repo manually",
		"Re-scan the rewritten history",
		"Force-push only after team coordination",
	}
	for i, title := range stepTitles {
		if plan.Steps[i].Title != title {
			t.Errorf("step %d: expected title %q, got %q", i, title, plan.Steps[i].Title)
		}
	}
}

func TestGenerateGitPlan_NoRawSecret(t *testing.T) {
	f := makeTestFindings()[0]
	plan := GenerateGitPlan(f)
	output := FormatPlan(plan)

	if strings.Contains(output, "ghp_abcdefghijklmnopqrstuvwxyz1234567890") {
		t.Error("plan contains raw secret")
	}
}

func TestGenerateGitPlan_HasRotationWarning(t *testing.T) {
	f := makeTestFindings()[0]
	plan := GenerateGitPlan(f)

	hasRotation := false
	for _, w := range plan.Warnings {
		if strings.Contains(strings.ToLower(w), "force-push") {
			hasRotation = true
			break
		}
	}
	if !hasRotation {
		t.Error("expected force-push coordination warning")
	}
}

func TestGenerateGitPlan_HasFilterRepoGuidance(t *testing.T) {
	f := makeTestFindings()[0]
	plan := GenerateGitPlan(f)

	hasFilterRepo := false
	for _, s := range plan.Steps {
		if strings.Contains(s.Title, "git filter-repo") || strings.Contains(s.Command, "git filter-repo") {
			hasFilterRepo = true
			break
		}
	}
	if !hasFilterRepo {
		t.Error("expected git filter-repo guidance")
	}
}

func TestGenerateDockerPlan_ENVField(t *testing.T) {
	f := makeTestFindings()[1]
	plan := GenerateDockerPlan(f)

	if len(plan.Steps) == 0 {
		t.Fatal("expected steps for Dockerfile ENV")
	}

	if !strings.Contains(plan.Steps[0].Title, "ENV") && !strings.Contains(plan.Steps[0].Description, "ENV") {
		t.Error("expected ENV-specific advice")
	}
}

func TestGenerateDockerPlan_ARGField(t *testing.T) {
	f := makeTestFindings()[2]
	plan := GenerateDockerPlan(f)

	if len(plan.Steps) == 0 {
		t.Fatal("expected steps for Dockerfile ARG")
	}

	if !strings.Contains(plan.Steps[0].Title, "ARG") && !strings.Contains(plan.Steps[0].Description, "ARG") {
		t.Error("expected ARG-specific advice")
	}
}

func TestGenerateDockerPlan_ComposeField(t *testing.T) {
	f := makeTestFindings()[3]
	plan := GenerateDockerPlan(f)

	if len(plan.Steps) == 0 {
		t.Fatal("expected steps for Compose environment")
	}
}

func TestGenerateDockerPlan_ImageHistoryField(t *testing.T) {
	f := makeTestFindings()[4]
	plan := GenerateDockerPlan(f)

	if len(plan.Steps) == 0 {
		t.Fatal("expected steps for image history")
	}
}

func TestGenerateAgentAdvice_SuggestsRedact(t *testing.T) {
	f := makeTestFindings()[5]
	plan := GenerateAgentAdvice(f)

	hasRedactCommand := false
	for _, s := range plan.Steps {
		if strings.Contains(s.Command, "redact") && strings.Contains(s.Command, "--dry-run") {
			hasRedactCommand = true
			break
		}
	}
	if !hasRedactCommand {
		t.Error("expected redact --dry-run suggestion")
	}
}

func TestGenerateAgentAdvice_HighSeverityHasRotate(t *testing.T) {
	f := makeTestFindings()[5]
	plan := GenerateAgentAdvice(f)

	hasRotate := false
	for _, s := range plan.Steps {
		if strings.Contains(strings.ToLower(s.Title), "rotate") || strings.Contains(strings.ToLower(s.Title), "revoke") {
			hasRotate = true
			break
		}
	}
	if !hasRotate {
		t.Error("expected rotate/revoke step for high severity")
	}
}

func TestGenerateAgentAdvice_LowSeverityNoRotate(t *testing.T) {
	f := makeTestFindings()[6]
	plan := GenerateAgentAdvice(f)

	hasRotate := false
	for _, s := range plan.Steps {
		if strings.Contains(strings.ToLower(s.Title), "rotate") || strings.Contains(strings.ToLower(s.Title), "revoke") {
			hasRotate = true
			break
		}
	}
	if hasRotate {
		t.Error("did not expect rotate/revoke step for low severity")
	}
}

func TestFormatPlan_ContainsFingerprint(t *testing.T) {
	f := makeTestFindings()[0]
	plan := GenerateGitPlan(f)
	output := FormatPlan(plan)

	if !strings.Contains(output, plan.Fingerprint) {
		t.Error("output should contain fingerprint")
	}
}

func updateGoldenFiles() bool {
	return os.Getenv("UPDATE_GOLDEN") == "1"
}

func TestGolden_GitRemediationPlan(t *testing.T) {
	f := makeTestFindings()[0]
	plan := GenerateGitPlan(f)
	got := FormatPlan(plan)

	goldenPath := filepath.Join("..", "..", "testdata", "golden", "remediate-git.txt")
	if updateGoldenFiles() {
		if err := os.WriteFile(goldenPath, []byte(got), 0644); err != nil {
			t.Fatal(err)
		}
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	if got != string(want) {
		t.Errorf("git remediation plan mismatch\nwant:\n%s\ngot:\n%s", string(want), got)
	}
}

func TestGolden_DockerRemediationPlan(t *testing.T) {
	f := makeTestFindings()[1]
	plan := GenerateDockerPlan(f)
	got := FormatPlan(plan)

	goldenPath := filepath.Join("..", "..", "testdata", "golden", "remediate-docker.txt")
	if updateGoldenFiles() {
		if err := os.WriteFile(goldenPath, []byte(got), 0644); err != nil {
			t.Fatal(err)
		}
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	if got != string(want) {
		t.Errorf("docker remediation plan mismatch\nwant:\n%s\ngot:\n%s", string(want), got)
	}
}

func TestGolden_AgentRemediationAdvice(t *testing.T) {
	f := makeTestFindings()[5]
	plan := GenerateAgentAdvice(f)
	got := FormatPlan(plan)

	goldenPath := filepath.Join("..", "..", "testdata", "golden", "remediate-agent.txt")
	if updateGoldenFiles() {
		if err := os.WriteFile(goldenPath, []byte(got), 0644); err != nil {
			t.Fatal(err)
		}
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	if got != string(want) {
		t.Errorf("agent remediation plan mismatch\nwant:\n%s\ngot:\n%s", string(want), got)
	}
}
