package report

import (
	"bytes"
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
			ID:          "sg-test1",
			Source:      finding.SourceFile,
			DetectorID:  "openai-api-key",
			SecretKind:  "OpenAI API Key",
			Severity:    finding.SevHigh,
			Confidence:  finding.ConfHigh,
			Location:    finding.Location{Path: "test.env", Line: 1, Column: 1},
			Preview:     "sk-t...3456",
			Fingerprint: "sha256:a1b2c3d4e5f6",
			Evidence:    finding.Evidence{Context: "OPENAI_API_KEY=\"[REDACTED]\""},
		},
		{
			ID:          "sg-test2",
			Source:      finding.SourceFile,
			DetectorID:  "github-token",
			SecretKind:  "GitHub Token",
			Severity:    finding.SevMedium,
			Confidence:  finding.ConfMedium,
			Location:    finding.Location{Path: "config.yml", Line: 5, Column: 10},
			Preview:     "ghp_...7890",
			Fingerprint: "sha256:b2c3d4e5f6a7",
		},
	}
}

func TestTerminalReport_NoSecrets(t *testing.T) {
	var buf bytes.Buffer
	WriteTerminal(&buf, nil, true, true)
	if !strings.Contains(buf.String(), "No secrets found") {
		t.Errorf("unexpected output: %s", buf.String())
	}
}

func TestTerminalReport_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	WriteTerminal(&buf, []finding.Finding{}, true, true)
	if !strings.Contains(buf.String(), "No secrets found") {
		t.Errorf("unexpected output: %s", buf.String())
	}
}

func TestTerminalReport_NoFullSecret(t *testing.T) {
	findings := makeTestFindings()
	var buf bytes.Buffer
	WriteTerminal(&buf, findings, true, true)
	output := buf.String()
	if strings.Contains(output, "sk-test_") && strings.Contains(output, "abcdefghijklmn") {
		t.Error("terminal report contains full secret")
	}
	if strings.Contains(output, "ghp_abcdefghijklmn") {
		t.Error("terminal report contains full secret")
	}
}

func TestTerminalReport_HidePreview(t *testing.T) {
	findings := makeTestFindings()
	var buf bytes.Buffer
	WriteTerminal(&buf, findings, false, true)
	output := buf.String()
	if strings.Contains(output, "Preview:") {
		t.Error("terminal report should not contain Preview when showPreview=false")
	}
}

func TestTerminalReport_HideFingerprints(t *testing.T) {
	findings := makeTestFindings()
	var buf bytes.Buffer
	WriteTerminal(&buf, findings, true, false)
	output := buf.String()
	if strings.Contains(output, "Fingerprint:") {
		t.Error("terminal report should not contain Fingerprint when showFingerprints=false")
	}
}

func TestJSONReport_ValidJSON(t *testing.T) {
	findings := makeTestFindings()
	var buf bytes.Buffer
	if err := WriteJSON(&buf, findings); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Error("JSON report is not valid JSON")
	}
}

func TestJSONReport_NoFullSecret(t *testing.T) {
	findings := makeTestFindings()
	var buf bytes.Buffer
	if err := WriteJSON(&buf, findings); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if strings.Contains(output, "sk-test_") && strings.Contains(output, "abcdefghijklmn") {
		t.Error("JSON report contains full secret")
	}
}

func TestJSONReport_RoundTrip(t *testing.T) {
	findings := makeTestFindings()
	var buf bytes.Buffer
	if err := WriteJSON(&buf, findings); err != nil {
		t.Fatal(err)
	}
	var decoded []finding.Finding
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(findings) {
		t.Errorf("expected %d findings, got %d", len(findings), len(decoded))
	}
}

func TestGolden_TerminalEmpty(t *testing.T) {
	var buf bytes.Buffer
	WriteTerminal(&buf, nil, true, true)
	got := buf.String()

	goldenPath := filepath.Join("..", "..", "testdata", "golden", "report-terminal-empty.txt")
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
		t.Errorf("empty terminal report mismatch\nwant:\n%s\ngot:\n%s", string(want), got)
	}
}

func updateGoldenFiles() bool {
	return os.Getenv("UPDATE_GOLDEN") == "1"
}

func TestGolden_TerminalReport(t *testing.T) {
	findings := makeTestFindings()
	var buf bytes.Buffer
	WriteTerminal(&buf, findings, true, true)
	got := buf.String()

	goldenPath := filepath.Join("..", "..", "testdata", "golden", "report-terminal.txt")
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
		t.Errorf("terminal report mismatch\nwant:\n%s\ngot:\n%s", string(want), got)
	}
}

func TestGolden_JSONReport(t *testing.T) {
	findings := makeTestFindings()
	var buf bytes.Buffer
	if err := WriteJSON(&buf, findings); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	goldenPath := filepath.Join("..", "..", "testdata", "golden", "report-json.json")
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
		t.Errorf("JSON report mismatch\nwant:\n%s\ngot:\n%s", string(want), got)
	}
}
