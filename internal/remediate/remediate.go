package remediate

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/huydt84/secret-guard/internal/finding"
)

type Step struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
}

type RemediationPlan struct {
	FindingID   string             `json:"finding_id"`
	Source      finding.SourceKind `json:"source"`
	DetectorID  string             `json:"detector_id"`
	SecretKind  string             `json:"secret_kind"`
	Severity    string             `json:"severity"`
	Preview     string             `json:"preview"`
	Fingerprint string             `json:"fingerprint"`
	Steps       []Step             `json:"steps"`
	Warnings    []string           `json:"warnings,omitempty"`
}

func LookupFinding(reportPath, findingID string) (finding.Finding, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return finding.Finding{}, fmt.Errorf("read report: %w", err)
	}

	var findings []finding.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return finding.Finding{}, fmt.Errorf("parse report: %w", err)
	}

	for _, f := range findings {
		if f.ID == findingID {
			return f, nil
		}
	}

	return finding.Finding{}, fmt.Errorf("finding %q not found in report", findingID)
}

func FormatPlan(plan RemediationPlan) string {
	s := fmt.Sprintf("Remediation plan for finding %s\n", plan.FindingID)
	s += fmt.Sprintf("  Secret kind: %s\n", plan.SecretKind)
	s += fmt.Sprintf("  Severity:    %s\n", plan.Severity)
	s += fmt.Sprintf("  Preview:     %s\n", plan.Preview)
	s += fmt.Sprintf("  Fingerprint: %s\n", plan.Fingerprint)
	s += "\nSteps:\n"
	for i, step := range plan.Steps {
		s += fmt.Sprintf("\n  %d. %s\n", i+1, step.Title)
		s += fmt.Sprintf("     %s\n", step.Description)
		if step.Command != "" {
			s += fmt.Sprintf("     $ %s\n", step.Command)
		}
	}
	for _, w := range plan.Warnings {
		s += fmt.Sprintf("\n  ⚠ %s\n", w)
	}
	return s
}
