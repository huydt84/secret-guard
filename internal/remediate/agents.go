package remediate

import (
	"github.com/huydinhtrong/secretguard/internal/finding"
)

func GenerateAgentAdvice(f finding.Finding) RemediationPlan {
	steps := []Step{
		{
			Title:       "Run SecretGuard redaction on agent data",
			Description: "Use the redact command with --dry-run first to review what will be redacted. Then apply with --apply to perform the redaction.",
			Command:     "secretguard redact --agents <agent-type> --dry-run",
		},
		{
			Title:       "Apply redaction after review",
			Description: "Once the dry-run output looks correct, apply the redaction in-place. SecretGuard will create a backup before modifying files.",
			Command:     "secretguard redact --agents <agent-type> --apply",
		},
	}

	warnings := []string{
		"Always review the dry-run output before applying redaction.",
		"Backups are created automatically when --apply is used. Use `secretguard restore --backup-id <id>` to revert if needed.",
	}

	if f.Severity >= finding.SevHigh {
		steps = append(steps, Step{
			Title:       "Rotate or revoke the credential",
			Description: "If this credential is known to be valid and has been exposed outside the local environment, rotate or revoke it at the provider immediately.",
		})
	}

	return RemediationPlan{
		FindingID:   f.ID,
		Source:      f.Source,
		DetectorID:  f.DetectorID,
		SecretKind:  f.SecretKind,
		Severity:    f.Severity.String(),
		Preview:     f.Preview,
		Fingerprint: f.Fingerprint,
		Steps:       steps,
		Warnings:    warnings,
	}
}
