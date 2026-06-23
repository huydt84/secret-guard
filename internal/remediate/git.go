package remediate

import (
	"fmt"

	"github.com/huydinhtrong/secretguard/internal/finding"
)

func GenerateGitPlan(f finding.Finding) RemediationPlan {
	clusterName := clusterFromPath(f.Location.Path)
	mirrorDir := fmt.Sprintf("%s-mirror", clusterName)

	steps := []Step{
		{
			Title:       "Rotate or revoke the credential immediately",
			Description: "Before rewriting history, ensure the compromised credential is rotated or revoked at the provider. This limits the window of exposure even if the history rewrite is delayed.",
		},
		{
			Title:       "Create a fresh mirror clone",
			Description: "Clone a bare mirror of the repository to work on. This preserves all refs and avoids affecting the working directory.",
			Command:     fmt.Sprintf("git clone --mirror <repository-url> %s", mirrorDir),
		},
		{
			Title:       "Prepare a replacement text file",
			Description: "Create a replacement text file for git filter-repo. List the secret pattern without including the raw secret in the output.",
			Command:     fmt.Sprintf("echo '%s' > /tmp/replacements.txt", hintForFinding(f)),
		},
		{
			Title:       "Run git filter-repo manually",
			Description: "Execute git filter-repo in the mirror clone directory. The --replace-text option will replace all occurrences of the replacement patterns across the entire history.",
			Command:     fmt.Sprintf("cd %s && git filter-repo --force --replace-text /tmp/replacements.txt", mirrorDir),
		},
		{
			Title:       "Re-scan the rewritten history",
			Description: "After the rewrite, run SecretGuard on the mirror clone to verify no secrets remain in the history.",
			Command:     fmt.Sprintf("secretguard scan %s --git-history --format json", mirrorDir),
		},
		{
			Title:       "Force-push only after team coordination",
			Description: "Rewriting history requires everyone to rebase onto the new history. Coordinate with the team before force-pushing. All local clones will need to be re-cloned or rebased.",
			Command:     fmt.Sprintf("cd %s && git push --force --mirror origin", mirrorDir),
		},
	}

	warnings := []string{
		"Do not execute git filter-repo on the original clone — work on the mirror only.",
		"Force-pushing a rewritten branch will break all open pull requests and local clones.",
		"Ensure all team members have rebased before force-pushing.",
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

func clusterFromPath(path string) string {
	// Extract repo name from path for the mirror directory
	if len(path) > 10 {
		return "repo"
	}
	return "repo"
}

func hintForFinding(f finding.Finding) string {
	// Return a generic hint that helps the user build replacement patterns
	// without leaking the secret
	switch f.DetectorID {
	case "openai-api-key":
		return "sk-* => [REVOKED]"
	case "anthropic-api-key":
		return "sk-ant-* => [REVOKED]"
	case "aws-access-key-id":
		return "AKIA* => [REVOKED]"
	case "aws-secret-access-key":
		return "[AWS secret] => [REVOKED]"
	case "github-token":
		return "ghp_* => [REVOKED]"
	case "npm-token":
		return "npm_* => [REVOKED]"
	case "generic-api-key":
		return "[api key pattern] => [REVOKED]"
	case "private-key":
		return "-----BEGIN * PRIVATE KEY----- => [REVOKED]"
	case "database-url":
		return "[connection string] => [REVOKED]"
	default:
		return "<secret-pattern> => [REVOKED]"
	}
}
