package detector

import (
	"regexp"

	"github.com/huydt84/secret-guard/internal/finding"
)

type Rule struct {
	ID         string
	Kind       string
	Pattern    *regexp.Regexp
	Severity   finding.Severity
	Confidence finding.Confidence
	// RequireKeyword means the rule only fires if a suspicious keyword
	// appears within the match line (AWS secret key requirement).
	RequireKeyword bool
}

var BuiltinRules = []Rule{
	{
		ID:         "openai-api-key",
		Kind:       "OpenAI API Key",
		Pattern:    regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`),
		Severity:   finding.SevHigh,
		Confidence: finding.ConfHigh,
	},
	{
		ID:         "anthropic-api-key",
		Kind:       "Anthropic API Key",
		Pattern:    regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`),
		Severity:   finding.SevHigh,
		Confidence: finding.ConfHigh,
	},
	{
		ID:         "aws-access-key-id",
		Kind:       "AWS Access Key ID",
		Pattern:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity:   finding.SevHigh,
		Confidence: finding.ConfHigh,
	},
	{
		ID:             "aws-secret-key",
		Kind:           "AWS Secret Access Key",
		Pattern:        regexp.MustCompile(`[A-Za-z0-9/+=]{40}`),
		Severity:       finding.SevHigh,
		Confidence:     finding.ConfMedium,
		RequireKeyword: true,
	},
	{
		ID:         "github-token",
		Kind:       "GitHub Token",
		Pattern:    regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{30,}`),
		Severity:   finding.SevHigh,
		Confidence: finding.ConfHigh,
	},
	{
		ID:         "npm-token",
		Kind:       "npm Token",
		Pattern:    regexp.MustCompile(`npm_[A-Za-z0-9]{20,}`),
		Severity:   finding.SevHigh,
		Confidence: finding.ConfHigh,
	},
	{
		ID:         "private-key",
		Kind:       "Private Key",
		Pattern:    regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		Severity:   finding.SevHigh,
		Confidence: finding.ConfHigh,
	},
	{
		ID:         "database-url",
		Kind:       "Database URL",
		Pattern:    regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^/:]+:[^@\s]+@`),
		Severity:   finding.SevHigh,
		Confidence: finding.ConfHigh,
	},
}

var entropyRule = Rule{
	ID:         "high-entropy",
	Kind:       "High-Entropy Token",
	Severity:   finding.SevMedium,
	Confidence: finding.ConfMedium,
}
