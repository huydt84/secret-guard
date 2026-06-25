package detector

import (
	"strings"

	"github.com/huydt84/secret-guard/internal/finding"
)

var suspiciousKeywords = []string{
	"api_key",
	"apikey",
	"secret",
	"token",
	"password",
	"passwd",
	"credential",
	"auth",
	"bearer",
	"private_key",
	"client_secret",
	"access_key",
	"refresh_token",
	"session_token",
	"OPENAI_API_KEY",
	"ANTHROPIC_API_KEY",
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"GITHUB_TOKEN",
	"NPM_TOKEN",
	"DATABASE_URL",
	"POSTGRES_PASSWORD",
	"MYSQL_PASSWORD",
	"REDIS_PASSWORD",
}

var keywordSet func() map[string]bool

func init() {
	ks := make(map[string]bool, len(suspiciousKeywords))
	for _, kw := range suspiciousKeywords {
		ks[strings.ToLower(kw)] = true
	}
	keywordSet = func() map[string]bool { return ks }
}

func containsKeyword(line string) bool {
	lower := strings.ToLower(line)
	ks := keywordSet()
	for kw := range ks {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func adjustConfidenceByContext(rule Rule, lineContent string) findingConfidence {
	if rule.RequireKeyword {
		if containsKeyword(lineContent) {
			return finding.ConfHigh
		}
		return finding.ConfLow
	}
	if !containsKeyword(lineContent) {
		return finding.ConfMedium
	}
	return rule.Confidence
}
