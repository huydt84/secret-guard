package detector

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/huydt84/secret-guard/internal/finding"
)

type findingConfidence = finding.Confidence

type matchResult struct {
	value  string
	line   int
	column int
	offset int
}

type Detector struct {
	rules     []Rule
	allowlist *Allowlist
}

func (d *Detector) Rules() []Rule         { return d.rules }
func (d *Detector) Allowlist() *Allowlist { return d.allowlist }

func New(rules []Rule, allowlist *Allowlist) *Detector {
	return &Detector{
		rules:     rules,
		allowlist: allowlist,
	}
}

func (d *Detector) DetectAll(source finding.SourceKind, path string, content []byte) []finding.Finding {
	text := string(content)
	var findings []finding.Finding
	var covered []interval

	for _, rule := range d.rules {
		matches := rule.Pattern.FindAllStringIndex(text, -1)
		for _, m := range matches {
			secret := text[m[0]:m[1]]
			lineNum, colNum := positionFromOffset(text, m[0])
			lineContent := extractLine(text, m[0])

			adjConf := adjustConfidenceByContext(rule, lineContent)

			if adjConf == finding.ConfLow {
				continue
			}

			if d.allowlist != nil && d.allowlist.IsAllowed(secret, path) {
				continue
			}

			covered = append(covered, interval{m[0], m[1]})

			f := finding.Finding{
				ID:          generateID(rule.ID, secret, path, lineNum),
				Source:      source,
				DetectorID:  rule.ID,
				SecretKind:  rule.Kind,
				Severity:    rule.Severity,
				Confidence:  adjConf,
				Location:    finding.Location{Path: path, Line: lineNum, Column: colNum},
				Preview:     finding.MaskPreview(secret),
				Fingerprint: finding.GenerateFingerprint(secret),
				Evidence:    finding.Evidence{Context: maskSecretInLine(lineContent, secret)},
			}
			findings = append(findings, f)
		}
	}

	entropyMatches := findHighEntropyTokens(text)
	for _, m := range entropyMatches {
		if isCovered(covered, m.offset, m.offset+len(m.value)) {
			continue
		}

		if d.allowlist != nil && d.allowlist.IsAllowed(m.value, path) {
			continue
		}

		lineContent := extractLine(text, m.offset)

		adjConf := finding.ConfMedium
		if containsKeyword(lineContent) {
			adjConf = finding.ConfHigh
		}

		f := finding.Finding{
			ID:          generateID(entropyRule.ID, m.value, path, m.line),
			Source:      source,
			DetectorID:  entropyRule.ID,
			SecretKind:  entropyRule.Kind,
			Severity:    entropyRule.Severity,
			Confidence:  adjConf,
			Location:    finding.Location{Path: path, Line: m.line, Column: m.column},
			Preview:     finding.MaskPreview(m.value),
			Fingerprint: finding.GenerateFingerprint(m.value),
			Evidence:    finding.Evidence{Context: maskSecretInLine(lineContent, m.value)},
		}
		findings = append(findings, f)
	}

	return findings
}

type interval struct{ start, end int }

func isCovered(intervals []interval, start, end int) bool {
	for _, iv := range intervals {
		if start >= iv.start && end <= iv.end {
			return true
		}
	}
	return false
}

func positionFromOffset(text string, offset int) (line, col int) {
	line = 1
	col = 1
	for i, c := range text {
		if i >= offset {
			break
		}
		if c == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

func extractLine(text string, offset int) string {
	start := offset
	for start > 0 && text[start-1] != '\n' {
		start--
	}
	end := offset
	for end < len(text) && text[end] != '\n' {
		end++
	}
	if end > start {
		return text[start:end]
	}
	return ""
}

func maskSecretInLine(line, secret string) string {
	if secret == "" || !strings.Contains(line, secret) {
		return line
	}
	return strings.ReplaceAll(line, secret, "[REDACTED]")
}

func generateID(ruleID, secret, path string, line int) string {
	h := sha256Of(fmt.Sprintf("%s:%s:%s:%d", ruleID, secret, path, line))
	return fmt.Sprintf("sg-%x", h[:8])
}

func sha256Of(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}
