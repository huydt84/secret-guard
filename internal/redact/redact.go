package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/huydt84/secret-guard/internal/detector"
	"github.com/huydt84/secret-guard/internal/finding"
)

var binaryExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".ico": true, ".svg": true, ".webp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".zip": true, ".tar": true, ".gz": true, ".bz2": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".db": true, ".sqlite": true, ".sqlite3": true,
}

func Marker(secretKind, fingerprint string) string {
	return fmt.Sprintf("[REDACTED:%s:%s]", secretKind, fingerprint)
}

type matchInterval struct {
	start, end  int
	value       string
	secretKind  string
	fingerprint string
	finding     finding.Finding
}

type Result struct {
	Content  []byte
	Findings []finding.Finding
}

func RedactText(content []byte, det *detector.Detector) (*Result, error) {
	text := string(content)
	var intervals []matchInterval

	for _, rule := range det.Rules() {
		locs := rule.Pattern.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			secret := text[loc[0]:loc[1]]
			if det.Allowlist() != nil && det.Allowlist().IsAllowed(secret, "") {
				continue
			}
			fp := finding.GenerateFingerprint(secret)
			intervals = append(intervals, matchInterval{
				start:       loc[0],
				end:         loc[1],
				value:       secret,
				secretKind:  rule.Kind,
				fingerprint: fp,
				finding: finding.Finding{
					ID:          fmt.Sprintf("redact-%x", fp),
					Source:      finding.SourceFile,
					DetectorID:  rule.ID,
					SecretKind:  rule.Kind,
					Severity:    rule.Severity,
					Confidence:  rule.Confidence,
					Preview:     finding.MaskPreview(secret),
					Fingerprint: fp,
				},
			})
		}
	}

	if len(intervals) == 0 {
		return &Result{Content: content}, nil
	}

	sort.Slice(intervals, func(i, j int) bool {
		return intervals[i].start < intervals[j].start
	})

	var merged []matchInterval
	for _, iv := range intervals {
		if len(merged) > 0 && iv.start < merged[len(merged)-1].end {
			continue
		}
		merged = append(merged, iv)
	}

	var b strings.Builder
	cursor := 0
	for _, m := range merged {
		b.WriteString(text[cursor:m.start])
		b.WriteString(Marker(m.secretKind, m.fingerprint))
		cursor = m.end
	}
	b.WriteString(text[cursor:])

	findings := make([]finding.Finding, len(merged))
	for i, m := range merged {
		findings[i] = m.finding
	}

	return &Result{Content: []byte(b.String()), Findings: findings}, nil
}

func RedactJSON(content []byte, det *detector.Detector) (*Result, error) {
	var root any
	if err := json.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	var findings []finding.Finding
	redactJSONValue(&root, det, &findings)

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal redacted JSON: %w", err)
	}

	return &Result{Content: out, Findings: findings}, nil
}

func redactJSONValue(v *any, det *detector.Detector, findings *[]finding.Finding) {
	switch val := (*v).(type) {
	case string:
		for _, rule := range det.Rules() {
			if rule.Pattern.MatchString(val) {
				if det.Allowlist() != nil && det.Allowlist().IsAllowed(val, "") {
					continue
				}
				fp := finding.GenerateFingerprint(val)
				*findings = append(*findings, finding.Finding{
					ID:          fmt.Sprintf("redact-%x", fp),
					Source:      finding.SourceFile,
					DetectorID:  rule.ID,
					SecretKind:  rule.Kind,
					Severity:    rule.Severity,
					Confidence:  rule.Confidence,
					Preview:     finding.MaskPreview(val),
					Fingerprint: fp,
				})
				*v = Marker(rule.Kind, fp)
				return
			}
		}
	case map[string]any:
		for k := range val {
			vv := val[k]
			redactJSONValue(&vv, det, findings)
			val[k] = vv
		}
	case []any:
		for i := range val {
			redactJSONValue(&val[i], det, findings)
		}
	}
}

func RedactJSONL(content []byte, det *detector.Detector) (*Result, error) {
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	var outBuf bytes.Buffer
	var allFindings []finding.Finding

	for i, line := range lines {
		if i > 0 {
			outBuf.WriteByte('\n')
		}
		if strings.TrimSpace(line) == "" {
			outBuf.WriteString(line)
			continue
		}

		var parsed any
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			result, err := RedactText([]byte(line), det)
			if err != nil {
				outBuf.WriteString(line)
				continue
			}
			outBuf.Write(result.Content)
			allFindings = append(allFindings, result.Findings...)
			continue
		}

		var findings []finding.Finding
		redactJSONValue(&parsed, det, &findings)

		compacted, err := json.Marshal(parsed)
		if err != nil {
			outBuf.WriteString(line)
			continue
		}
		outBuf.Write(compacted)
		allFindings = append(allFindings, findings...)
	}

	return &Result{Content: outBuf.Bytes(), Findings: allFindings}, nil
}

func RedactFile(path string, det *detector.Detector) (*Result, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if binaryExts[ext] {
		return nil, fmt.Errorf("cannot redact binary file: %s", path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	switch ext {
	case ".json":
		return RedactJSON(content, det)
	case ".jsonl":
		return RedactJSONL(content, det)
	default:
		return RedactText(content, det)
	}
}
