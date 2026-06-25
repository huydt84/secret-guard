package docker

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/huydt84/secret-guard/internal/detector"
	"github.com/huydt84/secret-guard/internal/finding"
)

var (
	envLine   = regexp.MustCompile(`(?i)^\s*ENV\s+(.+)$`)
	argLine   = regexp.MustCompile(`(?i)^\s*ARG\s+(.+)$`)
	copyEnv   = regexp.MustCompile(`(?i)^\s*(COPY|ADD)\s+(?:--[a-z]+\S*\s+)*\.env\b`)
	runLine   = regexp.MustCompile(`(?i)^\s*RUN\s+(.+)$`)
	exportPat = regexp.MustCompile(`(?i)(export|echo|printf)\s+([A-Za-z_][A-Za-z0-9_]*=?\S+)`)
)

type DockerfileScanner struct {
	path string
	det  *detector.Detector
}

func NewDockerfileScanner(path string, det *detector.Detector) *DockerfileScanner {
	return &DockerfileScanner{path: path, det: det}
}

func (s *DockerfileScanner) Scan() ([]finding.Finding, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read dockerfile: %w", err)
	}

	content := string(data)
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")

	var findings []finding.Finding
	for i, line := range lines {
		lineNum := i + 1

		if m := envLine.FindStringSubmatch(line); m != nil {
			fs := scanEnvOrArgs(s.path, "ENV", m[1], s.det, lineNum)
			findings = append(findings, fs...)
		}

		if m := argLine.FindStringSubmatch(line); m != nil {
			fs := scanEnvOrArgs(s.path, "ARG", m[1], s.det, lineNum)
			findings = append(findings, fs...)
		}

		if copyEnv.MatchString(line) {
			findings = append(findings, finding.Finding{
				ID:          fmt.Sprintf("dockerfile-risk-%d", lineNum),
				Source:      finding.SourceDocker,
				DetectorID:  "dockerfile-risk",
				SecretKind:  "Dockerfile Risk",
				Severity:    finding.SevMedium,
				Confidence:  finding.ConfHigh,
				Location:    finding.Location{Path: s.path, Line: lineNum, Column: 1},
				Preview:     finding.MaskPreview(".env file"),
				Fingerprint: fmt.Sprintf("sha256:dockerfile-copy-env-%d", lineNum),
			})
		}

		if m := runLine.FindStringSubmatch(line); m != nil {
			fs := scanRunLine(s.path, m[1], s.det, lineNum)
			findings = append(findings, fs...)
		}
	}

	return findings, nil
}

func scanEnvOrArgs(path, directive, value string, det *detector.Detector, lineNum int) []finding.Finding {
	var findings []finding.Finding

	pairs := splitEnvPairs(value)
	for _, pair := range pairs {
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			continue
		}
		val := pair[eq+1:]

		fs := det.DetectAll(finding.SourceDocker, path, []byte(val))
		for i := range fs {
			fs[i].Location = finding.Location{Path: path, Line: lineNum, Column: 1}
			fs[i].Metadata = map[string]string{"directive": directive}
		}
		findings = append(findings, fs...)
	}

	return findings
}

func splitEnvPairs(value string) []string {
	var pairs []string
	var current strings.Builder
	quote := byte(0)

	for i := 0; i < len(value); i++ {
		ch := value[i]
		if quote != 0 {
			current.WriteByte(ch)
			if ch == quote && (i == 0 || value[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			current.WriteByte(ch)
			continue
		}
		if ch == ' ' || ch == '\t' {
			s := strings.TrimSpace(current.String())
			if s != "" {
				pairs = append(pairs, s)
			}
			current.Reset()
			continue
		}
		current.WriteByte(ch)
	}
	s := strings.TrimSpace(current.String())
	if s != "" {
		pairs = append(pairs, s)
	}

	return pairs
}

func scanRunLine(path, cmd string, det *detector.Detector, lineNum int) []finding.Finding {
	var findings []finding.Finding

	exportMatches := exportPat.FindAllStringSubmatch(cmd, -1)
	for _, m := range exportMatches {
		exported := m[2]
		fs := det.DetectAll(finding.SourceDocker, path, []byte(exported))
		for i := range fs {
			fs[i].Location = finding.Location{Path: path, Line: lineNum, Column: 1}
			if fs[i].Metadata == nil {
				fs[i].Metadata = make(map[string]string)
			}
			fs[i].Metadata["directive"] = "RUN"
		}
		findings = append(findings, fs...)
	}

	return findings
}

// ScanDockerfile is a convenience wrapper.
func ScanDockerfile(path string, det *detector.Detector) ([]finding.Finding, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return NewDockerfileScanner(abs, det).Scan()
}
