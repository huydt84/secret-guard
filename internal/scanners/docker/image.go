package docker

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/huydinhtrong/secretguard/internal/detector"
	"github.com/huydinhtrong/secretguard/internal/finding"
)

type ImageScanner struct {
	image string
	det   *detector.Detector
}

func NewImageScanner(image string, det *detector.Detector) *ImageScanner {
	return &ImageScanner{image: image, det: det}
}

func (s *ImageScanner) Scan() ([]finding.Finding, error) {
	if !dockerAvailable() {
		return nil, fmt.Errorf("Docker daemon unavailable — cannot inspect image %s", s.image)
	}

	out, err := exec.Command("docker", "history", "--no-trunc", s.image).Output()
	if err != nil {
		return nil, fmt.Errorf("docker history %s: %w", s.image, err)
	}

	return scanHistoryOutput(string(out), s.image, s.det), nil
}

func scanHistoryOutput(output, image string, det *detector.Detector) []finding.Finding {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	var findings []finding.Finding

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "IMAGE") {
			continue
		}

		// Format: IMAGE \t CREATED \t CREATED BY \t SIZE (\t COMMENT)
		parts := strings.SplitN(line, "\t", 5)
		if len(parts) < 4 {
			continue
		}

		createdBy := strings.TrimSpace(parts[2])
		if createdBy == "" {
			continue
		}

		lineNum := i + 1
		fs := det.DetectAll(finding.SourceDocker, fmt.Sprintf("image:%s", image), []byte(createdBy))
		for j := range fs {
			fs[j].Location = finding.Location{
				Path:   fmt.Sprintf("image:%s", image),
				Line:   lineNum,
				Column: 1,
			}
		}
		findings = append(findings, fs...)
	}

	return findings
}

func dockerAvailable() bool {
	err := exec.Command("docker", "info").Run()
	return err == nil
}
