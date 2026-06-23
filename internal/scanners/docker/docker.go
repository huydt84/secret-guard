package docker

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/huydinhtrong/secretguard/internal/detector"
	"github.com/huydinhtrong/secretguard/internal/finding"
)

var supportedComposeNames = map[string]bool{
	"docker-compose.yml":  true,
	"docker-compose.yaml": true,
	"compose.yml":         true,
	"compose.yaml":        true,
}

type Scanner struct {
	det *detector.Detector
}

func New(det *detector.Detector) *Scanner {
	return &Scanner{det: det}
}

func (s *Scanner) ScanDockerfile(path string) ([]finding.Finding, error) {
	return ScanDockerfile(path, s.det)
}

func (s *Scanner) ScanCompose(path string) ([]finding.Finding, error) {
	return ScanCompose(path, s.det)
}

func (s *Scanner) ScanContainer(container string) ([]finding.Finding, error) {
	scanner := NewContainerScanner(container, s.det)
	return scanner.Scan()
}

func (s *Scanner) ScanImage(image string) ([]finding.Finding, error) {
	scanner := NewImageScanner(image, s.det)
	return scanner.Scan()
}

// ScanDocker runs all applicable Docker scanners in best-effort mode.
// If Docker daemon is unavailable for container/image scans, it logs warnings.
func (s *Scanner) ScanDocker(ctx context.Context, root string) ([]finding.Finding, error) {
	var allFindings []finding.Finding

	dockerfile := filepath.Join(root, "Dockerfile")
	if fi, err := filepath.Glob(dockerfile); err == nil && len(fi) > 0 {
		fs, err := s.ScanDockerfile(dockerfile)
		if err == nil {
			allFindings = append(allFindings, fs...)
		}
	}

	for name := range supportedComposeNames {
		composePath := filepath.Join(root, name)
		if fi, err := filepath.Glob(composePath); err == nil && len(fi) > 0 {
			fs, err := s.ScanCompose(composePath)
			if err == nil {
				allFindings = append(allFindings, fs...)
			}
		}
	}

	return allFindings, nil
}

func IsComposeFile(name string) bool {
	return supportedComposeNames[strings.ToLower(name)]
}
