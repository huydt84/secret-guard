package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/huydinhtrong/secretguard/internal/detector"
	"github.com/huydinhtrong/secretguard/internal/finding"
)

const DefaultMaxFileSize int64 = 10 * 1024 * 1024 // 10 MB

var ignoredDirNames = map[string]bool{
	"node_modules": true,
	".venv":        true,
	"venv":         true,
	"target":       true,
	"dist":         true,
	"build":        true,
	".next":        true,
}

var ignoredRelativePaths = []string{
	".git/objects",
}

type Scanner struct {
	det         *detector.Detector
	maxFileSize int64
}

type Option func(*Scanner)

func WithMaxFileSize(size int64) Option {
	return func(s *Scanner) {
		if size > 0 {
			s.maxFileSize = size
		}
	}
}

func New(det *detector.Detector, opts ...Option) *Scanner {
	s := &Scanner{
		det:         det,
		maxFileSize: DefaultMaxFileSize,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) Scan(root string) ([]finding.Finding, error) {
	var allFindings []finding.Finding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if ignoredDirNames[info.Name()] {
				return filepath.SkipDir
			}
			rel, err := filepath.Rel(root, path)
			if err == nil {
				for _, ignored := range ignoredRelativePaths {
					if rel == ignored || strings.HasPrefix(rel, ignored+"/") {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		if info.Size() > s.maxFileSize {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		if isBinary(data) {
			return nil
		}

		findings := s.det.DetectAll(finding.SourceFile, path, data)
		allFindings = append(allFindings, findings...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}

	return allFindings, nil
}

func isBinary(data []byte) bool {
	n := len(data)
	if n > 512 {
		n = 512
	}
	for _, b := range data[:n] {
		if b == 0 {
			return true
		}
	}
	return false
}
