package docker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/huydt84/secret-guard/internal/detector"
	"github.com/huydt84/secret-guard/internal/finding"
	"gopkg.in/yaml.v3"
)

type ComposeScanner struct {
	path string
	det  *detector.Detector
}

func NewComposeScanner(path string, det *detector.Detector) *ComposeScanner {
	return &ComposeScanner{path: path, det: det}
}

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	Environment any                 `yaml:"environment"`
	EnvFile     string              `yaml:"env_file"`
	Build       *composeBuild       `yaml:"build"`
	Labels      map[string]string   `yaml:"labels"`
	Command     any                 `yaml:"command"`
	Entrypoint  any                 `yaml:"entrypoint"`
	Healthcheck *composeHealthcheck `yaml:"healthcheck"`
}

type composeBuild struct {
	Args map[string]string `yaml:"args"`
}

type composeHealthcheck struct {
	Test any `yaml:"test"`
}

func (s *ComposeScanner) Scan() ([]finding.Finding, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read compose: %w", err)
	}

	var cf composeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("parse compose: %w", err)
	}

	var findings []finding.Finding

	for svcName, svc := range cf.Services {
		prefix := fmt.Sprintf("%s/service:%s", s.path, svcName)

		fs := scanComposeEnvironment(prefix, svc.Environment, s.det)
		findings = append(findings, fs...)

		if svc.EnvFile != "" {
			findings = append(findings, finding.Finding{
				ID:          fmt.Sprintf("compose-risk-%s-envfile", svcName),
				Source:      finding.SourceDocker,
				DetectorID:  "compose-risk",
				SecretKind:  "Compose Risk",
				Severity:    finding.SevMedium,
				Confidence:  finding.ConfHigh,
				Location:    finding.Location{Path: s.path, Line: 1},
				Preview:     finding.MaskPreview("env_file"),
				Fingerprint: fmt.Sprintf("sha256:compose-envfile-%s", svcName),
			})
		}

		if svc.Build != nil {
			fs := scanComposeBuildArgs(prefix, svc.Build, s.det)
			findings = append(findings, fs...)
		}

		fs = scanComposeLabels(prefix, svc.Labels, s.det)
		findings = append(findings, fs...)

		fs = scanComposeCommandLike(prefix, "command", svc.Command, s.det)
		findings = append(findings, fs...)

		fs = scanComposeCommandLike(prefix, "entrypoint", svc.Entrypoint, s.det)
		findings = append(findings, fs...)

		if svc.Healthcheck != nil {
			fs := scanComposeHealthcheck(prefix, svc.Healthcheck, s.det)
			findings = append(findings, fs...)
		}
	}

	return findings, nil
}

func scanComposeEnvironment(prefix string, env any, det *detector.Detector) []finding.Finding {
	if env == nil {
		return nil
	}

	var findings []finding.Finding

	switch v := env.(type) {
	case map[string]any:
		for key, val := range v {
			valStr, ok := val.(string)
			if !ok {
				continue
			}
			fs := det.DetectAll(finding.SourceDocker, prefix+"/"+key, []byte(valStr))
			for i := range fs {
				if fs[i].Metadata == nil {
					fs[i].Metadata = make(map[string]string)
				}
				fs[i].Metadata["field"] = key
			}
			findings = append(findings, fs...)
		}
	case []any:
		for _, item := range v {
			itemStr, ok := item.(string)
			if !ok {
				continue
			}
			eq := strings.IndexByte(itemStr, '=')
			if eq < 0 {
				continue
			}
			val := itemStr[eq+1:]
			key := itemStr[:eq]
			fs := det.DetectAll(finding.SourceDocker, prefix+"/"+key, []byte(val))
			for i := range fs {
				if fs[i].Metadata == nil {
					fs[i].Metadata = make(map[string]string)
				}
				fs[i].Metadata["field"] = key
			}
			findings = append(findings, fs...)
		}
	}

	return findings
}

func scanComposeBuildArgs(prefix string, build *composeBuild, det *detector.Detector) []finding.Finding {
	var findings []finding.Finding

	for key, val := range build.Args {
		fs := det.DetectAll(finding.SourceDocker, prefix+"/build.args/"+key, []byte(val))
		for i := range fs {
			if fs[i].Metadata == nil {
				fs[i].Metadata = make(map[string]string)
			}
			fs[i].Metadata["field"] = "build.args." + key
		}
		findings = append(findings, fs...)
	}

	return findings
}

func scanComposeLabels(prefix string, labels map[string]string, det *detector.Detector) []finding.Finding {
	var findings []finding.Finding

	for key, val := range labels {
		fs := det.DetectAll(finding.SourceDocker, prefix+"/labels/"+key, []byte(val))
		findings = append(findings, fs...)
	}

	return findings
}

func scanComposeCommandLike(prefix, field string, cmd any, det *detector.Detector) []finding.Finding {
	if cmd == nil {
		return nil
	}

	var findings []finding.Finding

	switch v := cmd.(type) {
	case string:
		fs := det.DetectAll(finding.SourceDocker, prefix+"/"+field, []byte(v))
		findings = append(findings, fs...)
	case []any:
		for _, item := range v {
			itemStr, ok := item.(string)
			if !ok {
				continue
			}
			fs := det.DetectAll(finding.SourceDocker, prefix+"/"+field, []byte(itemStr))
			findings = append(findings, fs...)
		}
	}

	return findings
}

func scanComposeHealthcheck(prefix string, hc *composeHealthcheck, det *detector.Detector) []finding.Finding {
	return scanComposeCommandLike(prefix, "healthcheck.test", hc.Test, det)
}

func ScanCompose(path string, det *detector.Detector) ([]finding.Finding, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return NewComposeScanner(abs, det).Scan()
}
