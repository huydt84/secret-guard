package docker

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/huydinhtrong/secretguard/internal/detector"
	"github.com/huydinhtrong/secretguard/internal/finding"
)

type ContainerScanner struct {
	container string
	det       *detector.Detector
}

func NewContainerScanner(container string, det *detector.Detector) *ContainerScanner {
	return &ContainerScanner{container: container, det: det}
}

type containerInspect struct {
	Config *struct {
		Env         []string          `json:"Env"`
		Cmd         []string          `json:"Cmd"`
		Entrypoint  []string          `json:"Entrypoint"`
		Labels      map[string]string `json:"Labels"`
		Healthcheck *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	HostConfig *struct {
		Binds []string `json:"Binds"`
	} `json:"HostConfig"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
}

func (s *ContainerScanner) Scan() ([]finding.Finding, error) {
	if !dockerAvailable() {
		return nil, fmt.Errorf("Docker daemon unavailable — cannot inspect container %s", s.container)
	}

	out, err := exec.Command("docker", "inspect", s.container).Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect %s: %w", s.container, err)
	}

	var containers []containerInspect
	if err := json.Unmarshal(out, &containers); err != nil {
		return nil, fmt.Errorf("parse inspect output: %w", err)
	}
	if len(containers) == 0 {
		return nil, fmt.Errorf("container %s not found", s.container)
	}

	ci := containers[0]
	var findings []finding.Finding
	prefix := fmt.Sprintf("container:%s", s.container)

	if ci.Config != nil {
		cf := scanContainerEnv(prefix, ci.Config.Env, s.det)
		findings = append(findings, cf...)

		cf = scanContainerCmd(prefix, "Cmd", ci.Config.Cmd, s.det)
		findings = append(findings, cf...)

		cf = scanContainerCmd(prefix, "Entrypoint", ci.Config.Entrypoint, s.det)
		findings = append(findings, cf...)

		cf = scanContainerLabels(prefix, ci.Config.Labels, s.det)
		findings = append(findings, cf...)

		if ci.Config.Healthcheck != nil {
			cf = scanContainerCmd(prefix, "Healthcheck.Test", ci.Config.Healthcheck.Test, s.det)
			findings = append(findings, cf...)
		}
	}

	if ci.HostConfig != nil {
		hf := scanContainerStrings(prefix, "HostConfig.Binds", ci.HostConfig.Binds, s.det)
		findings = append(findings, hf...)
	}

	for i, m := range ci.Mounts {
		mfs := s.det.DetectAll(finding.SourceDocker, prefix+"/Mounts/"+fmt.Sprint(i)+"/Source", []byte(m.Source))
		findings = append(findings, mfs...)
		mfs = s.det.DetectAll(finding.SourceDocker, prefix+"/Mounts/"+fmt.Sprint(i)+"/Destination", []byte(m.Destination))
		findings = append(findings, mfs...)
	}

	return findings, nil
}

func scanContainerEnv(prefix string, env []string, det *detector.Detector) []finding.Finding {
	var findings []finding.Finding

	for _, e := range env {
		eq := strings.IndexByte(e, '=')
		if eq < 0 {
			continue
		}
		key := e[:eq]
		val := e[eq+1:]

		fs := det.DetectAll(finding.SourceDocker, prefix+"/Env/"+key, []byte(val))
		for i := range fs {
			if fs[i].Metadata == nil {
				fs[i].Metadata = make(map[string]string)
			}
			fs[i].Metadata["field"] = "Config.Env." + key
		}
		findings = append(findings, fs...)
	}

	return findings
}

func scanContainerCmd(prefix, field string, cmd []string, det *detector.Detector) []finding.Finding {
	var findings []finding.Finding

	for _, c := range cmd {
		fs := det.DetectAll(finding.SourceDocker, prefix+"/"+field, []byte(c))
		findings = append(findings, fs...)
	}

	return findings
}

func scanContainerLabels(prefix string, labels map[string]string, det *detector.Detector) []finding.Finding {
	var findings []finding.Finding

	for key, val := range labels {
		fs := det.DetectAll(finding.SourceDocker, prefix+"/Labels/"+key, []byte(val))
		findings = append(findings, fs...)
	}

	return findings
}

func scanContainerStrings(prefix, field string, strs []string, det *detector.Detector) []finding.Finding {
	var findings []finding.Finding

	for _, s := range strs {
		fs := det.DetectAll(finding.SourceDocker, prefix+"/"+field, []byte(s))
		findings = append(findings, fs...)
	}

	return findings
}
