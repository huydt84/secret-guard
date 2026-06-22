package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version   int          `yaml:"version"`
	Scan      ScanConfig   `yaml:"scan"`
	Report    ReportConfig `yaml:"report"`
	Redaction RedactConfig `yaml:"redaction"`
	Allowlist Allowlist    `yaml:"allowlist"`
	Rules     RulesConfig  `yaml:"rules"`
}

type ScanConfig struct {
	Git    GitScanConfig    `yaml:"git"`
	Agents AgentsScanConfig `yaml:"agents"`
	Docker DockerScanConfig `yaml:"docker"`
}

type GitScanConfig struct {
	WorkingTree bool `yaml:"working_tree"`
	Staged      bool `yaml:"staged"`
	History     bool `yaml:"history"`
}

type AgentsScanConfig struct {
	Enabled  bool        `yaml:"enabled"`
	Codex    AgentConfig `yaml:"codex"`
	Opencode AgentConfig `yaml:"opencode"`
	Copilot  AgentConfig `yaml:"copilot"`
}

type AgentConfig struct {
	Enabled bool     `yaml:"enabled"`
	Paths   []string `yaml:"paths"`
}

type DockerScanConfig struct {
	Enabled    bool `yaml:"enabled"`
	Containers bool `yaml:"containers"`
	Images     bool `yaml:"images"`
	Compose    bool `yaml:"compose"`
	Dockerfile bool `yaml:"dockerfile"`
}

type ReportConfig struct {
	Format            string `yaml:"format"`
	FailOn            string `yaml:"fail_on"`
	ShowFingerprints  bool   `yaml:"show_fingerprints"`
	ShowSecretPreview bool   `yaml:"show_secret_preview"`
}

type RedactConfig struct {
	Backup  bool   `yaml:"backup"`
	Mode    string `yaml:"mode"`
	InPlace bool   `yaml:"in_place"`
}

type Allowlist struct {
	Paths        []string `yaml:"paths"`
	Fingerprints []string `yaml:"fingerprints"`
	Regexes      []string `yaml:"regexes"`
}

type RulesConfig struct {
	Custom []CustomRule `yaml:"custom"`
}

type CustomRule struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Severity string `yaml:"severity"`
}

func Default() *Config {
	return &Config{
		Version: 1,
		Scan: ScanConfig{
			Git: GitScanConfig{
				WorkingTree: true,
				Staged:      false,
				History:     false,
			},
			Agents: AgentsScanConfig{
				Enabled: true,
			},
			Docker: DockerScanConfig{
				Enabled: false,
			},
		},
		Report: ReportConfig{
			Format:            "terminal",
			FailOn:            "high",
			ShowFingerprints:  true,
			ShowSecretPreview: true,
		},
		Redaction: RedactConfig{
			Backup:  true,
			Mode:    "fingerprint",
			InPlace: false,
		},
		Allowlist: Allowlist{
			Regexes: []string{"dummy_[A-Za-z0-9]+"},
		},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}
