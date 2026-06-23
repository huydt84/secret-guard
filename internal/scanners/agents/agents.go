package agents

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/huydinhtrong/secretguard/internal/detector"
	"github.com/huydinhtrong/secretguard/internal/finding"
)

var supportedExts = map[string]bool{
	".txt":   true,
	".log":   true,
	".md":    true,
	".json":  true,
	".jsonl": true,
}

type AgentPath struct {
	Path  string `json:"path"`
	Agent string `json:"agent"`
}

type AgentScanner interface {
	Name() string
	DiscoverPaths(ctx context.Context) ([]AgentPath, error)
	ScanPath(ctx context.Context, path string, det *detector.Detector) ([]finding.Finding, error)
}

type CodexScanner struct{}

func (CodexScanner) Name() string { return "codex" }

func (s CodexScanner) DiscoverPaths(ctx context.Context) ([]AgentPath, error) {
	return discoverAgentDirs("codex", ".codex")
}

func (s CodexScanner) ScanPath(ctx context.Context, path string, det *detector.Detector) ([]finding.Finding, error) {
	return scanAgentPath(ctx, path, det, "codex")
}

type OpenCodeScanner struct{}

func (OpenCodeScanner) Name() string { return "opencode" }

func (s OpenCodeScanner) DiscoverPaths(ctx context.Context) ([]AgentPath, error) {
	return discoverOpenCodePaths()
}

func (s OpenCodeScanner) ScanPath(ctx context.Context, path string, det *detector.Detector) ([]finding.Finding, error) {
	return scanAgentPath(ctx, path, det, "opencode")
}

type CopilotScanner struct {
	IncludeVSCodeStorage bool
}

func (s CopilotScanner) Name() string { return "copilot" }

func (s CopilotScanner) DiscoverPaths(ctx context.Context) ([]AgentPath, error) {
	return discoverCopilotPaths(s.IncludeVSCodeStorage)
}

func (s CopilotScanner) ScanPath(ctx context.Context, path string, det *detector.Detector) ([]finding.Finding, error) {
	return scanAgentPath(ctx, path, det, "copilot")
}

func discoverAgentDirs(name string, relPaths ...string) ([]AgentPath, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil
	}

	var paths []AgentPath
	for _, rel := range relPaths {
		if path := resolveAgentPath(home, cwd, rel); path != "" {
			paths = append(paths, AgentPath{Path: path, Agent: name})
		}
	}
	return paths, nil
}

func discoverOpenCodePaths() ([]AgentPath, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil
	}

	var paths []AgentPath
	for _, candidate := range []string{filepath.Join("~", ".local", "share", "opencode", "log"), ".opencode"} {
		if path := resolveAgentPath(home, cwd, candidate); path != "" {
			paths = append(paths, AgentPath{Path: path, Agent: "opencode"})
		}
	}

	return paths, nil
}

func discoverCopilotPaths(includeVSCodeStorage bool) ([]AgentPath, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil
	}

	var dirs []string
	if copilotHome := os.Getenv("COPILOT_HOME"); copilotHome != "" {
		dirs = append(dirs, copilotHome)
	}
	dirs = append(dirs, filepath.Join(home, ".copilot"))
	if includeVSCodeStorage {
		dirs = append(dirs,
			filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "github.copilot"),
			filepath.Join(home, ".config", "Code", "User", "globalStorage", "github.copilot"),
		)
	}

	var paths []AgentPath
	for _, d := range dirs {
		if path := resolveAgentPath(home, cwd, d); path != "" {
			paths = append(paths, AgentPath{Path: path, Agent: "copilot"})
		}
	}
	return paths, nil
}

func resolveAgentPath(home, cwd, candidate string) string {
	path := candidate
	if strings.HasPrefix(candidate, "~/") {
		path = filepath.Join(home, strings.TrimPrefix(candidate, "~/"))
	} else if !filepath.IsAbs(candidate) {
		path = filepath.Join(cwd, candidate)
	}

	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return path
	}
	return ""
}

func scanAgentPath(ctx context.Context, path string, det *detector.Detector, agent string) ([]finding.Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("agent path %s: %w", path, err)
	}

	if !info.IsDir() {
		return scanAgentFile(path, det, agent)
	}

	var allFindings []finding.Finding
	err = filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if fi.IsDir() {
			return nil
		}
		if fi.Size() == 0 {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(p))
		if !supportedExts[ext] {
			return nil
		}

		findings, err := scanAgentFile(p, det, agent)
		if err != nil {
			return fmt.Errorf("scan %s: %w", p, err)
		}
		allFindings = append(allFindings, findings...)
		return nil
	})
	return allFindings, err
}

func scanAgentFile(path string, det *detector.Detector, agent string) ([]finding.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	findings := det.DetectAll(finding.SourceAgent, path, data)

	ext := strings.ToLower(filepath.Ext(path))
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	for i := range findings {
		if findings[i].Metadata == nil {
			findings[i].Metadata = make(map[string]string)
		}
		findings[i].Metadata["agent"] = agent

		if ext == ".json" || ext == ".jsonl" {
			if field := extractJSONField(lines, findings[i].Location.Line, findings[i].Location.Column); field != "" {
				findings[i].Metadata["field"] = field
			}
		}
	}

	return findings, nil
}

var jsonFieldPattern = regexp.MustCompile(`"([^"]+)"\s*:\s*`)

func extractJSONField(lines []string, lineNum, column int) string {
	if lineNum <= 0 || lineNum > len(lines) {
		return ""
	}
	line := lines[lineNum-1]
	if column > 0 && column <= len(line) {
		line = line[:column-1]
	}
	matches := jsonFieldPattern.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1][1]
}
