package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/huydt84/secret-guard/internal/config"
	"github.com/huydt84/secret-guard/internal/detector"
	"github.com/huydt84/secret-guard/internal/finding"
	"github.com/huydt84/secret-guard/internal/report"
	"github.com/huydt84/secret-guard/internal/scanners/agents"
	"github.com/huydt84/secret-guard/internal/scanners/docker"
	"github.com/huydt84/secret-guard/internal/scanners/filesystem"
	"github.com/huydt84/secret-guard/internal/scanners/git"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan for secrets in files, git, agents, or Docker",
	Long: `Scan for leaked secrets in the working tree, git history,
AI-agent session data, and Docker metadata.

If no path is given, scans the current directory.`,
	Args:          cobra.MaximumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "."
		if len(args) > 0 {
			path = args[0]
		}

		cfg := appCfg
		if cfg == nil {
			cfg = config.Default()
		}

		al, err := detector.NewAllowlist(
			cfg.Allowlist.Paths,
			cfg.Allowlist.Fingerprints,
			cfg.Allowlist.Regexes,
		)
		if err != nil {
			return fmt.Errorf("build allowlist: %w", err)
		}

		det := detector.New(detector.BuiltinRules, al)

		gitMode, _ := cmd.Flags().GetBool("git")
		gitStaged, _ := cmd.Flags().GetBool("git-staged")
		gitHistory, _ := cmd.Flags().GetBool("git-history")
		gitEnabled := gitMode || gitStaged || gitHistory

		agentsFlag, _ := cmd.Flags().GetString("agents")
		agentPath, _ := cmd.Flags().GetString("agent-path")

		dockerMode, _ := cmd.Flags().GetBool("docker")
		dockerfilePath, _ := cmd.Flags().GetString("dockerfile")
		composePath, _ := cmd.Flags().GetString("compose")
		containerID, _ := cmd.Flags().GetString("docker-container")
		imageID, _ := cmd.Flags().GetString("docker-image")
		dockerEnabled := dockerMode || dockerfilePath != "" || composePath != "" || containerID != "" || imageID != ""

		findings := make([]finding.Finding, 0)

		if gitEnabled {
			gitScanner := git.New(det)
			if gitMode {
				untracked, _ := cmd.Flags().GetBool("include-untracked")
				fs, err := gitScanner.ScanWorkingTree(path, untracked)
				if err != nil {
					return fmt.Errorf("git scan: %w", err)
				}
				findings = append(findings, fs...)
			}
			if gitStaged {
				fs, err := gitScanner.ScanStaged(path)
				if err != nil {
					return fmt.Errorf("git staged scan: %w", err)
				}
				findings = append(findings, fs...)
			}
			if gitHistory {
				fs, err := gitScanner.ScanHistory(path)
				if err != nil {
					return fmt.Errorf("git history scan: %w", err)
				}
				findings = append(findings, fs...)
			}
		} else if agentsFlag != "" {
			includeVSCodeStorage, _ := cmd.Flags().GetBool("include-vscode-storage")
			agentFindings, err := scanAgents(cmd.Context(), det, agentsFlag, agentPath, includeVSCodeStorage)
			if err != nil {
				return fmt.Errorf("agent scan: %w", err)
			}
			findings = agentFindings
		} else if dockerEnabled {
			dockerScanner := docker.New(det)

			if dockerfilePath != "" {
				fs, err := dockerScanner.ScanDockerfile(dockerfilePath)
				if err != nil {
					return fmt.Errorf("dockerfile scan: %w", err)
				}
				findings = append(findings, fs...)
			}
			if composePath != "" {
				fs, err := dockerScanner.ScanCompose(composePath)
				if err != nil {
					return fmt.Errorf("compose scan: %w", err)
				}
				findings = append(findings, fs...)
			}
			if containerID != "" {
				fs, err := dockerScanner.ScanContainer(containerID)
				if err != nil {
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Warning: docker container scan:", err)
				} else {
					findings = append(findings, fs...)
				}
			}
			if imageID != "" {
				fs, err := dockerScanner.ScanImage(imageID)
				if err != nil {
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Warning: docker image scan:", err)
				} else {
					findings = append(findings, fs...)
				}
			}
			if dockerMode {
				fs, err := dockerScanner.ScanDocker(cmd.Context(), path)
				if err != nil {
					return fmt.Errorf("docker scan: %w", err)
				}
				findings = append(findings, fs...)
			}
		} else {
			maxFileSize, _ := cmd.Flags().GetInt64("max-file-size")
			scanner := filesystem.New(det, filesystem.WithMaxFileSize(maxFileSize))
			findings, err = scanner.Scan(path)
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}
		}

		format, _ := cmd.Flags().GetString("format")
		switch format {
		case "json":
			if err := report.WriteJSON(cmd.OutOrStdout(), findings); err != nil {
				return err
			}
		default:
			showPreview := cfg.Report.ShowSecretPreview
			showFingerprints := cfg.Report.ShowFingerprints
			report.WriteTerminal(cmd.OutOrStdout(), findings, showPreview, showFingerprints)
		}

		failOn := cfg.Report.FailOn
		cliFailOn, _ := cmd.Flags().GetString("fail-on")
		if cliFailOn != "" {
			failOn = cliFailOn
		}

		skipDefaultFailOn := agentsFlag != "" && cliFailOn == ""
		if failOn != "" && !skipDefaultFailOn {
			count := countFindingsAtOrAbove(findings, failOn)
			if count > 0 {
				return fmt.Errorf("found %d finding(s) at or above %s severity", count, failOn)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().Bool("git", false, "Scan git working tree")
	scanCmd.Flags().Bool("git-staged", false, "Scan git staged changes")
	scanCmd.Flags().Bool("git-history", false, "Scan full git history")
	scanCmd.Flags().Bool("include-untracked", false, "Include untracked files in git working tree scan")
	scanCmd.Flags().String("agents", "", "Comma-separated agent types (codex,opencode,copilot)")
	scanCmd.Flags().String("agent-path", "", "Path to agent session file")
	scanCmd.Flags().Bool("docker", false, "Scan Docker metadata (Dockerfile, compose)")
	scanCmd.Flags().String("dockerfile", "", "Scan a specific Dockerfile")
	scanCmd.Flags().String("compose", "", "Scan a specific docker-compose file")
	scanCmd.Flags().String("docker-container", "", "Scan a container via docker inspect")
	scanCmd.Flags().String("docker-image", "", "Scan an image via docker history")
	scanCmd.Flags().Bool("include-vscode-storage", false, "Include VS Code storage in Copilot scan (disabled by default)")
	scanCmd.Flags().String("format", "terminal", "Output format (terminal, json)")
	scanCmd.Flags().Int64("max-file-size", filesystem.DefaultMaxFileSize, "Maximum file size in bytes to scan")
	scanCmd.Flags().String("fail-on", "", "Exit non-zero if findings at or above severity (low, medium, high, critical)")
}

func scanAgents(ctx context.Context, det *detector.Detector, agentsFlag, agentPath string, includeVSCodeStorage bool) ([]finding.Finding, error) {
	var scanners []agents.AgentScanner

	switch agentsFlag {
	case "all":
		scanners = []agents.AgentScanner{
			agents.CodexScanner{},
			agents.OpenCodeScanner{},
			agents.CopilotScanner{IncludeVSCodeStorage: includeVSCodeStorage},
		}
	default:
		for _, name := range strings.Split(agentsFlag, ",") {
			name = strings.TrimSpace(name)
			switch name {
			case "codex":
				scanners = append(scanners, agents.CodexScanner{})
			case "opencode":
				scanners = append(scanners, agents.OpenCodeScanner{})
			case "copilot":
				scanners = append(scanners, agents.CopilotScanner{IncludeVSCodeStorage: includeVSCodeStorage})
			default:
				return nil, fmt.Errorf("unknown agent: %s", name)
			}
		}
	}

	var allFindings []finding.Finding

	for _, s := range scanners {
		if agentPath != "" {
			findings, err := s.ScanPath(ctx, agentPath, det)
			if err != nil {
				return nil, fmt.Errorf("%s scan: %w", s.Name(), err)
			}
			allFindings = append(allFindings, findings...)
		} else {
			paths, err := s.DiscoverPaths(ctx)
			if err != nil {
				continue
			}
			for _, p := range paths {
				findings, err := s.ScanPath(ctx, p.Path, det)
				if err != nil {
					continue
				}
				allFindings = append(allFindings, findings...)
			}
		}
	}

	return allFindings, nil
}

func countFindingsAtOrAbove(findings []finding.Finding, severity string) int {
	var threshold finding.Severity
	switch severity {
	case "critical":
		threshold = finding.SevCritical
	case "high":
		threshold = finding.SevHigh
	case "medium":
		threshold = finding.SevMedium
	case "low":
		threshold = finding.SevLow
	default:
		return 0
	}
	count := 0
	for _, f := range findings {
		if f.Severity >= threshold {
			count++
		}
	}
	return count
}
