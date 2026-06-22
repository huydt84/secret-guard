package cli

import (
	"fmt"

	"github.com/huydinhtrong/secretguard/internal/config"
	"github.com/huydinhtrong/secretguard/internal/detector"
	"github.com/huydinhtrong/secretguard/internal/finding"
	"github.com/huydinhtrong/secretguard/internal/report"
	"github.com/huydinhtrong/secretguard/internal/scanners/filesystem"
	"github.com/huydinhtrong/secretguard/internal/scanners/git"

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
		if cliFailOn, _ := cmd.Flags().GetString("fail-on"); cliFailOn != "" {
			failOn = cliFailOn
		}

		if failOn != "" {
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
	scanCmd.Flags().Bool("docker", false, "Scan Docker metadata")
	scanCmd.Flags().String("format", "terminal", "Output format (terminal, json)")
	scanCmd.Flags().Int64("max-file-size", filesystem.DefaultMaxFileSize, "Maximum file size in bytes to scan")
	scanCmd.Flags().String("fail-on", "", "Exit non-zero if findings at or above severity (low, medium, high, critical)")
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
