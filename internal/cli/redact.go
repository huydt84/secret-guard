package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/huydt84/secret-guard/internal/config"
	"github.com/huydt84/secret-guard/internal/detector"
	"github.com/huydt84/secret-guard/internal/redact"
	"github.com/huydt84/secret-guard/internal/scanners/agents"

	"github.com/spf13/cobra"
)

var redactCmd = &cobra.Command{
	Use:   "redact",
	Short: "Redact secrets from a file or agent session",
	Long: `Redact detected secrets from files or AI-agent session data.
Defaults to dry-run; use --apply to write changes.`,
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := appCfg
		if cfg == nil {
			cfg = config.Default()
		}

		input, _ := cmd.Flags().GetString("input")
		output, _ := cmd.Flags().GetString("output")
		agentsFlag, _ := cmd.Flags().GetString("agents")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		apply, _ := cmd.Flags().GetBool("apply")

		if input == "" && agentsFlag == "" {
			return fmt.Errorf("specify --input or --agents")
		}
		if output != "" && apply {
			return fmt.Errorf("cannot use --output and --apply together")
		}
		if output != "" && agentsFlag != "" {
			return fmt.Errorf("cannot use --output with --agents")
		}

		if apply || output != "" {
			dryRun = false
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

		if agentsFlag != "" {
			return redactAgents(cmd, det, agentsFlag, dryRun, apply)
		}

		return redactFile(cmd, det, input, output, dryRun, apply)
	},
}

func init() {
	rootCmd.AddCommand(redactCmd)

	redactCmd.Flags().String("input", "", "Input file path")
	redactCmd.Flags().String("output", "", "Output file path")
	redactCmd.Flags().String("agents", "", "Comma-separated agent types (codex,opencode,copilot)")
	redactCmd.Flags().Bool("dry-run", true, "Show what would be redacted (default)")
	redactCmd.Flags().Bool("apply", false, "Apply redaction in-place")
}

func redactFile(cmd *cobra.Command, det *detector.Detector, input, output string, dryRun, apply bool) error {
	result, err := redact.RedactFile(input, det)
	if err != nil {
		return fmt.Errorf("redact: %w", err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Dry-run: %d secret(s) would be redacted in %s\n", len(result.Findings), input)
		for _, f := range result.Findings {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  - %s at %s:%d (%s)\n", f.SecretKind, input, f.Location.Line, f.Preview)
		}
		return nil
	}

	if output != "" {
		if err := os.WriteFile(output, result.Content, 0600); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Redacted %d secret(s) -> %s\n", len(result.Findings), output)
		return nil
	}

	if apply {
		bm, err := redact.NewBackupManager()
		if err != nil {
			return fmt.Errorf("backup manager: %w", err)
		}

		backup, err := bm.CreateBackup(input)
		if err != nil {
			return fmt.Errorf("backup: %w", err)
		}

		if err := os.WriteFile(input, result.Content, 0600); err != nil {
			return fmt.Errorf("write redacted: %w", err)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Backup created: %s\n", backup.ID)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Redacted %d secret(s) in %s\n", len(result.Findings), input)
		return nil
	}

	return nil
}

func redactAgents(cmd *cobra.Command, det *detector.Detector, agentsFlag string, dryRun, apply bool) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	agentPath, _ := cmd.Flags().GetString("agent-path")
	includeVSCodeStorage, _ := cmd.Flags().GetBool("include-vscode-storage")

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
				return fmt.Errorf("unknown agent: %s", name)
			}
		}
	}

	totalFindings := 0
	for _, s := range scanners {
		var paths []agents.AgentPath
		var err error

		if agentPath != "" {
			paths = []agents.AgentPath{{Path: agentPath, Agent: s.Name()}}
		} else {
			paths, err = s.DiscoverPaths(ctx)
			if err != nil {
				continue
			}
		}

		for _, p := range paths {
			entries, err := listAgentFiles(p.Path)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				result, err := redact.RedactFile(entry, det)
				if err != nil {
					continue
				}
				if len(result.Findings) == 0 {
					continue
				}

				if dryRun {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s: %d secret(s) would be redacted\n", s.Name(), entry, len(result.Findings))
					for _, f := range result.Findings {
						_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  - %s (%s)\n", f.SecretKind, f.Preview)
					}
				} else if apply {
					bm, err := redact.NewBackupManager()
					if err != nil {
						return fmt.Errorf("backup manager: %w", err)
					}
					backup, err := bm.CreateBackup(entry)
					if err != nil {
						return fmt.Errorf("backup %s: %w", entry, err)
					}
					if err := os.WriteFile(entry, result.Content, 0600); err != nil {
						return fmt.Errorf("write %s: %w", entry, err)
					}
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s: backup=%s redacted %d secret(s)\n", s.Name(), entry, backup.ID, len(result.Findings))
				}
				totalFindings += len(result.Findings)
			}
		}
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Total: %d secret(s) would be redacted across agent files\n", totalFindings)
	} else if apply {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Total: %d secret(s) redacted across agent files\n", totalFindings)
	}
	return nil
}

func listAgentFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{root}, nil
	}

	var files []string
	err = filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".txt", ".log", ".md", ".json", ".jsonl":
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
