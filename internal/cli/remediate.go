package cli

import (
	"fmt"

	"github.com/huydt84/secret-guard/internal/remediate"
	"github.com/spf13/cobra"
)

var remediateCmd = &cobra.Command{
	Use:   "remediate [git|docker|agents]",
	Short: "Generate a remediation plan",
	Long: `Generate a remediation plan for detected secrets.
Use with a subcommand: remediate git --finding-id FINDING_ID --report report.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("unknown remediate target: %s", args[0])
	},
}

var remediateGitCmd = &cobra.Command{
	Use:   "git",
	Short: "Generate a git history remediation plan",
	Long: `Generate a remediation plan for a secret found in git history.
The plan explains how to use git filter-repo to rewrite history
without executing it automatically.

Usage:
  secretguard remediate git --finding-id FINDING_ID --report report.json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		findingID, _ := cmd.Flags().GetString("finding-id")
		reportPath, _ := cmd.Flags().GetString("report")

		if findingID == "" {
			return fmt.Errorf("--finding-id is required")
		}
		if reportPath == "" {
			return fmt.Errorf("--report is required")
		}

		f, err := remediate.LookupFinding(reportPath, findingID)
		if err != nil {
			return fmt.Errorf("lookup finding: %w", err)
		}

		plan := remediate.GenerateGitPlan(f)
		_, _ = fmt.Fprint(cmd.OutOrStdout(), remediate.FormatPlan(plan))
		return nil
	},
}

var remediateDockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Generate a Docker remediation plan",
	Long: `Generate a remediation plan for a secret found in Docker metadata.
Provides safest practice alternatives such as BuildKit secrets,
env_file patterns, and Docker secrets.

Usage:
  secretguard remediate docker --finding-id FINDING_ID --report report.json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		findingID, _ := cmd.Flags().GetString("finding-id")
		reportPath, _ := cmd.Flags().GetString("report")

		if findingID == "" {
			return fmt.Errorf("--finding-id is required")
		}
		if reportPath == "" {
			return fmt.Errorf("--report is required")
		}

		f, err := remediate.LookupFinding(reportPath, findingID)
		if err != nil {
			return fmt.Errorf("lookup finding: %w", err)
		}

		plan := remediate.GenerateDockerPlan(f)
		_, _ = fmt.Fprint(cmd.OutOrStdout(), remediate.FormatPlan(plan))
		return nil
	},
}

var remediateAgentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Generate remediation advice for agent-discovered secrets",
	Long: `Generate remediation advice for a secret found in AI-agent data.
Recommends running secretguard redact with dry-run first,
then applying redaction. For high-severity findings, also
recommends rotating or revoking the credential.

Usage:
  secretguard remediate agents --finding-id FINDING_ID --report report.json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		findingID, _ := cmd.Flags().GetString("finding-id")
		reportPath, _ := cmd.Flags().GetString("report")

		if findingID == "" {
			return fmt.Errorf("--finding-id is required")
		}
		if reportPath == "" {
			return fmt.Errorf("--report is required")
		}

		f, err := remediate.LookupFinding(reportPath, findingID)
		if err != nil {
			return fmt.Errorf("lookup finding: %w", err)
		}

		plan := remediate.GenerateAgentAdvice(f)
		_, _ = fmt.Fprint(cmd.OutOrStdout(), remediate.FormatPlan(plan))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(remediateCmd)
	remediateCmd.AddCommand(remediateGitCmd)
	remediateCmd.AddCommand(remediateDockerCmd)
	remediateCmd.AddCommand(remediateAgentsCmd)

	remediateGitCmd.Flags().String("finding-id", "", "Finding ID to remediate")
	remediateGitCmd.Flags().String("report", "", "Path to JSON report file")
	remediateDockerCmd.Flags().String("finding-id", "", "Finding ID to remediate")
	remediateDockerCmd.Flags().String("report", "", "Path to JSON report file")
	remediateAgentsCmd.Flags().String("finding-id", "", "Finding ID to remediate")
	remediateAgentsCmd.Flags().String("report", "", "Path to JSON report file")
}
