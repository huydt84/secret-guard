package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var remediateCmd = &cobra.Command{
	Use:   "remediate [git|docker]",
	Short: "Generate or apply a remediation plan",
	Long: `Generate or apply a remediation plan for detected secrets.
Use with a subcommand: remediate git --finding-id FINDING_ID`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Remediate not yet implemented for: %s\n", args[0])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(remediateCmd)

	remediateCmd.Flags().String("finding-id", "", "Finding ID to remediate")
}
