package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var redactCmd = &cobra.Command{
	Use:   "redact",
	Short: "Redact secrets from a file or agent session",
	Long: `Redact detected secrets from files or AI-agent session data.
Defaults to dry-run; use --apply to write changes.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Redact not yet implemented.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(redactCmd)

	redactCmd.Flags().String("input", "", "Input file path")
	redactCmd.Flags().String("output", "", "Output file path")
	redactCmd.Flags().String("agents", "", "Comma-separated agent types")
	redactCmd.Flags().Bool("dry-run", true, "Show what would be redacted")
	redactCmd.Flags().Bool("apply", false, "Apply redaction in-place")
}
