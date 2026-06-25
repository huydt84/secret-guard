package cli

import (
	"fmt"

	"github.com/huydt84/secret-guard/internal/redact"
	"github.com/spf13/cobra"
)

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore a file from a backup",
	Long: `Restore a previously backed-up file to its original state.
Uses the backup ID returned by the redact command.`,
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		backupID, _ := cmd.Flags().GetString("backup-id")
		if backupID == "" {
			return fmt.Errorf("--backup-id is required")
		}

		bm, err := redact.NewBackupManager()
		if err != nil {
			return fmt.Errorf("backup manager: %w", err)
		}

		if err := bm.RestoreByID(backupID); err != nil {
			return fmt.Errorf("restore: %w", err)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restored backup %s\n", backupID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(restoreCmd)

	restoreCmd.Flags().String("backup-id", "", "Backup ID to restore from")
	_ = restoreCmd.MarkFlagRequired("backup-id")
}
