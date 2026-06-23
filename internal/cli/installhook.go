package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const hookContent = `#!/bin/sh
# SecretGuard pre-commit hook
# Runs secretguard scan --git-staged --fail-on high
# Install with: secretguard install-hook

exec secretguard scan --git-staged --fail-on high
`

var installHookCmd = &cobra.Command{
	Use:   "install-hook",
	Short: "Install a git pre-commit hook that scans staged changes",
	Long: `Install a git pre-commit hook that runs
  secretguard scan --git-staged --fail-on high
before each commit. The hook blocks commits if high-severity secrets are found.

Will not overwrite an existing hook without confirmation.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		hooksDir := filepath.Join(".git", "hooks")
		hookPath := filepath.Join(hooksDir, "pre-commit")

		if _, err := os.Stat(hookPath); err == nil {
			return fmt.Errorf("pre-commit hook already exists at %s", hookPath)
		}

		if err := os.MkdirAll(hooksDir, 0755); err != nil {
			return fmt.Errorf("create hooks dir: %w", err)
		}

		if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
			return fmt.Errorf("write hook: %w", err)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Installed pre-commit hook at %s\n", hookPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(installHookCmd)
}
