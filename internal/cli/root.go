package cli

import (
	"fmt"
	"os"

	"github.com/huydt84/secret-guard/internal/config"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	appCfg  *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "secretguard",
	Short: "Local-first secret leak detection and remediation tool",
	Long: `SecretGuard finds and safely remediates secret leaks in code,
git history, AI-agent local data, and Docker metadata.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if cfgFile == "" {
			return nil
		}
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		appCfg = cfg
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default .secretguard.yml)")
}
