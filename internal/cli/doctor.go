package cli

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system dependencies and configuration",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDoctor(cmd)
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command) error {
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Checking SecretGuard environment...")

	checks := []struct {
		name    string
		binary  string
		args    []string
		success bool
	}{
		{"git", "git", []string{"version"}, false},
		{"go", "go", []string{"version"}, false},
	}

	allPass := true
	for _, c := range checks {
		if err := exec.Command(c.binary, c.args...).Run(); err != nil {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  [FAIL] %s: not found\n", c.name)
			allPass = false
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  [PASS] %s: found\n", c.name)
		}
	}

	if allPass {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "All dependencies available.")
	} else {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Some dependencies missing.")
	}

	return nil
}
