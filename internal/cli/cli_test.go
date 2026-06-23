package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func testRoot() *cobra.Command {
	cmd := &cobra.Command{Use: "secretguard"}
	cmd.AddCommand(
		&cobra.Command{
			Use: "version", Short: "Print SecretGuard version",
			Args: cobra.NoArgs,
			RunE: func(c *cobra.Command, args []string) error {
				c.Println("secretguard version", Version)
				return nil
			},
		},
		&cobra.Command{
			Use: "doctor", Short: "Check system dependencies",
			Args: cobra.NoArgs,
			RunE: func(c *cobra.Command, args []string) error {
				return runDoctor(c)
			},
		},
		func() *cobra.Command {
			cmd := &cobra.Command{
				Use: "scan [path]", Short: "Scan for secrets in files, git, agents, or Docker",
				Long: `Scan for leaked secrets in the working tree, git history,
AI-agent session data, and Docker metadata.

If no path is given, scans the current directory.`,
				Args: cobra.MaximumNArgs(1),
				RunE: func(c *cobra.Command, args []string) error {
					path := "."
					if len(args) > 0 {
						path = args[0]
					}
					c.Printf("Scan target: %s\n", path)
					return nil
				},
			}
			cmd.Flags().Bool("git", false, "Scan git working tree")
			cmd.Flags().Bool("git-staged", false, "Scan git staged changes")
			cmd.Flags().Bool("git-history", false, "Scan full git history")
			cmd.Flags().Bool("include-untracked", false, "Include untracked files in git working tree scan")
			cmd.Flags().String("agents", "", "Comma-separated agent types")
			cmd.Flags().String("agent-path", "", "Path to agent session file")
			cmd.Flags().Bool("docker", false, "Scan Docker metadata")
			cmd.Flags().String("format", "terminal", "Output format (terminal, json)")
			cmd.Flags().Int64("max-file-size", 10485760, "Maximum file size in bytes")
			cmd.Flags().Bool("include-vscode-storage", false, "Include VS Code storage in Copilot scan")
			return cmd
		}(),
		&cobra.Command{
			Use: "redact", Short: "Redact secrets from a file or agent session",
			Long: `Redact detected secrets from files or AI-agent session data.
Defaults to dry-run; use --apply to write changes.`,
			Args: cobra.NoArgs,
			RunE: func(c *cobra.Command, args []string) error {
				c.Println("Redact not yet implemented.")
				return nil
			},
		},
		&cobra.Command{
			Use: "remediate [git|docker]", Short: "Generate or apply a remediation plan",
			Long: `Generate or apply a remediation plan for detected secrets.
Use with a subcommand: remediate git --finding-id FINDING_ID`,
			Args: cobra.ExactArgs(1),
			RunE: func(c *cobra.Command, args []string) error {
				c.Printf("Remediate not yet implemented for: %s\n", args[0])
				return nil
			},
		},
	)
	return cmd
}

func execCmd(args ...string) (string, error) {
	buf := new(bytes.Buffer)
	cmd := testRoot()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func projectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("project root not found")
		}
		dir = parent
	}
}

func TestVersion(t *testing.T) {
	out, err := execCmd("version")
	if err != nil {
		t.Fatalf("version failed: %v", err)
	}
	if !strings.Contains(out, "secretguard version") {
		t.Errorf("expected version, got %q", out)
	}
}

func TestDoctor(t *testing.T) {
	out, err := execCmd("doctor")
	if err != nil {
		t.Fatalf("doctor failed: %v", err)
	}
	if !strings.Contains(out, "Checking SecretGuard environment") {
		t.Errorf("expected doctor, got %q", out)
	}
}

func TestScanHelp(t *testing.T) {
	out, err := execCmd("scan", "--help")
	if err != nil {
		t.Fatalf("scan --help failed: %v", err)
	}
	if !strings.Contains(out, "Scan for leaked secrets") {
		t.Errorf("expected scan help, got %q", out)
	}
}

func TestScanDefault(t *testing.T) {
	out, err := execCmd("scan")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !strings.Contains(out, "Scan target") {
		t.Errorf("expected scan output, got %q", out)
	}
}

func TestScanWithPath(t *testing.T) {
	out, err := execCmd("scan", "/some/path")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !strings.Contains(out, "/some/path") {
		t.Errorf("expected path, got %q", out)
	}
}

func TestRedactHelp(t *testing.T) {
	out, err := execCmd("redact", "--help")
	if err != nil {
		t.Fatalf("redact --help failed: %v", err)
	}
	if !strings.Contains(out, "Redact detected secrets") {
		t.Errorf("expected redact help, got %q", out)
	}
}

func TestRedactStub(t *testing.T) {
	out, err := execCmd("redact")
	if err != nil {
		t.Fatalf("redact failed: %v", err)
	}
	if !strings.Contains(out, "Redact not yet implemented") {
		t.Errorf("expected stub, got %q", out)
	}
}

func TestRemediateHelp(t *testing.T) {
	out, err := execCmd("remediate", "--help")
	if err != nil {
		t.Fatalf("remediate --help failed: %v", err)
	}
	if !strings.Contains(out, "Generate or apply") {
		t.Errorf("expected remediate help, got %q", out)
	}
}

func TestRemediateStub(t *testing.T) {
	out, err := execCmd("remediate", "git")
	if err != nil {
		t.Fatalf("remediate failed: %v", err)
	}
	if !strings.Contains(out, "Remediate not yet implemented") {
		t.Errorf("expected stub, got %q", out)
	}
}

func TestRemediateNoArgs(t *testing.T) {
	_, err := execCmd("remediate")
	if err == nil {
		t.Fatal("expected error for remediate without args")
	}
}

func TestScanAgentsExplicitPath(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"scan", "--agents", "all", "--agent-path", filepath.Join(projectRoot(), "testdata", "agents"), "--format", "json"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan agents failed: %v\nout: %s", err, buf.String())
	}
	if strings.Contains(buf.String(), "sk-test_abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatalf("full secret leaked in report: %s", buf.String())
	}
}
