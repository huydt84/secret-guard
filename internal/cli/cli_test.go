package cli

import (
	"bytes"
	"fmt"
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
			cmd.Flags().Bool("docker", false, "Scan Docker metadata (Dockerfile, compose)")
			cmd.Flags().String("dockerfile", "", "Scan a specific Dockerfile")
			cmd.Flags().String("compose", "", "Scan a specific docker-compose file")
			cmd.Flags().String("docker-container", "", "Scan a container via docker inspect")
			cmd.Flags().String("docker-image", "", "Scan an image via docker history")
			cmd.Flags().String("format", "terminal", "Output format (terminal, json)")
			cmd.Flags().Int64("max-file-size", 10485760, "Maximum file size in bytes")
			cmd.Flags().Bool("include-vscode-storage", false, "Include VS Code storage in Copilot scan")
			return cmd
		}(),
		func() *cobra.Command {
			cmd := &cobra.Command{
				Use: "redact", Short: "Redact secrets from a file or agent session",
				Long: `Redact detected secrets from files or AI-agent session data.
Defaults to dry-run; use --apply to write changes.`,
				Args: cobra.NoArgs,
				RunE: func(c *cobra.Command, args []string) error {
					input, _ := cmd.Flags().GetString("input")
					agentsFlag, _ := cmd.Flags().GetString("agents")
					if input == "" && agentsFlag == "" {
						return fmt.Errorf("specify --input or --agents")
					}
					c.Printf("Redact stub: input=%s agents=%s\n", input, agentsFlag)
					return nil
				},
			}
			cmd.Flags().String("input", "", "Input file path")
			cmd.Flags().String("output", "", "Output file path")
			cmd.Flags().String("agents", "", "Comma-separated agent types")
			cmd.Flags().Bool("dry-run", true, "Show what would be redacted")
			cmd.Flags().Bool("apply", false, "Apply redaction in-place")
			return cmd
		}(),
		func() *cobra.Command {
			cmd := &cobra.Command{
				Use: "remediate [git|docker|agents]", Short: "Generate a remediation plan",
				Long: `Generate a remediation plan for detected secrets.
Use with a subcommand: remediate git --finding-id FINDING_ID --report report.json`,
				Args: cobra.ExactArgs(1),
				RunE: func(c *cobra.Command, args []string) error {
					c.Printf("Remediate not yet implemented for: %s\n", args[0])
					return nil
				},
			}
			gitCmd := &cobra.Command{
				Use: "git", Short: "Generate a git history remediation plan",
				Args: cobra.NoArgs,
				RunE: func(c *cobra.Command, args []string) error {
					findingID, _ := c.Flags().GetString("finding-id")
					reportPath, _ := c.Flags().GetString("report")
					if findingID == "" {
						return fmt.Errorf("--finding-id is required")
					}
					if reportPath == "" {
						return fmt.Errorf("--report is required")
					}
					c.Printf("Git remediate stub: finding=%s report=%s\n", findingID, reportPath)
					return nil
				},
			}
			gitCmd.Flags().String("finding-id", "", "Finding ID to remediate")
			gitCmd.Flags().String("report", "", "Path to JSON report file")
			dockerCmd := &cobra.Command{
				Use: "docker", Short: "Generate a Docker remediation plan",
				Args: cobra.NoArgs,
				RunE: func(c *cobra.Command, args []string) error {
					findingID, _ := c.Flags().GetString("finding-id")
					reportPath, _ := c.Flags().GetString("report")
					if findingID == "" {
						return fmt.Errorf("--finding-id is required")
					}
					if reportPath == "" {
						return fmt.Errorf("--report is required")
					}
					c.Printf("Docker remediate stub: finding=%s report=%s\n", findingID, reportPath)
					return nil
				},
			}
			dockerCmd.Flags().String("finding-id", "", "Finding ID to remediate")
			dockerCmd.Flags().String("report", "", "Path to JSON report file")
			agentsCmd := &cobra.Command{
				Use: "agents", Short: "Generate agent remediation advice",
				Args: cobra.NoArgs,
				RunE: func(c *cobra.Command, args []string) error {
					findingID, _ := c.Flags().GetString("finding-id")
					reportPath, _ := c.Flags().GetString("report")
					if findingID == "" {
						return fmt.Errorf("--finding-id is required")
					}
					if reportPath == "" {
						return fmt.Errorf("--report is required")
					}
					c.Printf("Agent remediate stub: finding=%s report=%s\n", findingID, reportPath)
					return nil
				},
			}
			agentsCmd.Flags().String("finding-id", "", "Finding ID to remediate")
			agentsCmd.Flags().String("report", "", "Path to JSON report file")
			cmd.AddCommand(gitCmd)
			cmd.AddCommand(dockerCmd)
			cmd.AddCommand(agentsCmd)
			return cmd
		}(),
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

func TestRedactRequiresInputOrAgents(t *testing.T) {
	_, err := execCmd("redact")
	if err == nil {
		t.Fatal("expected error when neither --input nor --agents is specified")
	}
	if !strings.Contains(err.Error(), "specify --input or --agents") {
		t.Errorf("expected error about input/agents, got %v", err)
	}
}

func TestRedactIntegration(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"redact", "--input", filepath.Join(projectRoot(), "testdata", "redact", "secrets.txt"), "--output", filepath.Join(t.TempDir(), "out.txt")})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("redact failed: %v\nout: %s", err, buf.String())
	}
	if strings.Contains(buf.String(), "sk-test_abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatalf("full secret leaked in output: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "Redacted") {
		t.Errorf("expected confirmation message, got %q", buf.String())
	}
}

func TestRemediateHelp(t *testing.T) {
	out, err := execCmd("remediate", "--help")
	if err != nil {
		t.Fatalf("remediate --help failed: %v", err)
	}
	if !strings.Contains(out, "Generate a remediation plan") {
		t.Errorf("expected remediate help, got %q", out)
	}
}

func TestRemediateGit(t *testing.T) {
	out, err := execCmd("remediate", "git", "--finding-id", "sg-001", "--report", "/tmp/report.json")
	if err != nil {
		t.Fatalf("remediate git failed: %v", err)
	}
	if !strings.Contains(out, "Git remediate stub") {
		t.Errorf("expected git remediate output, got %q", out)
	}
	if !strings.Contains(out, "sg-001") {
		t.Errorf("expected finding id in output, got %q", out)
	}
}

func TestRemediateDocker(t *testing.T) {
	out, err := execCmd("remediate", "docker", "--finding-id", "sg-002", "--report", "/tmp/report.json")
	if err != nil {
		t.Fatalf("remediate docker failed: %v", err)
	}
	if !strings.Contains(out, "Docker remediate stub") {
		t.Errorf("expected docker remediate output, got %q", out)
	}
}

func TestRemediateAgents(t *testing.T) {
	out, err := execCmd("remediate", "agents", "--finding-id", "sg-003", "--report", "/tmp/report.json")
	if err != nil {
		t.Fatalf("remediate agents failed: %v", err)
	}
	if !strings.Contains(out, "Agent remediate stub") {
		t.Errorf("expected agent remediate output, got %q", out)
	}
}

func TestRemediateGitMissingFindingID(t *testing.T) {
	_, err := execCmd("remediate", "git", "--report", "/tmp/report.json")
	if err == nil {
		t.Fatal("expected error for missing --finding-id")
	}
}

func TestRemediateGitMissingReport(t *testing.T) {
	_, err := execCmd("remediate", "git", "--finding-id", "sg-001")
	if err == nil {
		t.Fatal("expected error for missing --report")
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
