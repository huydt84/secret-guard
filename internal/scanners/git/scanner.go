package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/huydinhtrong/secretguard/internal/detector"
	"github.com/huydinhtrong/secretguard/internal/finding"
)

type Scanner struct {
	det *detector.Detector
}

func New(det *detector.Detector) *Scanner {
	return &Scanner{det: det}
}

func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %v: %s", args, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("git %v: %w", args, err)
	}
	return string(out), nil
}

func (s *Scanner) isGitRepo(dir string) error {
	_, err := runGit(dir, "rev-parse", "--git-dir")
	if err != nil {
		return fmt.Errorf("not a git repository: %s", dir)
	}
	return nil
}

func (s *Scanner) ScanWorkingTree(dir string, untracked bool) ([]finding.Finding, error) {
	if err := s.isGitRepo(dir); err != nil {
		return nil, err
	}

	args := []string{"ls-files"}
	if untracked {
		args = append(args, "--others", "--exclude-standard")
	}

	out, err := runGit(dir, args...)
	if err != nil {
		return nil, err
	}

	files := strings.Fields(out)
	var allFindings []finding.Finding

	for _, file := range files {
		fullPath := filepath.Join(dir, file)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		if isBinary(data) {
			continue
		}
		if int64(len(data)) > 10*1024*1024 {
			continue
		}
		findings := s.det.DetectAll(finding.SourceGit, file, data)
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

type stagedHunk struct {
	newStart   int
	addedLines []string
}

type stagedFile struct {
	path  string
	hunks []stagedHunk
}

func parseStagedDiff(out string) []stagedFile {
	var files []stagedFile
	var current *stagedFile

	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			if current != nil {
				files = append(files, *current)
			}
			parts := strings.Fields(line)
			var path string
			if len(parts) >= 4 {
				path = strings.TrimPrefix(parts[3], "b/")
			}
			current = &stagedFile{path: path}
		} else if strings.HasPrefix(line, "@@") && current != nil {
			parts := strings.Split(line, " ")
			if len(parts) >= 4 {
				newInfo := strings.TrimPrefix(parts[2], "+")
				if idx := strings.Index(newInfo, ","); idx >= 0 {
					newInfo = newInfo[:idx]
				}
				newStart, _ := strconv.Atoi(newInfo)
				if newStart < 1 {
					newStart = 1
				}
				current.hunks = append(current.hunks, stagedHunk{newStart: newStart})
			}
		} else if strings.HasPrefix(line, "+") && current != nil && len(current.hunks) > 0 {
			if strings.HasPrefix(line, "+++") {
				continue
			}
			hunk := &current.hunks[len(current.hunks)-1]
			hunk.addedLines = append(hunk.addedLines, line[1:])
		}
	}
	if current != nil {
		files = append(files, *current)
	}
	return files
}

func (s *Scanner) ScanStaged(dir string) ([]finding.Finding, error) {
	if err := s.isGitRepo(dir); err != nil {
		return nil, err
	}

	out, err := runGit(dir, "diff", "--cached", "--unified=0")
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}

	entries := parseStagedDiff(out)
	var allFindings []finding.Finding

	for _, entry := range entries {
		if len(entry.hunks) == 0 {
			continue
		}

		var contentLines []string
		var lineMapping []int

		for _, hunk := range entry.hunks {
			for i, added := range hunk.addedLines {
				contentLines = append(contentLines, added)
				lineMapping = append(lineMapping, hunk.newStart+i)
			}
		}

		if len(contentLines) == 0 {
			continue
		}

		content := strings.Join(contentLines, "\n")
		findings := s.det.DetectAll(finding.SourceGit, entry.path, []byte(content))

		for i := range findings {
			if findings[i].Location.Line > 0 && findings[i].Location.Line <= len(lineMapping) {
				findings[i].Location.Line = lineMapping[findings[i].Location.Line-1]
			}
		}

		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

type historyHunk struct {
	newStart   int
	addedLines []string
}

type historyFileChange struct {
	sha   string
	path  string
	hunks []historyHunk
}

func parseHistoryLog(out string) []historyFileChange {
	var changes []historyFileChange
	var currentSHA string
	var currentChange *historyFileChange

	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "commit ") {
			if currentChange != nil {
				changes = append(changes, *currentChange)
				currentChange = nil
			}
			parts := strings.Fields(line)
			if len(parts) > 1 {
				currentSHA = parts[1]
			}
		} else if strings.HasPrefix(line, "diff --git ") {
			if currentChange != nil {
				changes = append(changes, *currentChange)
				currentChange = nil
			}
			parts := strings.Fields(line)
			var path string
			if len(parts) >= 4 {
				path = strings.TrimPrefix(parts[3], "b/")
			}
			currentChange = &historyFileChange{sha: currentSHA, path: path}
		} else if strings.HasPrefix(line, "@@") && currentChange != nil && currentSHA != "" {
			parts := strings.Split(line, " ")
			if len(parts) >= 4 {
				newInfo := strings.TrimPrefix(parts[2], "+")
				if idx := strings.Index(newInfo, ","); idx >= 0 {
					newInfo = newInfo[:idx]
				}
				newStart, _ := strconv.Atoi(newInfo)
				if newStart < 1 {
					newStart = 1
				}
				currentChange.hunks = append(currentChange.hunks, historyHunk{newStart: newStart})
			}
		} else if strings.HasPrefix(line, "+") && currentChange != nil && len(currentChange.hunks) > 0 {
			if strings.HasPrefix(line, "+++") {
				continue
			}
			hunk := &currentChange.hunks[len(currentChange.hunks)-1]
			hunk.addedLines = append(hunk.addedLines, line[1:])
		}
	}
	if currentChange != nil {
		changes = append(changes, *currentChange)
	}
	return changes
}

func (s *Scanner) ScanHistory(dir string) ([]finding.Finding, error) {
	if err := s.isGitRepo(dir); err != nil {
		return nil, err
	}

	out, err := runGit(dir, "log", "-p", "--all", "--full-history", "--no-merges", "--no-ext-diff")
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}

	changes := parseHistoryLog(out)
	var allFindings []finding.Finding

	for _, ch := range changes {
		var contentLines []string
		var lineMapping []int

		for _, hunk := range ch.hunks {
			for i, added := range hunk.addedLines {
				contentLines = append(contentLines, added)
				lineMapping = append(lineMapping, hunk.newStart+i)
			}
		}

		if len(contentLines) == 0 {
			continue
		}

		content := strings.Join(contentLines, "\n")
		findings := s.det.DetectAll(finding.SourceGitHistory, ch.path, []byte(content))

		for i := range findings {
			findings[i].Location.CommitSHA = ch.sha
			if findings[i].Location.Line > 0 && findings[i].Location.Line <= len(lineMapping) {
				findings[i].Location.Line = lineMapping[findings[i].Location.Line-1]
			}
		}

		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func isBinary(data []byte) bool {
	n := len(data)
	if n > 512 {
		n = 512
	}
	for _, b := range data[:n] {
		if b == 0 {
			return true
		}
	}
	return false
}
