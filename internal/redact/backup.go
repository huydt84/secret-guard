package redact

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Backup struct {
	ID           string `json:"backup_id"`
	CreatedAt    string `json:"created_at"`
	OriginalPath string `json:"original_path"`
	BackupPath   string `json:"backup_path"`
	SHA256Before string `json:"sha256_before"`
	SHA256After  string `json:"sha256_after,omitempty"`
	FindingsCount int   `json:"findings_redacted"`
}

type BackupManager struct {
	rootDir string
}

func NewBackupManager() (*BackupManager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("home dir: %w", err)
	}
	rootDir := filepath.Join(home, ".secretguard", "backups")
	if err := os.MkdirAll(rootDir, 0700); err != nil {
		return nil, fmt.Errorf("create backup dir: %w", err)
	}
	return &BackupManager{rootDir: rootDir}, nil
}

func NewBackupManagerWithDir(rootDir string) *BackupManager {
	return &BackupManager{rootDir: rootDir}
}

func (bm *BackupManager) CreateBackup(originalPath string) (*Backup, error) {
	absPath, err := filepath.Abs(originalPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read original: %w", err)
	}

	beforeHash := sha256Hex(data)
	id := time.Now().Format("20060102-150405")
	backupDir := filepath.Join(bm.rootDir, id)
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("create backup dir: %w", err)
	}

	backupPath := filepath.Join(backupDir, filepath.Base(absPath))
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return nil, fmt.Errorf("write backup: %w", err)
	}

	b := &Backup{
		ID:            id,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		OriginalPath:  absPath,
		BackupPath:    backupPath,
		SHA256Before:  beforeHash,
		FindingsCount: 0,
	}

	metaPath := filepath.Join(backupDir, "backup.json")
	metaData, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
		return nil, fmt.Errorf("write metadata: %w", err)
	}

	return b, nil
}

func (bm *BackupManager) RestoreByID(backupID string) error {
	backupDir := filepath.Join(bm.rootDir, backupID)
	metaPath := filepath.Join(backupDir, "backup.json")

	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("read backup metadata: %w", err)
	}

	var b Backup
	if err := json.Unmarshal(metaData, &b); err != nil {
		return fmt.Errorf("parse backup metadata: %w", err)
	}

	if b.SHA256Before == "" {
		return fmt.Errorf("backup %s missing checksum", backupID)
	}

	currentData, err := os.ReadFile(b.OriginalPath)
	if err != nil {
		return fmt.Errorf("read current file: %w", err)
	}
	currentHash := sha256Hex(currentData)

	b.SHA256After = currentHash

	backupData, err := os.ReadFile(b.BackupPath)
	if err != nil {
		return fmt.Errorf("read backup file: %w", err)
	}
	backupHash := sha256Hex(backupData)

	if backupHash != b.SHA256Before {
		return fmt.Errorf("backup checksum mismatch: backup may be corrupted")
	}

	if err := os.WriteFile(b.OriginalPath, backupData, 0600); err != nil {
		return fmt.Errorf("restore file: %w", err)
	}

	metaData, err = json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal updated metadata: %w", err)
	}
	if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
		return fmt.Errorf("update metadata: %w", err)
	}

	return nil
}

func (bm *BackupManager) List() ([]Backup, error) {
	entries, err := os.ReadDir(bm.rootDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var backups []Backup
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		metaPath := filepath.Join(bm.rootDir, e.Name(), "backup.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var b Backup
		if err := json.Unmarshal(data, &b); err != nil {
			continue
		}
		backups = append(backups, b)
	}
	return backups, nil
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}
