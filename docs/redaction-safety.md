# Redaction Safety

SecretGuard redaction is designed to be safe by default.

## Dry-run first

Redaction always runs in dry-run mode unless `--apply` or `--output` is specified:

```bash
# Dry-run — shows what would be redacted
secretguard redact --input data.json

# Write to a new file (safe — original is untouched)
secretguard redact --input data.json --output data.redacted.json

# In-place redaction (creates a backup automatically)
secretguard redact --input data.json --apply
```

## Backup before write

When `--apply` is used, SecretGuard creates a backup before modifying the file:

```bash
secretguard redact --input data.json --apply
# Output:
#   Backup created: 20260623-163000
#   Redacted 3 secret(s) in data.json
```

Backup metadata includes:

- SHA-256 hash of the original file.
- SHA-256 hash of the redacted file.
- Finding IDs of redacted secrets.
- Timestamp.
- Full path to the backup file.

## Restore

Restore the original file from a backup:

```bash
secretguard restore --backup-id 20260623-163000
```

The restore command verifies checksums before writing. If the file has been modified since redaction, the restore is blocked.

## What gets redacted

Redaction replaces the full secret value with a safe marker:

```text
Before: OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456
After:  OPENAI_API_KEY=[REDACTED:openai_api_key:sha256=abc123def456]
```

The marker preserves structure (JSON validity, line length) while removing the raw secret.

## Supported formats

- Plain text files.
- JSON files (structure preserved).
- JSONL files (line-by-line).
- AI-agent session files (Codex, OpenCode, Copilot).

## Safety rules

- Full secrets are never stored in backups, logs, or reports.
- Binary files are never redacted (skipped automatically).
- Scan commands never mutate files.
- Dry-run mode never writes.
- Restore verifies checksums before writing.
