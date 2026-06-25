# SecretGuard

Local-first CLI for detecting and safely remediating secret leaks in code, git history, AI-agent data, and Docker metadata.

## Safety Warning

**SecretGuard handles sensitive data.** Always review findings before taking remediation action. Redaction is dry-run by default and requires `--apply` to write changes. Git history rewriting must never be automated. Rotate or revoke real credentials — do not rely on redaction alone.

## Installation

### Quick install macOS/Linux

```bash
# Latest release
curl -fsSL https://raw.githubusercontent.com/huydt84/secret-guard/main/install.sh | sh
# Specific release
VERSION=v0.1.0 curl -fsSL https://raw.githubusercontent.com/huydt84/secret-guard/main/install.sh | sh
```

### Manual install

1. Download archive for your OS/arch from [Releases](https://github.com/huydt84/secret-guard/releases).
2. Extract archive.
3. Move `secretguard` into PATH.

```bash
tar -xzf secretguard-darwin-arm64.tar.gz
chmod +x secretguard
sudo mv secretguard /usr/local/bin/
secretguard --help
```

### From source

```bash
go install github.com/huydt84/secret-guard/cmd/secretguard@latest
```

Verify checksums with `sha256sum -c checksums.txt` or `shasum -a 256 -c checksums.txt`.

## Quick start

```bash
# Build
make build

# Check dependencies
./bin/secretguard doctor

# Scan current directory for secrets
./bin/secretguard scan .

# Scan git history for deleted secrets
./bin/secretguard scan --git-history --format json > report.json
```

## Demo scenario

This walkthrough shows the complete detection-to-remediation workflow.

### 1. Create a test environment

```bash
mkdir -p /tmp/secretguard-demo && cd /tmp/secretguard-demo
git init
```

### 2. Commit a fake secret

```bash
echo "DATABASE_URL=postgres://user:supersecretpassword@localhost:5432/app" > .env
git add .env
git commit -m "add config"
```

### 3. Delete the secret from working tree

```bash
rm .env
echo "DATABASE_URL=postgres://user:supersecretpassword@localhost:5432/app" >> .gitignore
git add .gitignore
git commit -m "remove secret"
```

### 4. Scan git history — finds the deleted secret

```bash
secretguard scan --git-history --format json > report.json
```

### 5. Scan agent data

```bash
secretguard scan --agents all --agent-path /path/to/agent/sessions --format json >> report.json
```

### 6. Scan Docker metadata

```bash
secretguard scan --dockerfile testdata/docker/Dockerfile.bad
secretguard scan --compose testdata/docker/docker-compose.bad.yml
```

### 7. Safely redact agent data (dry-run first)

```bash
secretguard redact --agents opencode --dry-run
secretguard redact --agents opencode --apply
```

### 8. Generate a git remediation plan

```bash
secretguard remediate git --finding-id <FINDING_ID> --report report.json
```

The plan explains how to use `git filter-repo` to rewrite history without executing automatically.

### 9. Generate a Docker remediation plan

```bash
secretguard remediate docker --finding-id <FINDING_ID> --report report.json
```

The plan explains safest practice alternatives like BuildKit secrets, env_file, and Docker secrets.

## Usage

```bash
# Scan
secretguard scan .                                    # default filesystem scan
secretguard scan --git                                # working tree
secretguard scan --git-staged                         # staged changes
secretguard scan --git-history                        # full history
secretguard scan --agents codex,opencode,copilot      # agent data
secretguard scan --docker                             # Docker metadata
secretguard scan --format json                        # JSON output

# Redact
secretguard redact --input report.json --output report.redacted.json
secretguard redact --agents opencode --dry-run
secretguard redact --agents opencode --apply

# Restore
secretguard restore --backup-id BACKUP_ID

# Remediate (plan only, no automatic execution)
secretguard remediate git --finding-id FINDING_ID --report report.json
secretguard remediate docker --finding-id FINDING_ID --report report.json
secretguard remediate agents --finding-id FINDING_ID --report report.json

# Utilities
secretguard version
secretguard doctor
secretguard install-hook
```

## Safety guarantees

- **Scans never mutate files.**
- **Redaction is dry-run by default.** Use `--apply` to write.
- **In-place redaction creates a backup.** Restore with `secretguard restore --backup-id <id>`.
- **Restore verifies checksums.**
- **Git remediation generates a plan only.** It does not execute `git filter-repo`.
- **Docker remediation generates a plan only.** It does not remove containers or images.
- **No network calls.** No telemetry. No credential verification.
- **Full secrets never appear in reports, plans, or backups.** Only masked previews and fingerprints.

## Remediation examples

### Git history

```bash
# 1. Rotate the leaked credential at the provider.
# 2. Clone a mirror:
git clone --mirror <repository-url> repo-mirror
# 3. Run git filter-repo:
cd repo-mirror && git filter-repo --force --replace-text /tmp/replacements.txt
# 4. Rescan the mirror:
secretguard scan repo-mirror --git-history --format json
# 5. Coordinate with team before force-push:
cd repo-mirror && git push --force --mirror origin
```

### Docker

Remove secrets from Dockerfile `ENV`/`ARG` and use safer alternatives:

- `docker build --secret` for build-time secrets.
- `env_file` with restricted permissions for runtime secrets.
- Docker secrets for swarm deployments.
- Cloud secret managers for production.

## Non-goals

SecretGuard does not and will not:

- Contact external services or the internet.
- Verify credential validity with providers.
- Automatically rewrite git history.
- Automatically delete Docker containers or images.
- Provide a GUI or web dashboard.
- Scan remote repositories.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | No findings above threshold |
| 1    | Findings at or above `--fail-on` threshold |
| 2    | Usage or config error |
| 3    | Scanner runtime error |
| 4    | Redaction failed |
| 5    | Restore failed |

## Configuration

Create a `.secretguard.yml` file in your project root:

```yaml
version: 1
scan:
  git:
    working_tree: true
    staged: false
    history: false
  agents:
    enabled: true
  docker:
    enabled: false
report:
  format: terminal
  fail_on: high
  show_fingerprints: true
  show_secret_preview: true
allowlist:
  paths:
    - "testdata/**"
  fingerprints: []
  regexes:
    - "dummy_[A-Za-z0-9]+"
```

CLI flags override config file values.

## Development

```bash
make test
make vet
make build
```

## License

MIT
