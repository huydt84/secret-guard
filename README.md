# SecretGuard

Local-first secret leak detection and safe remediation for code, git history, AI-agent data, and Docker metadata.

## Safety Warning

**SecretGuard handles sensitive data.** Always review findings before taking remediation action. Redaction is dry-run by default and requires `--apply` to write changes. Git history rewriting must never be automated.

## Quick Start

```bash
# Build
make build

# Run
./bin/secretguard version
./bin/secretguard doctor
./bin/secretguard scan .
```

## Development

```bash
make test
make vet
make build
```

## License

MIT
