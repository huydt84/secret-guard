# Threat Model

## Scope

SecretGuard addresses the threat of accidental secret exposure through local data sources. It does not address remote scanning, credential verification, or network-level threats.

## Data sources

| Source | Threat |
|--------|--------|
| Git working tree | Secrets in currently tracked files |
| Git staged | Secrets in changes staged for commit |
| Git history | Secrets that were committed and later deleted |
| AI-agent data | Secrets in exported sessions, transcripts, logs |
| Dockerfile | Secrets baked into image layers via ENV/ARG |
| Compose | Secrets in environment definitions |
| Container metadata | Secrets visible via docker inspect |
| Image history | Secrets visible via docker history |

## Attacker model

| Attacker | Access | Risk |
|----------|--------|------|
| Contributor | Local repo, git history | Low — already has access |
| CI/CD user | Build logs, published images | Medium — may see env vars |
| Image puller | Image layers, history | High — can see baked secrets |
| Agent data reader | Session files, transcripts | Medium — leaked via prompt/response |

## Assumptions

- The user controls their local environment.
- Git repositories are cloned from trusted remotes.
- Docker images are pulled from trusted registries.
- Agent tools store data locally by default.

## Trust boundaries

```
User workstation
  ├── Git repository (controlled)
  ├── Docker daemon (controlled)
  ├── Agent session files (controlled)
  └── SecretGuard binary (trusted)
        └── Never makes network calls
```

## Key mitigations

- Scans are read-only.
- Redaction defaults to dry-run.
- Backups are created before in-place writes.
- Restore verifies checksums.
- Full secrets never appear in reports or plans.
- No network calls — no data exfiltration risk.

## Out of scope

- Third-party secret scanning services.
- Credential rotation automation.
- Network-level attacks.
- Physical access attacks.
- Social engineering.
