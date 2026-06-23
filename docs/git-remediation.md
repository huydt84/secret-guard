# Git Remediation

SecretGuard generates safe remediation plans for secrets found in git history. It does not execute git history rewrites automatically.

## Generate a plan

```bash
secretguard remediate git --finding-id FINDING_ID --report report.json
```

The plan includes these steps:

### 1. Rotate or revoke the credential

Before rewriting history, rotate the leaked credential at the provider. This limits the window of exposure even if the history rewrite is delayed.

### 2. Create a fresh mirror clone

```bash
git clone --mirror <repository-url> repo-mirror
```

Work on a mirror clone to avoid affecting your working directory.

### 3. Prepare a replacement text file

Create a replacement text file for `git filter-repo`. The replacement text maps secret patterns to redacted placeholders:

```text
ghp_* ==> [REVOKED]
```

### 4. Run git filter-repo

```bash
cd repo-mirror && git filter-repo --force --replace-text /tmp/replacements.txt
```

This rewrites the entire history in the mirror clone.

### 5. Re-scan the rewritten history

```bash
secretguard scan repo-mirror --git-history --format json
```

Verify no secrets remain before pushing.

### 6. Force-push after team coordination

```bash
cd repo-mirror && git push --force --mirror origin
```

**Warning:** Force-push breaks all open pull requests and requires all team members to re-clone or rebase.

## Safety rules

- SecretGuard never executes `git filter-repo` automatically.
- Plans never include the raw secret value.
- Always coordinate with your team before force-pushing.
- Rotate credentials first — rewriting history is not a substitute for revocation.
