# Docker Remediation

SecretGuard detects secrets in Docker metadata and generates safe remediation plans. It does not remove containers or images automatically.

## Generate a plan

```bash
secretguard remediate docker --finding-id FINDING_ID --report report.json
```

## Risk by field

### Dockerfile ENV

Secrets baked into `ENV` instructions are visible in the image layer. Anyone with access to the image can retrieve them via `docker history`.

**Fix:** Use `docker build --secret` to pass secrets at build time without persisting them.

```dockerfile
# Bad — secret baked into image
ENV DATABASE_URL=postgres://user:pass@localhost/db

# Good — pass at build time
# docker build --secret id=db_url,src=./db_url.txt .
RUN --mount=type=secret,id=db_url \
    export DATABASE_URL=$(cat /run/secrets/db_url)
```

### Dockerfile ARG

`ARG` values are visible in image history even though they are not persisted in the final image. BuildKit caches can also leak `ARG` values.

**Fix:** Use build-time secrets instead.

### Compose environment

Hard-coded environment values in `docker-compose.yml` are visible to anyone with access to the file or the running container's metadata.

**Fix:** Use `env_file` with restricted permissions and add the file to `.gitignore`.

### Container Config.Env

Environment variables in running containers are visible via `docker inspect`.

**Fix:** Recreate the container without secrets in environment variables. Use a secrets manager or local env file.

### Image history

Secrets that were set during a build step remain in the image history.

**Fix:** Rebuild the image using multi-stage builds and build-time secrets. Consider distroless base images.

## Safer alternatives

| Method | Build-time | Runtime | Persisted |
|--------|-----------|---------|-----------|
| Dockerfile ENV | Yes | Yes | Yes |
| Dockerfile ARG | Yes | No | In history |
| docker --secret | Yes | No | No |
| env_file | No | Yes | On disk |
| Docker secrets | No | Yes | Encrypted |
| Secret manager | No | Yes | External |

## Safety rules

- SecretGuard never removes containers or images automatically.
- Plans include safest practice alternatives.
- Rebuild and redeploy affected images after rotating credentials.
