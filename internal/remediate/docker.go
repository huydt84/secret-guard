package remediate

import (
	"strings"

	"github.com/huydinhtrong/secretguard/internal/finding"
)

func GenerateDockerPlan(f finding.Finding) RemediationPlan {
	field := classifyDockerField(f)
	steps := buildDockerSteps(field)
	warnings := buildDockerWarnings()

	return RemediationPlan{
		FindingID:   f.ID,
		Source:      f.Source,
		DetectorID:  f.DetectorID,
		SecretKind:  f.SecretKind,
		Severity:    f.Severity.String(),
		Preview:     f.Preview,
		Fingerprint: f.Fingerprint,
		Steps:       steps,
		Warnings:    warnings,
	}
}

type dockerField int

const (
	dockerFieldENV dockerField = iota + 1
	dockerFieldARG
	dockerFieldComposeEnv
	dockerFieldContainerEnv
	dockerFieldImageHistory
)

func classifyDockerField(f finding.Finding) dockerField {
	path := f.Location.Path

	if strings.HasPrefix(path, "image:") {
		return dockerFieldImageHistory
	}

	if f.Location.Line > 0 && path != "" {
		if strings.Contains(strings.ToLower(path), "dockerfile") {
			if strings.Contains(f.Evidence.Context, "ARG") {
				return dockerFieldARG
			}
			return dockerFieldENV
		}
		if strings.Contains(strings.ToLower(path), "compose") || strings.Contains(strings.ToLower(path), ".yml") {
			return dockerFieldComposeEnv
		}
	}

	if strings.HasPrefix(strings.ToLower(path), "sha256:") || len(path) >= 12 {
		return dockerFieldContainerEnv
	}

	return dockerFieldENV
}

func buildDockerSteps(field dockerField) []Step {
	switch field {
	case dockerFieldENV:
		return []Step{
			{
				Title:       "Remove the secret from Dockerfile ENV",
				Description: "ENV instructions bake secrets into the image layer. Any user with image access can retrieve them via `docker history` or `docker inspect`.",
				Command:     "Remove the ENV line containing the secret from the Dockerfile.",
			},
			{
				Title:       "Use build-time secrets instead",
				Description: "Pass secrets at build time using `docker build --secret`. The secret is available in the build context but not persisted in the image.",
				Command:     "docker build --secret id=mysecret,src=./mysecret.txt -t myimage .",
			},
			{
				Title:       "Use a local env file with restricted permissions",
				Description: "Store secrets in a .env file (chmod 600) and load them in the container at runtime. Ensure the .env file is in .dockerignore.",
				Command:     "echo SECRET=value > .env && chmod 600 .env",
			},
		}

	case dockerFieldARG:
		return []Step{
			{
				Title:       "Remove the secret from Dockerfile ARG",
				Description: "ARG values are visible in `docker history` even if not persisted in the final image. BuildKit caches can also leak ARG values.",
				Command:     "Remove the ARG line containing the secret from the Dockerfile.",
			},
			{
				Title:       "Use build-time secrets instead of ARG",
				Description: "BuildKit secrets (`--secret`) provide a safer way to pass secrets at build time without exposing them in image history.",
				Command:     "docker build --secret id=mysecret,src=./mysecret.txt -t myimage .",
			},
		}

	case dockerFieldComposeEnv:
		return []Step{
			{
				Title:       "Remove inline secrets from Compose environment",
				Description: "Hard-coded environment values in docker-compose.yml are visible to anyone with access to the file or the running container's metadata.",
				Command:     "Remove the sensitive environment variable from docker-compose.yml and use an env_file instead.",
			},
			{
				Title:       "Use an env_file with restricted permissions",
				Description: "Reference an external env_file in docker-compose.yml. The file should have restricted permissions (chmod 600) and be excluded from version control.",
				Command:     "echo SECRET=value > .env && echo .env >> .gitignore && chmod 600 .env",
			},
			{
				Title:       "Use Docker secrets for swarm deployments",
				Description: "Docker Swarm secrets are encrypted at rest and only mounted into containers that explicitly request them.",
				Command:     "docker secret create my_secret ./secret_value.txt",
			},
		}

	case dockerFieldContainerEnv:
		return []Step{
			{
				Title:       "Rotate the exposed credential immediately",
				Description: "Environment variables in running containers are visible via `docker inspect` and in the container metadata. The credential should be rotated at the provider.",
			},
			{
				Title:       "Recreate the container without secrets in env",
				Description: "Stop and remove the container, then recreate it using a secret injection method (env_file with restricted permissions, Docker secrets, or a secrets manager).",
			},
			{
				Title:       "Use a secrets manager or short-lived tokens",
				Description: "Modern deployments should use a secrets manager (HashiCorp Vault, AWS Secrets Manager) or short-lived tokens to avoid long-lived credentials in environment variables.",
			},
		}

	case dockerFieldImageHistory:
		return []Step{
			{
				Title:       "Rebuild the image without embedding secrets",
				Description: "The secret is embedded in the image history. Any user with pull access can retrieve it via `docker history`. Rebuild the image using build-time secrets or multi-stage builds.",
				Command:     "docker build --secret id=mysecret,src=./mysecret.txt -t myimage:fixed .",
			},
			{
				Title:       "Use multi-stage builds to isolate secrets",
				Description: "Multi-stage builds allow you to use secrets in intermediate stages without carrying them into the final image.",
				Command:     "See: https://docs.docker.com/build/building/multi-stage/",
			},
			{
				Title:       "Consider using a distroless base image",
				Description: "Distroless images reduce the attack surface and make it harder to accidentally leak secrets through shell history or package caches.",
			},
		}

	default:
		return []Step{
			{
				Title:       "Investigate the Docker secret exposure",
				Description: "The secret was detected in a Docker context. Rotate the credential and apply Docker best practices to avoid embedding secrets in images or metadata.",
			},
		}
	}
}

func buildDockerWarnings() []string {
	return []string{
		"Do not delete containers or images based on this plan alone — always coordinate with the team first.",
		"After rotating credentials, rebuild and redeploy any affected images or containers.",
		"Review all CI/CD pipelines that might have access to the exposed credential.",
	}
}
