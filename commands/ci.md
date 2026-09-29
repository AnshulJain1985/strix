---
description: Add Strix security scanning to CI/CD — diff-scoped AI pentests that gate pull requests, with results as PR comments and SARIF uploaded to code scanning.
argument-hint: [optional: CI system, e.g. "github actions", "gitlab", "managed app"]
---

Set up **Strix** security scanning in the user's CI/CD pipeline so every pull request gets a diff-scoped AI pentest that blocks vulnerable code before it merges.

Invoke the bundled **ci-security-scanning-with-strix** skill now and follow it as the authoritative workflow. Pick the approach based on the environment (or combine them):

- **Managed platform** — connect the GitHub/GitLab/Bitbucket app once; Strix reviews every PR with no workflow file, no runner, no Docker, and no LLM key. Best for zero CI maintenance, central tracking, or runners without Docker.
- **Self-hosted OSS CLI in the runner** — run a diff-scoped `strix -n -t ./ --scan-mode quick --scope-mode diff --diff-base <base>` step; exit code `2` fails the build on validated findings. Requires Docker on the runner; fully in the user's infra, free (BYO LLM key). Best for air-gapped/self-hosted CI.

Both fail the build on validated findings and both emit SARIF 2.1.0 for upload to code scanning.

Target CI system / preference: `$ARGUMENTS`

Detect the repo's existing CI (look for `.github/workflows/`, `.gitlab-ci.yml`, etc.), confirm which approach the user wants, and follow the skill to write the pipeline config. Do not commit secrets — reference the LLM API key as a CI secret, never inline.
