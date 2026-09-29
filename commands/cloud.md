---
description: Drive a managed Strix pentest on app.strix.ai via the `strix cloud` CLI — no local Docker or LLM key needed.
argument-hint: [optional: what to do, e.g. "scan ./", "scan example.com", "list critical vulns"]
---

Run a **managed** Strix pentest on the app.strix.ai platform using the `strix cloud` CLI (or the REST API). This needs no local Docker and no LLM key.

Invoke the bundled **managed-pentesting-with-strix** skill now and follow it as the authoritative workflow. It covers login and scopes, registering assets, safely reviewing and uploading local source, launching and polling scans, triaging vulnerabilities, exporting SARIF, downloading reports, PR reviews, credits, and schedules.

Requested action: `$ARGUMENTS`

Essentials from the skill:

- Authenticate first: `strix cloud login --scopes scans:read scans:write uploads:write billing:read`.
- **Only scan targets the user is authorized to test.**
- For a local source upload, do the safe two-step handoff: `strix cloud scans start --source . --dry-run --show-files --json`, review and capture `source.archive_sha256`, then rerun with the same selection flags plus `--approve-sha256 "$SHA"`.
- Output is JSON when not a TTY or with `--json`. Exit codes: `0` success, `1` error, `2` usage, `4` auth/plan limit, `5` payment required. Only top up credits (`strix cloud billing topup`) with explicit user approval after a `5`.
- If a scan launch is left ambiguous (network error / 5xx / interruption), check `strix cloud scans list` before retrying; delete an orphaned upload with `strix cloud uploads delete <id>`.

If no `strix` CLI is installed, tell the user how to install it (`curl -sSL https://strix.ai/install | bash`) or point them at the REST API docs at https://docs.app.strix.ai.
