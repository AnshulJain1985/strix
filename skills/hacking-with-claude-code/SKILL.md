---
name: hacking-with-claude-code
description: Run a Strix-style penetration test where Claude Code itself is the pentesting agent — no separate LLM API key and no Docker. You do the recon and exploitation with your own native tools (shell, file access, HTTP requests, browser) and file each validated finding through the bundled Strix reporting MCP server, which emits Strix's standard artifacts (vulnerabilities.json, per-finding Markdown, findings.sarif, run.json). Use this when the user wants to pentest, security-review, or hack a target from inside Claude Code without installing an LLM key or the Docker sandbox. For the full autonomous engine (its own agents, sandbox, and proxy), use the penetration-testing-with-strix skill instead.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
---

# Pentest with Claude Code as the engine

This is the **"Claude Code is the brain"** mode of Strix. Instead of Strix running its own LLM-driven agents (which need an LLM API key and a Docker sandbox), **you — Claude Code — are the pentester.** You reason and act with your own native tools, and you use the bundled **Strix reporting MCP server** to record findings so the output is identical to a native Strix scan.

- **No separate LLM API key**, because your own model does the thinking.
- **No Docker**, because you use your own shell/file/HTTP/browser tools, not the Strix sandbox.
- **Same artifacts** as a native run: `strix_runs/<run>/` with `vulnerabilities.json`, per-finding Markdown, `findings.sarif` (SARIF 2.1.0), and `run.json` — so results feed straight into CI, the **fix-security-vulnerabilities-with-strix** skill, and any SARIF consumer.

> When to use the full engine instead: if you want Strix's own tuned autonomous agents, its intercepting proxy (Caido), the isolated Docker sandbox, and unattended long-running scans, use **penetration-testing-with-strix** (self-hosted CLI) or **managed-pentesting-with-strix** (cloud). This mode trades that autonomy for zero setup and zero extra cost.

## The reporting tools (MCP server `strix`)

The plugin starts a stdio MCP server exposing these tools. If they are not available, tell the user the `strix` MCP server didn't start (it needs `uv` on PATH — the plugin launches `uv run --extra mcp-server python -m strix.mcp_server`) and stop.

- `strix_begin_engagement(targets, authorization_confirmed, scope?, instructions?, scope_mode?)` — open the engagement. **Call this first.**
- `strix_list_skills()` / `strix_load_skill(skills)` — browse and load Strix's built-in pentesting knowledge packs (75+ packs: vulnerability classes, recon, frameworks, protocols, technologies, tooling). These are the exact reference Strix's own agents use — no engagement required, consult them freely.
- `strix_report_vulnerability(title, severity, description, ...)` — file one validated finding (writes artifacts immediately).
- `strix_list_vulnerabilities()` / `strix_get_vulnerability(id)` — review what you've filed.
- `strix_update_vulnerability(id, fields)` — revise a finding (e.g. add `fix_verification`).
- `strix_delete_vulnerability(id, reason)` — retract a false positive.
- `strix_finish_engagement(executive_summary, ...)` — finalize the run and get artifact paths.

## Step 0 — Authorization (do this before anything else)

**Only test targets the user is authorized to test.** Before touching the target, confirm the user owns it or has explicit permission (their own repo/app, a written scope, a sanctioned engagement, or a CTF). If you cannot confirm, ask — do not scan. Pass `authorization_confirmed=true` to `strix_begin_engagement` only when this is genuinely true; the server blocks findings until you do. For a live web/API/network target, stay strictly within the scope the user gives (allowed hosts, excluded paths, rate limits, time windows) and prefer non-destructive proofs.

## Step 1 — Begin the engagement

Identify the target type and call `strix_begin_engagement` with every in-scope target and the authorization confirmation. Note the returned `run_dir`.

## Step 2 — Recon and exploit with your own tools

Work like the relevant target-specific skill describes — those skills (`find-security-vulnerabilities-in-code`, `web-app-penetration-testing`, `api-security-testing`, `owasp-top-10-testing`) are the methodology; here you execute it yourself instead of shelling out to `strix`:

- **Code / repo (white-box):** read the source, map routes/sinks/auth, trace data flow from untrusted input to dangerous sinks. Look for injection, broken access control / IDOR, SSRF, insecure deserialization, secrets in code, unsafe dependencies, and business-logic flaws. Confirm exploitability by reading the code path (and running it locally when safe).
- **Live web app / API:** enumerate endpoints (from an OpenAPI/GraphQL schema when available, or by crawling), then test each class hands-on with real requests — auth bypass, BOLA/IDOR and other broken object/function-level authorization, injection, XSS, SSRF, mass assignment, and business logic. Use multiple accounts to prove access-control findings.
- Use your shell, file tools, and HTTP/`curl` (and a browser when the app needs JS) to actually reproduce each issue.
- **Lean on Strix's knowledge packs.** Before testing a specific class or stack, call `strix_load_skill` for the relevant pack (e.g. `["idor"]`, `["ssrf"]`, `["sql_injection"]`, `["jwt"]`, or a technology like `["firebase"]`) to get Strix's exact payloads and workflow. Call `strix_list_skills` first if you're unsure what's available.

**Validate before you file.** Report only what you can prove with a concrete proof-of-concept — a request, a script, an observed response, or a precise code path. A theoretical concern with no PoC is a note to the user, not a `strix_report_vulnerability` call.

## Step 3 — File each validated finding

As soon as you confirm an issue, call `strix_report_vulnerability` with a specific title, correct `severity` (info/low/medium/high/critical), the `impact`, a step-by-step `poc_description` (and `poc_script_code` when runnable), root-cause `technical_analysis`, and `remediation_steps`. Add `cwe`, `cvss`, `endpoint`/`method` for web/API, or `code_locations` (file, line range, snippet, `fix_before`/`fix_after`) for code. Set `finding_class="code"` for static findings. **Never put live secrets in `evidence`** — say a secret leaked and must be rotated instead.

## Step 4 — Finish

When testing is complete, call `strix_finish_engagement` with a short `executive_summary` (and optional methodology / recommendations). It marks the run complete and returns the paths to `vulnerabilities.json`, `findings.sarif`, the `vulnerabilities/` Markdown reports, and `run.json`.

Then summarize for the user: what was in scope, what you tested, and each finding by severity with its PoC — and point them at the artifact paths. To remediate, hand off to **fix-security-vulnerabilities-with-strix** (it reads the same artifacts).

## Honesty about coverage

You tested what you had time and access to test. Say so plainly: list what you did **not** cover (unreached code paths, endpoints you lacked credentials for, areas out of scope). A clean run means "nothing proven in what was tested," not "the target is secure."
