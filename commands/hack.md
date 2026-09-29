---
description: Pentest a target using Claude Code itself as the engine — no LLM API key, no Docker. You do the recon/exploitation and file findings via the Strix reporting MCP server.
argument-hint: [target] (e.g. ./ , https://example.com , owner/repo , an API base URL)
---

Run a **Strix-style pentest where you (Claude Code) are the pentesting agent** — no separate LLM API key and no Docker sandbox. Invoke the bundled **hacking-with-claude-code** skill now and follow it as the authoritative workflow.

Target: `$ARGUMENTS`

In short:

1. **Authorization first.** Only test what the user is authorized to test. If you can't confirm they own the target or have explicit permission, ask before doing anything.
2. Call `strix_begin_engagement` (Strix reporting MCP server) with the in-scope target(s) and the authorization confirmation. If the `strix` MCP tools aren't available, tell the user the server didn't start (it needs `uv` on PATH) and stop.
3. Recon and exploit with your own native tools (shell, file access, `curl`/HTTP, browser), following the methodology of the matching target skill (`find-security-vulnerabilities-in-code`, `web-app-penetration-testing`, `api-security-testing`, or `owasp-top-10-testing`). Before testing a specific class or stack, load Strix's matching knowledge pack with `strix_load_skill` (browse them with `strix_list_skills`) to use its exact payloads and workflow. Only report what you can prove with a working proof-of-concept.
4. File each validated finding with `strix_report_vulnerability`, then call `strix_finish_engagement` to emit the artifacts (`vulnerabilities.json`, `findings.sarif`, per-finding Markdown, `run.json`) under `strix_runs/`.
5. Summarize findings by severity with their PoCs, state what you did **not** cover, and point the user at the artifacts. For remediation, use **/strix:fix**.

If you'd rather run Strix's full autonomous engine (its own agents + Docker sandbox + intercepting proxy), use **/strix:scan** instead — that path needs an LLM key or an app.strix.ai account.

If `$ARGUMENTS` is empty, ask the user for a target and its authorization status first.
