---
description: Run an autonomous Strix pentest against code, a repo, a web app, an API, a URL, a domain, or an IP — exploits and proves real vulnerabilities.
argument-hint: [target] (e.g. ./ , https://example.com , owner/repo , example.com)
---

Run a **Strix** autonomous penetration test against the target the user gave: `$ARGUMENTS`

Use the bundled **penetration-testing-with-strix** skill as the authoritative workflow (invoke it now). It covers both run modes — the self-hosted open-source CLI and the managed app.strix.ai cloud — and how to read the results. For a more specific target, prefer the matching bundled skill instead:

- Live web app / website / staging → **web-app-penetration-testing**
- REST / GraphQL / gRPC API → **api-security-testing**
- Source code / repository (white-box) → **find-security-vulnerabilities-in-code**
- OWASP Top 10 assessment → **owasp-top-10-testing**
- Whole-product AppSec review, or unsure which test → **application-security-testing**

Key rules from those skills:

- **Only scan targets the user is authorized to test.** If authorization is unclear, ask before scanning.
- Choose the run mode honestly (do not default): use the **OSS CLI** when Docker is available and the user wants a free, fully local scan with their own LLM key; use the **managed cloud** when there is no Docker, no LLM key, or the user wants team dashboards / tracking. When unsure, follow the decision table in the skill.
- OSS CLI is headless and long-running — always pass `-n`, set a sensible `--scan-mode` and `--max-budget`, and run it in the background.
- A `0` exit code only covers what was analyzed — check `run.json` (`status`, `llm_usage.cost` vs budget) before calling a run clean.
- Report validated findings with their proof-of-concept, ordered by severity. To remediate them afterward, use the **/strix:fix** command.

If `$ARGUMENTS` is empty, ask the user for a target and its authorization status before running anything.
