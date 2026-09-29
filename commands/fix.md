---
description: Remediate vulnerabilities found by a Strix scan — triage by severity, patch the root cause, and re-run Strix to prove each fix closes the exploit.
argument-hint: [optional: path to strix_runs/<run>/ , vulnerabilities.json, findings.sarif, or a cloud scan id]
---

Remediate the security findings from a **Strix** pentest and verify the fixes.

Invoke the bundled **fix-security-vulnerabilities-with-strix** skill now and follow it as the authoritative workflow. In short:

1. **Triage** — load the findings from wherever the scan ran (OSS CLI artifacts in `strix_runs/<run>/vulnerabilities/*.md` and `vulnerabilities.json`, or the cloud via `strix cloud vulns list --json`). Order work critical → high → medium → low. Every Strix finding was validated with a working PoC — do not dismiss one as a false positive without re-testing its PoC.
2. **Fix** — patch the root cause, not the payload; prefer the framework's built-in defense; keep the diff minimal and match the repo's existing patterns.
3. **Verify** — re-run Strix scoped to the changed area (diff scope, or `--instruction` focused on the original finding) and confirm the finding is gone; also re-run the raw PoC and the project's own test suite.
4. **Report** — per finding: severity, root cause, fix (file:line), and verification result. Never print live secrets; if one leaked, state that rotation is required.

Context / target for this fix session: `$ARGUMENTS`

If no findings source is given and none is discoverable in the working tree, ask the user where the scan results are (or run **/strix:scan** first).
