"""The Strix reporting MCP server.

Exposes a small set of tools over MCP (stdio) that let an external agent —
Claude Code, Cursor, or any MCP client — record and manage validated pentest
findings and emit Strix's standard artifacts. The agent supplies its own
intelligence and its own recon/exploitation tools; this server owns only the
structured-reporting half of a Strix run, reusing :class:`ReportState` so the
output is byte-for-byte the same shape as a native ``strix`` scan.

No LLM API key and no Docker are required: nothing here calls an LLM or starts
the sandbox. Findings are written under ``strix_runs/<run>/`` relative to the
working directory the server is launched from — for a Claude Code plugin that
is the user's project root, exactly where a native ``strix`` run writes them.
Name the run with the ``STRIX_RUN_NAME`` environment variable.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from strix.report import ReportState, set_global_report_state


logger = logging.getLogger(__name__)


class _Engagement:
    """Holds the single engagement's state for one server process.

    Findings are refused until :meth:`open` runs, so ``strix_begin_engagement``
    — where scope and, above all, authorization to test the target are recorded
    — is a required first step.
    """

    def __init__(self) -> None:
        self.state = ReportState(run_name=os.environ.get("STRIX_RUN_NAME") or None)
        self.started = False

    def require(self) -> ReportState:
        if not self.started:
            raise RuntimeError(
                "No engagement is open. Call strix_begin_engagement first — it "
                "records the target, scope, and your confirmation that testing "
                "is authorized before any finding can be filed."
            )
        return self.state


def _summarize(report: dict[str, Any]) -> dict[str, Any]:
    """A compact view of a finding for list responses."""
    return {
        "id": report.get("id"),
        "title": report.get("title"),
        "severity": report.get("severity"),
        "cwe": report.get("cwe"),
        "endpoint": report.get("endpoint"),
        "finding_class": report.get("finding_class"),
    }


def build_server() -> Any:
    """Construct the FastMCP server with the Strix reporting tools bound.

    The ``mcp`` import is deferred so ``import strix.mcp_server`` stays cheap and
    the optional dependency is only needed when the server is actually launched.
    """
    try:
        from mcp.server.fastmcp import FastMCP  # noqa: PLC0415 - optional dep, deferred
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise SystemExit(
            "The Strix MCP server needs the 'mcp' package. Install Strix with "
            "the mcp-server extra (`uv sync --extra mcp-server`, or "
            "`pip install strix-agent[mcp-server]`), or launch via `uv run "
            "--extra mcp-server python -m strix.mcp_server`."
        ) from exc

    engagement = _Engagement()
    set_global_report_state(engagement.state)

    mcp = FastMCP(
        "strix",
        instructions=(
            "Strix reporting tools. You are the pentester: do your own recon "
            "and exploitation with your native tools, prove each issue with a "
            "working proof-of-concept, then file it here so Strix emits its "
            "standard artifacts (vulnerabilities.json, per-finding Markdown, "
            "findings.sarif, run.json). Only test targets you are authorized "
            "to test. Start with strix_begin_engagement; end with "
            "strix_finish_engagement."
        ),
    )

    @mcp.tool()
    def strix_begin_engagement(
        targets: list[str],
        authorization_confirmed: bool,
        scope: str | None = None,
        instructions: str | None = None,
        scope_mode: str = "auto",
    ) -> str:
        """Open a pentest engagement and record its scope and authorization.

        Call this once before filing any finding. ``authorization_confirmed``
        MUST be true and must reflect a real authorization to test every listed
        target — the user's own asset, an explicit written scope, or a
        sanctioned engagement/CTF. If you cannot confirm authorization, stop and
        ask the user rather than passing true.

        Args:
            targets: The assets in scope (repo paths, URLs, domains, IPs, API
                base URLs). Testing anything not listed here is out of scope.
            authorization_confirmed: True only when testing every target is
                authorized. Filing findings is blocked until this is true.
            scope: Free-text scope/rules of engagement (allowed hosts, excluded
                paths, accounts, time windows).
            instructions: What the user asked you to focus on, if anything.
            scope_mode: "auto", "full", or "diff" — informational, mirrors the
                Strix CLI's scoping notion.
        """
        if not authorization_confirmed:
            return (
                "Engagement NOT started: authorization was not confirmed. Strix "
                "only tests targets the user is authorized to test. Confirm the "
                "user owns or has explicit permission to test "
                f"{', '.join(targets) or 'the target(s)'}, then call this again "
                "with authorization_confirmed=true."
            )
        if not targets:
            return "Engagement NOT started: provide at least one target."

        engagement.state.set_scan_config(
            {
                "targets": [{"target": t, "type": "unknown"} for t in targets],
                "user_instructions": instructions or "",
                "scope_mode": scope_mode,
                "scan_mode": "claude-code",
                "non_interactive": True,
                "authorization": {"confirmed": True, "scope": scope or ""},
            }
        )
        engagement.started = True
        run_dir = engagement.state.get_run_dir()
        logger.info("Engagement started for %s -> %s", targets, run_dir)
        return json.dumps(
            {
                "status": "engagement_open",
                "run_dir": str(run_dir),
                "targets": targets,
                "note": (
                    "Recon and exploit with your own tools; file each validated "
                    "finding with strix_report_vulnerability. Call "
                    "strix_finish_engagement when done."
                ),
            }
        )

    @mcp.tool()
    def strix_report_vulnerability(
        title: str,
        severity: str,
        description: str,
        impact: str | None = None,
        target: str | None = None,
        technical_analysis: str | None = None,
        poc_description: str | None = None,
        poc_script_code: str | None = None,
        remediation_steps: str | None = None,
        evidence: str | None = None,
        confidence: str | None = None,
        cvss: float | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        cve: str | None = None,
        cwe: str | None = None,
        code_locations: list[dict[str, Any]] | None = None,
        finding_class: str | None = None,
    ) -> str:
        """File a single validated vulnerability finding.

        Only report an issue you have actually proven — include a concrete
        proof-of-concept (``poc_description`` and, where applicable,
        ``poc_script_code``) rather than a theoretical concern. Each call writes
        the finding to ``vulnerabilities.json``, a per-finding Markdown file, and
        ``findings.sarif`` immediately.

        Args:
            title: Short, specific finding title.
            severity: One of info, low, medium, high, critical.
            description: What the vulnerability is.
            impact: What an attacker gains by exploiting it.
            target: The specific in-scope target this affects.
            technical_analysis: Root-cause / data-flow analysis.
            poc_description: Step-by-step reproduction of the exploit.
            poc_script_code: A runnable PoC (request, script) when applicable.
            remediation_steps: How to fix the root cause.
            evidence: Raw proof (response snippet, output) — never live secrets.
            confidence: firm / tentative, if you want to flag certainty.
            cvss: CVSS base score 0.0-10.0, if computed.
            endpoint: Affected URL/endpoint for web/API findings.
            method: HTTP method for web/API findings.
            cve: Related CVE id, if any.
            cwe: CWE id (e.g. "CWE-89").
            code_locations: For code findings, list of
                {file, start_line, end_line, snippet, fix_before, fix_after}.
            finding_class: "code" for static/source findings, else "dynamic".
        """
        state = engagement.require()
        report_id = state.add_vulnerability_report(
            title=title,
            severity=severity,
            description=description,
            impact=impact,
            target=target,
            technical_analysis=technical_analysis,
            poc_description=poc_description,
            poc_script_code=poc_script_code,
            remediation_steps=remediation_steps,
            evidence=evidence,
            confidence=confidence,
            cvss=cvss,
            endpoint=endpoint,
            method=method,
            cve=cve,
            cwe=cwe,
            code_locations=code_locations,
            finding_class=finding_class,
            agent_name="claude-code",
        )
        return json.dumps({"status": "filed", "id": report_id, "run_dir": str(state.get_run_dir())})

    @mcp.tool()
    def strix_update_vulnerability(report_id: str, fields: dict[str, Any]) -> str:
        """Update fields of an already-filed finding (e.g. add fix_verification,
        adjust severity, attach more evidence). ``fields`` maps finding fields to
        their new values."""
        state = engagement.require()
        try:
            state.update_vulnerability_report(report_id, fields)
        except Exception as exc:  # noqa: BLE001 - surface as tool error text
            return f"Update failed for {report_id}: {exc}"
        return json.dumps({"status": "updated", "id": report_id})

    @mcp.tool()
    def strix_delete_vulnerability(report_id: str, reason: str) -> str:
        """Retract a finding filed in error (false positive, duplicate). The
        ``reason`` is recorded."""
        state = engagement.require()
        try:
            state.delete_vulnerability_report(
                report_id, delete_reason=reason, deleted_by_agent_name="claude-code"
            )
        except Exception as exc:  # noqa: BLE001 - surface as tool error text
            return f"Delete failed for {report_id}: {exc}"
        return json.dumps({"status": "deleted", "id": report_id, "reason": reason})

    @mcp.tool()
    def strix_list_vulnerabilities() -> str:
        """List all findings filed so far this engagement (compact view)."""
        state = engagement.require()
        reports = state.get_existing_vulnerabilities()
        return json.dumps({"count": len(reports), "findings": [_summarize(r) for r in reports]})

    @mcp.tool()
    def strix_get_vulnerability(report_id: str) -> str:
        """Return the full stored record for one finding."""
        state = engagement.require()
        for report in state.get_existing_vulnerabilities():
            if report.get("id") == report_id:
                return json.dumps(report)
        return f"No finding with id {report_id}."

    @mcp.tool()
    def strix_finish_engagement(
        executive_summary: str,
        methodology: str = "",
        technical_analysis: str = "",
        recommendations: str = "",
    ) -> str:
        """Close the engagement and finalize all artifacts.

        Writes the executive report and marks the run complete. Returns the
        paths to every artifact so you can point the user at them or hand them
        to the fix workflow.

        Args:
            executive_summary: A short summary of what was tested and found.
            methodology: How you tested (optional).
            technical_analysis: Cross-finding technical notes (optional).
            recommendations: Prioritized remediation guidance (optional).
        """
        state = engagement.require()
        state.update_scan_final_fields(
            executive_summary=executive_summary,
            methodology=methodology,
            technical_analysis=technical_analysis,
            recommendations=recommendations,
        )
        run_dir = state.get_run_dir()
        findings = state.get_existing_vulnerabilities()
        return json.dumps(
            {
                "status": "completed",
                "run_dir": str(run_dir),
                "finding_count": len(findings),
                "artifacts": {
                    "vulnerabilities_json": str(run_dir / "vulnerabilities.json"),
                    "vulnerabilities_csv": str(run_dir / "vulnerabilities.csv"),
                    "sarif": str(run_dir / "findings.sarif"),
                    "reports_dir": str(run_dir / "vulnerabilities"),
                    "run_json": str(run_dir / "run.json"),
                },
            }
        )

    return mcp


def main() -> None:
    """Run the server over stdio."""
    logging.basicConfig(level=os.environ.get("STRIX_MCP_LOG_LEVEL", "INFO"))
    server = build_server()
    server.run()
