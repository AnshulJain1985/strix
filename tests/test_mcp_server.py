"""Tests for the Strix reporting MCP server (``strix.mcp_server``).

These exercise the "Claude Code is the brain" no-key mode: the server owns
only the reporting half of a run, reusing :class:`ReportState`. The heavy
``mcp`` server extra is guarded so the suite skips cleanly where it is absent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


pytest.importorskip("mcp.server.fastmcp")

from strix.mcp_server.server import build_server


_EXPECTED_TOOLS = {
    "strix_begin_engagement",
    "strix_report_vulnerability",
    "strix_update_vulnerability",
    "strix_delete_vulnerability",
    "strix_list_vulnerabilities",
    "strix_get_vulnerability",
    "strix_list_skills",
    "strix_load_skill",
    "strix_finish_engagement",
}


def _text(result: Any) -> str:
    """Extract the text payload from a FastMCP ``call_tool`` result.

    ``call_tool`` returns ``(content, structured)``; ``content`` is a list of
    ``TextContent``. Fall back to the raw result for older shapes.
    """
    content = result[0] if isinstance(result, tuple) else result
    return content[0].text


def _json(result: Any) -> Any:
    return json.loads(_text(result))


async def _begin(server: Any, **overrides: Any) -> Any:
    args: dict[str, Any] = {"targets": ["./"], "authorization_confirmed": True}
    args.update(overrides)
    return await server.call_tool("strix_begin_engagement", args)


async def test_build_server_registers_expected_tools() -> None:
    server = build_server()
    names = {tool.name for tool in await server.list_tools()}
    assert names == _EXPECTED_TOOLS


async def test_begin_requires_authorization() -> None:
    server = build_server()
    out = _text(await _begin(server, authorization_confirmed=False))
    assert "NOT started" in out
    # The engagement never opened, so filing a finding is still blocked.
    with pytest.raises(Exception, match="No engagement is open"):
        await server.call_tool(
            "strix_report_vulnerability",
            {"title": "x", "severity": "low", "description": "d"},
        )


async def test_begin_requires_a_target() -> None:
    server = build_server()
    out = _text(await _begin(server, targets=[]))
    assert "at least one target" in out


async def test_report_blocked_before_engagement() -> None:
    server = build_server()
    with pytest.raises(Exception, match="No engagement is open"):
        await server.call_tool(
            "strix_report_vulnerability",
            {"title": "SQLi", "severity": "high", "description": "d"},
        )


async def test_full_engagement_flow_writes_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    server = build_server()

    begin = _json(await _begin(server, scope="local repo"))
    assert begin["status"] == "engagement_open"

    filed = _json(
        await server.call_tool(
            "strix_report_vulnerability",
            {
                "title": "SQL injection in search",
                "severity": "high",
                "description": "User input concatenated into SQL.",
                "poc_description": "GET /search?q=' OR '1'='1",
                "cwe": "CWE-89",
                "cvss": 8.6,
                "endpoint": "/search",
                "method": "GET",
                "finding_class": "code",
            },
        )
    )
    assert filed["status"] == "filed"
    report_id = filed["id"]

    listing = _json(await server.call_tool("strix_list_vulnerabilities", {}))
    assert listing["count"] == 1
    assert listing["findings"][0]["id"] == report_id

    got = _json(await server.call_tool("strix_get_vulnerability", {"report_id": report_id}))
    assert got["title"] == "SQL injection in search"
    assert got["severity"] == "high"

    finished = _json(
        await server.call_tool(
            "strix_finish_engagement", {"executive_summary": "One high finding."}
        )
    )
    assert finished["status"] == "completed"
    assert finished["finding_count"] == 1

    artifacts = finished["artifacts"]
    for key in ("vulnerabilities_json", "sarif", "run_json"):
        assert Path(artifacts[key]).is_file(), f"missing artifact: {key}"

    sarif = json.loads(Path(artifacts["sarif"]).read_text())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1

    vulns = json.loads(Path(artifacts["vulnerabilities_json"]).read_text())
    assert len(vulns) == 1

    run = json.loads(Path(artifacts["run_json"]).read_text())
    assert run["status"] == "completed"

    md = Path(artifacts["reports_dir"]) / f"{report_id}.md"
    assert md.is_file()


async def test_update_and_delete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    server = build_server()
    await _begin(server)

    report_id = _json(
        await server.call_tool(
            "strix_report_vulnerability",
            {"title": "IDOR", "severity": "medium", "description": "no authz"},
        )
    )["id"]

    updated = _json(
        await server.call_tool(
            "strix_update_vulnerability",
            {"report_id": report_id, "fields": {"fix_verification": "patched and retested"}},
        )
    )
    assert updated["status"] == "updated"
    got = _json(await server.call_tool("strix_get_vulnerability", {"report_id": report_id}))
    assert got.get("fix_verification") == "patched and retested"

    deleted = _json(
        await server.call_tool(
            "strix_delete_vulnerability",
            {"report_id": report_id, "reason": "duplicate of vuln-0001"},
        )
    )
    assert deleted["status"] == "deleted"
    listing = _json(await server.call_tool("strix_list_vulnerabilities", {}))
    assert listing["count"] == 0


async def test_list_skills_returns_catalog() -> None:
    server = build_server()
    catalog = _json(await server.call_tool("strix_list_skills", {}))
    assert catalog["count"] > 0
    assert "vulnerabilities" in catalog["categories"]


async def test_load_skill_valid_and_invalid() -> None:
    server = build_server()
    loaded = _text(await server.call_tool("strix_load_skill", {"skills": ["xss"]}))
    assert "Skill: xss" in loaded

    bad = _text(await server.call_tool("strix_load_skill", {"skills": ["not_a_real_skill_xyz"]}))
    assert "Invalid skill" in bad
