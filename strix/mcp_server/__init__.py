"""Strix MCP server — expose Strix's structured pentest reporting to an
external MCP client (e.g. Claude Code) so the client's own model can drive a
pentest with no separate LLM API key.

This is the "Claude Code is the brain" mode: the client does the recon and
exploitation with its native tools (shell, files, HTTP, browser), and files
each validated finding through this server, which reuses Strix's
:class:`strix.report.ReportState` to emit the exact same artifacts a native
Strix run produces — ``vulnerabilities.json``, per-finding Markdown,
``findings.sarif`` (SARIF 2.1.0), and ``run.json`` — under ``strix_runs/``.
"""

from strix.mcp_server.server import build_server, main


__all__ = ["build_server", "main"]
