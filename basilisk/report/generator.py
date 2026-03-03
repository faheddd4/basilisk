"""
Basilisk Report Generator — multi-format vulnerability reporting.

Generates HTML, JSON, SARIF, Markdown, and PDF reports from scan findings.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from basilisk.core.config import OutputConfig
from basilisk.core.session import ScanSession


async def generate_report(session: ScanSession, output_config: OutputConfig) -> str:
    """Generate a report in the configured format."""
    output_dir = Path(output_config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = f"basilisk_{session.id}_{timestamp}"

    fmt = output_config.format.lower()
    if fmt == "json":
        path = output_dir / f"{base_name}.json"
        _write_json_report(session, path)
    elif fmt == "sarif":
        path = output_dir / f"{base_name}.sarif"
        _write_sarif_report(session, path)
    elif fmt == "markdown":
        path = output_dir / f"{base_name}.md"
        _write_markdown_report(session, path)
    elif fmt == "html":
        path = output_dir / f"{base_name}.html"
        _write_html_report(session, path)
    else:
        path = output_dir / f"{base_name}.json"
        _write_json_report(session, path)

    return str(path)


def _write_json_report(session: ScanSession, path: Path) -> None:
    """Write a JSON report."""
    report = {
        "basilisk_version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session": session.summary,
        "profile": session.profile.to_dict(),
        "findings": [f.to_dict() for f in session.findings],
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)


def _write_sarif_report(session: ScanSession, path: Path) -> None:
    """Write a SARIF 2.1.0 report for CI/CD integration."""
    rules = []
    results = []
    seen_rules: set[str] = set()

    for finding in session.findings:
        rule_id = finding.attack_module.replace("basilisk.attacks.", "BSLK/")
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.description or finding.title},
                "defaultConfiguration": {"level": _sarif_level(finding.severity.value)},
                "helpUri": f"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "properties": {"category": finding.category.value, "owasp_id": finding.category.owasp_id},
            })

        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(finding.severity.value),
            "message": {"text": f"{finding.title}\n\nPayload: {finding.payload[:200]}"},
            "properties": {
                "finding_id": finding.id,
                "confidence": finding.confidence,
                "severity": finding.severity.value,
                "remediation": finding.remediation,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/refs/heads/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Basilisk",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/rothackers/basilisk",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }

    with open(path, "w") as f:
        json.dump(sarif, f, indent=2)


def _write_markdown_report(session: ScanSession, path: Path) -> None:
    """Write a Markdown report."""
    lines = [
        "# 🐍 Basilisk Scan Report",
        "",
        f"**Session:** `{session.id}`",
        f"**Target:** `{session.config.target.url}`",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Mode:** {session.config.mode.value}",
        f"**Model:** {session.profile.detected_model}",
        f"**Total Findings:** {len(session.findings)}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    summary = session.summary
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = summary["severity_counts"].get(sev, 0)
        lines.append(f"| {sev.upper()} | {count} |")

    lines.extend(["", "## Findings", ""])

    for f in sorted(session.findings, key=lambda x: x.severity.numeric, reverse=True):
        lines.extend([
            f"### {f.severity.icon} [{f.severity.value.upper()}] {f.title}",
            "",
            f"**ID:** `{f.id}`",
            f"**Category:** {f.category.value} ({f.category.owasp_id})",
            f"**Confidence:** {f.confidence:.0%}",
            "",
            f"**Payload:**",
            f"```",
            f"{f.payload}",
            f"```",
            "",
            f"**Response:**",
            f"```",
            f"{f.response[:500]}",
            f"```",
            "",
            f"**Remediation:** {f.remediation}",
            "",
            "---",
            "",
        ])

    with open(path, "w") as f:
        f.write("\n".join(lines))


def _write_html_report(session: ScanSession, path: Path) -> None:
    """Write a styled HTML report."""
    findings_html = ""
    for f in sorted(session.findings, key=lambda x: x.severity.numeric, reverse=True):
        color_map = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"}
        color = color_map.get(f.severity.value, "#6b7280")
        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color};">
            <div class="finding-header">
                <span class="severity" style="background: {color};">{f.severity.value.upper()}</span>
                <span class="finding-id">{f.id}</span>
                <span class="owasp">{f.category.owasp_id}</span>
            </div>
            <h3>{f.title}</h3>
            <p>{f.description}</p>
            <details>
                <summary>Payload</summary>
                <pre><code>{_html_escape(f.payload)}</code></pre>
            </details>
            <details>
                <summary>Response</summary>
                <pre><code>{_html_escape(f.response[:500])}</code></pre>
            </details>
            <p class="remediation"><strong>Remediation:</strong> {f.remediation}</p>
        </div>"""

    summary = session.summary
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Basilisk Scan Report — {session.id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0a; color: #e5e5e5; padding: 2rem; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{ text-align: center; padding: 2rem 0; border-bottom: 2px solid #dc2626; }}
        .header h1 {{ font-size: 2.5rem; color: #dc2626; }}
        .header .subtitle {{ color: #a3a3a3; margin-top: 0.5rem; }}
        .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin: 2rem 0; }}
        .stat {{ background: #171717; border-radius: 8px; padding: 1rem; text-align: center; }}
        .stat .value {{ font-size: 2rem; font-weight: bold; }}
        .stat .label {{ color: #a3a3a3; font-size: 0.85rem; }}
        .finding {{ background: #171717; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }}
        .finding-header {{ display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.5rem; }}
        .severity {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
        .finding-id {{ color: #a3a3a3; font-size: 0.85rem; }}
        .owasp {{ color: #22d3ee; font-size: 0.85rem; }}
        h3 {{ margin: 0.5rem 0; }}
        details {{ margin: 0.5rem 0; }}
        summary {{ cursor: pointer; color: #60a5fa; }}
        pre {{ background: #0a0a0a; padding: 1rem; border-radius: 4px; overflow-x: auto; margin: 0.5rem 0; font-size: 0.85rem; }}
        .remediation {{ color: #4ade80; margin-top: 0.5rem; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐍 Basilisk Scan Report</h1>
            <p class="subtitle">Session: {session.id} | Target: {session.config.target.url} | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
        </div>
        <div class="stats">
            <div class="stat"><div class="value" style="color: #dc2626;">{summary['severity_counts'].get('critical', 0)}</div><div class="label">Critical</div></div>
            <div class="stat"><div class="value" style="color: #ea580c;">{summary['severity_counts'].get('high', 0)}</div><div class="label">High</div></div>
            <div class="stat"><div class="value" style="color: #ca8a04;">{summary['severity_counts'].get('medium', 0)}</div><div class="label">Medium</div></div>
            <div class="stat"><div class="value" style="color: #2563eb;">{summary['severity_counts'].get('low', 0)}</div><div class="label">Low</div></div>
            <div class="stat"><div class="value" style="color: #6b7280;">{summary['severity_counts'].get('info', 0)}</div><div class="label">Info</div></div>
        </div>
        <h2>Findings</h2>
        {findings_html}
    </div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)


def _sarif_level(severity: str) -> str:
    """Map Basilisk severity to SARIF level."""
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity, "note")


def _html_escape(text: str) -> str:
    """Basic HTML escaping."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
