"""Local reports with escaped evidence and deterministic severity ordering."""

from __future__ import annotations

import csv
import html
import io
import json
from collections import Counter
from typing import Any

from .models import SEVERITIES


def render(report: dict[str, Any], fmt: str) -> str:
    rows = sorted(report.get("findings", []), key=lambda f: -SEVERITIES[f["severity"]])
    counts = dict(Counter(f["severity"] for f in rows))
    if fmt == "json":
        return json.dumps({**report, "findings": rows}, indent=2, ensure_ascii=True)
    if fmt == "csv":
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(
            ["section", "severity", "id", "object", "title", "evidence", "mitre", "detection", "remediation"]
        )

        def cell(value: Any) -> str:
            text = str(value)
            return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text

        for key in ("timestamp", "scope", "authorization", "coverage", "attack_paths"):
            writer.writerow(["metadata", "", key, "", "", cell(json.dumps(report.get(key))), "", "", ""])
        for f in rows:
            writer.writerow(
                [
                    cell(v)
                    for v in (
                        "finding",
                        f["severity"],
                        f["id"],
                        f["affected_object"],
                        f["title"],
                        json.dumps(f["evidence"]),
                        f["mitre"],
                        f["detection"],
                        f["remediation"],
                    )
                ]
            )
        return stream.getvalue()
    if fmt in {"markdown", "terminal"}:

        def clean(value: Any) -> str:
            return html.escape(str(value)).replace("\n", " ").replace("`", "'")

        lines = [
            "# ADSentinel assessment",
            "",
            "## Executive summary",
            "",
            f"{len(rows)} configuration findings. Severity counts: {counts}.",
            "No findings does not establish security; inspect collection coverage.",
            "",
            "## Scope and authorization",
            "",
            clean(report.get("scope")),
            clean(report.get("authorization")),
            "Scan timestamp: " + clean(report.get("timestamp")),
            "",
            "## Coverage and limitations",
            "",
            clean(report.get("coverage")),
            "",
            "## Findings",
            "",
        ]
        for f in rows:
            lines.extend(
                [
                    f"### {f['severity']} ? {clean(f['title'])}",
                    "",
                    "Object: " + clean(f["affected_object"]),
                    "Evidence reference: " + clean(f["id"]),
                    "Evidence: " + clean(json.dumps(f["evidence"])),
                    "MITRE ATT&CK: " + f["mitre"],
                    "Confidence: " + clean(f["confidence"]),
                    "Detection: " + clean(f["detection"]),
                    "Remediation: " + clean(f["remediation"]),
                    "",
                ]
            )
        lines.extend(
            [
                "## Attack-path references",
                "",
                clean(report.get("attack_paths", {})),
                "",
                "## Prioritized remediation roadmap",
                "",
            ]
        )
        lines.extend(f"{i}. [{f['severity']}] {clean(f['remediation'])}" for i, f in enumerate(rows, 1))
        return "\n".join(lines) + "\n"
    if fmt == "html":

        def esc(value: Any) -> str:
            return html.escape(str(value))

        sections = []
        for f in rows:
            sections.append(
                "<article><h3>"
                + esc(f["severity"] + " ? " + f["title"])
                + "</h3>"
                + "".join(
                    "<p><strong>" + esc(k) + ":</strong> " + esc(v) + "</p>"
                    for k, v in f.items()
                    if k not in {"title", "severity"}
                )
                + "</article>"
            )
        return (
            "<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            """<meta http-equiv='Content-Security-Policy' content="default-src 'none'; style-src 'unsafe-inline'">"""
            "<title>ADSentinel assessment</title><style>body{font:16px system-ui;max-width:1000px;"
            "margin:3rem auto;padding:0 1rem;color:#193046}article{border-left:4px solid #357;"
            "padding:1rem;background:#f3f6f9;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}"
            "h1,h2{color:#123}</style><h1>ADSentinel assessment</h1><h2>Executive summary</h2><p>"
            + esc(f"{len(rows)} findings; {counts}")
            + ". No findings does not establish security.</p><h2>Scope and authorization</h2><pre>"
            + esc(json.dumps({k: report.get(k) for k in ("timestamp", "scope", "authorization")}, indent=2))
            + "</pre><h2>Coverage and limitations</h2><pre>"
            + esc(json.dumps(report.get("coverage"), indent=2))
            + "</pre><h2>Findings</h2>"
            + "".join(sections)
            + "<h2>Attack-path references</h2><pre>"
            + esc(json.dumps(report.get("attack_paths", {}), indent=2))
            + "</pre><h2>Prioritized remediation roadmap</h2><ol>"
            + "".join("<li>" + esc(f["severity"] + ": " + f["remediation"]) + "</li>" for f in rows)
            + "</ol></html>"
        )
    raise ValueError("Unsupported report format")
