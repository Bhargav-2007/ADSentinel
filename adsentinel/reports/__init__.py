"""Local reports with escaped evidence and deterministic severity ordering."""

from __future__ import annotations

import csv
import html
import io
import json
from collections import Counter
from typing import Any

from ..models import SEVERITIES


def render(report: dict[str, Any], fmt: str) -> str:
    rows = sorted(report.get("findings", []), key=lambda f: -SEVERITIES[f["severity"]])
    counts = dict(Counter(f["severity"] for f in rows))
    if fmt == "json":
        return json.dumps({**report, "findings": rows}, indent=2, ensure_ascii=True, default=str)
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
        from jinja2 import Environment, PackageLoader, select_autoescape

        environment = Environment(
            loader=PackageLoader("adsentinel.reports", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )
        return environment.get_template("assessment.html").render(report=report, findings=rows, counts=counts)
    raise ValueError("Unsupported report format")
