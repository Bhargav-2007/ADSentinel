"""Run any supported rule module through a common timestamped result contract."""

from __future__ import annotations

from typing import Any

from ..core.models import Evidence, ModuleResult, ScanError, utcnow
from ..rules import MODULES, evaluate


def run_module(module: str, data: dict[str, Any]) -> ModuleResult:
    started = utcnow()
    if module not in MODULES:
        return ModuleResult(
            module, started, utcnow(), errors=[ScanError("unsupported", module, "Unknown module", False)]
        )
    findings, coverage = evaluate(data, [module])
    evidence = [
        Evidence(
            f.id,
            str(f.evidence.get("evidence_reference", data.get("source", "local evidence"))),
            started,
            f.evidence,
            f.confidence,
        )
        for f in findings
    ]
    errors = [
        ScanError(
            str(error.get("code", error.get("type", "collection"))),
            str(error.get("operation", module)),
            str(error.get("message", "Collection coverage incomplete")),
        )
        for error in data.get("errors", [])
        if isinstance(error, dict)
    ]
    return ModuleResult(module, started, utcnow(), findings, evidence, errors, coverage[module])
