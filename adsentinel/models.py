"""Portable evidence and finding models."""

from dataclasses import asdict, dataclass
from typing import Any

SEVERITIES = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 0}


@dataclass
class Finding:
    id: str
    module: str
    title: str
    severity: str
    affected_object: str
    evidence: dict[str, Any]
    mitre: str
    detection: str
    remediation: str
    confidence: str = "configuration indicator"

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError("Unknown severity")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITIES[f.severity], f.id, f.affected_object))
