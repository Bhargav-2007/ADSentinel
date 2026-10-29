"""Portable evidence and finding models."""

import hashlib
import json
from dataclasses import asdict, dataclass, field
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

    description: str = ""
    evidence_references: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    rule_id: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError("Unknown severity")
        if not self.rule_id:
            self.rule_id = self.id
            digest = hashlib.sha256(
                json.dumps(
                    [self.module, self.id, self.affected_object, self.evidence], sort_keys=True, default=str
                ).encode()
            ).hexdigest()[:16]
            self.id = self.id + "-" + digest
        if not self.description:
            self.description = (
                self.title + ". Review the evidence and collection limitations before remediation."
            )
        if not self.evidence_references:
            self.evidence_references = [str(self.evidence.get("evidence_reference", self.id))]
        if not self.references:
            self.references = ["https://attack.mitre.org/techniques/" + self.mitre.replace(".", "/") + "/"]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITIES[f.severity], f.id, f.affected_object))
