"""Uniform execution contracts, including partial failures and timestamped evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..models import Finding


@dataclass
class Evidence:
    id: str
    source: str
    collected_at: datetime
    data: dict[str, Any]
    confidence: str = "observed"


@dataclass
class ScanError:
    code: str
    operation: str
    message: str
    recoverable: bool = True


@dataclass
class ModuleResult:
    module: str
    started_at: datetime
    completed_at: datetime
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
