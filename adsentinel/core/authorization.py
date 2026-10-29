"""Engagement scope enforcement and source-interface preflight without target contact."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from ..security import SafetyError, read_json


@dataclass(frozen=True)
class Scope:
    reference: str
    source_address: str
    domain: str
    targets: frozenset[str]
    valid_from: str
    valid_until: str
    max_duration_seconds: int = 3600
    max_parallel_tasks: int = 5
    allowed_accounts: frozenset[str] = frozenset()

    @classmethod
    def load(cls, path: str) -> Scope:
        data = read_json(path)
        return cls(
            str(data["reference"]),
            str(ipaddress.ip_address(data["source_address"])),
            data["domain"],
            frozenset(str(ipaddress.ip_address(t)) for t in data["targets"]),
            data["valid_from"],
            data["valid_until"],
            min(3600, int(data.get("max_duration_seconds", 3600))),
            min(5, int(data.get("max_parallel_tasks", 5))),
            frozenset(str(u).casefold() for u in data.get("allowed_accounts", [])),
        )

    def validate_account(self, username: str | None) -> None:
        if username and username.casefold() not in self.allowed_accounts:
            raise SafetyError("Named account is not in the local authorized account inventory")

    def preflight(self, targets: list[str], domain: str | None, mode: str = "passive") -> dict[str, Any]:
        now = datetime.now(ZoneInfo("Asia/Kolkata"))
        if not self.valid_from <= now.date().isoformat() <= self.valid_until:
            raise SafetyError("Engagement authorization is outside its validity period")
        if domain and domain.casefold() != self.domain.casefold():
            raise SafetyError("Domain is outside authorized scope")
        if any(t not in self.targets for t in targets):
            raise SafetyError("One or more targets are outside the explicit host allowlist; use IP addresses")
        if mode == "high-impact":
            raise SafetyError("High-impact testing requires a separate explicit maintenance window")
        if mode == "active" and not 10 <= now.hour < 22:
            raise SafetyError("Active testing is outside the 10:00–22:00 IST window")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as local:
                local.bind((self.source_address, 0))
        except OSError as exc:
            raise SafetyError(
                "Authorized source interface is not assigned locally; no targets contacted"
            ) from exc
        for address in targets:
            # UDP connect computes the local route; no datagram is sent.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                route.connect((address, 9))
                if route.getsockname()[0] != self.source_address:
                    raise SafetyError("Route would use a source outside the engagement scope")
        return {
            "authorization_reference": self.reference,
            "status": "ready",
            "target_count": len(targets),
            "source_verified": True,
            "target_contact": False,
        }
