"""Protocol credentials are never part of evidence or printable representations."""

from __future__ import annotations

import getpass
import os
from dataclasses import dataclass, field

from ..security import SafetyError, identity


@dataclass(frozen=True)
class Credentials:
    username: str | None = None
    domain: str = ""
    password: str | None = field(default=None, repr=False)

    @classmethod
    def from_environment(
        cls, username: str | None, domain: str, variable: str, prompt: bool = False
    ) -> Credentials:
        if username:
            identity(username)
        password = os.environ.get(variable) if username else None
        if username and not password and prompt:
            password = getpass.getpass("Directory password: ")
        if username and not password:
            raise SafetyError(
                "Credential environment variable is missing; use --prompt-password for secure input"
            )
        return cls(username, domain, password)
