"""Centralized input, authorization, redaction and protected file handling."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any


class SafetyError(ValueError):
    """An input violates the assessment safety policy."""


def hostname(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p) for p in value.split(".")
    ):
        raise SafetyError("Invalid hostname or domain")
    return value


def identity(value: str) -> str:
    if not value or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise SafetyError("Invalid identity")
    return value


def target(value: str) -> str:
    if "/" in value:
        net = ipaddress.ip_network(value, strict=False)
        if net.num_addresses > 256:
            raise SafetyError("Target range exceeds 256 addresses")
        return str(net)
    return hostname(value)


def safe_path(value: str | Path, root: Path | None = None) -> Path:
    root = (root or Path.cwd()).resolve()
    candidate = Path(value)
    if ".." in candidate.parts or any(":" in p for p in candidate.parts if p != candidate.anchor):
        raise SafetyError("Path traversal or alternate data stream rejected")
    absolute = candidate if candidate.is_absolute() else root / candidate
    resolved = absolute.resolve()
    if not resolved.is_relative_to(root):
        raise SafetyError("Paths must remain inside the workspace")
    # Do not follow even in-workspace symbolic links for evidence files.
    cursor = root
    for part in absolute.relative_to(root).parts:
        cursor /= part
        if cursor.is_symlink():
            raise SafetyError("Symbolic links are not accepted")
    return resolved


def protect_directory(path: Path) -> None:
    """Owner-only POSIX permissions or a protected owner-rights Windows DACL."""
    if os.name == "posix":
        os.chmod(path, 0o700)
        return
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        descriptor = ctypes.c_void_p()
        convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        convert.restype = wintypes.BOOL
        apply = advapi.SetFileSecurityW
        apply.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
        apply.restype = wintypes.BOOL
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        if not convert("D:P(A;OICI;FA;;;OW)", 1, ctypes.byref(descriptor), None):
            raise SafetyError("Cannot construct private Windows output permissions")
        try:
            if not apply(str(path), 0x80000004, descriptor):
                raise SafetyError("Cannot secure Windows output directory")
        finally:
            kernel.LocalFree(descriptor)


def protected_write(path: str | Path, content: str) -> Path:
    dest = safe_path(path)
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    protect_directory(dest.parent)
    # Exclusive creation prevents clobbering evidence and following an existing link.
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
        handle.write(content)
    return dest


SECRET_KEYS = {
    "password",
    "unicodepwd",
    "hash",
    "hashes",
    "token",
    "access_token",
    "ticket",
    "private_key",
    "secret",
    "clientsecret",
    "ms-mcs-admpwd",
    "mslaps-password",
    "mslaps-encryptedpassword",
    "msds-managedpassword",
    "credentials",
    "certificate",
}


def redact(value: Any) -> Any:
    """Strip secret-bearing fields recursively, including untrusted imported records."""
    if isinstance(value, dict):

        def secret_key(key: str) -> bool:
            compact = re.sub(r"[^a-z0-9]", "", key.lower())
            exact = {re.sub(r"[^a-z0-9]", "", s) for s in SECRET_KEYS}
            return compact in exact or compact.endswith(
                ("password", "token", "privatekey", "secret", "credentials", "ticket", "hashes")
            )

        return {k: "[REDACTED]" if secret_key(k) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def read_json(path: str | Path) -> dict[str, Any]:
    p = safe_path(path)
    if p.stat().st_size > 256_000_000:
        raise SafetyError("Evidence exceeds 256 MB limit")
    with p.open(encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise SafetyError("Evidence must be a JSON object")
    return data


def authorize(active: bool, high_impact: bool, authorized: bool, owned: bool) -> None:
    if (active or high_impact) and not authorized:
        raise SafetyError("This mode requires --authorize")
    if high_impact and not owned:
        raise SafetyError("This mode also requires --i-own-this-environment")


def ldap_filter(attribute: str, value: str) -> str:
    from ldap3.utils.conv import escape_filter_chars

    if attribute not in {"sAMAccountName", "objectClass", "cn"}:
        raise SafetyError("LDAP attribute is not allowlisted")
    return f"({attribute}={escape_filter_chars(value)})"


def graph_url(resource: str) -> str:
    if resource not in {
        "users",
        "groups",
        "applications",
        "servicePrincipals",
        "roleManagement/directory/roleAssignments",
        "organization",
    }:
        raise SafetyError("Graph resource is not allowlisted")
    return "https://graph.microsoft.com/v1.0/" + resource
