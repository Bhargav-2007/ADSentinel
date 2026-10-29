"""Bounded SYSVOL policy reads and parsers; no remote execution or file writes."""

from __future__ import annotations

import configparser
import struct
from typing import Any

import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException
from impacket.smbconnection import SessionError, SMBConnection

from ..core.auth import Credentials
from ..security import SafetyError

POLICY_FILES = [
    "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf",
    "Machine/Registry.pol",
    "User/Registry.pol",
    "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml",
    "Machine/Preferences/Groups/Groups.xml",
    "Machine/Scripts/scripts.ini",
    "User/Scripts/scripts.ini",
]


def registry_policy(data: bytes) -> list[dict[str, Any]]:
    if (
        len(data) > 1_000_000
        or len(data) < 8
        or data[:4] != b"PReg"
        or struct.unpack_from("<I", data, 4)[0] != 1
    ):
        raise SafetyError("Invalid Registry.pol header or size")
    cursor = 8
    records = []

    def word(expected: bytes) -> None:
        nonlocal cursor
        if data[cursor : cursor + len(expected)] != expected:
            raise SafetyError("Malformed Registry.pol delimiter")
        cursor += len(expected)

    def text() -> str:
        nonlocal cursor
        start = cursor
        while cursor + 2 <= len(data):
            pair = data[cursor : cursor + 2]
            cursor += 2
            if pair == b"\x00\x00":
                return data[start : cursor - 2].decode("utf-16-le")
        raise SafetyError("Unterminated Registry.pol string")

    while cursor < len(data):
        word(b"[\x00")
        key = text()
        word(b";\x00")
        name = text()
        word(b";\x00")
        if cursor + 4 > len(data):
            raise SafetyError("Truncated Registry.pol type")
        kind = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        word(b";\x00")
        if cursor + 4 > len(data):
            raise SafetyError("Truncated Registry.pol size")
        length = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        word(b";\x00")
        if length > 64000 or cursor + length > len(data):
            raise SafetyError("Invalid Registry.pol data bounds")
        value = data[cursor : cursor + length]
        cursor += length
        word(b"]\x00")
        parsed: Any = struct.unpack("<I", value)[0] if kind == 4 and len(value) == 4 else None
        # Only security policy DWORDs are retained; arbitrary registry string values can contain secrets.
        if parsed is not None:
            records.append({"key": key, "value_name": name, "type": kind, "value": parsed})
        if len(records) > 10000:
            raise SafetyError("Registry.pol record limit exceeded")
    return records


def policy_metadata(path: str, data: bytes) -> dict[str, Any]:
    if len(data) > 1_000_000:
        raise SafetyError("SYSVOL policy file exceeds 1 MB")
    if path.lower().endswith(".pol"):
        rows = registry_policy(data)
        return {"registry_dwords": rows}
    if path.lower().endswith(".xml"):
        root = ET.fromstring(data)
        return {
            "xml_object_count": len(list(root)),
            "credential_attribute_present": any(
                name.lower() in {"cpassword", "password"} and bool(value)
                for node in root.iter()
                for name, value in node.attrib.items()
            ),
            "scheduled_task_count": sum(
                e.tag.rsplit("}", 1)[-1] in {"Task", "TaskV2", "ImmediateTask", "ImmediateTaskV2"}
                for e in root.iter()
            ),
            "group_policy_count": sum(e.tag.rsplit("}", 1)[-1] == "Group" for e in root.iter()),
        }
    text = data.decode("utf-16" if data[:2] in {b"\xff\xfe", b"\xfe\xff"} else "utf-8-sig", errors="strict")
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read_string(text)
    metadata: dict[str, Any] = {"sections": parser.sections()}
    if path.lower().endswith("scripts.ini"):
        metadata["script_entry_count"] = sum(len(parser.items(section)) for section in parser.sections())
    elif parser.has_section("Event Audit"):
        metadata["audit_settings"] = {key: value for key, value in parser.items("Event Audit")}
    if parser.has_section("Group Membership"):
        metadata["restricted_group_settings"] = dict(parser.items("Group Membership"))
    return metadata


def collect_sysvol(
    dc: str, domain: str, credentials: Credentials, gpos: list[dict[str, Any]], timeout: int = 30
) -> list[dict[str, Any]]:
    connection = SMBConnection(remoteName=dc, remoteHost=dc, timeout=timeout)
    username = credentials.username or ""
    auth_domain = credentials.domain
    if "\\" in username:
        auth_domain, username = username.split("\\", 1)
    elif "@" in username:
        username, auth_domain = username.rsplit("@", 1)
    results = []
    try:
        connection.login(username, credentials.password or "", auth_domain)
        for gpo in gpos[:128]:
            props = gpo.get("properties", {})
            unc = props.get("gpcpath")
            if not isinstance(unc, str):
                continue
            parts = unc.replace("/", "\\").strip("\\").split("\\")
            if (
                len(parts) != 5
                or parts[0].casefold() != domain.casefold()
                or parts[1].upper() != "SYSVOL"
                or parts[2].casefold() != domain.casefold()
                or parts[3].casefold() != "policies"
                or ".." in parts
            ):
                raise SafetyError("GPO path is outside the requested domain SYSVOL policies directory")
            import uuid

            uuid.UUID(parts[4].strip("{}"))
            prefix = "\\".join(parts[2:])
            row = {"id": gpo["id"], "files": [], "errors": []}
            for relative in POLICY_FILES:
                body = bytearray()

                def receive(block: bytes) -> None:
                    body.extend(block)
                    if len(body) > 1_000_000:
                        raise SafetyError("SYSVOL file exceeds 1 MB")

                try:
                    connection.getFile("SYSVOL", prefix + "\\" + relative.replace("/", "\\"), receive)
                    row["files"].append({"path": relative, **policy_metadata(relative, bytes(body))})
                except SessionError as exc:
                    # Missing optional files are coverage details, not evidence that a control is disabled.
                    row["errors"].append({"path": relative, "code": str(exc.getErrorCode())})
                except (
                    ValueError,
                    DefusedXmlException,
                    ET.ParseError,
                    configparser.Error,
                    UnicodeError,
                ) as exc:
                    row["errors"].append({"path": relative, "type": type(exc).__name__})
            results.append(row)
    finally:
        connection.close()
    return results
