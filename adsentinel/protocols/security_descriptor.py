"""Parse self-relative Windows security descriptors without retrieving credential values."""

from __future__ import annotations

import struct
import uuid
from typing import Any

from ..security import SafetyError

EXTENDED = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesAll",
    "89e95b76-444d-4c62-991a-0facbeda640c": "GetChangesInFilteredSet",
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",
}
MEMBER_GUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"


def sid_at(data: bytes, offset: int = 0) -> tuple[str, int]:
    if offset < 0 or offset + 8 > len(data):
        raise SafetyError("Truncated SID")
    revision, count = data[offset : offset + 2]
    size = 8 + 4 * count
    if revision != 1 or count > 15 or offset + size > len(data):
        raise SafetyError("Invalid SID encoding")
    authority = int.from_bytes(data[offset + 2 : offset + 8], "big")
    sub = struct.unpack_from("<" + "I" * count, data, offset + 8)
    return "S-1-" + str(authority) + "".join("-" + str(n) for n in sub), size


def parse_descriptor(data: bytes) -> dict[str, Any]:
    if len(data) < 20 or len(data) > 2_000_000:
        raise SafetyError("Invalid security descriptor size")
    revision, _, control, owner_offset, group_offset, _, dacl_offset = struct.unpack_from("<BBHIIII", data)
    if revision != 1 or not control & 0x8000:
        raise SafetyError("Only self-relative security descriptors are supported")
    result: dict[str, Any] = {
        "owner": sid_at(data, owner_offset)[0] if owner_offset else None,
        "group": sid_at(data, group_offset)[0] if group_offset else None,
        "protected": bool(control & 0x1000),
        "aces": [],
        "unsupported_ace_types": [],
    }
    if not control & 4 or not dacl_offset:
        result["null_dacl"] = True
        return result
    if dacl_offset + 8 > len(data):
        raise SafetyError("Truncated DACL")
    _, _, acl_size, ace_count, _ = struct.unpack_from("<BBHHH", data, dacl_offset)
    end = dacl_offset + acl_size
    if end > len(data) or acl_size < 8 or ace_count > 20000:
        raise SafetyError("Invalid DACL bounds")
    pos = dacl_offset + 8
    for _ in range(ace_count):
        if pos + 8 > end:
            raise SafetyError("Truncated ACE")
        ace_type, flags, size, mask = struct.unpack_from("<BBHI", data, pos)
        if size < 8 or pos + size > end:
            raise SafetyError("Invalid ACE bounds")
        body = data[pos : pos + size]
        cursor = 8
        object_guid = inherited_guid = None
        if ace_type in {5, 6}:
            if len(body) < 12:
                raise SafetyError("Truncated object ACE")
            object_flags = struct.unpack_from("<I", body, 8)[0]
            cursor = 12
            if object_flags & 1:
                if cursor + 16 > len(body):
                    raise SafetyError("Truncated object GUID")
                object_guid = str(uuid.UUID(bytes_le=body[cursor : cursor + 16]))
                cursor += 16
            if object_flags & 2:
                if cursor + 16 > len(body):
                    raise SafetyError("Truncated inherited GUID")
                inherited_guid = str(uuid.UUID(bytes_le=body[cursor : cursor + 16]))
                cursor += 16
        if ace_type in {0, 1, 5, 6}:
            principal, _ = sid_at(body, cursor)
            result["aces"].append(
                {
                    "principal": principal,
                    "allow": ace_type in {0, 5},
                    "mask": mask,
                    "flags": flags,
                    "inherited": bool(flags & 0x10),
                    "inherit_only": bool(flags & 8),
                    "object_guid": object_guid,
                    "inherited_object_guid": inherited_guid,
                }
            )
        else:
            result["unsupported_ace_types"].append(ace_type)
        pos += size
    return result


def ace_rights(
    ace: dict[str, Any], class_guid: str | None = None, attribute_guids: dict[str, str] | None = None
) -> set[str]:
    """Conservative mapping; class-restricted inheritance requires a matching class GUID."""
    if ace["inherit_only"]:
        return set()
    inherited_class = ace.get("inherited_object_guid")
    if ace["inherited"] and inherited_class and inherited_class != class_guid:
        return set()
    mask = ace["mask"]
    obj = ace.get("object_guid")
    rights = set()
    if not obj:
        for bit, name in (
            (0x10000000, "GenericAll"),
            (0x40000000, "GenericWrite"),
            (0x40000, "WriteDACL"),
            (0x80000, "WriteOwner"),
        ):
            if mask & bit:
                rights.add(name)
        if mask & 0xF01FF == 0xF01FF:
            rights.add("GenericAll")
        elif mask & 0x20028 == 0x20028:
            rights.add("GenericWrite")
        if mask & 0x100:
            rights.add("AllExtendedRights")
    if mask & 0x100 and obj in EXTENDED:
        rights.add(EXTENDED[obj])
    if mask & 0x20 and obj == MEMBER_GUID:
        rights.add("AddMember")
    if mask & 0x10 and attribute_guids and obj in attribute_guids:
        rights.add(attribute_guids[obj])
    return rights


def descriptor_edges(
    descriptor: dict[str, Any],
    object_id: str,
    class_guid: str | None = None,
    attribute_guids: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    allowed: dict[str, set[str]] = {}
    denied: dict[str, set[str]] = {}
    for ace in descriptor["aces"]:
        bucket = allowed if ace["allow"] else denied
        bucket.setdefault(ace["principal"], set()).update(ace_rights(ace, class_guid, attribute_guids))
    edges = []
    for principal, rights in allowed.items():
        deny = denied.get(principal, set())
        if "GenericAll" in deny:
            continue
        for right in sorted(rights - deny):
            edges.append(
                {
                    "source": principal,
                    "target": object_id,
                    "relation": right,
                    "source_kind": "security_descriptor",
                    "confidence": "allow-ACE indicator",
                }
            )
    if descriptor.get("owner"):
        edges.append(
            {
                "source": descriptor["owner"],
                "target": object_id,
                "relation": "Owns",
                "confidence": "owner indicator; OWNER RIGHTS and effective token require review",
            }
        )
    return edges
