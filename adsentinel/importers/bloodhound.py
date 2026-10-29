"""Import real SharpHound v5/v6 JSON, ZIP/GZIP, and explicit node/edge graphs.

Archive contents are read in memory, never extracted. Stable object identifiers
are preserved; display names are aliases, never the primary identity key.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import stat
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from .. import __version__
from ..security import SafetyError, redact, safe_path

KINDS = {
    "users": "User",
    "groups": "Group",
    "computers": "Computer",
    "domains": "Domain",
    "ous": "OU",
    "gpos": "GPO",
    "containers": "Container",
    "certtemplates": "CertTemplate",
    "enterprisecas": "EnterpriseCA",
    "rootcas": "RootCA",
    "aiacas": "AIACA",
    "ntauthstores": "NTAuthStore",
    "issuancepolicies": "IssuancePolicy",
}
COLLECTIONS = {"CertTemplate": "templates", "EnterpriseCA": "cas"}
ALIASES = {"WriteDacl": "WriteDACL", "GetChanges": "GetChanges", "GetChangesAll": "GetChangesAll"}
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_OBJECTS = 250000
MAX_EDGES = 2000000


def documents(source: Path) -> Iterator[tuple[str, dict[str, Any], str]]:
    """Yield bounded documents and content checksums without archive extraction."""
    paths = sorted(source.rglob("*")) if source.is_dir() else [source]
    total = 0
    files = 0
    for item in paths:
        item = safe_path(item)
        if not item.is_file() or item.suffix.lower() not in {".zip", ".json", ".gz"}:
            continue
        if item.stat().st_size > MAX_FILE:
            raise SafetyError("Input file exceeds 64 MiB")
        if item.suffix.lower() == ".zip":
            with zipfile.ZipFile(item) as archive:
                if len(archive.infolist()) > 1000:
                    raise SafetyError("Archive exceeds 1,000 entries")
                blobs = []
                for member in archive.infolist():
                    member_path = PurePosixPath(member.filename.replace("\\", "/"))
                    if (
                        member_path.is_absolute()
                        or ".." in member_path.parts
                        or any(":" in p for p in member_path.parts)
                    ):
                        raise SafetyError("Unsafe archive member name")
                    if stat.S_ISLNK(member.external_attr >> 16):
                        raise SafetyError("Archive symbolic link rejected")
                    if member.is_dir() or member_path.suffix.lower() != ".json":
                        continue
                    if member.file_size > MAX_FILE or member.flag_bits & 1:
                        raise SafetyError("Oversized or encrypted archive member")
                    total += member.file_size
                    if total > MAX_TOTAL:
                        raise SafetyError("Uncompressed import exceeds 256 MiB")
                    blobs.append((item.name + "!" + member.filename, archive.read(member)))
        else:
            if item.suffix.lower() == ".gz":
                with gzip.open(item, "rb") as stream:
                    blob = stream.read(MAX_FILE + 1)
            else:
                blob = item.read_bytes()
            if len(blob) > MAX_FILE:
                raise SafetyError("Decompressed file exceeds 64 MiB")
            total += len(blob)
            if total > MAX_TOTAL:
                raise SafetyError("Import exceeds 256 MiB")
            blobs = [(str(item.relative_to(Path.cwd())), blob)]
        for name, blob in blobs:
            files += 1
            if files > 1000:
                raise SafetyError("Import exceeds 1,000 JSON documents")
            try:
                data = json.loads(blob.decode("utf-8-sig"))
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise SafetyError("Invalid JSON document: " + name) from exc
            if not isinstance(data, dict):
                raise SafetyError("JSON document must be an object: " + name)
            # A provenance manifest is not a collection.
            if "meta" not in data and not ("nodes" in data and "edges" in data):
                continue
            yield name, data, hashlib.sha256(blob).hexdigest()


def broad_principal(sid: str) -> bool:
    """Well-known broad groups; do not assume arbitrary non-admin users are low privilege."""
    return (
        sid.endswith(("-S-1-1-0", "-S-1-5-11"))
        or sid in {"S-1-1-0", "S-1-5-11"}
        or (sid.startswith("S-1-5-21-") and sid.rsplit("-", 1)[-1] in {"513", "515"})
    )


def import_bloodhound(path: str | Path) -> dict[str, Any]:
    return import_documents(documents(safe_path(path)))


def import_documents(items: Iterator[tuple[str, dict[str, Any], str]]) -> dict[str, Any]:
    """Normalize collector documents supplied by files or an authenticated LDAP collector."""
    nodes: dict[str, dict[str, Any]] = {}
    records: dict[str, tuple[str, dict[str, Any], str]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    issues: list[dict[str, str]] = []
    manifests = []
    counts: Counter[str] = Counter()
    duplicates = 0

    def edge(src: Any, dst: Any, relation: str, reference: str, **properties: Any) -> None:
        if not isinstance(src, str) or not isinstance(dst, str) or not src or not dst:
            issues.append({"reference": reference, "reason": "relationship missing string identifier"})
            return
        if len(edges) >= MAX_EDGES:
            raise SafetyError("Graph exceeds 2,000,000 relationships")
        key = (src.upper(), dst.upper(), ALIASES.get(relation, relation))
        edges.setdefault(
            key,
            {
                "source": key[0],
                "target": key[1],
                "relation": key[2],
                "evidence_reference": reference,
                **properties,
            },
        )

    def object_rows(value: Any, reference: str) -> list[dict[str, Any]]:
        if value is None:
            return []
        if not isinstance(value, list):
            issues.append({"reference": reference, "reason": "malformed nested array omitted"})
            return []
        rows = [row for row in value if isinstance(row, dict)]
        if len(rows) != len(value):
            issues.append({"reference": reference, "reason": "malformed nested object omitted"})
        return rows

    for filename, doc, checksum in items:
        manifests.append({"file": filename, "sha256": checksum})
        if "nodes" in doc and "edges" in doc and "meta" not in doc:
            if not isinstance(doc["nodes"], list) or not isinstance(doc["edges"], list):
                raise SafetyError("Graph nodes and edges must be arrays")
            if len(doc["nodes"]) > MAX_OBJECTS or len(doc["edges"]) > MAX_EDGES:
                raise SafetyError("Explicit graph exceeds object/edge limits")
            for node in doc["nodes"]:
                if not isinstance(node, dict) or not isinstance(node.get("id"), str):
                    raise SafetyError("Graph node requires string id")
                nodes[node["id"].upper()] = {**redact(node), "id": node["id"].upper()}
            for item in doc["edges"]:
                if not isinstance(item, dict):
                    raise SafetyError("Graph edge must be an object")
                edge(item.get("source"), item.get("target"), item.get("relation", "Unknown"), filename)
            continue
        meta = doc.get("meta", {})
        kind = meta.get("type")
        data = doc.get("data")
        if not isinstance(data, list) or not isinstance(kind, str):
            raise SafetyError("SharpHound collection requires meta.type and a data array")
        if meta.get("version") not in {5, 6}:
            raise SafetyError("Unsupported SharpHound schema version; supported: 5 and 6")
        if kind not in KINDS:
            issues.append({"reference": filename, "reason": "unsupported collection type: " + kind})
            continue
        if meta.get("count") != len(data):
            issues.append({"reference": filename, "reason": "declared count differs from record count"})
        for index, record in enumerate(data):
            ref = f"{filename}#/data/{index}"
            if not isinstance(record, dict) or not isinstance(record.get("ObjectIdentifier"), str):
                issues.append({"reference": ref, "reason": "object missing ObjectIdentifier"})
                continue
            if record.get("IsDeleted") is True:
                continue
            oid = record["ObjectIdentifier"].upper()
            props = record.get("Properties")
            if not isinstance(props, dict):
                issues.append({"reference": ref, "reason": "missing Properties object"})
                continue
            # Malformed relationship fields are omitted with an issue, not silently interpreted.
            for field in (
                "Aces",
                "Members",
                "AllowedToDelegate",
                "AllowedToAct",
                "ChildObjects",
                "Links",
                "EnabledCertTemplates",
                "LocalGroups",
                "Trusts",
            ):
                if field in record:
                    value = record[field]
                    if not isinstance(value, list) or any(not isinstance(v, dict) for v in value):
                        issues.append(
                            {"reference": ref + "/" + field, "reason": "malformed relationship array omitted"}
                        )
                        record[field] = (
                            [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []
                        )
            if oid in records:
                duplicates += 1
                existing = records[oid][1]
                if existing != record:
                    issues.append(
                        {
                            "reference": ref,
                            "reason": "duplicate differs; relationship arrays merged, first conflicting scalar retained",
                        }
                    )
                    for field, value in record.items():
                        if isinstance(value, list) and isinstance(existing.get(field), list):
                            merged = {json.dumps(v, sort_keys=True): v for v in existing[field] + value}
                            existing[field] = list(merged.values())
                        elif field not in existing:
                            existing[field] = value
                        elif isinstance(value, dict) and isinstance(existing[field], dict):
                            if (
                                value.get("Collected") is True
                                and existing[field].get("Collected") is not True
                            ):
                                existing[field] = value
                            elif isinstance(value.get("Results"), list) and isinstance(
                                existing[field].get("Results"), list
                            ):
                                merged = {
                                    json.dumps(v, sort_keys=True): v
                                    for v in existing[field]["Results"] + value["Results"]
                                }
                                existing[field]["Results"] = list(merged.values())
                continue
            if len(nodes) >= MAX_OBJECTS:
                raise SafetyError("Graph exceeds 250,000 objects")
            counts[kind] += 1
            records[oid] = (kind, record, ref)
            node_type = KINDS[kind]
            nodes[oid] = {
                "id": oid,
                "type": node_type,
                "name": props.get("name", oid),
                "properties": redact(props),
                "evidence_reference": ref,
                "high_value": node_type == "Domain"
                or props.get("highvalue") is True
                or (node_type == "Group" and oid.rsplit("-", 1)[-1] in {"512", "518", "519", "544"}),
            }
    if not manifests:
        raise SafetyError("No supported collection documents found")
    result: dict[str, Any] = {
        "schema_version": "1.1",
        "kind": "adsentinel.graph",
        "source": "BloodHound/SharpHound import",
        "collector_version": __version__,
        "nodes": [],
        "edges": [],
    }
    published: dict[str, list[str]] = defaultdict(list)
    replication: dict[tuple[str, str], set[str]] = defaultdict(set)
    for oid, (kind, record, ref) in records.items():
        props = record["Properties"]
        normalized: dict[str, Any] = {
            "id": oid,
            "name": props.get("name", oid),
            "properties": redact(props),
            "evidence_reference": ref,
        }
        mappings = {
            "dontreqpreauth": "preauth_required",
            "pwdneverexpires": "password_never_expires",
            "hasspn": "has_spn",
            "unconstraineddelegation": "unconstrained_delegation",
            "trustedtoauth": "protocol_transition",
            "haslaps": "laps_enabled",
            "enabled": "enabled",
        }
        for key, out in mappings.items():
            if type(props.get(key)) is bool:
                if key == "unconstraineddelegation" and props.get("isdc") is True:
                    continue
                normalized[out] = not props[key] if key == "dontreqpreauth" else props[key]
        collection = COLLECTIONS.get(KINDS[kind], kind)
        result.setdefault(collection, []).append(normalized)
        for ace in record.get("Aces", []):
            if not isinstance(ace, dict):
                issues.append({"reference": ref, "reason": "malformed ACE"})
                continue
            right = ace.get("RightName")
            if not isinstance(right, str):
                issues.append({"reference": ref, "reason": "ACE missing RightName"})
                continue
            principal = ace.get("PrincipalSID")
            edge(principal, oid, right, ref + "/Aces", inherited=ace.get("IsInherited"), source_kind="acl")
            if (
                kind == "domains"
                and right in {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet"}
                and isinstance(principal, str)
            ):
                replication[(principal.upper(), oid)].add(right)
        for member in record.get("Members", []):
            edge(member.get("ObjectIdentifier"), oid, "MemberOf", ref + "/Members")
        primary_group = record.get("PrimaryGroupSID")
        if isinstance(primary_group, str):
            edge(oid, primary_group, "MemberOf", ref + "/PrimaryGroupSID")
        for item in record.get("AllowedToDelegate", []):
            edge(oid, item.get("ObjectIdentifier"), "AllowedToDelegate", ref + "/AllowedToDelegate")
        for item in record.get("AllowedToAct", []):
            edge(item.get("ObjectIdentifier"), oid, "AllowedToAct", ref + "/AllowedToAct")
        for item in record.get("ChildObjects", []):
            edge(oid, item.get("ObjectIdentifier"), "Contains", ref + "/ChildObjects")
        contained = record.get("ContainedBy")
        if isinstance(contained, dict):
            edge(contained.get("ObjectIdentifier"), oid, "Contains", ref + "/ContainedBy")
        for item in record.get("Links", []):
            edge(item.get("GUID"), oid, "GPLink", ref + "/Links", enforced=item.get("IsEnforced"))
        if kind == "computers":
            for field, relation in (
                ("LocalAdmins", "AdminTo"),
                ("RemoteDesktopUsers", "CanRDP"),
                ("PSRemoteUsers", "CanPSRemote"),
                ("DcomUsers", "ExecuteDCOM"),
            ):
                value = record.get(field, {})
                if isinstance(value, dict) and value.get("Collected") is True:
                    for item in object_rows(value.get("Results"), ref):
                        edge(item.get("ObjectIdentifier"), oid, relation, ref + "/" + field)
            for group in record.get("LocalGroups", []):
                group_id = str(group.get("ObjectIdentifier", ""))
                local_relation = {"544": "AdminTo", "555": "CanRDP", "580": "CanPSRemote"}.get(
                    group_id.rsplit("-", 1)[-1]
                )
                if local_relation:
                    for item in object_rows(group.get("Results"), ref):
                        edge(item.get("ObjectIdentifier"), oid, local_relation, ref + "/LocalGroups")
            for field in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
                value = record.get(field, {})
                if isinstance(value, dict) and value.get("Collected") is True:
                    for item in object_rows(value.get("Results"), ref):
                        edge(
                            item.get("ComputerSID", oid), item.get("UserSID"), "HasSession", ref + "/" + field
                        )
        if kind == "enterprisecas":
            registry_data = record.get("CARegistryData")
            ca_security = registry_data.get("CASecurity", {}) if isinstance(registry_data, dict) else {}
            if not isinstance(ca_security, dict):
                issues.append({"reference": ref, "reason": "malformed CA security omitted"})
                ca_security = {}
            normalized["ca_security_collected"] = ca_security.get("Collected") is True
            if normalized["ca_security_collected"]:
                normalized["enrollers"] = sorted(
                    {
                        a["PrincipalSID"].upper()
                        for a in object_rows(ca_security.get("Data"), ref)
                        if a.get("RightName") == "Enroll" and isinstance(a.get("PrincipalSID"), str)
                    }
                )
            for item in record.get("EnabledCertTemplates", []):
                template = item.get("ObjectIdentifier", "").upper()
                if template:
                    published[template].append(oid)
                    edge(template, oid, "PublishedTo", ref + "/EnabledCertTemplates")
        if kind == "domains":
            for trust in record.get("Trusts", []):
                result.setdefault("trusts", []).append(
                    {
                        "id": oid + "->" + str(trust.get("TargetDomainSid")),
                        "source_domain": oid,
                        "target_domain": trust.get("TargetDomainSid"),
                        "name": trust.get("TargetDomainName"),
                        "trust_type": trust.get("TrustType"),
                        "sid_filtering": trust.get("SidFilteringEnabled"),
                        "direction": trust.get("TrustDirection"),
                        "transitive": trust.get("IsTransitive"),
                        "evidence_reference": ref + "/Trusts",
                    }
                )
    template_enrollers: dict[str, list[str]] = defaultdict(list)
    for relationship in edges.values():
        if relationship["relation"] in {"Enroll", "GenericAll", "AllExtendedRights"}:
            template_enrollers[relationship["target"]].append(relationship["source"])
    for template in result.get("templates", []):
        props = template["properties"]
        oid = template["id"]
        for key, out in (
            ("enrolleesuppliessubject", "enrollee_supplies_subject"),
            ("authenticationenabled", "client_authentication"),
            ("requiresmanagerapproval", "manager_approval"),
            ("authorizedsignatures", "authorized_signatures"),
        ):
            if key in props:
                template[out] = props[key]
        template["published"] = oid in published
        template["published_cas"] = published.get(oid, [])
        template["ekus"] = props.get("effectiveekus", props.get("ekus"))
        enrollers = template_enrollers.get(oid, [])
        template["enrollers"] = sorted(set(enrollers))
        template["low_privilege_enrollment"] = any(broad_principal(p) for p in enrollers)
    for (principal, domain), rights in sorted(replication.items()):
        mapped = [
            {
                "GetChanges": "DS-Replication-Get-Changes",
                "GetChangesAll": "DS-Replication-Get-Changes-All",
                "GetChangesInFilteredSet": "DS-Replication-Get-Changes-In-Filtered-Set",
            }[r]
            for r in sorted(rights)
        ]
        result.setdefault("replication_rights", []).append(
            {"principal": principal, "domain": domain, "rights": mapped}
        )
        if {"GetChanges", "GetChangesAll"} <= rights:
            edge(
                principal,
                domain,
                "DCSync",
                "derived:combined-domain-root-replication-aces",
                source_kind="derived",
            )
    for item in list(edges.values()):
        for key in ("source", "target"):
            oid = item[key]
            if oid not in nodes:
                nodes[oid] = {
                    "id": oid,
                    "name": oid,
                    "type": "Unresolved",
                    "properties": {},
                    "high_value": False,
                }
    result["nodes"] = sorted(nodes.values(), key=lambda n: n["id"])
    result["edges"] = sorted(edges.values(), key=lambda e: (e["source"], e["target"], e["relation"]))
    result["provenance"] = {
        "documents": manifests,
        "collection_counts": dict(sorted(counts.items())),
        "duplicates": duplicates,
        "issues": issues,
        "unresolved_nodes": sum(n["type"] == "Unresolved" for n in nodes.values()),
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "limitations": [
            "Collector ACEs are not a Windows effective-access evaluation.",
            "Unknown relationships are retained; only explicitly modeled edges are traversed.",
        ],
    }
    return result
