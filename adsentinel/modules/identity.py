"""Derive observations from actual imported/directory properties, not prefilled risk flags."""

from __future__ import annotations

from typing import Any

from ..models import Finding
from .privileged_access import privileged_principals


def enrich(data: dict[str, Any]) -> None:
    privileged = privileged_principals(data)
    # Use dataset collection time, not today's date, for historic-logon age analysis.
    reference = data.get("provenance", {}).get("assessment_time")
    for record in data.get("users", []):
        props = record.get("properties", {})
        if "reversible_encryption" in props:
            record["reversible_encryption"] = props["reversible_encryption"]
        encryption = props.get("encryption_types")
        if isinstance(encryption, int) and encryption:
            record["rc4_only"] = bool(encryption & 4) and not bool(encryption & 24)
        if record.get("has_spn") is True:
            record["manual_service_account"] = not bool(props.get("gmsa_policy"))
        logon = props.get("lastlogontimestamp")
        if isinstance(reference, int) and isinstance(logon, int) and logon > 0:
            record["inactive"] = reference - logon > 90 * 86400
            if record.get("id") in privileged:
                record["dormant_privileged"] = record["inactive"]
        if record.get("id") in privileged:
            record["privileged"] = True

    nodes = {n["id"]: n for n in data.get("nodes", [])}
    for collection, field, rights in (
        ("gpos", "writable_by_low_privilege", {"GenericAll", "GenericWrite", "WriteDACL", "WriteOwner"}),
        ("computers", "excessive_laps_readers", {"ReadLAPSPassword"}),
        ("users", "excessive_gmsa_readers", {"ReadGMSAPassword"}),
    ):
        targets = {r["id"]: r for r in data.get(collection, []) if "id" in r}
        for edge in data.get("edges", []):
            if (
                edge.get("target") in targets
                and edge.get("relation") in rights
                and edge.get("source") not in privileged
                and nodes.get(edge.get("source"), {}).get("type") in {"User", "Group", "Computer"}
            ):
                targets[edge["target"]][field] = True


def assess(data: dict[str, Any], modules: list[str]) -> list[Finding]:
    findings = []
    privileged = privileged_principals(data)

    def add(
        code: str,
        module: str,
        title: str,
        obj: dict[str, Any],
        evidence: dict[str, Any],
        severity: str,
        mitre: str,
        remediation: str,
    ) -> None:
        evidence["evidence_reference"] = obj.get("evidence_reference", obj["id"])
        findings.append(
            Finding(
                code,
                module,
                title,
                severity,
                obj["id"],
                evidence,
                mitre,
                "Monitor directory attribute changes (5136), account changes (4738) and authentication events.",
                remediation,
            )
        )

    if "delegation" in modules:
        for edge in data.get("edges", []):
            if edge["relation"] in {"AllowedToDelegate", "AllowedToAct"}:
                add(
                    "ADS-DELEGATION",
                    "delegation",
                    "Constrained delegation relationship",
                    {"id": edge["source"]},
                    edge.copy(),
                    "MEDIUM",
                    "T1550.003",
                    "Review delegation service scope and allowed principals; enforce administrative tiers.",
                )
    for user in data.get("users", []):
        if "account-hygiene" in modules:
            if user.get("enabled") is False and user["id"] in privileged:
                add(
                    "ADS-DISABLED-PRIV",
                    "account-hygiene",
                    "Disabled account retains privileged membership",
                    user,
                    {"enabled": False},
                    "MEDIUM",
                    "T1078.002",
                    "Remove unnecessary privileged group membership after owner review.",
                )
            if user.get("inactive") is True:
                add(
                    "ADS-INACTIVE",
                    "account-hygiene",
                    "Replicated last-logon timestamp exceeds review threshold",
                    user,
                    {
                        "lastlogontimestamp": user.get("properties", {}).get("lastlogontimestamp"),
                        "threshold_days": 90,
                    },
                    "LOW",
                    "T1078.002",
                    "Confirm inactivity using authoritative logs before disabling the account.",
                )
        if "privileged-access" in modules and user["id"] in privileged:
            add(
                "ADS-STANDING-PRIV",
                "privileged-access",
                "Standing privileged membership",
                user,
                {"source": "transitive MemberOf expansion"},
                "INFO",
                "T1078.002",
                "Review business need, use separate administrative accounts and time-bound privilege where available.",
            )
    if "password-policy" in modules:
        for policy in data.get("password_policies", []):
            if policy.get("complexity") is False:
                add(
                    "ADS-POLICY-COMPLEXITY",
                    "password-policy",
                    "Password complexity disabled",
                    policy,
                    {"complexity": False},
                    "MEDIUM",
                    "T1110",
                    "Review complexity and length requirements against organizational policy.",
                )
            if policy.get("lockout_threshold") in {0, "0"}:
                add(
                    "ADS-NO-LOCKOUT",
                    "password-policy",
                    "Account lockout threshold disabled",
                    policy,
                    {"lockout_threshold": 0},
                    "MEDIUM",
                    "T1110",
                    "Set a tested lockout policy and monitor authentication failures.",
                )
    if "azure-ad" in modules:
        for principal in data.get("service_principals", []):
            if principal.get("sensitive_permissions"):
                add(
                    "ADS-GRAPH-GRANT",
                    "azure-ad",
                    "Sensitive application permission grant requires review",
                    principal,
                    {"grants": principal["sensitive_permissions"]},
                    "HIGH",
                    "T1098.003",
                    "Validate business need and remove unnecessary application permissions; prefer narrowly scoped identities.",
                )
        from ..protocols.graph_client import SENSITIVE

        for grant in data.get("consent_grants", []):
            sensitive = sorted(set(grant.get("scopes", [])) & SENSITIVE)
            if sensitive and grant.get("consent_type") == "AllPrincipals":
                add(
                    "ADS-GRAPH-CONSENT",
                    "azure-ad",
                    "Tenant-wide consent includes sensitive delegated scopes",
                    grant,
                    {"scopes": sensitive, "client_id": grant.get("client_id")},
                    "HIGH",
                    "T1098.003",
                    "Review tenant-wide consent, revoke unnecessary grants and restrict future consent.",
                )
    if any(m in modules for m in ("gpo", "baseline", "detection-coverage")):
        for gpo in data.get("gpo_files", []):
            for policy_file in gpo.get("files", []):
                evidence = {
                    "path": policy_file["path"],
                    "scope": "GPO configuration, not effective host policy",
                }
                if "gpo" in modules and policy_file.get("credential_attribute_present"):
                    add(
                        "ADS-GPP-CREDENTIAL",
                        "gpo",
                        "SYSVOL preference file contains a credential attribute",
                        gpo,
                        evidence.copy(),
                        "HIGH",
                        "T1552.006",
                        "Remove stored preference credentials and rotate affected passwords; never redistribute the file.",
                    )
                if "gpo" in modules and policy_file.get("script_entry_count", 0):
                    add(
                        "ADS-GPO-SCRIPTS",
                        "gpo",
                        "GPO deploys scripts requiring owner review",
                        gpo,
                        {**evidence, "entry_count": policy_file["script_entry_count"]},
                        "INFO",
                        "T1484.001",
                        "Review script ownership, signing, deployment scope and referenced file permissions.",
                    )
                for setting in policy_file.get("registry_dwords", []):
                    if (
                        "detection-coverage" in modules
                        and setting["value_name"].lower() == "enablescriptblocklogging"
                        and "powershell" in setting["key"].lower()
                        and setting["value"] == 0
                    ):
                        add(
                            "ADS-GPO-LOGGING",
                            "detection-coverage",
                            "GPO explicitly disables PowerShell script-block logging",
                            gpo,
                            {**evidence, "setting": setting},
                            "MEDIUM",
                            "T1059.001",
                            "Enable script-block logging in the effective policy and verify event 4104 delivery.",
                        )
    if "trusts" in modules:
        for collection in ("users", "groups", "computers"):
            for obj in data.get(collection, []):
                history = obj.get("properties", {}).get("sidhistory", [])
                if history:
                    add(
                        "ADS-SIDHISTORY",
                        "trusts",
                        "SIDHistory values require migration and privilege review",
                        obj,
                        {"sid_history": history},
                        "HIGH" if any(s in privileged for s in history) else "MEDIUM",
                        "T1134.005",
                        "Validate migration purpose and remove stale SIDHistory after access review.",
                    )
    if data.get("anonymous_directory_read") and any(m in modules for m in ("ldap", "recon")):
        observation = data["anonymous_directory_read"]
        add(
            "ADS-ANONYMOUS-LDAP",
            "ldap" if "ldap" in modules else "recon",
            "Directory objects readable without account authentication",
            {"id": observation["endpoint"]},
            {"object_count": observation["object_count"]},
            "MEDIUM",
            "T1087.002",
            "Review anonymous directory access requirements and remove unnecessary object-read permissions.",
        )
    return findings
