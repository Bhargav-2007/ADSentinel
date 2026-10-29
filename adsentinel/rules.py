"""Evidence-driven rules. Missing fields are unknown, never a passing control."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Finding

MODULES = (
    "recon bloodhound kerberos adcs delegation acl dcsync-check attack-path gpo laps gmsa "
    "smb ldap ntlm dns rdp winrm trusts azure-ad account-hygiene password-policy "
    "privileged-access baseline detection-coverage"
).split()


@dataclass(frozen=True)
class Rule:
    module: str
    collection: str
    field: str
    expected: Any
    severity: str
    title: str
    mitre: str
    remediation: str
    detection: str


RULES = [
    Rule(
        "kerberos",
        "users",
        "preauth_required",
        False,
        "HIGH",
        "Kerberos preauthentication disabled",
        "T1558.004",
        "Require Kerberos preauthentication after compatibility review.",
        "Review events 4768 and 4738.",
    ),
    Rule(
        "kerberos",
        "users",
        "has_spn",
        True,
        "MEDIUM",
        "Service principal eligible for service-ticket requests",
        "T1558.003",
        "Use gMSAs and long unique service passwords; prefer AES.",
        "Review anomalous 4769 service-ticket requests.",
    ),
    Rule(
        "kerberos",
        "users",
        "rc4_only",
        True,
        "HIGH",
        "RC4-only Kerberos account",
        "T1558.003",
        "Enable AES and rotate service credentials after compatibility testing.",
        "Review encryption types in event 4769.",
    ),
    Rule(
        "delegation",
        "computers",
        "unconstrained_delegation",
        True,
        "HIGH",
        "Unconstrained delegation enabled",
        "T1558",
        "Remove unconstrained delegation from non-DC systems.",
        "Monitor changes to userAccountControl with event 5136.",
    ),
    Rule(
        "delegation",
        "users",
        "protocol_transition",
        True,
        "MEDIUM",
        "Protocol transition configured",
        "T1550.003",
        "Review delegation targets and restrict service identities.",
        "Monitor delegation attribute changes and 4769.",
    ),
    Rule(
        "gpo",
        "gpos",
        "writable_by_low_privilege",
        True,
        "HIGH",
        "Low-privilege GPO modification path",
        "T1484.001",
        "Restrict GPO and SYSVOL write ACLs; review linked OU scope.",
        "Monitor 5136 and SYSVOL file modifications.",
    ),
    Rule(
        "laps",
        "computers",
        "laps_enabled",
        False,
        "MEDIUM",
        "LAPS coverage gap",
        "T1078.003",
        "Deploy Windows LAPS and restrict password-read rights.",
        "Monitor LAPS operational logs and directory access.",
    ),
    Rule(
        "laps",
        "computers",
        "excessive_laps_readers",
        True,
        "HIGH",
        "Excessive LAPS password-read rights",
        "T1555",
        "Limit LAPS readers to approved administrative identities.",
        "Audit LAPS attribute reads with scoped SACLs and event 4662.",
    ),
    Rule(
        "gmsa",
        "users",
        "excessive_gmsa_readers",
        True,
        "HIGH",
        "Excessive gMSA password-read rights",
        "T1555",
        "Restrict PrincipalsAllowedToRetrieveManagedPassword.",
        "Monitor gMSA security descriptor changes and 4662.",
    ),
    Rule(
        "gmsa",
        "users",
        "manual_service_account",
        True,
        "MEDIUM",
        "Unmanaged service account",
        "T1078.002",
        "Migrate eligible services to gMSAs.",
        "Review service logons and service-account changes.",
    ),
    Rule(
        "smb",
        "computers",
        "smb_signing_required",
        False,
        "HIGH",
        "SMB signing not required",
        "T1557.001",
        "Require SMB signing through a tested policy rollout.",
        "Review SMB server audit logs and relay-related logons.",
    ),
    Rule(
        "smb",
        "computers",
        "smb1_enabled",
        True,
        "HIGH",
        "SMBv1 enabled",
        "T1210",
        "Remove SMBv1 after identifying dependencies.",
        "Monitor SMBv1 usage in SMBServer audit logs.",
    ),
    Rule(
        "smb",
        "computers",
        "anonymous_shares",
        True,
        "MEDIUM",
        "Anonymous share access reported",
        "T1135",
        "Remove anonymous access and review share and NTFS ACLs.",
        "Review 5140 and 5145 events.",
    ),
    Rule(
        "ldap",
        "computers",
        "ldap_signing_required",
        False,
        "HIGH",
        "LDAP signing not required",
        "T1557.001",
        "Require LDAP signing after auditing incompatible clients.",
        "Review Directory Service events 2887 and 2889.",
    ),
    Rule(
        "ldap",
        "computers",
        "channel_binding_required",
        False,
        "MEDIUM",
        "LDAP channel binding not enforced",
        "T1557.001",
        "Enforce LDAP channel binding after compatibility assessment.",
        "Review LDAP channel-binding audit events.",
    ),
    Rule(
        "ntlm",
        "computers",
        "ntlmv1_enabled",
        True,
        "HIGH",
        "NTLMv1 accepted",
        "T1557.001",
        "Disable LM and NTLMv1 and audit remaining NTLM dependencies.",
        "Review event 4624 authentication package details.",
    ),
    Rule(
        "dns",
        "dns",
        "insecure_dynamic_updates",
        True,
        "HIGH",
        "Insecure DNS dynamic updates",
        "T1557",
        "Require secure dynamic updates and review DNS ACLs.",
        "Monitor DNS record changes and server audit logs.",
    ),
    Rule(
        "dns",
        "dns",
        "zone_transfer_unrestricted",
        True,
        "MEDIUM",
        "Unrestricted zone transfer reported",
        "T1018",
        "Restrict zone transfers to approved secondary servers.",
        "Review DNS transfer logs.",
    ),
    Rule(
        "rdp",
        "computers",
        "nla_required",
        False,
        "MEDIUM",
        "RDP NLA not required",
        "T1021.001",
        "Require NLA and restrict RDP access.",
        "Review 4624 type 10 and TerminalServices logs.",
    ),
    Rule(
        "rdp",
        "computers",
        "excessive_rdp_access",
        True,
        "MEDIUM",
        "Excessive RDP access",
        "T1021.001",
        "Limit Remote Desktop Users and use administrative tiers.",
        "Monitor Remote Desktop Users changes and type 10 logons.",
    ),
    Rule(
        "winrm",
        "computers",
        "winrm_basic_http",
        True,
        "HIGH",
        "WinRM Basic authentication over HTTP",
        "T1021.006",
        "Disable Basic authentication and use Kerberos or validated TLS.",
        "Review WinRM and PowerShell operational logs.",
    ),
    Rule(
        "trusts",
        "trusts",
        "sid_filtering",
        False,
        "HIGH",
        "SID filtering disabled on a trust",
        "T1134.005",
        "Review trust type and enforce appropriate SID filtering.",
        "Monitor trust changes and SIDHistory modifications.",
    ),
    Rule(
        "account-hygiene",
        "users",
        "password_never_expires",
        True,
        "MEDIUM",
        "Account password never expires",
        "T1078.002",
        "Review account purpose and adopt managed service identities.",
        "Monitor userAccountControl changes and account use.",
    ),
    Rule(
        "account-hygiene",
        "users",
        "reversible_encryption",
        True,
        "HIGH",
        "Reversible password encryption enabled",
        "T1003",
        "Disable reversible encryption and rotate affected passwords.",
        "Monitor account and password policy changes.",
    ),
    Rule(
        "account-hygiene",
        "users",
        "dormant_privileged",
        True,
        "HIGH",
        "Dormant privileged account",
        "T1078.002",
        "Disable unused privileged accounts after owner review.",
        "Alert on logon by dormant privileged identities.",
    ),
    Rule(
        "privileged-access",
        "users",
        "tiering_violation",
        True,
        "HIGH",
        "Privileged account used on lower-tier host",
        "T1078.002",
        "Separate administrative tiers and use privileged workstations.",
        "Correlate privileged group membership with 4624 logons.",
    ),
    Rule(
        "baseline",
        "computers",
        "unsupported_os",
        True,
        "HIGH",
        "Unsupported operating system reported",
        "T1210",
        "Upgrade or isolate unsupported systems.",
        "Correlate asset inventory with vendor lifecycle data.",
    ),
    Rule(
        "detection-coverage",
        "computers",
        "script_block_logging",
        False,
        "MEDIUM",
        "PowerShell script-block logging disabled",
        "T1059.001",
        "Enable script-block logging and forward events securely.",
        "Verify receipt of PowerShell event 4104.",
    ),
    Rule(
        "detection-coverage",
        "computers",
        "security_auditing",
        False,
        "HIGH",
        "Security auditing disabled",
        "T1562.002",
        "Apply advanced audit policy and validate SIEM forwarding.",
        "Monitor 4719 audit-policy changes and log gaps.",
    ),
    Rule(
        "azure-ad",
        "users",
        "hybrid_privileged",
        True,
        "HIGH",
        "Synchronized identity has cloud privilege",
        "T1078.004",
        "Use dedicated cloud-only privileged identities and phishing-resistant MFA.",
        "Correlate Entra audit and sign-in logs with sync activity.",
    ),
    Rule(
        "azure-ad",
        "applications",
        "overprivileged",
        True,
        "HIGH",
        "Overprivileged application reported",
        "T1098.003",
        "Review consent grants and remove unnecessary permissions.",
        "Monitor app role assignment and consent audit events.",
    ),
    Rule(
        "azure-ad",
        "applications",
        "expired_credential",
        True,
        "MEDIUM",
        "Expired application credential metadata",
        "T1078.004",
        "Remove expired credentials and rotate active credentials.",
        "Monitor credential additions and service-principal sign-ins.",
    ),
]

DANGEROUS = {
    "GenericAll",
    "GenericWrite",
    "WriteDACL",
    "WriteOwner",
    "ForceChangePassword",
    "AddMember",
    "Owns",
}


def evaluate(data: dict[str, Any], modules: list[str]) -> tuple[list[Finding], dict[str, Any]]:
    findings = []
    coverage: dict[str, Any] = {}
    selected = set(modules)
    if "baseline" in selected:
        selected.update({"smb", "ldap", "ntlm", "laps", "kerberos", "adcs"})
    for module in modules:
        coverage[module] = {
            "status": "no applicable evidence",
            "evaluated_fields": 0,
            "limitations": "Imported indicators are not proof of effective access or exploitability.",
        }
    for index, rule in enumerate(RULES, 1):
        if rule.module not in selected:
            continue
        for record in data.get(rule.collection, []):
            if rule.field not in record:
                continue
            slot = coverage.setdefault(rule.module, {"status": "evaluated", "evaluated_fields": 0})
            slot["evaluated_fields"] += 1
            slot["status"] = "evaluated"
            if type(record[rule.field]) is not type(rule.expected) or record[rule.field] != rule.expected:
                continue
            findings.append(
                Finding(
                    f"ADS-{index:03}",
                    rule.module,
                    rule.title,
                    rule.severity,
                    str(record.get("id", record.get("name", "unknown"))),
                    {"collection": rule.collection, "field": rule.field, "value": record[rule.field]},
                    rule.mitre,
                    rule.detection,
                    rule.remediation,
                )
            )

    def add(
        code: str,
        module: str,
        title: str,
        severity: str,
        obj: str,
        evidence: dict[str, Any],
        mitre: str,
        remediation: str,
    ) -> None:
        findings.append(
            Finding(
                code,
                module,
                title,
                severity,
                obj,
                evidence,
                mitre,
                "Monitor directory changes (5136) and scoped object access (4662).",
                remediation,
            )
        )

    if "adcs" in selected:
        for template in data.get("templates", []):
            if (
                template.get("enrollee_supplies_subject") is True
                and template.get("client_authentication") is True
                and template.get("low_privilege_enrollment") is True
                and template.get("manager_approval") is False
                and template.get("authorized_signatures") == 0
                and template.get("published") is True
            ):
                add(
                    "ADS-ESC1",
                    "adcs",
                    "ESC1 configuration indicators",
                    "HIGH",
                    template["id"],
                    {k: v for k, v in template.items() if k != "id"},
                    "T1649",
                    "Disable supplied subject names or restrict enrollment; require approval and review CA policy.",
                )
    if "acl" in selected:
        for edge in data.get("edges", []):
            if edge.get("relation") in DANGEROUS:
                add(
                    "ADS-ACL",
                    "acl",
                    "Potential directory control edge",
                    "HIGH",
                    str(edge["target"]),
                    edge,
                    "T1098",
                    "Review inheritance, deny ACEs and effective access; remove excessive rights.",
                )
    if "dcsync-check" in selected:
        for acl in data.get("replication_rights", []):
            rights = set(acl.get("rights", []))
            if {"DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"} <= rights:
                add(
                    "ADS-DCSYNC",
                    "dcsync-check",
                    "Replication permission combination reported",
                    "CRITICAL",
                    acl["principal"],
                    acl,
                    "T1003.006",
                    "Verify domain-root scope, group expansion, deny ACEs and filtered-set requirements; restrict replication rights.",
                )
    if "password-policy" in selected:
        for policy in data.get("password_policies", []):
            for field, threshold in (("minimum_length", 14), ("history_length", 24)):
                value = policy.get(field)
                if isinstance(value, int) and value < threshold:
                    add(
                        "ADS-POLICY-" + field,
                        "password-policy",
                        "Password policy review needed: " + field,
                        "MEDIUM",
                        policy.get("id", "domain"),
                        {field: value},
                        "T1110",
                        "Review password policy against organizational requirements; favor long passwords and MFA.",
                    )
    for module in modules:
        related = [f for f in findings if f.module == module]
        if related:
            coverage[module]["status"] = "evaluated"
        coverage[module]["finding_count"] = len(related)
    return findings, coverage


def validate_evidence(data: dict[str, Any]) -> None:
    from .security import SafetyError

    collections = {r.collection for r in RULES} | {
        "templates",
        "edges",
        "replication_rights",
        "password_policies",
        "groups",
        "ous",
    }
    for name in collections:
        value = data.get(name, [])
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise SafetyError(f"Evidence collection {name} must be an array of objects")
        for item in value:
            if name == "edges" and not all(
                isinstance(item.get(k), str) for k in ("source", "target", "relation")
            ):
                raise SafetyError("Edges require string source, target, relation")
            if name == "templates" and not isinstance(item.get("id"), str):
                raise SafetyError("Templates require an id")
            if name == "replication_rights" and (
                not isinstance(item.get("principal"), str)
                or not isinstance(item.get("rights"), list)
                or any(not isinstance(r, str) for r in item["rights"])
            ):
                raise SafetyError("Replication rights require principal and string rights list")
