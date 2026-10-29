"""Protocol execution plans and conservative, cancellable collection orchestration."""

from __future__ import annotations

import ipaddress
import time
from typing import Any

from ..core.auth import Credentials
from ..core.authorization import Scope
from ..security import SafetyError, target
from .dns_client import collect_dns
from .ldap_client import LDAPClient
from .rdp_client import probe_rdp
from .smb_client import collect_smb
from .winrm_client import probe_winrm

DIRECTORY_MODULES = {
    "recon",
    "bloodhound",
    "kerberos",
    "adcs",
    "delegation",
    "acl",
    "dcsync-check",
    "gpo",
    "laps",
    "gmsa",
    "trusts",
    "account-hygiene",
    "password-policy",
    "privileged-access",
    "baseline",
    "detection-coverage",
    "attack-path",
    "full-audit",
    "ldap",
}


def requested_protocol(command: str, explicit: str | None, has_domain: bool, has_target: bool) -> str | None:
    if explicit:
        return explicit
    if command == "azure-ad":
        return "graph"
    if command in {"smb", "ntlm", "rdp", "winrm"} and has_target:
        return "smb" if command == "ntlm" else command
    if command == "dns" and has_domain:
        return "dns"
    if command in DIRECTORY_MODULES and has_domain:
        return "ldap"
    return None


def expand_targets(value: str | None, dc: str | None, scope: Scope | None = None) -> list[str]:
    chosen = value or dc
    if not chosen:
        return []
    target(chosen)
    if "/" not in chosen:
        return [chosen]
    network = ipaddress.ip_network(chosen, strict=False)
    if scope:
        return sorted(t for t in scope.targets if ipaddress.ip_address(t) in network)
    return [str(ip) for ip in network.hosts()]


def plan(
    protocol: str | None, targets: list[str], domain: str | None, username: str | None, timeout: int
) -> dict[str, Any]:
    actions = {
        "ldap": [
            "Verify LDAPS certificate",
            "Bind once",
            "Read RootDSE",
            "Paged domain/configuration/schema searches",
            "Read owner/DACL descriptors (no SACL)",
            "Normalize objects and permissions; never request secret attributes",
        ],
        "smb": [
            "Negotiate SMB",
            "Read signing requirement",
            "Single account/anonymous login if share enumeration selected",
            "Enumerate shares and list roots without writes",
        ],
        "dns": ["DNS A/AAAA/MX/NS/SOA and DC/Kerberos/GC SRV queries", "One randomized A wildcard query"],
        "rdp": ["TCP/3389 X.224 negotiation requesting TLS without CredSSP; no authentication"],
        "winrm": [
            "HTTP/5985 WS-Management Identify; no credentials, command execution or redirect following"
        ],
        "graph": [
            "GET Microsoft Graph user/application/service-principal inventory with supplied token; no consent or writes"
        ],
    }
    if protocol == "graph":
        from .graph_client import SELECTS

        actions["graph"] = ["GET https://graph.microsoft.com/v1.0/" + resource for resource in SELECTS]
        actions["graph"].append(
            "GET /v1.0/servicePrincipals/{collected-UUID}/appRoleAssignments; IDs require inventory, never guessed"
        )
    permissions = {
        "ldap": ["Directory/configuration/schema read", "READ_CONTROL for owner/DACL metadata; no SACL read"],
        "smb": [
            "SMB negotiation needs no account",
            "Share/root listing requires the selected account's read permissions",
        ],
        "dns": ["DNS query access; AXFR additionally requires --authorize"],
        "rdp": ["TCP/3389 negotiation only; no account or logon rights tested"],
        "winrm": ["HTTP/5985 Identify only; no account or remoting rights tested"],
        "graph": [
            "User.Read.All",
            "Group.Read.All",
            "Application.Read.All",
            "RoleManagement.Read.Directory",
            "Directory.Read.All for delegated consent inventory (no write permissions required)",
        ],
    }
    return {
        "protocol": protocol,
        "targets": ["https://graph.microsoft.com"] if protocol == "graph" else targets,
        "domain": domain,
        "actions": actions.get(protocol or "", ["Read local evidence"]),
        "required_permissions": permissions.get(protocol or "", ["local input read"]),
        "authentication": "supplied environment bearer token"
        if protocol == "graph"
        else ("environment credential for named account" if username else "anonymous or no authentication"),
        "request_timeout_seconds": timeout,
        "concurrency": 1,
        "whole_run_limit_seconds": 3600,
    }


def collect(
    protocol: str,
    targets: list[str],
    domain: str | None,
    credentials: Credentials,
    timeout: int,
    scope: Scope | None = None,
    port: int = 636,
    shares: bool = True,
    check_smb1: bool = False,
    zone_transfer: bool = False,
    collection: str = "default",
    ca_file: str | None = None,
    tls_server_name: str | None = None,
    module: str | None = None,
) -> dict[str, Any]:
    if not targets:
        raise SafetyError("A controller or target is required for network collection")
    source = scope.source_address if scope else None
    if scope:
        scope.preflight(targets, domain, "active" if zone_transfer else "network")
        scope.validate_account(credentials.username)
    if protocol == "ldap":
        if not domain:
            raise SafetyError("LDAP collection requires --domain")
        with LDAPClient(
            domain,
            targets[0],
            credentials,
            timeout,
            port,
            ca_file=ca_file,
            source_address=source,
            tls_server_name=tls_server_name,
        ) as client:
            directory = client.collect(collection)
        if credentials.username is None and directory.get("nodes"):
            directory["anonymous_directory_read"] = {
                "endpoint": targets[0],
                "object_count": len(directory["nodes"]),
            }
        if module in {"recon", "full-audit"}:
            try:
                ipaddress.ip_address(targets[0])
                directory["dns"] = [collect_dns(domain, targets[0], timeout, source_address=source)]
            except ValueError:
                directory.setdefault("errors", []).append(
                    {
                        "operation": "dns",
                        "message": "DNS collection requires an explicit controller IP; no resolver fallback used",
                    }
                )
        return directory
    result: dict[str, Any] = {
        "source": "live read-only " + protocol,
        "computers": [],
        "errors": [],
        "nodes": [],
        "edges": [],
    }
    started = time.monotonic()
    for host in targets:
        if time.monotonic() - started >= (scope.max_duration_seconds if scope else 3600):
            raise SafetyError("Whole-run deadline reached")
        if protocol == "smb":
            record = collect_smb(host, credentials, timeout, shares, check_smb1)
        elif protocol == "rdp":
            record = probe_rdp(host, timeout, source)
        elif protocol == "winrm":
            record = probe_winrm(host, timeout, source)
        elif protocol == "dns":
            if not domain:
                raise SafetyError("DNS collection requires --domain")
            result["dns"] = [collect_dns(domain, host, timeout, zone_transfer, source)]
            break
        else:
            raise SafetyError("Unsupported collection protocol")
        result["computers"].append(record)
        if record.get("error"):
            result["errors"].append(
                {
                    "target": host,
                    "operation": protocol,
                    "message": "Endpoint probe failed",
                    "details": record["error"],
                }
            )
        result["errors"].extend({"target": host, **error} for error in record.get("errors", []))
    return result
