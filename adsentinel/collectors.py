"""Explicit, read-only collectors. No secret attributes or authentication probes."""

from __future__ import annotations

import os
import ssl
from typing import Any
from urllib.parse import urlsplit

import httpx

from .security import SafetyError, graph_url, hostname, identity

LDAP_ATTRIBUTES = [
    "sAMAccountName",
    "objectClass",
    "distinguishedName",
    "memberOf",
    "member",
    "userAccountControl",
    "servicePrincipalName",
    "msDS-SupportedEncryptionTypes",
    "dNSHostName",
    "minPwdLength",
    "pwdHistoryLength",
    "lockoutThreshold",
]


def normalize_ldap(entries: list[dict[str, Any]]) -> dict[str, Any]:
    data: dict[str, Any] = {
        "users": [],
        "groups": [],
        "computers": [],
        "ous": [],
        "edges": [],
        "password_policies": [],
    }
    # Without a loaded server schema ldap3 returns single-valued attributes as lists.
    scalar_fields = {
        "sAMAccountName",
        "userAccountControl",
        "msDS-SupportedEncryptionTypes",
        "minPwdLength",
        "pwdHistoryLength",
        "lockoutThreshold",
    }
    for entry in entries:
        attrs = entry["attributes"]
        for key in scalar_fields:
            if isinstance(attrs.get(key), list):
                attrs[key] = attrs[key][0] if attrs[key] else None
    dn_names = {}
    for entry in entries:
        attrs = entry["attributes"]
        name = attrs.get("sAMAccountName") or entry["dn"]
        dn_names[entry["dn"].casefold()] = name
    for entry in entries:
        attrs = entry["attributes"]
        name = dn_names[entry["dn"].casefold()]
        classes = [str(c).lower() for c in attrs.get("objectClass", [])]
        record: dict[str, Any] = {"id": name, "dn": entry["dn"]}
        uac = int(attrs.get("userAccountControl") or 0)
        if "computer" in classes:
            kind = "computers"
            record["unconstrained_delegation"] = bool(uac & 0x80000)
            # Domain controllers legitimately use unconstrained delegation.
            if uac & 0x2000:
                record.pop("unconstrained_delegation")
        elif "group" in classes:
            kind = "groups"
        elif "user" in classes:
            kind = "users"
            record.update(
                preauth_required=not bool(uac & 0x400000),
                password_never_expires=bool(uac & 0x10000),
                reversible_encryption=bool(uac & 0x80),
                protocol_transition=bool(uac & 0x1000000),
                has_spn=bool(attrs.get("servicePrincipalName")),
            )
            encryption = attrs.get("msDS-SupportedEncryptionTypes")
            if isinstance(encryption, int) and encryption:
                record["rc4_only"] = bool(encryption & 4) and not bool(encryption & 24)
        elif "organizationalunit" in classes:
            kind = "ous"
        elif "domaindns" in classes:
            data["password_policies"].append(
                {
                    "id": name,
                    **{
                        out: int(attrs[key])
                        for key, out in (
                            ("minPwdLength", "minimum_length"),
                            ("pwdHistoryLength", "history_length"),
                        )
                        if attrs.get(key) is not None
                    },
                }
            )
            continue
        else:
            continue
        if attrs.get("userAccountControl") is None:
            for key in (
                "preauth_required",
                "password_never_expires",
                "reversible_encryption",
                "protocol_transition",
                "unconstrained_delegation",
            ):
                record.pop(key, None)
        data[kind].append(record)
        for group in attrs.get("memberOf", []):
            data["edges"].append(
                {"source": name, "target": dn_names.get(group.casefold(), group), "relation": "MemberOf"}
            )
    return data


def collect_ldap(
    domain: str, dc: str, username: str | None, password_env: str, timeout: int = 30, port: int = 636
) -> dict[str, Any]:
    from ldap3 import Connection, Server, Tls

    hostname(domain)
    hostname(dc)
    if username:
        identity(username)
    password = os.environ.get(password_env) if username else None
    if username and not password:
        raise SafetyError("LDAP password environment variable is missing")
    server = Server(dc, port=port, use_ssl=True, connect_timeout=timeout, tls=Tls(validate=ssl.CERT_REQUIRED))
    connection = Connection(
        server,
        user=username,
        password=password,
        read_only=True,
        receive_timeout=timeout,
        auto_referrals=False,
        raise_exceptions=True,
    )
    entries = []
    try:
        if not connection.bind():
            raise SafetyError("LDAP bind failed")
        base = ",".join("DC=" + part for part in domain.split("."))
        response = connection.extend.standard.paged_search(
            base,
            "(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit)(objectClass=domainDNS))",
            attributes=LDAP_ATTRIBUTES,
            paged_size=500,
            generator=True,
            time_limit=timeout,
        )
        for entry in response:
            if entry.get("type") == "searchResEntry":
                entries.append(entry)
                if len(entries) > 100000:
                    raise SafetyError("LDAP object limit exceeded")
        if connection.result.get("result", 0) != 0:
            raise SafetyError("LDAP collection incomplete; server returned an error")
    finally:
        connection.unbind()
    result = normalize_ldap(entries)
    result["source"] = (
        "read-only LDAPS; no security descriptors, host policies, sessions or secrets collected"
    )
    return result


def check_graph_link(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "graph.microsoft.com"
        or not parsed.path.startswith("/v1.0/")
        or parsed.fragment
    ):
        raise SafetyError("Untrusted Graph pagination URL rejected")


def collect_graph(token_env: str, timeout: int = 30) -> dict[str, Any]:
    token = os.environ.get(token_env)
    if not token:
        raise SafetyError("Graph token environment variable is missing")
    result: dict[str, Any] = {}
    # Explicit selects exclude credential values; no write endpoints or automatic consent.
    selects = {
        "users": "id,displayName,userPrincipalName,onPremisesSyncEnabled,accountEnabled",
        "applications": "id,displayName,appId,passwordCredentials,keyCredentials",
        "servicePrincipals": "id,displayName,appId,appRoles",
    }
    with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        for resource, select in selects.items():
            url: str | None = graph_url(resource)
            rows = []
            seen: set[str] = set()
            params: dict[str, str] | None = {"$select": select, "$top": "100"}
            while url:
                check_graph_link(url)
                if url in seen or len(seen) >= 1000:
                    raise SafetyError("Graph pagination cycle or page limit exceeded")
                seen.add(url)
                response = client.get(url, params=params, headers={"Authorization": "Bearer " + token})
                if response.status_code != 200:
                    raise SafetyError(
                        f"Graph request failed with HTTP {response.status_code}; verify read permissions"
                    )
                body = response.json()
                if not isinstance(body.get("value"), list):
                    raise SafetyError("Invalid Graph collection response")
                for item in body["value"]:
                    # Keep inventory and credential expiry metadata only.
                    row = {
                        "id": item["id"],
                        "name": item.get("displayName"),
                        "synchronized": item.get("onPremisesSyncEnabled"),
                    }
                    if resource == "applications":
                        from datetime import datetime, timezone

                        ends = [
                            c.get("endDateTime")
                            for key in ("passwordCredentials", "keyCredentials")
                            for c in item.get(key, [])
                            if c.get("endDateTime")
                        ]
                        row["expired_credential"] = any(
                            datetime.fromisoformat(end.replace("Z", "+00:00")) < datetime.now(timezone.utc)
                            for end in ends
                        )
                    rows.append(row)
                url = body.get("@odata.nextLink")
                params = None
            result[resource] = rows
    result["source"] = "Microsoft Graph read-only inventory; tenant is determined by supplied token"
    return result
