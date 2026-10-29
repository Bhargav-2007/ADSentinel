"""Scoped DNS queries and separately authorized zone-transfer checks."""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from ..security import hostname


def collect_dns(
    domain: str,
    server: str,
    timeout: int = 10,
    zone_transfer: bool = False,
    source_address: str | None = None,
    port: int = 53,
) -> dict[str, Any]:
    hostname(domain)
    ipaddress.ip_address(server)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.port = port
    resolver.timeout = timeout
    resolver.lifetime = timeout
    result: dict[str, Any] = {"id": domain, "records": [], "errors": []}
    queries = [(domain, kind) for kind in ("A", "AAAA", "MX", "NS", "SOA")]
    queries += [
        (prefix + domain, "SRV") for prefix in ("_ldap._tcp.dc._msdcs.", "_kerberos._tcp.", "_gc._tcp.")
    ]
    wildcard = uuid.uuid4().hex + "." + domain
    queries.append((wildcard, "A"))
    for name, kind in queries:
        try:
            answer = resolver.resolve(name, kind, source=source_address, search=False)
            values = [r.to_text() for r in answer]
            result["records"].append(
                {
                    "name": name,
                    "type": kind,
                    "ttl": answer.rrset.ttl if answer.rrset is not None else None,
                    "values": values,
                }
            )
            if name == wildcard:
                result["wildcard_observed"] = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            if name == wildcard:
                result["wildcard_observed"] = False
        except dns.exception.DNSException as exc:
            result["errors"].append({"query": name, "type": kind, "error": type(exc).__name__})
    if zone_transfer:
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(server, domain, timeout=timeout, lifetime=timeout, source=source_address)
            )
            if zone is not None:
                result["zone_transfer_unrestricted"] = True
                result["zone_record_count"] = len(zone.nodes)
        except dns.exception.DNSException as exc:
            result["zone_transfer_result"] = type(exc).__name__
    result["limitations"] = [
        "DNS responses alone do not establish dynamic-update policy or record staleness."
    ]
    return result
