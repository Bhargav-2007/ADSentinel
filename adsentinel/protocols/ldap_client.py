"""Verified LDAPS inventory, domain/configuration/schema parsing and ACL collection."""

from __future__ import annotations

import hashlib
import json
import ssl
import struct
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from ldap3 import BASE, SUBTREE, Connection, Server, Tls
from ldap3.protocol.microsoft import security_descriptor_control

from ..core.auth import Credentials
from ..importers.bloodhound import import_documents
from ..security import SafetyError, hostname
from .security_descriptor import descriptor_edges, parse_descriptor, sid_at

ATTRIBUTES = [
    "objectClass",
    "objectGUID",
    "objectSid",
    "sAMAccountName",
    "distinguishedName",
    "cn",
    "displayName",
    "userAccountControl",
    "servicePrincipalName",
    "member",
    "memberOf",
    "primaryGroupID",
    "msDS-SupportedEncryptionTypes",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-GroupMSAMembership",
    "lastLogonTimestamp",
    "pwdLastSet",
    "adminCount",
    "sIDHistory",
    "dNSHostName",
    "operatingSystem",
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-PasswordExpirationTime",
    "nTSecurityDescriptor",
    "minPwdLength",
    "pwdHistoryLength",
    "pwdProperties",
    "lockoutThreshold",
    "lockoutDuration",
    "maxPwdAge",
    "msDS-Behavior-Version",
    "trustPartner",
    "trustDirection",
    "trustType",
    "trustAttributes",
    "gPLink",
    "gPCFileSysPath",
    "gPCWQLFilter",
    "flags",
    "msDS-MinimumPasswordLength",
    "msDS-PasswordHistoryLength",
    "msDS-PasswordComplexityEnabled",
    "msDS-PasswordReversibleEncryptionEnabled",
    "msDS-LockoutThreshold",
    "msDS-LockoutDuration",
    "msDS-PSOAppliesTo",
    "msDS-PasswordSettingsPrecedence",
    "nETBIOSName",
    "dnsRoot",
    "siteObject",
    "location",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-RA-Signature",
    "msPKI-Template-Schema-Version",
    "pKIExtendedKeyUsage",
    "pKIExpirationPeriod",
    "pKIOverlapPeriod",
    "certificateTemplates",
]
MULTI = {
    "objectClass",
    "servicePrincipalName",
    "member",
    "memberOf",
    "sIDHistory",
    "msDS-AllowedToDelegateTo",
    "msDS-PSOAppliesTo",
    "pKIExtendedKeyUsage",
    "certificateTemplates",
}
SENSITIVE_BINARY = {
    "nTSecurityDescriptor",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-GroupMSAMembership",
}


def filetime_seconds(value: Any) -> int | None:
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, datetime):
        return int(value.timestamp())
    try:
        return int(value) // 10000000 - 11644473600
    except (ValueError, TypeError):
        return None


def scalar(value: Any) -> Any:
    return value[0] if isinstance(value, list) and value else None if value == [] else value


def sid_value(value: Any) -> str | None:
    value = scalar(value)
    if isinstance(value, bytes):
        return sid_at(value)[0]
    return str(value) if value else None


class LDAPClient:
    def __init__(
        self,
        domain: str,
        dc: str,
        credentials: Credentials,
        timeout: int = 30,
        port: int = 636,
        ca_file: str | None = None,
        source_address: str | None = None,
        tls_server_name: str | None = None,
    ):
        hostname(domain)
        hostname(dc)
        self.started = time.monotonic()
        self.domain = domain
        self.timeout = timeout
        self.base = ",".join("DC=" + part for part in domain.split("."))
        username = credentials.username
        if username and "@" not in username and "\\" not in username:
            username += "@" + domain
        self.connection = Connection(
            Server(
                dc,
                port=port,
                use_ssl=True,
                connect_timeout=timeout,
                tls=Tls(
                    validate=ssl.CERT_REQUIRED,
                    ca_certs_file=ca_file,
                    valid_names=[tls_server_name] if tls_server_name else None,
                ),
            ),
            user=username,
            password=credentials.password,
            read_only=True,
            auto_referrals=False,
            receive_timeout=timeout,
            raise_exceptions=True,
            source_address=source_address,
            check_names=False,
        )

    def __enter__(self) -> LDAPClient:
        try:
            if not self.connection.bind():
                raise SafetyError("LDAPS authentication failed")
            self.connection.search(
                "",
                "(objectClass=*)",
                search_scope=BASE,
                attributes=[
                    "defaultNamingContext",
                    "configurationNamingContext",
                    "schemaNamingContext",
                    "rootDomainNamingContext",
                    "domainControllerFunctionality",
                    "forestFunctionality",
                ],
            )
            if not self.connection.response:
                raise SafetyError("RootDSE discovery failed")
            self.root = {k: scalar(v) for k, v in self.connection.response[0]["attributes"].items()}
            if str(self.root.get("defaultNamingContext", "")).casefold() != self.base.casefold():
                self.connection.unbind()
                raise SafetyError("Controller naming context does not match requested domain")
            return self
        except BaseException:
            self.connection.unbind()
            raise

    def __exit__(self, *args: Any) -> None:
        self.connection.unbind()

    def search(
        self, base: str, query: str, attributes: list[str], security: bool = False
    ) -> list[dict[str, Any]]:
        rows = []
        kwargs = {"controls": security_descriptor_control(sdflags=5)} if security else {}
        # Filters are fixed by the caller; arbitrary CLI filters are not accepted.
        for item in self.connection.extend.standard.paged_search(
            base,
            query,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=500,
            generator=True,
            time_limit=self.timeout,
            **kwargs,
        ):
            if time.monotonic() - self.started >= 3600:
                raise SafetyError("LDAP whole-run deadline reached")
            if item.get("type") == "searchResEntry":
                rows.append(item)
                if len(rows) > 100000:
                    raise SafetyError("LDAP collection exceeds 100,000 objects")
        if self.connection.result.get("result", 0) != 0:
            raise SafetyError("LDAP query incomplete; check read access and directory limits")
        return rows

    def collect(self, collection: str = "default") -> dict[str, Any]:
        filters = {
            "users": "(&(objectClass=user)(!(objectClass=computer)))",
            "groups": "(objectClass=group)",
            "computers": "(objectClass=computer)",
            "gpo": "(|(objectClass=groupPolicyContainer)(objectClass=organizationalUnit))",
        }
        directory_filter = filters.get(
            collection,
            "(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit)(objectClass=domainDNS)"
            "(objectClass=groupPolicyContainer)(objectClass=trustedDomain)(objectClass=msDS-PasswordSettings))",
        )
        records = self.search(self.base, directory_filter, ATTRIBUTES, True)
        config = self.root.get("configurationNamingContext")
        if config and collection not in {"users", "groups", "computers", "gpo"}:
            records += self.search(
                config,
                "(|(objectClass=pKIEnrollmentService)(objectClass=pKICertificateTemplate)(objectClass=crossRef)"
                "(objectClass=site)(objectClass=subnet))",
                ATTRIBUTES,
                True,
            )
        schema = self.root.get("schemaNamingContext")
        attribute_guids: dict[str, str] = {}
        class_guids: dict[str, str] = {}
        if schema:
            for record in self.search(
                schema,
                "(|(objectClass=classSchema)(objectClass=attributeSchema))",
                ["lDAPDisplayName", "schemaIDGUID"],
            ):
                attrs = record["attributes"]
                name = str(scalar(attrs.get("lDAPDisplayName")))
                raw = scalar(record.get("raw_attributes", {}).get("schemaIDGUID"))
                if not isinstance(raw, bytes) or len(raw) != 16:
                    continue
                guid = str(uuid.UUID(bytes_le=raw))
                class_guids[name.lower()] = guid
                if name.lower() in {"ms-mcs-admpwd", "mslaps-password", "mslaps-encryptedpassword"}:
                    attribute_guids[guid] = "ReadLAPSPassword"
        return normalize_records(records, self.root, class_guids, attribute_guids)


def normalize_records(
    records: list[dict[str, Any]],
    root: dict[str, Any],
    class_guids: dict[str, str] | None = None,
    attribute_guids: dict[str, str] | None = None,
) -> dict[str, Any]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    extra: dict[str, list[dict[str, Any]]] = {
        "password_policies": [],
        "sites": [],
        "subnets": [],
        "directory_partitions": [],
    }
    dn_ids: dict[str, str] = {}
    dn_records: dict[str, dict[str, Any]] = {}
    acl_edges = []
    issues = []
    now = int(datetime.now(timezone.utc).timestamp())
    for record in records:
        attrs = {k: v if k in MULTI else scalar(v) for k, v in record["attributes"].items()}
        raw = record.get("raw_attributes", {})
        sid = sid_value(raw.get("objectSid", attrs.get("objectSid")))
        guid = scalar(raw.get("objectGUID"))
        oid = sid or (
            str(uuid.UUID(bytes_le=guid)).upper()
            if isinstance(guid, bytes) and len(guid) == 16
            else record["dn"]
        )
        dn_ids[record["dn"].casefold()] = oid
        dn_records[record["dn"].casefold()] = attrs
    for record in records:
        attrs = dn_records[record["dn"].casefold()]
        raw = record.get("raw_attributes", {})
        oid = dn_ids[record["dn"].casefold()]
        sid = sid_value(raw.get("objectSid", attrs.get("objectSid")))
        classes = [str(c).lower() for c in attrs.get("objectClass", [])]
        classification = next(
            (
                kind
                for cls, kind in [
                    ("computer", "computers"),
                    ("group", "groups"),
                    ("user", "users"),
                    ("organizationalunit", "ous"),
                    ("domaindns", "domains"),
                    ("grouppolicycontainer", "gpos"),
                    ("pkienrollmentservice", "enterprisecas"),
                    ("pkicertificatetemplate", "certtemplates"),
                ]
                if cls in classes
            ),
            None,
        )
        if not classification:
            if "msds-passwordsettings" in classes:
                extra["password_policies"].append(
                    {
                        "id": oid,
                        "minimum_length": attrs.get("msDS-MinimumPasswordLength"),
                        "history_length": attrs.get("msDS-PasswordHistoryLength"),
                        "complexity": attrs.get("msDS-PasswordComplexityEnabled"),
                        "precedence": attrs.get("msDS-PasswordSettingsPrecedence"),
                        "applies_to": attrs.get("msDS-PSOAppliesTo", []),
                    }
                )
            elif "trusteddomain" in classes:
                bits = int(attrs.get("trustAttributes") or 0)
                extra.setdefault("trusts", []).append(
                    {
                        "id": oid,
                        "name": attrs.get("trustPartner"),
                        "direction": attrs.get("trustDirection"),
                        "trust_type": attrs.get("trustType"),
                        "attributes": bits,
                        "selective_authentication": bool(bits & 0x10),
                        "sid_filtering": bool(bits & 4),
                        "within_forest": bool(bits & 0x20),
                    }
                )
            else:
                collection = (
                    "sites"
                    if "site" in classes
                    else "subnets"
                    if "subnet" in classes
                    else "directory_partitions"
                )
                extra[collection].append(
                    {
                        "id": oid,
                        "name": attrs.get("cn"),
                        "netbios": attrs.get("nETBIOSName"),
                        "dns_root": attrs.get("dnsRoot"),
                        "site": attrs.get("siteObject"),
                    }
                )
            continue
        domain = next((str(v) for v in [attrs.get("dnsRoot")] if v), "")
        if not domain:
            domain = ".".join(part[3:] for part in record["dn"].split(",") if part.lower().startswith("dc="))
        name = attrs.get("sAMAccountName") or attrs.get("displayName") or attrs.get("cn") or oid
        if classification == "computers" and attrs.get("dNSHostName"):
            name = attrs["dNSHostName"]
        props: dict[str, Any] = {
            "name": str(name) + "@" + domain.upper(),
            "domain": domain.upper(),
            "distinguishedname": record["dn"],
            "samaccountname": attrs.get("sAMAccountName"),
            "dnshostname": attrs.get("dNSHostName"),
            "domainsid": oid.rsplit("-", 1)[0]
            if classification in {"users", "computers", "groups"} and sid_value(raw.get("objectSid"))
            else oid,
        }
        uac = attrs.get("userAccountControl")
        if uac is not None:
            uac = int(uac)
            props.update(
                dontreqpreauth=bool(uac & 0x400000),
                pwdneverexpires=bool(uac & 0x10000),
                unconstraineddelegation=bool(uac & 0x80000),
                trustedtoauth=bool(uac & 0x1000000),
                enabled=not bool(uac & 2),
                isdc=bool(uac & 0x2000),
                reversible_encryption=bool(uac & 0x80),
            )
        if "servicePrincipalName" in attrs:
            props["serviceprincipalnames"] = attrs["servicePrincipalName"]
            props["hasspn"] = bool(attrs["servicePrincipalName"])
        for key in ("lastLogonTimestamp", "pwdLastSet"):
            props[key.lower()] = filetime_seconds(attrs.get(key))
        props["admincount"] = bool(int(attrs.get("adminCount") or 0))
        if "sIDHistory" in attrs:
            history = raw.get("sIDHistory", attrs["sIDHistory"])
            props["sidhistory"] = [sid_value(v) for v in history if sid_value(v)]
        encryption = attrs.get("msDS-SupportedEncryptionTypes")
        if encryption is not None:
            props["encryption_types"] = int(encryption)
        expiration = attrs.get("msLAPS-PasswordExpirationTime") or attrs.get("ms-Mcs-AdmPwdExpirationTime")
        if classification == "computers" and expiration is not None:
            props["haslaps"] = int(expiration) > 0
            props["laps_expiration"] = filetime_seconds(expiration)
        if classification == "certtemplates":
            props.update(
                enrolleesuppliessubject=bool(int(attrs.get("msPKI-Certificate-Name-Flag") or 0) & 1),
                requiresmanagerapproval=bool(int(attrs.get("msPKI-Enrollment-Flag") or 0) & 2),
                authorizedsignatures=int(attrs.get("msPKI-RA-Signature") or 0),
                schemaversion=attrs.get("msPKI-Template-Schema-Version"),
                effectiveekus=attrs.get("pKIExtendedKeyUsage", []),
            )
            props["authenticationenabled"] = not props["effectiveekus"] or any(
                eku in props["effectiveekus"]
                for eku in (
                    "1.3.6.1.5.5.7.3.2",
                    "1.3.6.1.4.1.311.20.2.2",
                    "1.3.6.1.4.1.311.10.3.4",
                    "2.5.29.37.0",
                )
            )
            for key in ("pKIExpirationPeriod", "pKIOverlapPeriod"):
                value = scalar(raw.get(key))
                if isinstance(value, bytes) and len(value) == 8:
                    props[key.lower() + "_seconds"] = -struct.unpack("<q", value)[0] // 10000000
        obj: dict[str, Any] = {"ObjectIdentifier": oid, "Properties": props, "Aces": []}
        sd = scalar(raw.get("nTSecurityDescriptor"))
        if isinstance(sd, bytes):
            try:
                descriptor = parse_descriptor(sd)
                class_guid = (class_guids or {}).get(classes[-1]) if classes else None
                parsed = descriptor_edges(descriptor, oid, class_guid, attribute_guids)
                acl_edges.extend(parsed)
                obj["Aces"] = [
                    {"PrincipalSID": e["source"], "RightName": e["relation"], "IsInherited": False}
                    for e in parsed
                ]
                if descriptor.get("unsupported_ace_types"):
                    issues.append(
                        {"object": oid, "reason": "conditional/unsupported ACEs require manual access review"}
                    )
            except SafetyError:
                issues.append({"object": oid, "reason": "security descriptor parse failure"})
        if classification == "groups":
            obj["Members"] = [
                {"ObjectIdentifier": dn_ids.get(dn.casefold(), dn)} for dn in attrs.get("member", [])
            ]
        if attrs.get("primaryGroupID") is not None and sid:
            obj["PrimaryGroupSID"] = sid.rsplit("-", 1)[0] + "-" + str(attrs["primaryGroupID"])
        targets = attrs.get("msDS-AllowedToDelegateTo", [])
        host_ids = {
            str(a.get("dNSHostName")).casefold(): dn_ids[dn]
            for dn, a in dn_records.items()
            if a.get("dNSHostName")
        }
        obj["AllowedToDelegate"] = [
            {"ObjectIdentifier": host_ids.get(spn.split("/")[1].split(":")[0].casefold(), spn)}
            for spn in targets
            if "/" in spn
        ]
        for attribute, label in (
            ("msDS-AllowedToActOnBehalfOfOtherIdentity", "rbcd_policy"),
            ("msDS-GroupMSAMembership", "gmsa_policy"),
        ):
            blob = scalar(raw.get(attribute))
            if isinstance(blob, bytes):
                try:
                    policy = parse_descriptor(blob)
                    props[label] = {"owner": policy["owner"], "aces": policy["aces"]}
                    if label == "gmsa_policy":
                        denied_readers = {
                            a["principal"] for a in policy["aces"] if not a["allow"] and a["mask"] & 0x10
                        }
                        obj["Aces"].extend(
                            {
                                "PrincipalSID": a["principal"],
                                "RightName": "ReadGMSAPassword",
                                "IsInherited": a["inherited"],
                            }
                            for a in policy["aces"]
                            if a["allow"]
                            and a["mask"] & 0x10
                            and not a["inherit_only"]
                            and a["principal"] not in denied_readers
                        )
                    if label == "rbcd_policy":
                        obj["AllowedToAct"] = [
                            {"ObjectIdentifier": a["principal"]}
                            for a in policy["aces"]
                            if a["allow"] and a["mask"] & 0x100 and not a["inherit_only"]
                        ]
                except SafetyError:
                    issues.append({"object": oid, "reason": label + " parse failure"})
        if classification == "domains":
            extra["password_policies"].append(
                {
                    "id": oid,
                    "minimum_length": attrs.get("minPwdLength"),
                    "history_length": attrs.get("pwdHistoryLength"),
                    "complexity": bool(int(attrs.get("pwdProperties") or 0) & 1),
                    "reversible_encryption": bool(int(attrs.get("pwdProperties") or 0) & 16),
                    "lockout_threshold": attrs.get("lockoutThreshold"),
                    "lockout_duration": attrs.get("lockoutDuration"),
                }
            )
        if classification == "gpos":
            props["gpcpath"] = attrs.get("gPCFileSysPath")
            props["wmi_filter"] = attrs.get("gPCWQLFilter")
        if attrs.get("gPLink"):
            import re

            obj["Links"] = [
                {"GUID": dn_ids.get(dn.casefold(), dn), "IsEnforced": bool(int(flags) & 2)}
                for dn, flags in re.findall(r"\[LDAP://([^;]+);(\d+)\]", attrs["gPLink"], re.I)
                if not int(flags) & 1
            ]
        if classification == "enterprisecas":
            obj["EnabledCertTemplates"] = [
                {"ObjectIdentifier": dn_ids[r["dn"].casefold()]}
                for r in records
                if scalar(r["attributes"].get("cn")) in attrs.get("certificateTemplates", [])
                and "pKICertificateTemplate" in r["attributes"].get("objectClass", [])
            ]
        buckets.setdefault(classification, []).append(obj)
    docs = [
        (
            "ldaps:" + kind,
            {"meta": {"type": kind, "version": 6, "count": len(rows)}, "data": rows},
            hashlib.sha256(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest(),
        )
        for kind, rows in buckets.items()
    ]
    result = import_documents(iter(docs))
    for collection, rows in extra.items():
        result.setdefault(collection, []).extend(rows)
    result["source"] = "Verified LDAPS domain/configuration/schema enumeration"
    result["rootdse"] = root
    result["provenance"]["issues"].extend(issues)
    result["provenance"]["assessment_time"] = now
    return result
