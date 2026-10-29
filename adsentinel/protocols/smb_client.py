"""Read-only SMB negotiation, one login and bounded share enumeration."""

from __future__ import annotations

from typing import Any

from impacket import smb
from impacket.smbconnection import SessionError, SMBConnection

from ..core.auth import Credentials
from ..security import hostname


def collect_smb(
    host: str,
    credentials: Credentials,
    timeout: int = 10,
    shares: bool = True,
    check_smb1: bool = False,
    port: int = 445,
) -> dict[str, Any]:
    hostname(host)
    result: dict[str, Any] = {"id": host, "shares": [], "errors": []}
    connection = None
    try:
        connection = SMBConnection(remoteName=host, remoteHost=host, timeout=timeout, sess_port=port)
        dialect = connection.getDialect()
        result["smb_dialect"] = str(dialect)
        result["smb_signing_required"] = bool(connection.isSigningRequired())
        if dialect == smb.SMB_DIALECT:
            result["smb1_enabled"] = True
        if shares:
            username = credentials.username or ""
            domain = credentials.domain
            if "\\" in username:
                domain, username = username.split("\\", 1)
            elif "@" in username:
                username, domain = username.rsplit("@", 1)
            connection.login(username, credentials.password or "", domain)
            result["guest_session"] = bool(connection.isGuestSession())
            for share in connection.listShares()[:256]:
                name = str(share["shi1_netname"]).rstrip("\x00")
                row: dict[str, Any] = {
                    "name": name,
                    "type": int(share["shi1_type"]),
                    "administrative": name.endswith("$"),
                    "write_access": "not tested",
                }
                # Directory listing is read-only. Never create test files to infer writability.
                if name.upper() != "IPC$":
                    try:
                        listing = connection.listPath(name, "*", password=None)
                        row["root_listable"] = True
                        row["root_entry_count"] = len(listing)
                    except SessionError:
                        row["root_listable"] = False
                result["shares"].append(row)
            if not credentials.username:
                result["anonymous_share_enumeration"] = True
                if any(s.get("root_listable") for s in result["shares"]):
                    result["anonymous_shares"] = True
    except (SessionError, OSError) as exc:
        result["errors"].append(
            {
                "operation": "smb",
                "type": type(exc).__name__,
                "message": "SMB connection, authentication or share operation failed",
            }
        )
    finally:
        if connection:
            connection.close()
    if check_smb1 and "smb1_enabled" not in result:
        legacy = None
        try:
            legacy = SMBConnection(
                remoteName=host,
                remoteHost=host,
                timeout=timeout,
                preferredDialect=smb.SMB_DIALECT,
                sess_port=port,
            )
            result["smb1_enabled"] = legacy.getDialect() == smb.SMB_DIALECT
        except (OSError, SessionError):
            result["smb1_probe"] = "not negotiated; network errors do not prove SMBv1 disabled"
        finally:
            if legacy:
                legacy.close()
    return result
