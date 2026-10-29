"""Unauthenticated WS-Management Identify; never invokes remote commands."""

from __future__ import annotations

from typing import Any

import defusedxml.ElementTree as ET
import httpx
from defusedxml.common import DefusedXmlException

from ..security import hostname

IDENTIFY = b"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:i="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><i:Identify/></s:Body></s:Envelope>"""


def probe_winrm(
    host: str,
    timeout: int = 10,
    source_address: str | None = None,
    tls: bool = False,
    port: int | None = None,
) -> dict[str, Any]:
    hostname(host)
    result: dict[str, Any] = {
        "id": host,
        "transport": "https" if tls else "http",
        "remoting_access": "not tested",
    }
    netloc = "[" + host + "]" if ":" in host else host
    url = f"{'https' if tls else 'http'}://{netloc}:{port or (5986 if tls else 5985)}/wsman"
    try:
        transport = httpx.HTTPTransport(local_address=source_address, verify=True)
        with httpx.Client(
            transport=transport, timeout=timeout, follow_redirects=False, trust_env=False
        ) as client:
            with client.stream(
                "POST", url, content=IDENTIFY, headers={"Content-Type": "application/soap+xml;charset=UTF-8"}
            ) as response:
                body = bytearray()
                for block in response.iter_bytes():
                    body.extend(block)
                    if len(body) > 64000:
                        result["error"] = "WSMan response exceeds size limit"
                        return result
                result["http_status"] = response.status_code
                result["authentication_advertised"] = response.headers.get("www-authenticate", "")[:1024]
                if response.status_code == 401:
                    result["wsman_authentication_required"] = True
                elif (
                    response.status_code == 200
                    and b"<!DOCTYPE" not in body.upper()
                    and b"<!ENTITY" not in body.upper()
                ):
                    root = ET.fromstring(body)
                    names = {e.tag.rsplit("}", 1)[-1]: (e.text or "")[:1024] for e in root.iter()}
                    if "IdentifyResponse" in names:
                        result["winrm_identified"] = True
                        result["product_version"] = names.get("ProductVersion")
    except (httpx.HTTPError, ET.ParseError, DefusedXmlException) as exc:
        result["error"] = {"type": type(exc).__name__, "message": "WSMan Identify or TLS validation failed"}
    result["limitations"] = [
        "Advertised auth methods do not prove successful authentication or effective remoting access."
    ]
    return result
