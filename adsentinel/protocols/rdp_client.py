"""RDP negotiation only: no authentication, desktop session or NLA bypass."""

from __future__ import annotations

import socket
import struct
from typing import Any

from ..security import SafetyError, hostname


def receive_tpkt(stream: socket.socket) -> bytes:
    header = bytearray()
    while len(header) < 4:
        block = stream.recv(4 - len(header))
        if not block:
            raise SafetyError("Truncated RDP TPKT header")
        header.extend(block)
    if header[:2] != b"\x03\x00":
        raise SafetyError("Invalid RDP TPKT header")
    length = struct.unpack("!H", header[2:4])[0]
    if not 11 <= length <= 4096:
        raise SafetyError("Invalid RDP packet length")
    body = bytearray()
    while len(body) < length - 4:
        block = stream.recv(length - 4 - len(body))
        if not block:
            raise SafetyError("Truncated RDP packet")
        body.extend(block)
    return bytes(body)


def probe_rdp(
    host: str, timeout: int = 10, source_address: str | None = None, port: int = 3389
) -> dict[str, Any]:
    hostname(host)
    result: dict[str, Any] = {"id": host, "rdp_access": "not tested", "restricted_admin": "unknown"}
    # Request TLS without CredSSP. Selection proves a non-NLA negotiation path;
    # HYBRID_REQUIRED_BY_SERVER establishes that this connection requires NLA.
    request = bytes.fromhex("030000130ee000000000000100080001000000")
    try:
        with socket.create_connection(
            (host, port), timeout=timeout, source_address=(source_address, 0) if source_address else None
        ) as stream:
            stream.settimeout(timeout)
            result["rdp_endpoint_reachable"] = True
            stream.sendall(request)
            body = receive_tpkt(stream)
            if len(body) >= 15 and body[7] in {2, 3}:
                kind, _, length, value = struct.unpack_from("<BBHI", body, 7)
                if length != 8:
                    raise SafetyError("Invalid RDP negotiation length")
                result["negotiation_type"] = kind
                result["negotiation_value"] = value
                if kind == 2 and value in {0, 1}:
                    result["nla_required"] = False
                elif kind == 3 and value in {5, 6}:
                    result["nla_required"] = True
    except OSError as exc:
        result["error"] = {"type": type(exc).__name__, "message": "RDP connection failed"}
    return result
