"""Real loopback sockets exercise wire parsers without contacting assessment targets."""

import json
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import dns.message
import dns.rcode
import dns.rrset
import httpx
import pytest

from adsentinel.protocols.dns_client import collect_dns
from adsentinel.protocols.graph_client import GraphClient
from adsentinel.protocols.rdp_client import probe_rdp
from adsentinel.protocols.winrm_client import probe_winrm
from adsentinel.security import SafetyError


@pytest.mark.parametrize("kind,value,nla", [(2, 1, False), (3, 5, True)])
def test_rdp_actual_loopback_negotiation(kind, value, nla):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def server():
            connection, _ = listener.accept()
            with connection:
                assert connection.recv(1024).startswith(b"\x03\x00")
                packet = bytes.fromhex("030000130ed00000000000") + struct.pack("<BBHI", kind, 0, 8, value)
                # Fragment the header to verify correct stream framing.
                connection.sendall(packet[:2])
                connection.sendall(packet[2:])

        thread = threading.Thread(target=server)
        thread.start()
        result = probe_rdp("127.0.0.1", timeout=2, port=listener.getsockname()[1])
        thread.join(timeout=3)
    assert result["nla_required"] is nla


def test_winrm_actual_loopback_identify():
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.path == "/wsman"
            body = self.rfile.read(int(self.headers["Content-Length"]))
            assert b"Identify" in body and "Authorization" not in self.headers
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                b'<s:Envelope xmlns:s="urn:soap"><s:Body><IdentifyResponse><ProductVersion>Test WSMan</ProductVersion></IdentifyResponse></s:Body></s:Envelope>'
            )

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        result = probe_winrm("127.0.0.1", timeout=2, port=server.server_port)
        assert result["winrm_identified"] is True
        assert result["product_version"] == "Test WSMan"
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_dns_real_loopback_datagrams():
    stop = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(0.2)

        def respond():
            while not stop.is_set():
                try:
                    raw, address = server.recvfrom(4096)
                except socket.timeout:
                    continue
                query = dns.message.from_wire(raw)
                response = dns.message.make_response(query)
                question = query.question[0]
                if str(question.name) == "unit.test." and question.rdtype == 1:
                    response.answer.append(dns.rrset.from_text("unit.test.", 60, "IN", "A", "192.0.2.1"))
                else:
                    response.set_rcode(dns.rcode.NXDOMAIN)
                server.sendto(response.to_wire(), address)

        thread = threading.Thread(target=respond)
        thread.start()
        try:
            result = collect_dns("unit.test", "127.0.0.1", timeout=2, port=server.getsockname()[1])
            assert result["records"][0]["values"] == ["192.0.2.1"]
            assert result["wildcard_observed"] is False
        finally:
            stop.set()
            thread.join(timeout=3)


def test_extended_graph_readonly_partial_coverage(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        if request.url.path.endswith("roleAssignments"):
            return httpx.Response(403)
        if request.url.path.endswith("users"):
            return httpx.Response(
                200, json={"value": [{"id": "u", "displayName": "test", "onPremisesSyncEnabled": True}]}
            )
        return httpx.Response(200, json={"value": []})

    monkeypatch.setenv("MOCK_GRAPH", "unit-only-token")
    with GraphClient("MOCK_GRAPH", transport=httpx.MockTransport(handler)) as client:
        result = client.collect()
    assert result["users"][0]["synchronized"] is True
    assert result["errors"][0]["status"] == 403
    assert len(requests) == 8
    assert "unit-only-token" not in json.dumps(result)


def test_extended_graph_nextlink_boundary(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"value": [], "@odata.nextLink": "https://evil.test/steal"})

    monkeypatch.setenv("MOCK_GRAPH", "unit-only-token")
    with GraphClient("MOCK_GRAPH", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(SafetyError):
            client.collection("users")


def test_smb_actual_loopback_server(tmp_path):
    from impacket.smbserver import SimpleSMBServer

    from adsentinel.core.auth import Credentials
    from adsentinel.protocols.smb_client import collect_smb

    (tmp_path / "test.txt").write_text("local protocol test")
    service = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=0)
    service.setSMB2Support(True)
    service.addShare("LAB", str(tmp_path), readOnly="yes")
    tcp = service.getServer()
    thread = threading.Thread(target=service.start, daemon=True)
    thread.start()
    try:
        result = collect_smb("127.0.0.1", Credentials(), timeout=3, shares=True, port=tcp.server_address[1])
        assert isinstance(result["smb_signing_required"], bool)
        assert any(s["name"] == "LAB" and s.get("root_listable") for s in result["shares"])
        assert all(s["write_access"] == "not tested" for s in result["shares"])
    finally:
        tcp.shutdown()
        tcp.server_close()
        thread.join(timeout=5)
