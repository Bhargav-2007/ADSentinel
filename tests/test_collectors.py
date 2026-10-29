import httpx
import pytest

from adsentinel.collectors import check_graph_link, collect_graph, normalize_ldap
from adsentinel.security import SafetyError


@pytest.mark.parametrize(
    "url",
    [
        "http://graph.microsoft.com/v1.0/users",
        "https://evil.test/v1.0/users",
        "https://graph.microsoft.com@evil.test/v1.0/users",
        "https://graph.microsoft.com:444/v1.0/users",
    ],
)
def test_graph_blocks_token_exfiltration(url):
    with pytest.raises(SafetyError):
        check_graph_link(url)


def test_graph_paging_mock(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["authorization"] == "Bearer mock-token"
        if request.url.path.endswith("users") and "page=2" not in str(request.url):
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "1", "displayName": "u"}],
                    "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page=2",
                },
            )
        return httpx.Response(200, json={"value": []})

    original = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs)
    )
    monkeypatch.setenv("MOCK_GRAPH", "mock-token")
    data = collect_graph("MOCK_GRAPH")
    assert data["users"][0]["id"] == "1"
    assert len(requests) == 4
    assert all(r.method == "GET" for r in requests)


def test_graph_rejects_malicious_nextlink(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"value": [], "@odata.nextLink": "https://evil.test/steal"})

    original = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs)
    )
    monkeypatch.setenv("MOCK_GRAPH", "mock-token")
    with pytest.raises(SafetyError):
        collect_graph("MOCK_GRAPH")


def test_ldap_normalization():
    records = [
        {
            "dn": "CN=u,DC=corp,DC=lab",
            "attributes": {
                "sAMAccountName": "u",
                "objectClass": ["user"],
                "userAccountControl": 4194304,
                "memberOf": ["CN=g,DC=corp,DC=lab"],
            },
        },
        {"dn": "CN=g,DC=corp,DC=lab", "attributes": {"sAMAccountName": "g", "objectClass": ["group"]}},
    ]
    data = normalize_ldap(records)
    assert data["users"][0]["preauth_required"] is False
    assert data["edges"][0] == {"source": "u", "target": "g", "relation": "MemberOf"}


def test_local_mock_ldap_service():
    from ldap3 import MOCK_SYNC, Connection, Server

    connection = Connection(Server("mock"), client_strategy=MOCK_SYNC)
    connection.strategy.add_entry(
        "CN=u,DC=corp,DC=lab",
        {"objectClass": ["person", "user"], "sAMAccountName": "u", "userAccountControl": 4194304},
    )
    assert connection.bind()
    connection.search(
        "DC=corp,DC=lab",
        "(objectClass=user)",
        attributes=["objectClass", "sAMAccountName", "userAccountControl"],
    )
    data = normalize_ldap(connection.response)
    assert data["users"][0]["id"] == "u"
    connection.unbind()


def test_ldap_missing_uac_is_unknown():
    result = normalize_ldap(
        [
            {
                "dn": "CN=u,DC=corp,DC=lab",
                "attributes": {"sAMAccountName": "u", "objectClass": ["user"], "userAccountControl": []},
            }
        ]
    )
    assert "preauth_required" not in result["users"][0]


def test_ldap_collector_safe_connection(monkeypatch):
    import ssl

    import ldap3

    from adsentinel.collectors import collect_ldap

    calls = {}

    class Standard:
        def paged_search(self, *args, **kwargs):
            calls["query"] = args
            calls["attributes"] = kwargs["attributes"]
            return iter(
                [
                    {
                        "type": "searchResEntry",
                        "dn": "CN=u,DC=corp,DC=lab",
                        "attributes": {
                            "sAMAccountName": ["u"],
                            "objectClass": ["user"],
                            "userAccountControl": ["4194304"],
                        },
                    }
                ]
            )

    class Extension:
        standard = Standard()

    class FakeConnection:
        extend = Extension()
        result = {"result": 0}

        def __init__(self, server, **kwargs):
            calls["connection"] = kwargs

        def bind(self):
            return True

        def unbind(self):
            calls["unbound"] = True

    def server(host, **kwargs):
        calls["server"] = kwargs
        return host

    monkeypatch.setattr(ldap3, "Server", server)
    monkeypatch.setattr(ldap3, "Connection", FakeConnection)
    monkeypatch.setenv("MOCK_PASSWORD", "mock-value")
    result = collect_ldap("corp.lab", "dc.corp.lab", "u@corp.lab", "MOCK_PASSWORD")
    assert result["users"][0]["preauth_required"] is False
    assert calls["server"]["use_ssl"] is True
    assert calls["server"]["tls"].validate == ssl.CERT_REQUIRED
    assert calls["connection"]["read_only"] is True
    assert calls["connection"]["auto_referrals"] is False
    assert "msDS-ManagedPassword" not in calls["attributes"]
    assert calls["unbound"]
