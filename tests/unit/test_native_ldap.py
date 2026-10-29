"""Actual LDAP attribute shapes and binary-policy metadata, independent of fake risk flags."""

import struct

from adsentinel.protocols.ldap_client import filetime_seconds, normalize_records


def test_native_ldap_normalization_from_wire_attribute_shapes():
    domain_sid = b"\x01\x04" + (5).to_bytes(6, "big") + struct.pack("<IIII", 21, 100, 200, 300)
    user_sid = b"\x01\x05" + (5).to_bytes(6, "big") + struct.pack("<IIIII", 21, 100, 200, 300, 1100)
    group_sid = b"\x01\x05" + (5).to_bytes(6, "big") + struct.pack("<IIIII", 21, 100, 200, 300, 513)
    records = [
        {
            "dn": "DC=unit,DC=test",
            "attributes": {
                "objectClass": ["top", "domainDNS"],
                "objectSid": [domain_sid],
                "minPwdLength": [8],
                "pwdHistoryLength": [10],
                "pwdProperties": [1],
            },
            "raw_attributes": {"objectSid": [domain_sid]},
        },
        {
            "dn": "CN=u,DC=unit,DC=test",
            "attributes": {
                "objectClass": ["top", "person", "user"],
                "sAMAccountName": ["u"],
                "userAccountControl": [4194304],
                "servicePrincipalName": ["HTTP/unit.test"],
                "primaryGroupID": [513],
            },
            "raw_attributes": {"objectSid": [user_sid]},
        },
        {
            "dn": "CN=g,DC=unit,DC=test",
            "attributes": {
                "objectClass": ["top", "group"],
                "sAMAccountName": ["Domain Users"],
                "member": ["CN=u,DC=unit,DC=test"],
            },
            "raw_attributes": {"objectSid": [group_sid]},
        },
    ]
    data = normalize_records(records, {"defaultNamingContext": "DC=unit,DC=test"})
    assert data["users"][0]["preauth_required"] is False
    assert data["users"][0]["has_spn"] is True
    assert data["password_policies"][0]["minimum_length"] == 8
    assert data["domains"][0]["id"] == "S-1-5-21-100-200-300"
    assert any(e["source"].endswith("-1100") and e["target"].endswith("-513") for e in data["edges"])


def test_filetime_conversion_and_unknown():
    assert filetime_seconds(116444736000000000) == 0
    assert filetime_seconds(0) is None
    assert filetime_seconds("not-a-time") is None
