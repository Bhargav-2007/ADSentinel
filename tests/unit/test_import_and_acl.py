import json
import struct
import uuid
import zipfile
from pathlib import Path

import pytest

from adsentinel.graph import analyze_graph, graphml
from adsentinel.importers.bloodhound import import_bloodhound
from adsentinel.protocols.security_descriptor import ace_rights, descriptor_edges, parse_descriptor, sid_at
from adsentinel.security import SafetyError


def collection(rows, kind="users"):
    return {"meta": {"version": 6, "type": kind, "count": len(rows)}, "data": rows}


def test_duplicate_objects_merge_relationships(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    first = {"ObjectIdentifier": "G1", "Properties": {"name": "g"}, "Members": [{"ObjectIdentifier": "U1"}]}
    second = {**first, "Members": [{"ObjectIdentifier": "U2"}]}
    Path("a.json").write_text(json.dumps(collection([first], "groups")))
    Path("b.json").write_text(json.dumps(collection([second], "groups")))
    graph = import_bloodhound(".")
    assert graph["provenance"]["duplicates"] == 1
    assert {(e["source"], e["target"]) for e in graph["edges"]} == {("U1", "G1"), ("U2", "G1")}


@pytest.mark.parametrize("member", ["../escape.json", "/absolute.json", "x:stream.json", r"..\escape.json"])
def test_archive_traversal_rejected(tmp_path, monkeypatch, member):
    monkeypatch.chdir(tmp_path)
    with zipfile.ZipFile("bad.zip", "w") as archive:
        archive.writestr(member, json.dumps(collection([])))
    with pytest.raises(SafetyError):
        import_bloodhound("bad.zip")


def test_bad_objects_and_unknown_edges_are_recorded(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("input.json").write_text(
        json.dumps(
            collection(
                [
                    None,
                    {"Properties": {}},
                    {"ObjectIdentifier": "U", "Properties": {"name": "u"}, "Aces": None},
                    {
                        "ObjectIdentifier": "V",
                        "Properties": {"name": "v"},
                        "Aces": [{"PrincipalSID": "U", "RightName": "FutureRight"}],
                    },
                ]
            )
        )
    )
    graph = import_bloodhound("input.json")
    assert len(graph["provenance"]["issues"]) == 3
    assert graph["edges"][0]["relation"] == "FutureRight"
    assert not analyze_graph(graph, "U", "V")["paths"]


def test_graphml_and_disambiguation():
    graph = {
        "nodes": [
            {"id": "u", "type": "User", "name": "U@A"},
            {"id": "da", "type": "Group", "name": "DOMAIN ADMINS@A", "high_value": True},
        ],
        "edges": [{"source": "u", "target": "da", "relation": "GenericAll"}],
    }
    assert analyze_graph(graph, "U@A", "DOMAIN ADMINS")["paths"]
    xml = graphml(graph)
    assert 'edgedefault="directed"' in xml and "GenericAll" in xml
    graph["nodes"].append({"id": "u2", "name": "U@B", "type": "User"})
    with pytest.raises(SafetyError):
        analyze_graph(graph, "U", "DOMAIN ADMINS")


def binary_sid(rid=1100):
    return b"\x01\x02" + (5).to_bytes(6, "big") + struct.pack("<II", 21, rid)


def descriptor(allow=True, mask=0x100, guid="1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", flags=0):
    body = struct.pack("<II", mask, 1) + uuid.UUID(guid).bytes_le + binary_sid()
    ace = struct.pack("<BBH", 5 if allow else 6, flags, 4 + len(body)) + body
    acl = struct.pack("<BBHHH", 4, 0, 8 + len(ace), 1, 0) + ace
    return struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20) + acl


def test_real_binary_descriptor_layout():
    assert sid_at(binary_sid())[0] == "S-1-5-21-1100"
    sd = parse_descriptor(descriptor())
    assert ace_rights(sd["aces"][0]) == {"GetChangesAll"}
    assert descriptor_edges(sd, "DOMAIN")[0]["relation"] == "GetChangesAll"
    denied = parse_descriptor(descriptor(False))
    assert descriptor_edges(denied, "DOMAIN") == []
    inherit_only = parse_descriptor(descriptor(flags=8))
    assert not descriptor_edges(inherit_only, "DOMAIN")


@pytest.mark.parametrize("data", [b"", b"\x01" * 20, descriptor()[:-3]])
def test_truncated_descriptor_rejected(data):
    with pytest.raises(SafetyError):
        parse_descriptor(data)
