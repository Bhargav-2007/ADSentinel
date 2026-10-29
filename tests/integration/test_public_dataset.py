"""Tests run on the maintainers' actual pinned archive, not a generated scan result."""

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from adsentinel.graph import analyze_graph
from adsentinel.importers.bloodhound import import_bloodhound
from adsentinel.modules.adcs import candidate_edges
from adsentinel.modules.runner import run_module
from adsentinel.rules import MODULES, evaluate

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "datasets/public/bloodhound-sample-data/ad_sampledata.zip"


@pytest.fixture(scope="module")
def public_graph():
    graph = import_bloodhound(DATASET)
    graph["edges"].extend(candidate_edges(graph))
    return graph


def test_pinned_source_checksum():
    manifest = json.loads(DATASET.with_name("provenance.json").read_text())
    assert hashlib.sha256(DATASET.read_bytes()).hexdigest() == manifest["sha256"]


def test_actual_objects_and_acl_relationships(public_graph):
    identifiers = set()
    expected_aces = set()
    with zipfile.ZipFile(DATASET) as archive:
        for name in archive.namelist():
            if not name.endswith(".json"):
                continue
            document = json.loads(archive.read(name))
            for obj in document["data"]:
                if obj.get("IsDeleted"):
                    continue
                oid = obj["ObjectIdentifier"].upper()
                identifiers.add(oid)
                for ace in obj.get("Aces", []):
                    relation = {"WriteDacl": "WriteDACL"}.get(ace["RightName"], ace["RightName"])
                    expected_aces.add((ace["PrincipalSID"].upper(), oid, relation))
    actual_nodes = {n["id"] for n in public_graph["nodes"]}
    actual_edges = {(e["source"], e["target"], e["relation"]) for e in public_graph["edges"]}
    assert identifiers <= actual_nodes
    assert expected_aces <= actual_edges
    assert len(public_graph["domains"]) == 3
    assert len(public_graph["templates"]) == 106
    assert len(public_graph["cas"]) == 4


def test_known_adcs_positive_and_negative_controls(public_graph):
    findings, _ = evaluate(public_graph, ["adcs"])
    cases = {(f.rule_id, f.evidence.get("template_name")) for f in findings}
    assert ("ADS-ESC1", "ESC1SMARTCARD@PHANTOM.CORP") in cases
    assert ("ADS-ESC1", "ESC1@PHANTOM.CORP") not in cases
    assert ("ADS-ESC1", "SMARTCARDLOGON@PHANTOM.CORP") not in cases
    assert ("ADS-ESC3", "ESC3-SELF2@PHANTOM.CORP") in cases
    assert ("ADS-ESC4", "ABUSABLETEMPLATE@PHANTOM.CORP") in cases
    assert len({f.id for f in findings}) == len(findings)


def test_actual_acl_path_and_certificate_candidate_path(public_graph):
    result = analyze_graph(public_graph, "SVC_PAYADMIN@PHANTOM.CORP", "DOMAIN ADMINS@PHANTOM.CORP")
    assert [e["relation"] for e in result["paths"][0]["edges"]] == ["AddMember"]
    known = {(e["source"], e["target"], e["relation"]) for e in public_graph["edges"]}
    assert all((e["source"], e["target"], e["relation"]) in known for e in result["paths"][0]["edges"])
    assert any(e["relation"] == "ADCSESC1" for e in public_graph["edges"])


@pytest.mark.parametrize("module", MODULES)
def test_module_result_contract_with_public_collector_data(public_graph, module):
    result = run_module(module, public_graph)
    assert result.module == module
    assert result.completed_at >= result.started_at
    for finding in result.findings:
        assert finding.id and finding.description and finding.evidence_references
        assert finding.detection and finding.remediation and finding.references and finding.mitre
