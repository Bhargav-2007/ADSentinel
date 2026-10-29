"""Reproduce public-data checks and measure actual import/graph runtime locally.

This never connects to assessment targets or uploads data. It checks independent
raw-archive relationships before recording validation metrics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
import tracemalloc
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from adsentinel import __version__
from adsentinel.graph import analyze_graph
from adsentinel.importers.bloodhound import import_bloodhound
from adsentinel.modules.adcs import candidate_edges
from adsentinel.rules import evaluate
from adsentinel.security import protected_write


def validate(dataset: str) -> dict:
    tracemalloc.start()
    start = time.perf_counter()
    graph = import_bloodhound(dataset)
    import_seconds = time.perf_counter() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    expected_aces = set()
    expected_nodes = set()
    raw_counts = Counter()
    with zipfile.ZipFile(dataset) as archive:
        for name in archive.namelist():
            if not name.endswith(".json"):
                continue
            document = json.loads(archive.read(name))
            raw_counts[document["meta"]["type"]] += len(document["data"])
            for row in document["data"]:
                if row.get("IsDeleted"):
                    continue
                oid = row["ObjectIdentifier"].upper()
                expected_nodes.add(oid)
                for ace in row.get("Aces", []):
                    expected_aces.add(
                        (
                            ace["PrincipalSID"].upper(),
                            oid,
                            {"WriteDacl": "WriteDACL"}.get(ace["RightName"], ace["RightName"]),
                        )
                    )
    actual_edges = {(e["source"], e["target"], e["relation"]) for e in graph["edges"]}
    missing_aces = expected_aces - actual_edges
    missing_nodes = expected_nodes - {n["id"] for n in graph["nodes"]}
    graph["edges"].extend(candidate_edges(graph))
    findings, _ = evaluate(graph, ["adcs", "acl", "dcsync-check"])
    adcs = {(f.rule_id, f.evidence.get("template_name")) for f in findings if f.module == "adcs"}
    controls = [
        ("ADS-ESC1", "ESC1SMARTCARD@PHANTOM.CORP", True),
        ("ADS-ESC1", "ESC1@PHANTOM.CORP", False),
        ("ADS-ESC1", "SMARTCARDLOGON@PHANTOM.CORP", False),
        ("ADS-ESC3", "ESC3-SELF2@PHANTOM.CORP", True),
        ("ADS-ESC4", "ABUSABLETEMPLATE@PHANTOM.CORP", True),
    ]
    control_results = [
        {"rule": code, "object": name, "expected": expected, "actual": (code, name) in adcs}
        for code, name, expected in controls
    ]
    paths = analyze_graph(graph, "SVC_PAYADMIN@PHANTOM.CORP", "DOMAIN ADMINS@PHANTOM.CORP")
    scale_results = []
    for copies in (1, 10, 25):
        nodes = [
            {**node, "id": f"{i}:" + node["id"], "name": f"{i}:" + node["name"]}
            for i in range(copies)
            for node in graph["nodes"]
        ]
        edges = [
            {**edge, "source": f"{i}:" + edge["source"], "target": f"{i}:" + edge["target"]}
            for i in range(copies)
            for edge in graph["edges"]
        ]
        source_id = "0:" + paths["paths"][0]["source"]
        target_id = "0:" + paths["paths"][0]["edges"][-1]["target"]
        began = time.perf_counter()
        result = analyze_graph({"nodes": nodes, "edges": edges}, source_id, target_id)
        scale_results.append(
            {
                "copies": copies,
                "nodes": len(nodes),
                "edges": len(edges),
                "seconds": round(time.perf_counter() - began, 6),
                "paths": len(result["paths"]),
            }
        )
    fp = sum(not c["expected"] and c["actual"] for c in control_results)
    fn = sum(c["expected"] and not c["actual"] for c in control_results)
    return {
        "version": __version__,
        "date": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "dataset_sha256": hashlib.sha256(Path(dataset).read_bytes()).hexdigest(),
        "raw_collection_counts": dict(raw_counts),
        "unique_collected_objects": len(expected_nodes),
        "graph_nodes": len(graph["nodes"]),
        "graph_edges": len(graph["edges"]),
        "unique_raw_ace_relationships": len(expected_aces),
        "missing_ace_relationships": len(missing_aces),
        "missing_objects": len(missing_nodes),
        "import_seconds_with_tracemalloc": round(import_seconds, 6),
        "peak_python_allocation_bytes": peak,
        "duplicates": graph["provenance"]["duplicates"],
        "issues": dict(Counter(i["reason"] for i in graph["provenance"]["issues"])),
        "findings_by_rule": dict(Counter(f.rule_id for f in findings)),
        "adcs_controls": control_results,
        "control_true_positives": sum(c["expected"] and c["actual"] for c in control_results),
        "control_true_negatives": sum(not c["expected"] and not c["actual"] for c in control_results),
        "control_false_positives": fp,
        "control_false_negatives": fn,
        "known_path": paths["paths"][0],
        "scaling": scale_results,
        "scope_of_accuracy_claim": "Five reviewed ADCS controls and raw object/ACE preservation only; not whole-dataset ground truth.",
        "pass": not missing_aces and not missing_nodes and fp == 0 and fn == 0 and bool(paths["paths"]),
        "live_lab_validation": "blocked: authorized source interface unavailable; no target contact",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="datasets/public/bloodhound-sample-data/ad_sampledata.zip")
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    result = validate(arguments.dataset)
    protected_write(arguments.output, json.dumps(result, indent=2, sort_keys=True))
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "pass",
                    "graph_nodes",
                    "graph_edges",
                    "missing_ace_relationships",
                    "control_false_positives",
                    "control_false_negatives",
                    "scaling",
                )
            },
            indent=2,
        )
    )
    raise SystemExit(0 if result["pass"] else 1)
