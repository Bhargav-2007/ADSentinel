"""Directed graph analysis over observed relationships, with bounded BFS and DFS."""

from __future__ import annotations

# Only creates GraphML elements; does not parse XML input.
import xml.etree.ElementTree as ET  # nosec B405
from collections import Counter, deque
from typing import Any

from .security import SafetyError

RIGHTS = {
    "MemberOf",
    "GenericAll",
    "GenericWrite",
    "WriteDACL",
    "WriteOwner",
    "AddMember",
    "ForceChangePassword",
    "DCSync",
    "ReadLAPSPassword",
    "ReadGMSAPassword",
    "CanRDP",
    "CanPSRemote",
    "AdminTo",
    "AllowedToDelegate",
    "Owns",
    "AllowedToAct",
    "HasSession",
    "AddAllowedToAct",
    "AddKeyCredentialLink",
    "WriteAccountRestrictions",
    "ExecuteDCOM",
    "ADCSESC1",
    "ADCSESC3",
    "ADCSESC4",
    "CertificateImpersonation",
}
# Structural/individual enrollment edges must never be treated as control of a domain.
STRUCTURAL = {
    "Contains",
    "GPLink",
    "PublishedTo",
    "Enroll",
    "GetChanges",
    "GetChangesAll",
    "GetChangesInFilteredSet",
    "AllExtendedRights",
    "WritePKIEnrollmentFlag",
    "WritePKINameFlag",
}


def analyze(
    edges: list[dict[str, Any]], source: str, destination: str, max_depth: int = 6, all_paths: bool = False
) -> dict[str, Any]:
    return _search(edges, [source], [destination], max_depth, all_paths)


def _search(
    edges: list[dict[str, Any]], sources: list[str], destinations: list[str], max_depth: int, all_paths: bool
) -> dict[str, Any]:
    if not 1 <= max_depth <= 12 or len(edges) > 2000000:
        raise SafetyError("Graph size or depth exceeds safety limits")
    adjacency: dict[str, list[dict[str, Any]]] = {}
    skipped: Counter[str] = Counter()
    for edge in edges:
        if edge.get("relation") not in RIGHTS:
            skipped[str(edge.get("relation"))] += 1
            continue
        adjacency.setdefault(str(edge["source"]).casefold(), []).append(edge)
    goals = {d.casefold() for d in destinations}
    # Shortest search stores one visit per node, bounding dense graphs to O(V+E).
    frontier: deque[tuple[str, list[dict[str, Any]], frozenset[str], str]] = deque(
        (s.casefold(), [], frozenset({s.casefold()}), s) for s in sources if s.casefold() not in goals
    )
    visited = {s.casefold() for s in sources}
    paths: list[dict[str, Any]] = []
    expanded = 0
    max_frontier = 100000
    while frontier:
        node, path, seen, origin = frontier.pop() if all_paths else frontier.popleft()
        expanded += 1
        if expanded > 100000 or len(frontier) > max_frontier:
            raise SafetyError("Graph expansion limit reached; narrow the scope")
        if node in goals:
            paths.append(
                {
                    "source": origin,
                    "target": node,
                    "edges": path,
                    "risk_score": min(100, sum(10 if e["relation"] == "MemberOf" else 30 for e in path)),
                    "remediation": [
                        f"Review and restrict {e['relation']} from {e['source']} to {e['target']}"
                        for e in path
                    ],
                }
            )
            if not all_paths or len(paths) >= 1000:
                break
            continue
        if len(path) >= max_depth:
            continue
        for edge in adjacency.get(node, []):
            nxt = str(edge["target"]).casefold()
            if nxt in seen or (not all_paths and nxt in visited):
                continue
            visited.add(nxt)
            frontier.append((nxt, path + [edge], seen | {nxt}, origin))
    paths.sort(key=lambda p: (len(p["edges"]), p["source"], str(p["edges"])))
    frequency = Counter(str(e["target"]) for p in paths for e in p["edges"][:-1])
    intermediate_sets = [{str(e["target"]) for e in p["edges"][:-1]} for p in paths]
    common = sorted(set.intersection(*intermediate_sets)) if intermediate_sets else []
    return {
        "source": sources[0] if len(sources) == 1 else sources,
        "target": destinations[0] if len(destinations) == 1 else destinations,
        "paths": paths,
        "chokepoints": dict(frequency.most_common()),
        "common_intermediates": common,
        "expanded_states": expanded,
        "path_limit": 1000,
        "truncated": all_paths and len(paths) >= 1000,
        "skipped_relationship_types": dict(sorted(skipped.items())),
        "interpretation": "Candidate paths from supplied relationships; effective access requires review. "
        "Common intermediates describe returned paths, not whole-graph dominators.",
    }


def resolve_nodes(data: dict[str, Any], name: str) -> list[str]:
    matches = []
    for node in data.get("nodes", []):
        aliases = {
            node["id"].casefold(),
            str(node.get("name", "")).casefold(),
            str(node.get("name", "")).split("@")[0].casefold(),
            str(node.get("properties", {}).get("samaccountname", "")).casefold(),
        }
        if name.casefold() in aliases:
            matches.append(node["id"])
    if not data.get("nodes"):
        return [name]
    if not matches:
        raise SafetyError("No graph object matches: " + name)
    return sorted(matches)


def analyze_graph(
    data: dict[str, Any],
    source: str | None,
    destination: str | None,
    max_depth: int = 6,
    all_paths: bool = False,
) -> dict[str, Any]:
    nodes = data.get("nodes", [])
    targets = (
        resolve_nodes(data, destination) if destination else [n["id"] for n in nodes if n.get("high_value")]
    )
    if not targets:
        raise SafetyError("Specify --to or provide high-value graph nodes")
    if source:
        sources = resolve_nodes(data, source)
        if len(sources) > 1:
            raise SafetyError("Ambiguous source; use the full object identifier or qualified name")
    else:
        # Exclude users already members of privileged groups from automatic low-privilege path searches.
        privileged = {n["id"].casefold() for n in nodes if n.get("high_value")}
        reverse: dict[str, list[str]] = {}
        for edge in data.get("edges", []):
            if edge["relation"] == "MemberOf":
                reverse.setdefault(edge["target"].casefold(), []).append(edge["source"].casefold())
        queue = deque(privileged)
        while queue:
            for parent in reverse.get(queue.popleft(), []):
                if parent not in privileged:
                    privileged.add(parent)
                    queue.append(parent)
        sources = [
            n["id"]
            for n in nodes
            if n.get("type") == "User"
            and n["id"].casefold() not in privileged
            and n.get("properties", {}).get("enabled") is not False
        ]
        if not sources:
            raise SafetyError("No non-privileged user sources; specify --from")
    result = _search(data.get("edges", []), sources, targets, max_depth, all_paths)
    names = {n["id"].casefold(): n.get("name", n["id"]) for n in nodes}
    for path in result["paths"]:
        path["source_name"] = names.get(path["source"].casefold(), path["source"])
        path["target_name"] = names.get(path["target"].casefold(), path["target"])
    result["high_value_targets"] = [n["id"] for n in nodes if n.get("high_value")]
    return result


def graphml(data: dict[str, Any]) -> str:
    ns = "http://graphml.graphdrawing.org/xmlns"
    ET.register_namespace("", ns)
    root = ET.Element(f"{{{ns}}}graphml")
    for key, domain in (("name", "node"), ("type", "node"), ("relation", "edge")):
        ET.SubElement(
            root, f"{{{ns}}}key", {"id": key, "for": domain, "attr.name": key, "attr.type": "string"}
        )
    graph = ET.SubElement(root, f"{{{ns}}}graph", {"id": "ADSentinel", "edgedefault": "directed"})
    nodes = {n["id"]: n for n in data.get("nodes", [])}
    for edge in data.get("edges", []):
        for side in ("source", "target"):
            nodes.setdefault(edge[side], {"id": edge[side], "name": edge[side], "type": "Unresolved"})
    for oid, node in sorted(nodes.items()):
        element = ET.SubElement(graph, f"{{{ns}}}node", {"id": oid})
        for key in ("name", "type"):
            ET.SubElement(element, f"{{{ns}}}data", {"key": key}).text = str(node.get(key, ""))
    for index, edge in enumerate(data.get("edges", [])):
        element = ET.SubElement(
            graph, f"{{{ns}}}edge", {"id": f"e{index}", "source": edge["source"], "target": edge["target"]}
        )
        ET.SubElement(element, f"{{{ns}}}data", {"key": "relation"}).text = edge["relation"]
    return ET.tostring(root, encoding="unicode", xml_declaration=True)
