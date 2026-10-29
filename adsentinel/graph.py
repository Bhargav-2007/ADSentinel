"""Bounded directed relationship analysis; never executes attack paths."""

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
    "Enroll",
    "GPLink",
    "Owns",
}


def analyze(
    edges: list[dict[str, Any]], source: str, destination: str, max_depth: int = 6, all_paths: bool = False
) -> dict[str, Any]:
    if not 1 <= max_depth <= 12 or len(edges) > 100000:
        raise SafetyError("Graph size or depth exceeds safety limits")
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        if edge.get("relation") not in RIGHTS:
            raise SafetyError("Unknown graph relationship")
        adjacency.setdefault(str(edge["source"]).casefold(), []).append(edge)
    queue: deque[tuple[str, list[dict[str, Any]], set[str]]] = deque(
        [(source.casefold(), [], {source.casefold()})]
    )
    paths: list[dict[str, Any]] = []
    expanded = 0
    while queue:
        node, path, seen = queue.popleft()
        expanded += 1
        if expanded > 50000:
            raise SafetyError("Graph expansion limit reached; narrow the scope")
        if node == destination.casefold():
            paths.append(
                {
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
        if len(path) >= max_depth:
            continue
        for edge in adjacency.get(node, []):
            nxt = str(edge["target"]).casefold()
            if nxt not in seen:
                queue.append((nxt, path + [edge], seen | {nxt}))
    counts = Counter(e["target"] for p in paths for e in p["edges"][:-1])
    return {
        "source": source,
        "target": destination,
        "paths": paths,
        "chokepoints": dict(counts.most_common()),
        "path_limit": 1000,
        "truncated": all_paths and len(paths) >= 1000,
        "interpretation": "Candidate paths from supplied relationships; effective access requires review.",
    }
