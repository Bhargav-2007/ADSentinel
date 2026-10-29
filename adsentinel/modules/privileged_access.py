"""Group expansion and privilege classification used by ACL and hygiene checks."""

from collections import defaultdict, deque
from typing import Any


def privileged_principals(data: dict[str, Any]) -> set[str]:
    privileged = {
        n["id"] for n in data.get("nodes", []) if n.get("high_value") and n.get("type") in {"Group", "User"}
    }
    privileged |= {
        n["id"]
        for n in data.get("nodes", [])
        if n.get("type") == "Group"
        and n["id"].rsplit("-", 1)[-1]
        in {"516", "517", "520", "521", "526", "527", "548", "549", "550", "551"}
    }
    reverse: dict[str, list[str]] = defaultdict(list)
    for edge in data.get("edges", []):
        if edge.get("relation") == "MemberOf":
            reverse[edge["target"]].append(edge["source"])
    queue = deque(privileged)
    while queue:
        for member in reverse.get(queue.popleft(), []):
            if member not in privileged:
                privileged.add(member)
                queue.append(member)
    return privileged
