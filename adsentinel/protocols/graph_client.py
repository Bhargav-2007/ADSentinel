"""Read-only Microsoft Graph inventory and permission analysis with partial-error coverage."""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from ..collectors import check_graph_link
from ..security import SafetyError

SELECTS = {
    "users": "id,displayName,userPrincipalName,onPremisesSyncEnabled,accountEnabled",
    "groups": "id,displayName,securityEnabled,onPremisesSyncEnabled",
    "applications": "id,displayName,appId,passwordCredentials,keyCredentials,requiredResourceAccess",
    "servicePrincipals": "id,displayName,appId,appRoles,oauth2PermissionScopes",
    "roleManagement/directory/roleDefinitions": "id,displayName,isBuiltIn,rolePermissions",
    "roleManagement/directory/roleAssignments": "id,principalId,roleDefinitionId,directoryScopeId",
    "oauth2PermissionGrants": "id,clientId,consentType,principalId,resourceId,scope",
    "organization": "id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime",
}
SENSITIVE = {
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Application.ReadWrite.OwnedBy",
    "Directory.AccessAsUser.All",
}
PRIVILEGED_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Hybrid Identity Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Privileged Authentication Administrator",
}


class GraphClient:
    def __init__(self, token_env: str, timeout: int = 30, transport: httpx.BaseTransport | None = None):
        token = os.environ.get(token_env)
        if not token:
            raise SafetyError("Graph token environment variable is missing")
        self.headers = {"Authorization": "Bearer " + token}
        self.client = httpx.Client(
            timeout=timeout, follow_redirects=False, trust_env=False, transport=transport
        )
        self.started = time.monotonic()
        self.errors: list[dict[str, Any]] = []

    def __enter__(self) -> GraphClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.client.close()
        self.headers.clear()

    def collection(self, resource: str) -> list[dict[str, Any]]:
        if resource not in SELECTS:
            pieces = resource.split("/")
            if len(pieces) != 3 or pieces[0] != "servicePrincipals" or pieces[2] != "appRoleAssignments":
                raise SafetyError("Graph resource is not allowlisted")
            try:
                uuid.UUID(pieces[1])
            except ValueError as exc:
                raise SafetyError("Invalid service principal identifier") from exc
        url: str | None = "https://graph.microsoft.com/v1.0/" + resource
        initial_params = {}
        if resource in {"users", "groups", "applications", "servicePrincipals"}:
            initial_params["$top"] = "100"
        if resource in SELECTS and resource != "oauth2PermissionGrants":
            initial_params["$select"] = SELECTS[resource]
        params: dict[str, str] | None = initial_params
        rows: list[dict[str, Any]] = []
        visited: set[str] = set()
        while url:
            if time.monotonic() - self.started > 3600:
                raise SafetyError("Graph whole-run deadline reached")
            check_graph_link(url)
            if url in visited or len(visited) >= 1000:
                raise SafetyError("Graph pagination cycle or page limit exceeded")
            visited.add(url)
            with self.client.stream("GET", url, params=params, headers=self.headers) as response:
                if response.status_code != 200:
                    self.errors.append(
                        {
                            "resource": resource,
                            "status": response.status_code,
                            "message": "Read denied, throttled or unavailable; coverage incomplete",
                        }
                    )
                    break
                raw = bytearray()
                for block in response.iter_bytes():
                    raw.extend(block)
                    if len(raw) > 16_000_000:
                        raise SafetyError("Graph page exceeds 16 MB")
                import json

                body = json.loads(raw)
            if not isinstance(body.get("value"), list):
                raise SafetyError("Graph response is not a collection")
            rows.extend(item for item in body["value"] if isinstance(item, dict))
            if len(rows) > 100000:
                raise SafetyError("Graph object limit exceeded")
            url = body.get("@odata.nextLink")
            if url is not None and not isinstance(url, str):
                raise SafetyError("Invalid Graph nextLink")
            params = None
        return rows

    def collect(self) -> dict[str, Any]:
        raw = {resource: self.collection(resource) for resource in SELECTS}
        result: dict[str, Any] = {
            "source": "Microsoft Graph read-only inventory and direct permission assignments",
            "users": [],
            "groups": [],
            "applications": [],
            "service_principals": [],
            "roles": [],
            "role_assignments": [],
            "consent_grants": [],
            "organization": [],
            "errors": self.errors,
        }

        def inventory(row: dict[str, Any]) -> dict[str, Any]:
            return {"id": row["id"], "name": row.get("displayName")}

        definitions = {r["id"]: r for r in raw["roleManagement/directory/roleDefinitions"]}
        privileged = set()
        for row in raw["roleManagement/directory/roleAssignments"]:
            definition = definitions.get(row.get("roleDefinitionId"), {})
            role = definition.get("displayName", row.get("roleDefinitionId"))
            result["role_assignments"].append(
                {
                    **inventory(row),
                    "principal_id": row.get("principalId"),
                    "role": role,
                    "scope": row.get("directoryScopeId"),
                }
            )
            if role in PRIVILEGED_ROLES:
                privileged.add(row.get("principalId"))
        for row in raw["users"]:
            user = {
                **inventory(row),
                "synchronized": row.get("onPremisesSyncEnabled"),
                "enabled": row.get("accountEnabled"),
            }
            if row.get("id") in privileged and row.get("onPremisesSyncEnabled") is True:
                user["hybrid_privileged"] = True
            result["users"].append(user)
        result["groups"] = [inventory(r) for r in raw["groups"]]
        result["roles"] = [{**inventory(r), "built_in": r.get("isBuiltIn")} for r in definitions.values()]
        resources = {r["id"]: r for r in raw["servicePrincipals"]}
        for row in raw["servicePrincipals"]:
            principal = {**inventory(row), "app_id": row.get("appId"), "sensitive_permissions": []}
            try:
                assignments = self.collection("servicePrincipals/" + row["id"] + "/appRoleAssignments")
            except (ValueError, SafetyError):
                self.errors.append(
                    {"resource": "servicePrincipals", "message": "Invalid service principal identifier"}
                )
                assignments = []
            for grant in assignments:
                roles = resources.get(grant.get("resourceId"), {}).get("appRoles", [])
                role = next((r.get("value") for r in roles if r.get("id") == grant.get("appRoleId")), None)
                if role in SENSITIVE:
                    principal["sensitive_permissions"].append(
                        {
                            "permission": role,
                            "grant_id": grant.get("id"),
                            "resource_id": grant.get("resourceId"),
                        }
                    )
            result["service_principals"].append(principal)
        for row in raw["applications"]:
            app = {**inventory(row), "app_id": row.get("appId"), "expiry_metadata": []}
            for key in ("passwordCredentials", "keyCredentials"):
                for credential in row.get(key, []):
                    end = credential.get("endDateTime")
                    if end:
                        expires = datetime.fromisoformat(end)
                        app["expiry_metadata"].append(
                            {"kind": key, "expires": end, "expired": expires < datetime.now(timezone.utc)}
                        )
            app["expired_credential"] = any(c["expired"] for c in app["expiry_metadata"])
            result["applications"].append(app)
        for grant in raw["oauth2PermissionGrants"]:
            result["consent_grants"].append(
                {
                    "id": grant["id"],
                    "client_id": grant.get("clientId"),
                    "consent_type": grant.get("consentType"),
                    "scopes": grant.get("scope", "").split(),
                    "resource_id": grant.get("resourceId"),
                }
            )
        result["organization"] = [
            {
                **inventory(r),
                "sync_enabled": r.get("onPremisesSyncEnabled"),
                "last_sync": r.get("onPremisesLastSyncDateTime"),
            }
            for r in raw["organization"]
        ]
        result["limitations"] = [
            "Direct role assignments only; group-based and PIM eligible privilege are not resolved.",
            "Connect/PTA/PHS host configuration and MFA coverage are not inferred from sync metadata.",
        ]
        return result
