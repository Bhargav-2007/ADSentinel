"""Strict YAML settings; authorization can only be granted on the command line."""

from typing import Any

import yaml

from .security import SafetyError, safe_path

ALLOWED = {
    "target": {"domain", "domain_controller", "ldap_port", "ldaps_port", "entra_tenant"},
    "authentication": {"username", "password_env", "graph_token_env", "kerberos", "hashes"},
    "scan": {"mode", "modules"},
    "output": {"directory", "formats"},
    "safety": {
        "require_authorization",
        "allow_credential_extraction",
        "allow_certificate_requests",
        "allow_relay_validation",
        "allow_password_spraying",
        "max_parallel_tasks",
        "timeout_seconds",
    },
}


def load_config(path: str) -> dict[str, Any]:
    source = safe_path(path)
    if source.stat().st_size > 64000:
        raise SafetyError("Configuration exceeds 64 KB")
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) - set(ALLOWED):
        raise SafetyError("Unknown configuration sections")
    for section, values in data.items():
        if not isinstance(values, dict) or set(values) - ALLOWED[section]:
            raise SafetyError(f"Unknown or secret configuration key in {section}")
    safety = data.get("safety", {})
    if safety.get("require_authorization", True) is not True:
        raise SafetyError("Authorization requirements cannot be disabled")
    if any(safety.get(key, False) is not False for key in safety if key.startswith("allow_")):
        raise SafetyError("Intrusive operations cannot be enabled in configuration")
    if data.get("scan", {}).get("mode", "passive") != "passive":
        raise SafetyError("Only passive mode is supported by configuration")
    auth = data.get("authentication", {})
    if auth.get("kerberos", False) or auth.get("hashes", False):
        raise SafetyError("Kerberos and hash authentication are not implemented")
    for key in ("password_env", "graph_token_env", "username"):
        if key in auth and not isinstance(auth[key], str):
            raise SafetyError("Authentication settings must be strings")
    for section, key in (
        ("target", "domain"),
        ("target", "domain_controller"),
        ("target", "entra_tenant"),
        ("output", "directory"),
    ):
        if key in data.get(section, {}) and not isinstance(data[section][key], str):
            raise SafetyError(f"{section}.{key} must be a string")
    for key in ("ldap_port", "ldaps_port"):
        value = data.get("target", {}).get(key, 636)
        if type(value) is not int or not 1 <= value <= 65535:
            raise SafetyError("Invalid configured LDAP port")
    value = safety.get("max_parallel_tasks", 5)
    if type(value) is not int or not 1 <= value <= 32:
        raise SafetyError("max_parallel_tasks must be between 1 and 32")
    formats = data.get("output", {}).get("formats", ["json"])
    if (
        not isinstance(formats, list)
        or not formats
        or any(f not in {"json", "csv", "markdown", "html", "terminal"} for f in formats)
    ):
        raise SafetyError("Unknown output formats")
    return data
