import struct

import pytest

from adsentinel.core.auth import Credentials
from adsentinel.core.authorization import Scope
from adsentinel.protocols.gpo_client import policy_metadata, registry_policy
from adsentinel.security import SafetyError


def test_registry_pol_actual_binary_layout():
    def text(value):
        return value.encode("utf-16-le") + b"\x00\x00"

    raw = (
        b"PReg"
        + struct.pack("<I", 1)
        + b"[\x00"
        + text(r"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")
    )
    raw += b";\x00" + text("EnableScriptBlockLogging") + b";\x00" + struct.pack("<I", 4)
    raw += b";\x00" + struct.pack("<I", 4) + b";\x00" + struct.pack("<I", 0) + b"]\x00"
    parsed = registry_policy(raw)
    assert parsed[0]["value_name"] == "EnableScriptBlockLogging"
    assert parsed[0]["value"] == 0
    with pytest.raises(SafetyError):
        registry_policy(raw[:-2])


def test_gpp_credential_presence_without_disclosure():
    # An intentionally non-secret test value verifies that no raw attribute is retained.
    result = policy_metadata("Groups.xml", b'<Groups><Group cpassword="unit-test-marker"/></Groups>')
    assert result["credential_attribute_present"]
    assert "unit-test-marker" not in str(result)
    assert (
        policy_metadata("scripts.ini", b"[Startup]\n0CmdLine=test.cmd\n0Parameters=\n")["script_entry_count"]
        == 2
    )


def test_credentials_repr_never_contains_secret():
    assert "unit-only-marker" not in repr(Credentials("u", "unit.test", "unit-only-marker"))


def test_scope_rejects_targets_before_source_check():
    scope = Scope("UNIT", "127.0.0.1", "unit.test", frozenset({"127.0.0.1"}), "2020-01-01", "2099-01-01")
    with pytest.raises(SafetyError, match="allowlist"):
        scope.preflight(["192.0.2.1"], "unit.test")
    with pytest.raises(SafetyError, match="Domain"):
        scope.preflight(["127.0.0.1"], "other.test")
    with pytest.raises(SafetyError, match="maintenance"):
        scope.preflight(["127.0.0.1"], "unit.test", "high-impact")
    assert scope.preflight(["127.0.0.1"], "unit.test")["target_contact"] is False


def test_scope_restricts_named_accounts():
    scope = Scope(
        "UNIT",
        "127.0.0.1",
        "unit.test",
        frozenset({"127.0.0.1"}),
        "2020-01-01",
        "2099-01-01",
        allowed_accounts=frozenset({"reader@unit.test"}),
    )
    scope.validate_account("Reader@unit.test")
    scope.validate_account(None)
    with pytest.raises(SafetyError, match="account inventory"):
        scope.validate_account("unlisted@unit.test")
