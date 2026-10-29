"""Explicit opt-in live lab checks. Skipped by default; never discover targets automatically."""

import os

import pytest

from adsentinel.core.auth import Credentials
from adsentinel.core.authorization import Scope
from adsentinel.protocols.orchestrator import collect


@pytest.mark.lab
@pytest.mark.parametrize("protocol", ["ldap", "dns", "smb", "rdp", "winrm"])
def test_authorized_lab_protocol(protocol):
    if os.environ.get("ADS_SENTINEL_RUN_LAB") != "1":
        pytest.skip("Live lab execution is explicitly opt-in; not part of public-data validation")
    scope_path = os.environ.get("ADS_SENTINEL_LAB_SCOPE")
    if not scope_path:
        pytest.fail("ADS_SENTINEL_LAB_SCOPE is required")
    scope = Scope.load(scope_path)
    # Choose only the controller explicitly identified in local inventory.
    controller = os.environ.get("ADS_SENTINEL_LAB_DC")
    if not controller:
        pytest.fail("ADS_SENTINEL_LAB_DC is required; no target guessing")
    scope.preflight([controller], scope.domain)
    credentials = Credentials.from_environment(
        os.environ.get("ADS_SENTINEL_USERNAME"), scope.domain, "ADS_SENTINEL_PASSWORD"
    )
    evidence = collect(protocol, [controller], scope.domain, credentials, 10, scope)
    assert evidence.get("source")
    if protocol == "ldap":
        assert evidence.get("domains") and evidence.get("nodes")
    elif protocol == "dns":
        assert evidence.get("dns")
    else:
        assert evidence.get("computers")
    assert not any(c.get("error") or c.get("errors") for c in evidence.get("computers", []))
    assert not evidence.get("errors"), (
        "Collector returned errors; inspect protected evidence before accepting validation"
    )
