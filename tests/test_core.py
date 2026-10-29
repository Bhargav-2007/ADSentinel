import json
import os
from pathlib import Path

import pytest

from adsentinel.cli import build_parser, main
from adsentinel.config import load_config
from adsentinel.graph import analyze
from adsentinel.models import Finding, sorted_findings
from adsentinel.reports import render
from adsentinel.rules import MODULES, evaluate, validate_evidence
from adsentinel.security import (
    SafetyError,
    authorize,
    graph_url,
    hostname,
    ldap_filter,
    protected_write,
    read_json,
    redact,
    safe_path,
    target,
)


@pytest.mark.parametrize("module", MODULES + ["report", "full-audit", "dcsync-validate"])
def test_cli_commands(module):
    assert build_parser().parse_args([module]).command == module


@pytest.mark.parametrize("args", [["--json", "recon"], ["recon", "--json"]])
def test_global_flags(args):
    assert build_parser().parse_args(args).json


@pytest.mark.parametrize(
    "active,high,auth,owned,allowed",
    [
        (False, False, False, False, True),
        (True, False, False, False, False),
        (True, False, True, False, True),
        (False, True, True, False, False),
        (False, True, True, True, True),
        (False, True, False, True, False),
    ],
)
def test_authorization(active, high, auth, owned, allowed):
    if allowed:
        authorize(active, high, auth, owned)
    else:
        with pytest.raises(SafetyError):
            authorize(active, high, auth, owned)


def test_safe_queries():
    assert (
        ldap_filter("sAMAccountName", "x*)(objectClass=*)")
        == r"(sAMAccountName=x\2a\29\28objectClass=\2a\29)"
    )
    with pytest.raises(SafetyError):
        ldap_filter("bad)(", "x")
    with pytest.raises(SafetyError):
        graph_url("users?$filter=evil")


@pytest.mark.parametrize("value", ["corp.lab/evil", "x\n", "-host", "a..b", "https://corp.lab"])
def test_invalid_hosts(value):
    with pytest.raises(SafetyError):
        hostname(value)


def test_scope():
    assert target("10.0.0.0/24") == "10.0.0.0/24"
    with pytest.raises(SafetyError):
        target("10.0.0.0/8")


def test_paths_and_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for value in ["../escape", "results/../../escape", "results/x:stream", "report.txt:stream"]:
        with pytest.raises(SafetyError):
            safe_path(value)
    p = protected_write("results/evidence.json", '{"ok": true}')
    assert read_json(p) == {"ok": True}
    with pytest.raises(FileExistsError):
        protected_write(p, "overwrite")
    if os.name == "posix":
        assert p.stat().st_mode & 0o777 == 0o600
        assert p.parent.stat().st_mode & 0o777 == 0o700


def test_severity():
    def finding(severity):
        return Finding("id", "acl", "title", severity, "x", {}, "T1098", "detect", "fix")

    assert sorted_findings([finding("LOW"), finding("CRITICAL")])[0].severity == "CRITICAL"
    with pytest.raises(ValueError):
        finding("bad")


def test_rules_unknown_and_strict_boolean():
    findings, coverage = evaluate({"users": [{"id": "u", "preauth_required": False}]}, ["kerberos", "smb"])
    assert len(findings) == 1
    assert coverage["smb"]["status"] == "no applicable evidence"
    assert not evaluate({"users": [{"preauth_required": 0}]}, ["kerberos"])[0]


def test_esc1_complete_conditions():
    template = {
        "id": "t",
        "enrollee_supplies_subject": True,
        "client_authentication": True,
        "low_privilege_enrollment": True,
        "manager_approval": False,
        "authorized_signatures": 0,
        "published": True,
    }
    assert evaluate({"templates": [template]}, ["adcs"])[0]
    template.pop("published")
    assert not evaluate({"templates": [template]}, ["adcs"])[0]


def test_replication_requires_combined_rights():
    row = {"principal": "svc", "rights": ["DS-Replication-Get-Changes"]}
    assert not evaluate({"replication_rights": [row]}, ["dcsync-check"])[0]
    row["rights"].append("DS-Replication-Get-Changes-All")
    assert evaluate({"replication_rights": [row]}, ["dcsync-check"])[0][0].severity == "CRITICAL"


def test_graph_cycles_depth_and_all_paths():
    edges = [
        {"source": a, "target": b, "relation": "MemberOf"}
        for a, b in [("u", "g"), ("g", "u"), ("g", "da"), ("u", "da")]
    ]
    assert len(analyze(edges, "U", "DA")["paths"][0]["edges"]) == 1
    assert len(analyze(edges, "u", "da", all_paths=True)["paths"]) == 2
    assert not analyze(edges, "u", "absent")["paths"]
    with pytest.raises(SafetyError):
        analyze(edges, "u", "da", max_depth=13)


def test_redaction_nested():
    value = {"users": [{"password": "sensitive", "nested": {"access_token": "token"}, "id": "u"}]}
    assert "sensitive" not in json.dumps(redact(value))
    assert redact(value)["users"][0]["id"] == "u"


@pytest.mark.parametrize("fmt", ["json", "csv", "markdown", "html", "terminal"])
def test_report(fmt):
    finding = Finding(
        "id", "acl", "<script>alert(1)</script>", "HIGH", "=CMD()", {}, "T1098", "detect", "fix"
    )
    report = {"timestamp": "today", "findings": [finding.to_dict()], "coverage": {}, "scope": {}}
    rendered = render(report, fmt)
    assert "fix" in rendered
    if fmt == "html":
        assert "<script>" not in rendered
        assert "&lt;script&gt;" in rendered
    if fmt == "csv":
        assert "'=CMD()" in rendered


def test_config_rejects_secrets_and_authorization_bypass(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for text in [
        "authentication:\n  password: secret",
        "safety:\n  require_authorization: false",
        "scan:\n  mode: active",
        "safety:\n  allow_relay_validation: true",
    ]:
        Path("test.yaml").write_text(text)
        with pytest.raises(SafetyError):
            load_config("test.yaml")


def test_evidence_shape():
    with pytest.raises(SafetyError):
        validate_evidence({"users": {}})
    with pytest.raises(SafetyError):
        validate_evidence({"edges": [{"source": "x"}]})


def test_end_to_end(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    Path("evidence.json").write_text(
        json.dumps({"users": [{"id": "u", "preauth_required": False, "password": "secret-value"}]})
    )
    assert main(["kerberos", "--input", "evidence.json", "--output", "results/out.json", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert len(report["findings"]) == 1
    assert "secret-value" not in "".join(p.read_text() for p in Path("results").iterdir())
    assert main(["report", "--input", "results/out.json", "--output", "results/out.html", "--quiet"]) == 0
    assert Path("results/out.html").exists()


def test_dry_run_no_side_effects(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["recon", "--collect", "ldap", "--dry-run", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["network"] == "ldap"
    assert not Path("results").exists()


def test_intrusive_gate_precedes_execution(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["adcs", "--request-test"]) == 2
    assert main(["dcsync-validate", "--authorize", "--i-own-this-environment"]) == 2
    assert not Path("results").exists()


def test_redaction_preserves_password_policy_and_hygiene():
    evidence = {
        "password_policies": [{"id": "domain", "minimum_length": 8}],
        "users": [{"id": "u", "password_never_expires": True, "password": "secret"}],
    }
    safe = redact(evidence)
    validate_evidence(safe)
    findings, _ = evaluate(safe, ["password-policy", "account-hygiene"])
    assert len(findings) == 2


def test_full_audit_example(tmp_path, monkeypatch):
    source = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "unit-evidence.json"
    evidence = source.read_text()
    monkeypatch.chdir(tmp_path)
    Path("evidence.json").write_text(evidence)
    assert main(["full-audit", "--input", "evidence.json", "--output", "results/audit.json", "--quiet"]) == 0
    report = json.loads(Path("results/audit.json").read_text())
    assert len(report["findings"]) >= 15
    assert report["inventory"]["users"] == 2


def test_full_audit_with_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("evidence.json").write_text(
        json.dumps({"edges": [{"source": "u", "target": "da", "relation": "MemberOf"}]})
    )
    assert (
        main(
            [
                "full-audit",
                "--input",
                "evidence.json",
                "--from",
                "u",
                "--to",
                "da",
                "--output",
                "results/audit.json",
                "--quiet",
            ]
        )
        == 0
    )
    assert json.loads(Path("results/audit.json").read_text())["attack_paths"]["paths"]


def test_config_multiple_formats(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("evidence.json").write_text("{}")
    Path("config.yaml").write_text("output:\n  formats: [json, html, markdown]\n")
    assert main(["recon", "--input", "evidence.json", "--config", "config.yaml", "--quiet"]) == 0
    assert len(list(Path("results").glob("*.html"))) == 1
    assert len(list(Path("results").glob("*.md"))) == 1
