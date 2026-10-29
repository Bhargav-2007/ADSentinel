"""Cross-platform terminal interface. Network collection is always opt-in."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .collectors import collect_graph, collect_ldap
from .config import load_config
from .graph import analyze
from .models import sorted_findings
from .reports import render
from .rules import MODULES, evaluate, validate_evidence
from .security import (
    SafetyError,
    authorize,
    hostname,
    identity,
    protected_write,
    read_json,
    redact,
    safe_path,
    target,
)

TAGLINE = "Authorized Active Directory attack-path discovery, privilege-escalation assessment, and remediation reporting."
ACTIVE_FLAGS = ["asrep-roast", "kerberoast", "zone-transfer", "find-writable-shares", "crack", "active-check"]
HIGH_FLAGS = ["request-test", "relay-validate", "extract", "password-spray"]
SELECTORS = {
    "kerberos": ["enum"],
    "adcs": ["enum", "find-vulnerable", "esc1-check", "esc8-check"],
    "delegation": ["enum"],
    "acl": ["enum", "find-dangerous", "find-dcsync", "path"],
    "gpo": ["enum", "find-writable", "find-scripts", "find-scheduled-tasks", "risk-report"],
    "laps": ["enum", "find-readers", "find-unprotected-hosts", "risk-report"],
    "gmsa": ["enum", "find-readers", "find-manual-service-accounts", "risk-report"],
    "smb": ["check-signing", "find-shares", "relay-surface"],
    "ldap": ["check-signing", "check-channel-binding", "find-anonymous-access"],
    "ntlm": ["relay-surface", "check-ntlmv1", "risk-report"],
    "dns": ["enum", "find-stale-records"],
    "rdp": ["enum", "find-access", "risk-report"],
    "winrm": ["enum", "find-access", "risk-report"],
    "trusts": ["enum", "find-risky", "find-sidhistory", "risk-report"],
    "azure-ad": [
        "enum",
        "find-privileged-roles",
        "find-privileged-apps",
        "find-risky-consent",
        "hybrid-report",
    ],
    "account-hygiene": ["find-inactive", "find-privileged-dormant", "risk-report"],
    "password-policy": ["find-exceptions"],
    "privileged-access": ["find-nested", "find-tiering-issues", "risk-report"],
    "detection-coverage": ["check-sysmon", "check-adcs"],
}


def common(parser: argparse.ArgumentParser, suppress: bool = False) -> None:
    for flag in ("no-color", "verbose", "quiet", "json"):
        parser.add_argument(
            "--" + flag, action="store_true", default=argparse.SUPPRESS if suppress else False
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="adsentinel", description=TAGLINE)
    parser.add_argument("--version", action="version", version=__version__)
    common(parser)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in MODULES + ["report", "full-audit", "dcsync-validate"]:
        sub = commands.add_parser(
            name,
            help=f"{name} evidence assessment",
            description=(
                "Analyze normalized evidence. Selectors document assessment intent; the module runs all available rules. "
                "Live collection requires --collect. Unsupported checks remain unknown."
            ),
        )
        common(sub, True)
        for flag in ("domain", "dc", "user", "target", "tenant", "input", "output", "config"):
            sub.add_argument("--" + flag)
        sub.add_argument("--format", choices=["json", "csv", "markdown", "html", "terminal"], default="json")
        sub.add_argument("--results-dir", default="results")
        sub.add_argument("--password-env", default="ADS_SENTINEL_PASSWORD")
        sub.add_argument("--graph-token-env", default="ADS_SENTINEL_GRAPH_TOKEN")
        sub.add_argument("--authorize", action="store_true")
        sub.add_argument("--i-own-this-environment", action="store_true")
        sub.add_argument("--authorization-reference", default="Not supplied")
        sub.add_argument("--dry-run", action="store_true")
        sub.add_argument(
            "--no-redact", action="store_true", help="Private lab only; requires ownership acknowledgement"
        )
        sub.add_argument("--collect", choices=["ldap", "graph"], help="Explicit read-only network collection")
        sub.add_argument("--timeout", type=int, default=30)
        sub.add_argument("--ldaps-port", type=int, default=636)
        sub.add_argument("--from", dest="source")
        sub.add_argument("--to", dest="destination")
        sub.add_argument("--max-depth", type=int, default=6)
        sub.add_argument("--find-all", action="store_true")
        sub.add_argument("--find-shortest", action="store_true")
        sub.add_argument("--export-graph")
        sub.add_argument(
            "--collection",
            choices=[
                "default",
                "users",
                "groups",
                "computers",
                "acl",
                "sessions",
                "delegation",
                "certservices",
                "gpo",
                "all",
            ],
            default="default",
        )
        sub.add_argument("--framework", choices=["microsoft", "cis"], default="microsoft")
        sub.add_argument("--wordlist")
        for flag in sorted(set(SELECTORS.get(name, []) + ACTIVE_FLAGS + HIGH_FLAGS)):
            sub.add_argument("--" + flag, action="store_true")
    return parser


def execute(args: argparse.Namespace, console: Console) -> int:
    config = load_config(args.config) if args.config else {}
    t = config.get("target", {})
    auth = config.get("authentication", {})
    args.domain = args.domain or t.get("domain")
    args.dc = args.dc or t.get("domain_controller")
    args.user = args.user or auth.get("username")
    args.tenant = args.tenant or t.get("entra_tenant")
    args.ldaps_port = t.get("ldaps_port", args.ldaps_port)
    args.password_env = auth.get("password_env", args.password_env)
    args.graph_token_env = auth.get("graph_token_env", args.graph_token_env)
    timeout = config.get("safety", {}).get("timeout_seconds", args.timeout)
    if not isinstance(timeout, int) or not 1 <= timeout <= 120:
        raise SafetyError("Timeout must be between 1 and 120 seconds")
    if not 1 <= args.ldaps_port <= 65535 or not 1 <= args.max_depth <= 12:
        raise SafetyError("Invalid port or graph depth")
    for value in (args.domain, args.dc, args.tenant):
        if value:
            hostname(value)
    if args.target:
        target(args.target)
    for value in (args.user, args.source, args.destination):
        if value:
            identity(value)
    for value in (args.input, args.output, args.export_graph, args.wordlist):
        if value:
            safe_path(value)
    results_dir = safe_path(config.get("output", {}).get("directory", args.results_dir))
    if args.no_redact and not args.i_own_this_environment:
        raise SafetyError("--no-redact is restricted to acknowledged private labs (--i-own-this-environment)")
    active = any(getattr(args, f.replace("-", "_"), False) for f in ACTIVE_FLAGS)
    high = args.command == "dcsync-validate" or any(
        getattr(args, f.replace("-", "_"), False) for f in HIGH_FLAGS
    )
    authorize(active, high, args.authorize, args.i_own_this_environment)
    if active or high:
        console.print(
            "Authorized use only. Intrusive testing can expose credentials or disrupt production.",
            style="yellow",
            markup=False,
        )
    modules = (
        config.get("scan", {}).get("modules", MODULES) if args.command == "full-audit" else [args.command]
    )
    if not isinstance(modules, list) or any(
        m not in MODULES for m in modules if args.command == "full-audit"
    ):
        raise SafetyError("Unknown scan module")
    plan = {
        "command": args.command,
        "modules": modules,
        "network": args.collect,
        "input": args.input,
        "scope": {"domain": args.domain, "dc": args.dc, "target": args.target, "tenant_label": args.tenant},
        "active_requested": active,
        "high_impact_requested": high,
        "supported": not (active or high),
        "results_directory": str(results_dir),
    }
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0
    if active or high:
        raise SafetyError(
            "This validation mode is not implemented. No network action or credential operation was performed."
        )
    if args.command == "report":
        if not args.input:
            raise SafetyError("report requires --input with an ADSentinel report JSON")
        report = read_json(args.input)
        if report.get("schema_version") != "1.0" or "findings" not in report:
            raise SafetyError("Input is not an ADSentinel report")
    else:
        if args.collect and args.input:
            raise SafetyError("Choose either --collect or --input")
        if not args.collect and not args.input:
            raise SafetyError(
                "Supply --input evidence.json or explicitly select --collect ldap|graph; use --dry-run to preview"
            )
        if args.collect == "ldap":
            if not args.domain or not args.dc:
                raise SafetyError("LDAPS collection requires --domain and --dc")
            with console.status("Collecting read-only LDAPS inventory...", spinner="dots"):
                data = collect_ldap(
                    args.domain, args.dc, args.user, args.password_env, timeout, args.ldaps_port
                )
        elif args.collect == "graph":
            with console.status("Collecting read-only Microsoft Graph inventory...", spinner="dots"):
                data = collect_graph(args.graph_token_env, timeout)
        else:
            data = read_json(args.input)
        validate_evidence(data)
        if not args.no_redact:
            data = redact(data)
        findings, coverage = evaluate(data, modules)
        stamp = datetime.now(timezone.utc).isoformat()
        run = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        raw_path = protected_write(results_dir / (run + ".raw.json"), json.dumps(data, indent=2, default=str))
        paths = {}
        if (
            args.command == "attack-path"
            or (args.command == "acl" and getattr(args, "path", False))
            or (args.command == "full-audit" and args.source and args.destination)
        ):
            if not args.source or not args.destination:
                raise SafetyError("Path analysis requires --from and --to")
            paths = analyze(
                data.get("edges", []), args.source, args.destination, args.max_depth, args.find_all
            )
            coverage["attack-path" if args.command == "full-audit" else args.command]["status"] = (
                "evaluated" if data.get("edges") else "no applicable evidence"
            )
        report = {
            "schema_version": "1.0",
            "tool_version": __version__,
            "timestamp": stamp,
            "scope": plan["scope"],
            "authorization": {
                "authorize": args.authorize,
                "ownership_acknowledged": args.i_own_this_environment,
                "reference": args.authorization_reference,
                "mode": "read-only evidence assessment",
            },
            "coverage": coverage,
            "raw_evidence_reference": str(raw_path.relative_to(Path.cwd())),
            "inventory": {k: len(v) for k, v in data.items() if isinstance(v, list)},
            "findings": [f.to_dict() for f in sorted_findings(findings)],
            "attack_paths": paths,
        }
        if args.command == "bloodhound":
            report["collection"] = {
                "requested": args.collection,
                "method": "normalized relationship preparation",
                "limitation": "Not a SharpHound ZIP or native BloodHound CE import; no session collection.",
            }
        if args.export_graph:
            protected_write(args.export_graph, json.dumps({"edges": data.get("edges", [])}, indent=2))
    if not args.no_redact:
        report = redact(report)
    fmt = args.format
    if args.output:
        suffix = Path(args.output).suffix.lower()
        fmt = {".html": "html", ".md": "markdown", ".csv": "csv", ".json": "json"}.get(suffix, fmt)
    rendered = render(report, fmt)
    if args.output:
        output_path = protected_write(args.output, rendered)
    else:
        output_path = protected_write(
            results_dir
            / (uuid.uuid4().hex + ".report." + {"markdown": "md", "terminal": "txt"}.get(fmt, fmt)),
            rendered,
        )
    if args.config and not args.output:
        for extra_format in config.get("output", {}).get("formats", []):
            if extra_format != fmt:
                extension = {"markdown": "md", "terminal": "txt"}.get(extra_format, extra_format)
                protected_write(output_path.with_suffix("." + extension), render(report, extra_format))
    if args.verbose and not args.quiet:
        console.print(json.dumps(report.get("coverage", {}), indent=2), markup=False)
    if args.json:
        print(render(report, "json"))
    elif not args.quiet:
        if fmt == "terminal":
            console.print(rendered, markup=False, highlight=False)
        else:
            table = Table(title="ADSentinel findings")
            for heading in ("Severity", "Object", "Finding"):
                table.add_column(heading)
            for finding in report.get("findings", []):
                table.add_row(
                    Text(
                        finding["severity"],
                        style={
                            "CRITICAL": "bold red",
                            "HIGH": "red",
                            "MEDIUM": "yellow",
                            "LOW": "cyan",
                            "INFO": "green",
                        }[finding["severity"]],
                    ),
                    Text(str(finding["affected_object"])),
                    Text(finding["title"]),
                )
            console.print(table)
        console.print(f"Report saved: {output_path}", markup=False)
        console.print("Review coverage: unknown checks are not passing controls.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(no_color=args.no_color, quiet=args.quiet or args.json, stderr=True, highlight=False)
    try:
        return execute(args, console)
    except (SafetyError, OSError, ValueError, KeyError, TypeError) as exc:
        # Errors never include server response bodies or credential-bearing tracebacks.
        message = (
            str(exc)
            if isinstance(exc, SafetyError)
            else "Operation failed; verify evidence schema, paths and configuration."
        )
        if args.json:
            print(json.dumps({"error": message}))
        else:
            print("Error: " + message, file=sys.stderr)
        return 2
    except Exception:
        message = "Collector failed; check endpoint reachability, TLS trust and read permissions."
        if args.json:
            print(json.dumps({"error": message}))
        else:
            print("Error: " + message, file=sys.stderr)
        return 2
