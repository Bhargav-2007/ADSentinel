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

from .. import __version__
from ..config import load_config
from ..core.auth import Credentials
from ..core.authorization import Scope
from ..core.logging import get_logger
from ..graph import analyze_graph, graphml
from ..importers.bloodhound import import_bloodhound
from ..models import sorted_findings
from ..modules.adcs import candidate_edges
from ..modules.runner import run_module
from ..protocols.graph_client import GraphClient
from ..protocols.orchestrator import collect, expand_targets, requested_protocol
from ..protocols.orchestrator import plan as collection_plan
from ..reports import render
from ..rules import MODULES, evaluate, validate_evidence
from ..security import (
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
    "delegation": ["enum", "find-unconstrained", "find-constrained", "find-rbc", "risk-report"],
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
    for name in MODULES + ["report", "full-audit", "dcsync-validate", "import", "lab-preflight"]:
        sub = commands.add_parser(
            name,
            help=f"{name} evidence assessment",
            description=(
                "Analyze normalized evidence. Selectors document assessment intent; the module runs all available rules. "
                "Domain/controller or target arguments select live read-only collection. Unsupported checks are explicitly reported."
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
        sub.add_argument(
            "--collect",
            choices=["ldap", "graph", "smb", "dns", "rdp", "winrm"],
            help="Select a read-only protocol collector",
        )
        sub.add_argument("--graph", help="Imported ADSentinel graph JSON")
        sub.add_argument(
            "--source",
            dest="import_source",
            choices=["bloodhound-ce", "sharphound", "graph"],
            default="bloodhound-ce",
        )
        sub.add_argument("--anonymous", action="store_true")
        sub.add_argument("--prompt-password", action="store_true")
        sub.add_argument("--scope-file", help="Local engagement scope JSON; validated before target contact")
        sub.add_argument("--ca-cert", help="Trusted lab CA bundle inside the workspace")
        sub.add_argument(
            "--tls-server-name", help="Expected LDAPS certificate DNS identity when connecting to an IP"
        )
        sub.add_argument("--check-smb1", action="store_true")
        sub.add_argument(
            "--read-sysvol",
            action="store_true",
            help="Read bounded GPO policy files over SMB; requires --mode network",
        )
        sub.add_argument(
            "--mode", choices=["passive", "detection", "network", "active", "high-impact"], default="passive"
        )
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
            sub.add_argument(
                "--" + flag,
                action="store_true",
                help=(
                    "UNSUPPORTED validation backend; authorization is still checked"
                    if flag in ACTIVE_FLAGS + HIGH_FLAGS and flag != "zone-transfer"
                    else None
                ),
            )
    return parser


def execute(args: argparse.Namespace, console: Console) -> int:
    logger = get_logger(args.verbose)
    logger.info("scan_started command=" + args.command)
    config = load_config(args.config) if args.config else {}
    if args.mode == "passive":
        args.mode = config.get("scan", {}).get("mode", "passive")
    t = config.get("target", {})
    auth = config.get("authentication", {})
    args.domain = args.domain or t.get("domain")
    if args.graph and args.input:
        raise SafetyError("Choose --graph or --input")
    args.input = args.graph or args.input
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
    for value in (args.domain, args.dc, args.tenant, args.tls_server_name):
        if value:
            hostname(value)
    if args.target:
        target(args.target)
    for value in (args.user, args.source, args.destination):
        if value:
            identity(value)
    for value in (args.input, args.output, args.export_graph, args.wordlist, args.scope_file, args.ca_cert):
        if value:
            safe_path(value)
    results_dir = safe_path(config.get("output", {}).get("directory", args.results_dir))
    if args.no_redact and not args.i_own_this_environment:
        raise SafetyError("--no-redact is restricted to acknowledged private labs (--i-own-this-environment)")
    active = args.mode == "active" or any(getattr(args, f.replace("-", "_"), False) for f in ACTIVE_FLAGS)
    high = (
        args.mode == "high-impact"
        or args.command == "dcsync-validate"
        or any(getattr(args, f.replace("-", "_"), False) for f in HIGH_FLAGS)
    )
    authorize(active, high, args.authorize, args.i_own_this_environment)
    if active or high:
        print(
            "Authorized use only. Intrusive testing can expose credentials or disrupt production.",
            file=sys.stderr,
        )
    modules = (
        config.get("scan", {}).get("modules", MODULES) if args.command == "full-audit" else [args.command]
    )
    if not isinstance(modules, list) or any(
        m not in MODULES for m in modules if args.command == "full-audit"
    ):
        raise SafetyError("Unknown scan module")
    scope = Scope.load(args.scope_file) if args.scope_file else None
    if args.command == "lab-preflight":
        if not scope:
            raise SafetyError("lab-preflight requires --scope-file")
        print(json.dumps(scope.preflight(sorted(scope.targets), scope.domain), indent=2))
        return 0
    if not args.input and args.command not in {"import", "report"}:
        args.collect = requested_protocol(
            args.command, args.collect, bool(args.domain), bool(args.target or args.dc)
        )
    targets = expand_targets(args.target, args.dc, scope)
    plan = {
        "command": args.command,
        "modules": modules,
        "network": args.collect,
        "input": args.input,
        "scope": {"domain": args.domain, "dc": args.dc, "target": args.target, "tenant_label": args.tenant},
        "active_requested": active,
        "high_impact_requested": high,
        "supported": not (high or (active and not getattr(args, "zone_transfer", False))),
        "collection_plan": collection_plan(args.collect, targets, args.domain, args.user, timeout),
        "results_directory": str(results_dir),
    }
    if args.collect == "ldap":
        plan["collection_plan"]["port"] = args.ldaps_port
    if args.collect in {"dns", "rdp", "winrm"} or (
        args.collect == "smb"
        and not getattr(args, "find_shares", False)
        and args.command not in {"recon", "full-audit"}
    ):
        plan["collection_plan"]["authentication"] = "no account authentication"
    if args.zone_transfer:
        plan["collection_plan"]["actions"].append("Attempt one authorized DNS AXFR over TCP")
    if args.read_sysvol:
        plan["collection_plan"]["actions"].append(
            "Read bounded optional SYSVOL policy files from the selected DC"
        )
    if scope:
        plan["authorization_reference"] = scope.reference
        plan["required_source_address"] = scope.source_address
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0
    if high or (active and not getattr(args, "zone_transfer", False)):
        raise SafetyError(
            "Unsupported validation backend. No network action or credential operation was performed."
        )
    if args.command == "import":
        if not args.input or not args.output:
            raise SafetyError("import requires --input and --output")
        data = import_bloodhound(args.input)
        data["edges"].extend(candidate_edges(data))
        protected_write(args.output, json.dumps(redact(data), indent=2, sort_keys=True))
        summary = {"nodes": len(data["nodes"]), "edges": len(data["edges"]), "provenance": data["provenance"]}
        if args.json:
            print(json.dumps(summary, indent=2))
        elif not args.quiet:
            console.print(json.dumps(summary, indent=2), markup=False)
        return 0
    if args.command == "report":
        if not args.input:
            raise SafetyError("report requires --input with an ADSentinel report JSON")
        report = read_json(args.input)
        if report.get("kind") == "adsentinel.graph":
            findings, coverage = evaluate(report, MODULES)
            report = {
                "schema_version": "1.1",
                "tool_version": __version__,
                "timestamp": report.get("provenance", {}).get("imported_at"),
                "scope": {"source": report.get("source"), "provenance": report.get("provenance")},
                "authorization": {"mode": "offline imported data analysis"},
                "coverage": coverage,
                "findings": [f.to_dict() for f in sorted_findings(findings)],
                "inventory": {k: len(v) for k, v in report.items() if isinstance(v, list)},
                "attack_paths": {},
            }
        elif report.get("schema_version") not in {"1.0", "1.1"} or "findings" not in report:
            raise SafetyError("Input is not an ADSentinel report or graph")
    else:
        if args.collect and args.input:
            raise SafetyError("Choose either --collect or --input")
        if not args.collect and not args.input:
            raise SafetyError(
                "Supply --input evidence.json or explicitly select --collect ldap|graph; use --dry-run to preview"
            )
        if args.anonymous and args.user:
            raise SafetyError("Choose a named account or --anonymous")
        if args.collect and not args.input:
            if args.command == "bloodhound" and args.collection == "sessions":
                raise SafetyError(
                    "Native live session collection is unsupported; import authorized SharpHound session data"
                )
            unsupported = {
                "ldap": ["check_signing", "check_channel_binding"],
                "ntlm": ["check_ntlmv1"],
                "adcs": ["esc8_check"],
                "rdp": ["find_access"],
                "winrm": ["find_access"],
                "detection-coverage": ["check_sysmon", "check_adcs"],
            }
            for selector in unsupported.get(args.command, []):
                if getattr(args, selector, False):
                    raise SafetyError(
                        "Unsupported live check: --"
                        + selector.replace("_", "-")
                        + "; endpoint reachability cannot establish this policy or effective access"
                    )
        if args.read_sysvol and args.mode != "network":
            raise SafetyError("--read-sysvol requires --mode network")
        if args.read_sysvol and (args.collect != "ldap" or not args.domain):
            raise SafetyError("SYSVOL policy reads require LDAP collection and a domain")

        if args.collect == "graph":
            if scope:
                raise SafetyError("This isolated lab scope does not authorize cloud endpoints")
            with console.status("Collecting read-only Microsoft Graph inventory...", spinner="dots"):
                with GraphClient(args.graph_token_env, timeout) as graph_client:
                    data = graph_client.collect()
        elif args.collect:
            if args.target and "/" in args.target:
                if not sys.stdin.isatty():
                    raise SafetyError(
                        "Broad scans require interactive confirmation; use individual hosts for automation"
                    )
                print(
                    "Type SCAN " + args.target + " to confirm the authorized range: ",
                    file=sys.stderr,
                    end="",
                    flush=True,
                )
                if sys.stdin.readline().strip() != "SCAN " + args.target:
                    raise SafetyError("Broad scan cancelled")
            if scope:
                scope.preflight(targets, args.domain, "active" if args.zone_transfer else "network")
            needs_account = (
                args.collect == "ldap"
                or args.read_sysvol
                or (
                    args.collect == "smb"
                    and (getattr(args, "find_shares", False) or args.command in {"recon", "full-audit"})
                )
            )
            if scope and needs_account:
                scope.validate_account(args.user)
            credentials = Credentials.from_environment(
                args.user if needs_account else None,
                args.domain or "",
                args.password_env,
                args.prompt_password,
            )
            with console.status("Collecting read-only " + args.collect + " evidence...", spinner="dots"):
                data = collect(
                    args.collect,
                    targets,
                    args.domain,
                    credentials,
                    timeout,
                    scope,
                    args.ldaps_port,
                    shares=getattr(args, "find_shares", False) or args.command in {"recon", "full-audit"},
                    check_smb1=args.check_smb1,
                    zone_transfer=getattr(args, "zone_transfer", False),
                    collection=args.collection if args.command == "bloodhound" else "default",
                    ca_file=args.ca_cert,
                    tls_server_name=args.tls_server_name,
                    module=args.command,
                )
                if args.read_sysvol:
                    from ..protocols.gpo_client import collect_sysvol

                    data["gpo_files"] = collect_sysvol(
                        targets[0], args.domain, credentials, data.get("gpos", []), timeout
                    )

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
            paths = analyze_graph(data, args.source, args.destination, args.max_depth, args.find_all)
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
                "scope_reference": scope.reference if scope else None,
            },
            "coverage": coverage,
            "raw_evidence_reference": str(raw_path.relative_to(Path.cwd())),
            "inventory": {k: len(v) for k, v in data.items() if isinstance(v, list)},
            "findings": [f.to_dict() for f in sorted_findings(findings)],
            "collection_errors": data.get("errors", []) + data.get("provenance", {}).get("issues", []),
            "attack_paths": paths,
        }
        if args.command == "bloodhound":
            report["collection"] = {
                "requested": args.collection,
                "method": "native LDAPS object/ACL collection or imported SharpHound relationships",
                "limitation": "Native live session/local-group collection is not available; imported session/local-group evidence is supported.",
            }
        report["module_results"] = [
            run_module(module, data).to_dict() for module in modules if module in MODULES
        ]
        if args.export_graph:
            protected_write(
                args.export_graph,
                graphml(data)
                if Path(args.export_graph).suffix.lower() == ".graphml"
                else json.dumps(data, indent=2, default=str),
            )
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
    logger.info("scan_completed findings=" + str(len(report.get("findings", []))))
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
    except KeyboardInterrupt:
        print("Scan cancelled; no further targets will be contacted.", file=sys.stderr)
        return 130
    except Exception:
        message = "Collector failed; check endpoint reachability, TLS trust and read permissions."
        if args.json:
            print(json.dumps({"error": message}))
        else:
            print("Error: " + message, file=sys.stderr)
        return 2
