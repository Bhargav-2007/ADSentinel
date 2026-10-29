# Architecture

The CLI package validates intent, builds action plans, checks authorization and calls protocol orchestration. core/auth.py keeps secrets out of representations, core/authorization.py enforces engagement scope, core/models.py defines Evidence/ScanError/ModuleResult, and core/logging.py emits controlled structured events.

protocols/ owns verified LDAPS, bounded SMB/DNS/RDP/WSMan, optional SYSVOL and read-only Graph. The security-descriptor parser handles binary owner/DACL/ACE structures with bounds and explicit effective-access limitations. Secret-valued LDAP attributes are never requested.

importers/bloodhound.py consumes actual collector documents without extracting archives. It preserves identifiers/checksums/provenance, merges duplicate relationships and retains unknown rights. Import discrepancies are coverage issues, not security findings.

rules.py holds shared declarative checks. modules/ implements compound AD CS/identity checks, transitive membership and ModuleResult. Commands share tested code instead of unused wrappers or empty feature folders. graph.py handles BFS/DFS, alias resolution, limits and GraphML. Containment, publication and standalone enrollment are not domain control.

reports/ uses standard JSON/CSV/Markdown and packaged autoescaped Jinja2 HTML. Findings have stable rule IDs plus unique deterministic object/evidence digests. Outputs are exclusive-created and protected. The original flat collector API remains for compatibility regression tests; the CLI uses protocol clients.

Flow: CLI/config → authorization/plan → collector/importer → normalized graph/provenance → rules/graph → ModuleResult → separate protected raw evidence and reports. Missing fields remain unknown; paths require validation.
