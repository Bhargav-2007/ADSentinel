# Unit and local integration results

ADSentinel 0.2.0, 2026-10-29. Commands: python -m pytest -q --junitxml=results/windows-tests.xml; the same command through Ubuntu WSL writes results/linux-tests.xml. These results do not contact live assessment targets.

| Platform | Passed | Skipped | Failures | Errors | JUnit seconds |
|---|---:|---:|---:|---:|---:|
| Windows / Python 3.11 | 126 | 5 | 0 | 0 | 5.341 |
| Ubuntu WSL / Python 3.14 | 126 | 5 | 0 | 0 | 12.270 |

Five skipped cases are deliberately disabled live LDAP/DNS/SMB/RDP/WinRM lab tests; they are not passing lab validations. Two upstream ldap3/pyasn1 deprecation warnings remain. Windows uses a source-built mypy because local application control blocked its compiled wheel.

Other checks: Ruff lint/format PASS; mypy PASS across 33 application source files; Bandit PASS; pip-audit reports no known vulnerabilities (editable project itself skipped as unpublished source); wheel/sdist build PASS; installed-wheel CLI and packaged Jinja2 template smoke check PASS. Secret scanning is configured in CI with network verification disabled, not represented as a locally executed secret-scanner audit.

Coverage includes authorization, scope/source/account restrictions, paths and file permissions, redaction, report escaping, graph traversal, real binary descriptor/POL layouts, LDAP attribute shapes, real official public-data checks and actual loopback SMB/DNS/RDP/WSMan exchanges. Graph and LDAP also have mocked-transport regressions. Fabricated unit fixtures are never presented as collected assessment data.

Expected behavior matched these assertions; no default-suite failure/error remains. This is not whole-environment TP/FP/FN measurement. Evidence: ignored local JUnit files, executable tests, public dataset validation and build artifacts. Live AD manual comparison, Docker execution and packaged Windows EXE validation remain outstanding. Final result: PASS for unit/local/public assertions; release blocked on live validation and unsupported capabilities.
