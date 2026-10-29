# Development

Install editable development dependencies in a virtual environment, then run:
```bash
python -m pytest -q
python -m ruff check adsentinel tests
python -m ruff format --check adsentinel tests
python -m mypy adsentinel
python -m bandit -r adsentinel -q
python -m pip_audit
```

Modules separate safety/file handling, configuration, collectors, normalization, rule evaluation, graph analysis, reporting and CLI orchestration. Add evidence fields and detection rules in `rules.py`, with positive, negative and unknown-evidence tests. Do not add network side effects to rule evaluation. Keep collectors read-only and use mocks in integration tests.

GitHub Actions checks Python 3.11?3.13 on Linux and Windows, lint, formatting, types, static security analysis, dependencies and secret scanning. Before release require manual code review of authorization gates, collectors, dependency changes, data handling and documentation; run an isolated AD/Entra lab validation and review rendered reports. Repository branch protection and mandatory review settings must be configured by the repository owner; no automatic release job is provided.

## Local verification

Verified on Windows with Python 3.11: 73 pytest cases, Ruff lint and formatting, mypy, Bandit, and pip-audit in an isolated virtual environment. The audit found no known vulnerabilities after updating the virtual environment's pip/setuptools. ADSentinel itself is an editable local distribution and is not a published vulnerability database package. ldap3 emits two upstream pyasn1 deprecation warnings in mock tests.

The synthetic full audit generated 18 findings; HTML, CSV, Markdown, JSON and terminal rendering are tested. Windows output DACL was inspected as protected owner-only with inheritance. Linux CI is configured but has not been executed in this local Windows session. No live AD/Entra assessment, Docker build or PyInstaller binary test was performed.
