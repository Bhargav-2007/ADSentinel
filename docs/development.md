# Development and release review

Use a private virtual environment, install .[dev], then run:

```bash
python -m pytest -q
python -m ruff check adsentinel tests scripts
python -m ruff format --check adsentinel tests scripts
python -m mypy adsentinel
python -m bandit -r adsentinel -q
python -m pip_audit --skip-editable
python -m build --wheel --sdist
python scripts/validate_public.py --output results/public-validation.json
```

Tests cover CLI/auth/path/redaction/report behavior, actual binary descriptor and Registry.pol layouts, LDAP attribute shapes, official sample object/ACL preservation and reviewed AD CS cases. Loopback integration uses actual local SMB, DNS, RDP and HTTP sockets; LDAP/Graph also have local mocks. No real assessment target is contacted by the default suite. Live tests are explicitly opt-in and scope-checked.

Public sample and large-graph results are documented under validation/. Keep fixture-only records in tests/fixtures; never present them as collected results. No live module is declared complete without native/manual AD lab comparisons and false-positive/negative analysis.

CI checks Linux/Windows Python versions, tests, Ruff, mypy, Bandit, dependency audit, secret scanning, wheel/sdist build and public-data validation. Dependency audit is a separate development operation that contacts vulnerability services with package metadata; runtime never uploads assessment data. Manual code/security review, a real isolated lab test, report review and approval are required before release. Branch protection/manual reviewer settings must be configured by the repository owner. No release/deploy job is provided.
