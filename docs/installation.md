# Installation

Python 3.11 or newer is required. All assessment commands are identical on Windows and Linux.

PowerShell:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
python -m adsentinel --help
```

Bash:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m adsentinel --help
```

Use `adsentinel` after activating the environment, or `python -m adsentinel` when the scripts directory is not on PATH. Use a local trusted CA for LDAPS; certificate verification cannot be disabled. Use a DNS hostname matching the server certificate.

Docker (Linux): `docker build -t adsentinel .` then `docker run --rm adsentinel --help`. Mount evidence and an owner-writable results directory inside `/app` for assessments. The container runs as an unprivileged user.

Windows executable, built on Windows:
```powershell
python -m pip install pyinstaller
python -m PyInstaller --onefile --name adsentinel --collect-all ldap3 packaging/entrypoint.py
```
Review and sign binaries before release. Building a Linux binary does not produce a Windows executable.
