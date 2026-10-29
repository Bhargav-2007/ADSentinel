# Installation

Python 3.11+ is required. Commands are the same on Linux and Windows.

PowerShell:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools
python -m pip install -e '.[dev]'
python -m adsentinel --help
```

Bash:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools
python -m pip install -e '.[dev]'
python -m adsentinel --help
```

Use python -m adsentinel if the console-script directory is not on PATH. LDAPS requires trusted CA/certificate names; --ca-cert and --tls-server-name support private labs without disabling verification. Password/token values come only from environment or secure password prompts.

Linux Docker:
```bash
docker build -t adsentinel .
docker run --rm adsentinel --help
```
Mount only approved evidence and an owner-writable results directory inside /app. The image runs unprivileged. Docker build/run has not been validated locally because the daemon is unavailable.

Windows executable instructions, build on Windows:
```powershell
python -m pip install pyinstaller
python -m PyInstaller --onefile --name adsentinel --collect-all ldap3 --collect-all impacket --collect-data adsentinel packaging/entrypoint.py
```
The executable workflow is unvalidated; review dynamic imports, packaged templates, signing and isolated-lab behavior before distribution. Wheel/sdist builds are tested. A Linux build does not produce a Windows executable.
