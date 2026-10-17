# LPE Sentinel — Linux Privilege Escalation Detection and Security Auditing Toolkit

**LPE Sentinel** is an educational, defensive security auditing toolkit designed to scan Linux systems for privilege escalation vectors, dangerous permission misconfigurations, and common security weaknesses.

---

## 🎯 Project Overview & Purpose

The goal of this project is to provide a structured, transparent, and modular audit tool for security students, system administrators, and cybersecurity researchers. It automates common manual security audit checks (such as SUID/SGID binaries, misconfigured sudo rules, and world-writable critical files) while presenting the findings in an easy-to-read format.

---

## 🛡️ Safety & Project Scope

* **Defensive Auditing Only:** LPE Sentinel inspects and reports on system security posture. It **does not** exploit vulnerabilities or attempt to gain elevated privileges.
* **No Weaponization:** No exploit payloads, reverse shells, or automated privilege escalation attacks are included.
* **No Automatic Remediation:** The toolkit identifies and reports security issues, leaving system configuration and remediation decisions to the authorized administrator.
* **Read-Only Operation:** All scanner modules strictly perform read-only inspections. File writing occurs exclusively when the user explicitly requests report generation, with overwrite protection enabled by default.
* **Authorized Testing Only:** Never run this toolkit on systems or networks where you do not have explicit, written authorization.

---

## 🔍 Modules & Core Features

* **System Information (`[1]`)**: Detects and displays operating system name, release, hostname, current username, architecture, Python version, and platform category.
* **Security Audit Submenu (`[2]`)**:
  * **SUID/SGID Scanner**: Recursively inspects user-specified directories for files with `stat.S_ISUID` or `stat.S_ISGID` permission bits enabled.
  * **Defensive Binary Risk Classification**: Cross-references discovered SUID/SGID executable basenames against a bundled local reference catalog of standard utilities (e.g., shells, interpreters, file copiers, search tools) that warrant administrative review when granted elevated permissions. Conservative severities (HIGH/MEDIUM) highlight potential review targets without executing binaries or assuming exploitability.
  * **Risky Write Permissions Scanner**: Checks explicitly supplied file paths for group- or world-writable permission bits (`0o020`, `0o002`).
  * **Sudo Configuration Auditor**: Audits explicitly supplied sudoers files for preliminary risk indicators (`NOPASSWD`, unrestricted `ALL` commands, wildcards).
  * **Session Audit Summary**: Displays cumulative findings counts, severity distributions, unique affected resource metrics, and scanner categories after each completed scan.
* **Report Generation (`[3]`)**: Safely exports cumulative session findings into a structured, validated JSON report using collision-safe atomic file writes.

---

## ⚠️ Platform Limitations & Testing Notice

* **Linux-Only Security Scanners**: The security scanner modules (`suid_sgid.py`, `sensitive_permissions.py`, and `sudo_audit.py`) rely on POSIX filesystem semantics, permission bits, and configuration syntax. On Windows or macOS, these scanners issue a warning and cleanly return without performing an audit.
* **Reference Dataset & Limitations**: The binary risk catalog in `binary_risk.py` is an offline reference dataset inspired by administrative audit guidelines and GTFOBins. A catalog match indicates that a binary warrants security review by a system administrator; it is not proof of an active vulnerability, successful exploit, or misconfiguration on its own.
* **Windows Host vs. Linux Target**: Passing the unit test suite on Windows verifies logic and error handling using mock objects; it **does not** substitute for testing actual scanner behavior on Linux. Real-world validation must be performed in an isolated Linux environment (e.g., Kali Linux in VirtualBox).

---

## 💻 Environment Setup

* **Development OS:** Windows 10/11 (Python 3.x standard library, Git)
* **Testing & Target OS:** Kali Linux running inside a VirtualBox virtual machine
* **Architecture:** Host-to-guest workflow where code developed and maintained on Windows is tested inside an isolated Kali Linux guest environment.
* **Dependencies:** Zero external dependencies; built entirely on Python's standard library.

---

## 📁 Project Structure

```text
LPE-Sentinel/
├── docs/
│   └── PROJECT_SCOPE.md       # Ethical boundaries and defensive scope documentation
├── reports/                   # Destination for generated audit reports
├── scripts/                   # Helper utility scripts for setup and testing
├── src/
│   └── lpe_sentinel/
│       ├── __init__.py        # Package metadata and version definition
│       ├── audit_diff.py      # Historical audit comparison and diff analysis
│       ├── audit_engine.py    # Non-interactive unified audit orchestrator
│       ├── audit_history.py   # SQLite persistence manager for audit history
│       ├── audit_summary.py   # In-memory findings summary and scanner categorization
│       ├── binary_risk.py     # Defensive SUID/SGID reference inventory and risk classifier
│       ├── export.py          # Secure JSON, CSV, and HTML report exporters
│       ├── main.py            # Primary CLI entry point and menu orchestration
│       ├── models.py          # Finding data model and severity definitions
│       ├── remediation_guidance.py # Advisory remediation guidance and hardening references
│       ├── report_validation.py # JSON report schema and data validator
│       ├── reporting.py       # Safe JSON report generator with atomic file writes
│       ├── sensitive_permissions.py # Group/world-writable file scanner (Linux only)
│       ├── sudo_audit.py      # Sudoers configuration auditor (Linux only)
│       ├── suid_sgid.py       # SUID/SGID file permission scanner (Linux only)
│       ├── summary_formatter.py # Plain-text terminal audit summary formatter
│       ├── system_info.py     # Host metadata and platform detection
│       ├── web/               # Self-contained HTTP web dashboard module
│       │   ├── demo_data.py   # Safe simulated demonstration audit findings
│       │   ├── server.py      # Defensive HTTP server, routing, and CSRF protection
│       │   └── templates.py   # Responsive web UI HTML/CSS/JS templates
│       └── web_app.py         # Standalone web dashboard server entry point
├── tests/                     # Comprehensive unit, integration, and security test suites
├── .gitignore                 # Excluded files for Python, OS, and local environments
├── LICENSE                    # MIT License
├── README.md                  # Project overview and documentation
└── requirements.txt           # Standard-library only declaration
```

---

## 🚀 Getting Started & Usage

### 1. Interactive CLI:

```bash
# From the project root
python src/lpe_sentinel/main.py
```

### 2. Local Web Dashboard:

```bash
# Start web server on default loopback (127.0.0.1:8080)
python src/lpe_sentinel/web_app.py

# Or specify custom loopback port and auto-open browser
python src/lpe_sentinel/web_app.py --port 8765 --open-browser
```

> **🔒 Local Loopback Binding & Security Notice:**
> - The web server binds strictly to the local loopback interface (`127.0.0.1`) by default.
> - Binding to a non-loopback host (e.g. `0.0.0.0`) is refused by default to prevent accidental exposure of an unauthenticated service. Operators on isolated test networks must pass the explicit acknowledgement flag: `--allow-non-loopback`.
> - It is designed solely for local administrative review and **must not** be exposed to untrusted networks or deployed in multi-user/production environments.
> - All mutating endpoints (`POST /api/run-audit`) require matching Origin/Referer and cryptographically validated CSRF tokens.

### 3. Live Audits vs. Simulated Demo Results:

- **Simulated Demo Mode (`GET /api/demo-audit`)**: Allows exploring dashboard capabilities, interactive finding filters (severity, category, text search), and export workflows safely on any platform without running host scans. A prominent blue banner clearly distinguishes demo data from live audit results.
- **Live Audit Mode (`POST /api/run-audit`)**: Triggers the non-interactive unified scanner engine. Supported only on Linux systems; non-Linux hosts receive a clean platform warning (`UNSUPPORTED_PLATFORM`).
- **Audit History & Comparison**: Live audits are automatically persisted to a local SQLite database (`~/.lpe_sentinel/audit_history.db`). Past audits can be reloaded (`GET /api/history/<scan_id>`), compared side-by-side (`GET /api/history/compare?older=<id>&newer=<id>`), and exported.

### 4. Report Exports:

Audit reports can be exported in three secure formats from saved records without re-running scanners:
- **JSON (`GET /api/history/<scan_id>/export/json`)**: Schema-validated machine-readable audit report.
- **CSV (`GET /api/history/<scan_id>/export/csv`)**: Tabular export with spreadsheet formula injection protection (`=`, `+`, `-`, `@`, `\t`, `\r` escaping).
- **HTML (`GET /api/history/<scan_id>/export/html`)**: Standalone printable audit report with strict HTML escaping, CSS styling, and remediation guidance.

### 5. Programmatic Unified Audit:

```python
from lpe_sentinel.audit_engine import run_unified_audit

# Runs all scanners non-interactively
result = run_unified_audit()
print(f"Status: {result.status} | Findings: {result.summary['total_findings']}")
```

---

## 🧪 Running Tests

To run the complete test suite:

```bash
# Run with pytest
python -m pytest -q

# Run with standard library unittest
python -m unittest discover tests
```

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
