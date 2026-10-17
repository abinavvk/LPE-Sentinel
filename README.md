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
  * **Risky Write Permissions Scanner**: Checks explicitly supplied file paths for group- or world-writable permission bits (`0o020`, `0o002`).
  * **Sudo Configuration Auditor**: Audits explicitly supplied sudoers files for preliminary risk indicators (`NOPASSWD`, unrestricted `ALL` commands, wildcards).
  * **Session Audit Summary**: Displays cumulative findings counts, severity distributions, unique affected resource metrics, and scanner categories after each completed scan.
* **Report Generation (`[3]`)**: Safely exports cumulative session findings into a structured, validated JSON report using collision-safe atomic file writes.

---

## ⚠️ Platform Limitations & Testing Notice

* **Linux-Only Security Scanners**: The security scanner modules (`suid_sgid.py`, `sensitive_permissions.py`, and `sudo_audit.py`) rely on POSIX filesystem semantics, permission bits, and configuration syntax. On Windows or macOS, these scanners issue a warning and cleanly return without performing an audit.
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
│       ├── audit_summary.py   # In-memory findings summary and scanner categorization
│       ├── main.py            # Primary CLI entry point and menu orchestration
│       ├── models.py          # Finding data model and severity definitions
│       ├── report_validation.py # JSON report schema and data validator
│       ├── reporting.py       # Safe JSON report generator with atomic file writes
│       ├── sensitive_permissions.py # Group/world-writable file scanner (Linux only)
│       ├── sudo_audit.py      # Sudoers configuration auditor (Linux only)
│       ├── suid_sgid.py       # SUID/SGID file permission scanner (Linux only)
│       ├── summary_formatter.py # Plain-text terminal audit summary formatter
│       └── system_info.py     # Host metadata and platform detection
├── tests/                     # Comprehensive unit and integration test suites
├── .gitignore                 # Excluded files for Python, OS, and local environments
├── LICENSE                    # MIT License
├── README.md                  # Project overview and documentation
└── requirements.txt           # Standard-library only declaration
```

---

## 🚀 Getting Started

To launch the interactive CLI:

```bash
# From the project root
python src/lpe_sentinel/main.py
```

---

## 🧪 Running Tests

To run the complete test suite:

```bash
# From the project root
python -m unittest discover -s tests -v
```

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
