"""
Sudo Configuration Auditor Module for LPE Sentinel.

Audits explicitly specified sudoers configuration files on Linux for common
security review patterns:
  - NOPASSWD privilege rules (SUDO-001)
  - Unrestricted ALL command specifications (SUDO-002)
  - Wildcard-heavy command patterns (SUDO-003)

Strictly read-only: does not execute commands, alter system files, or read
unspecified locations. Evidence contains only pattern categories and line numbers.
"""

import os
import platform
import re
import stat
import warnings
from typing import Any, Iterable, List

from lpe_sentinel.models import Finding

MITRE_ATTACK_ID = "T1548.003"


def is_linux_platform() -> bool:
    """Check if the current host operating system is Linux."""
    return platform.system().strip().lower() == "linux"


def _get_file_stat(file_path: str) -> os.stat_result:
    """
    Retrieve file stat without following symlinks.

    Separated for robustness and cross-platform testability.
    """
    return os.lstat(file_path)


def _check_sudo_rule_line(line: str, line_no: int, file_path: str) -> List[Finding]:
    """
    Inspect a single non-comment sudoers configuration line for risk patterns.

    Returns:
        List of Finding objects for any matched patterns on this line.
    """
    findings: List[Finding] = []
    abs_path = os.path.abspath(file_path)

    # 1. Detect NOPASSWD tag
    if re.search(r"\bNOPASSWD\b", line, re.IGNORECASE):
        findings.append(
            Finding(
                finding_id="SUDO-001",
                title="Sudo NOPASSWD Rule Detected",
                severity="MEDIUM",
                description=(
                    "A sudo rule was identified containing the NOPASSWD tag, allowing execution "
                    "of commands without password authentication. If permitted commands can be "
                    "manipulated, unprivileged users may escalate privileges."
                ),
                evidence=f"Line {line_no}: Matched NOPASSWD tag",
                affected_resource=abs_path,
                recommendation=(
                    "Review whether passwordless execution is strictly required for this rule. "
                    "Enforce least privilege and restrict target command arguments."
                ),
                mitre_attack=MITRE_ATTACK_ID,
            )
        )

    # Split command specification (typically after '=' in sudoers syntax)
    if "=" in line:
        parts = line.split("=", 1)
        cmd_part = parts[1]
    else:
        cmd_part = line

    # Remove runas specifications like (ALL:ALL) or (root) to avoid matching runas as a command
    cleaned_cmd = re.sub(r"\([^)]*\)", "", cmd_part).strip()

    # 2. Detect unrestricted ALL command specification
    # Matches '= ALL', 'NOPASSWD: ALL', or 'ALL' as executable target
    if re.search(r"(?:^|[\s:,])ALL\b", cleaned_cmd):
        findings.append(
            Finding(
                finding_id="SUDO-002",
                title="Unrestricted Sudo ALL Command Rule Detected",
                severity="MEDIUM",
                description=(
                    "A sudo rule appears to permit execution of ALL commands. Allowing blanket "
                    "administrative execution grants broad control and circumvents least privilege."
                ),
                evidence=f"Line {line_no}: Matched unrestricted ALL command specification",
                affected_resource=abs_path,
                recommendation=(
                    "Restrict sudo permissions to specific, required binary paths rather than "
                    "granting blanket ALL administrative command access."
                ),
                mitre_attack=MITRE_ATTACK_ID,
            )
        )

    # 3. Detect Wildcard pattern in command specification
    if "*" in cleaned_cmd:
        findings.append(
            Finding(
                finding_id="SUDO-003",
                title="Wildcard Pattern in Sudo Command Rule Detected",
                severity="LOW",
                description=(
                    "A sudo rule includes wildcard patterns (*) in command paths or parameters. "
                    "Wildcards in sudoers can allow unexpected command invocation or argument bypass."
                ),
                evidence=f"Line {line_no}: Matched wildcard (*) command specification",
                affected_resource=abs_path,
                recommendation=(
                    "Specify exact command paths and parameters rather than wildcards (*) to prevent "
                    "unintended argument or command expansion."
                ),
                mitre_attack=MITRE_ATTACK_ID,
            )
        )

    return findings


def scan_sudo_config(target_paths: Iterable[Any]) -> List[Finding]:
    """
    Audit an explicit list of sudoers configuration files for potential risk patterns.

    Args:
        target_paths: An explicit list or iterable of configuration file paths.

    Returns:
        List of Finding objects for detected review patterns.
        On unsupported operating systems (non-Linux), issues a RuntimeWarning and returns [].
    """
    if not is_linux_platform():
        current_os = platform.system()
        warnings.warn(
            f"Sudo configuration auditing is only supported on Linux. "
            f"Current platform is '{current_os}'. No audit performed.",
            RuntimeWarning,
            stacklevel=2,
        )
        return []

    findings: List[Finding] = []

    for path_entry in target_paths:
        try:
            raw_path = str(path_entry).strip() if path_entry is not None else ""
        except Exception:
            continue

        if not raw_path:
            continue

        try:
            st = _get_file_stat(raw_path)
        except (OSError, PermissionError, FileNotFoundError):
            continue

        # Skip symlinks without following
        if stat.S_ISLNK(st.st_mode):
            continue

        # Inspect regular files only
        if not stat.S_ISREG(st.st_mode):
            continue

        abs_path = os.path.abspath(raw_path)

        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except (OSError, PermissionError, FileNotFoundError):
            continue

        for line_no, raw_line in enumerate(lines, 1):
            line = raw_line.strip()

            # Ignore blank lines
            if not line:
                continue

            # Ignore comments
            if line.startswith("#"):
                continue

            rule_findings = _check_sudo_rule_line(line, line_no, abs_path)
            findings.extend(rule_findings)

    return findings
