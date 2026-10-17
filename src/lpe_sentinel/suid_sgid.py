"""
SUID / SGID File Permission Scanner Module for LPE Sentinel.

Recursively scans specified directories on Linux systems for files with
Set User ID (SUID) and Set Group ID (SGID) permission bits enabled.
Strictly read-only: does not execute, modify, or change file permissions.
"""

import os
import platform
import stat
import warnings
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from lpe_sentinel.models import Finding
    from lpe_sentinel.binary_risk import assess_binary_risk
except ImportError:
    from models import Finding
    try:
        from binary_risk import assess_binary_risk
    except ImportError:
        assess_binary_risk = None

# MITRE ATT&CK reference for abuse of elevation control mechanism
MITRE_ATTACK_ID = "T1548.001"


def is_linux_platform() -> bool:
    """Check if the current host operating system is Linux."""
    return platform.system().strip().lower() == "linux"


def _get_file_stat(file_path: str) -> os.stat_result:
    """
    Retrieve file stat without following symlinks.

    Separated for robustness and testability across platforms.
    """
    return os.lstat(file_path)


def _build_finding(file_path: str, st_mode: int, is_suid: bool, is_sgid: bool) -> Finding:
    """
    Construct a structured Finding instance for an identified SUID/SGID file.

    Severity is set to INFO by default for safe discovery without assuming exploitability.
    """
    octal_perms = oct(st_mode & 0o7777)
    symbolic_perms = stat.filemode(st_mode)

    if is_suid and is_sgid:
        finding_id = "SUID-SGID-001"
        title = "SUID and SGID Permissions Detected"
        description = (
            "The file has both SUID (Set User ID) and SGID (Set Group ID) permission bits "
            "enabled. When executed, it runs with elevated owner and group privileges."
        )
        recommendation = (
            "Verify whether this binary requires elevated SUID and SGID execution rights. "
            f"If unnecessary, remove special permission bits using: chmod ug-s '{file_path}'"
        )
    elif is_suid:
        finding_id = "SUID-001"
        title = "SUID Permission Detected"
        description = (
            "The file has the SUID (Set User ID) permission bit enabled. "
            "When executed, it runs with the privileges of the file owner."
        )
        recommendation = (
            "Verify whether this binary requires elevated SUID execution rights. "
            f"If unnecessary, remove the SUID bit using: chmod u-s '{file_path}'"
        )
    else:
        finding_id = "SGID-001"
        title = "SGID Permission Detected"
        description = (
            "The file has the SGID (Set Group ID) permission bit enabled. "
            "When executed, it runs with the privileges of the file group."
        )
        recommendation = (
            "Verify whether this binary requires elevated SGID execution rights. "
            f"If unnecessary, remove the SGID bit using: chmod g-s '{file_path}'"
        )

    evidence = f"Permissions: {symbolic_perms} ({octal_perms})"

    return Finding(
        finding_id=finding_id,
        title=title,
        severity="INFO",
        description=description,
        evidence=evidence,
        affected_resource=os.path.abspath(file_path),
        recommendation=recommendation,
        mitre_attack=MITRE_ATTACK_ID,
    )


def scan_suid_sgid(search_paths: Iterable[Any]) -> List[Finding]:
    """
    Recursively inspect search_paths for regular files with SUID/SGID bits enabled.

    Args:
        search_paths: An explicit list or iterable of directory paths to inspect.

    Returns:
        List of Finding objects for discovered SUID/SGID files.
        On unsupported operating systems (non-Linux), issues a RuntimeWarning and returns [].
    """
    if not is_linux_platform():
        current_os = platform.system()
        warnings.warn(
            f"SUID/SGID scanner is only supported on Linux. Current platform is '{current_os}'. "
            "No audit performed.",
            RuntimeWarning,
            stacklevel=2,
        )
        return []

    findings: List[Finding] = []

    for path_entry in search_paths:
        try:
            target_dir = Path(path_entry).resolve()
        except Exception:
            continue

        # Skip if target does not exist or is not a directory
        try:
            if not target_dir.exists() or not target_dir.is_dir():
                continue
        except (OSError, PermissionError):
            continue

        # Recursively walk directories without following directory symlinks
        for root, dirs, files in os.walk(str(target_dir), followlinks=False):
            for filename in files:
                file_path = os.path.join(root, filename)

                try:
                    # Use lstat to inspect metadata without following broken or outside symlinks
                    st = _get_file_stat(file_path)
                except (OSError, PermissionError, FileNotFoundError):
                    continue

                # Only inspect regular files
                if not stat.S_ISREG(st.st_mode):
                    continue

                mode = st.st_mode
                is_suid = bool(mode & stat.S_ISUID)
                is_sgid = bool(mode & stat.S_ISGID)

                if is_suid or is_sgid:
                    findings.append(_build_finding(file_path, mode, is_suid, is_sgid))
                    if assess_binary_risk is not None:
                        risk_finding = assess_binary_risk(file_path, mode, is_suid, is_sgid)
                        if risk_finding is not None:
                            findings.append(risk_finding)

    return findings
