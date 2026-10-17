"""
Sensitive File Permission Scanner Module for LPE Sentinel.

Inspects an explicit list of file paths on Linux to detect insecure
write permissions (world-writable or group-writable).
Strictly read-only: does not read file contents, change permissions, or follow symlinks.
"""

import os
import platform
import stat
import warnings
from typing import Any, Iterable, List

from lpe_sentinel.models import Finding

MITRE_ATTACK_ID = "T1222.002"


def is_linux_platform() -> bool:
    """Check if the current host operating system is Linux."""
    return platform.system().strip().lower() == "linux"


def _get_file_stat(file_path: str) -> os.stat_result:
    """
    Retrieve file stat without following symlinks.

    Separated for robustness and testability across platforms.
    """
    return os.lstat(file_path)


def _build_permission_finding(
    file_path: str, mode: int, is_world_writable: bool, is_group_writable: bool
) -> Finding:
    """
    Construct a structured Finding instance for an insecurely permissioned file.

    Severities:
      - HIGH for world-writable sensitive configuration files.
      - MEDIUM for group-writable files.
    """
    octal_perms = oct(mode & 0o7777)
    symbolic_perms = stat.filemode(mode)
    abs_path = os.path.abspath(file_path)

    if is_world_writable:
        finding_id = "PERM-001"
        severity = "HIGH"
        title = "World-Writable File Permissions"
        description = (
            f"The file '{abs_path}' is writable by any user on the system (world-writable). "
            "If this file is used by privileged processes or contains sensitive configuration, "
            "unauthorized modification may lead to privilege escalation or system compromise."
        )
        recommendation = (
            f"Remove world-write permissions using: chmod o-w '{abs_path}'. "
            "Ensure the file is owned by root or an appropriate service account."
        )
    else:
        finding_id = "PERM-002"
        severity = "MEDIUM"
        title = "Group-Writable File Permissions"
        description = (
            f"The file '{abs_path}' is writable by members of its owning group. "
            "If non-privileged users belong to this group, they may modify critical configurations."
        )
        recommendation = (
            f"Review group membership and remove unnecessary group-write access using: "
            f"chmod g-w '{abs_path}'."
        )

    evidence = f"Permissions: {symbolic_perms} ({octal_perms})"

    return Finding(
        finding_id=finding_id,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        affected_resource=abs_path,
        recommendation=recommendation,
        mitre_attack=MITRE_ATTACK_ID,
    )


def scan_sensitive_permissions(target_paths: Iterable[Any]) -> List[Finding]:
    """
    Inspect an explicit list of file paths for insecure write permissions.

    Args:
        target_paths: An explicit list or iterable of file paths to inspect.

    Returns:
        List of Finding objects for discovered group- or world-writable files.
        On unsupported operating systems (non-Linux), issues a RuntimeWarning and returns [].
    """
    if not is_linux_platform():
        current_os = platform.system()
        warnings.warn(
            f"Sensitive file permission scanning is only supported on Linux. "
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
            # Use lstat to inspect metadata without following symlinks
            st = _get_file_stat(raw_path)
        except (OSError, PermissionError, FileNotFoundError):
            continue

        mode = st.st_mode

        # If it is a symlink, do NOT follow it
        if stat.S_ISLNK(mode):
            continue

        # Inspect regular files only
        if not stat.S_ISREG(mode):
            continue

        is_world_writable = bool(mode & stat.S_IWOTH)
        is_group_writable = bool(mode & stat.S_IWGRP)

        # Only report if world-writable or group-writable
        if is_world_writable or is_group_writable:
            findings.append(
                _build_permission_finding(
                    raw_path, mode, is_world_writable, is_group_writable
                )
            )

    return findings
