"""
Unified Security Audit Orchestrator Module for LPE Sentinel.

Provides a non-interactive, programmatic audit engine that runs all implemented
security scanners (SUID/SGID, sensitive file permissions, sudoers configuration)
in a single unified audit session.

Strictly read-only: does not execute discovered binaries, alter permissions,
or run shell commands. Designed to be invoked directly by web backends, agents,
and test suites without interactive CLI prompts.
"""

import os
import platform
import stat
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

try:
    from lpe_sentinel import sensitive_permissions, sudo_audit
    from lpe_sentinel.audit_summary import summarize_findings
    from lpe_sentinel.models import Finding
    from lpe_sentinel.reporting import build_report_data
    from lpe_sentinel.sensitive_permissions import scan_sensitive_permissions
    from lpe_sentinel.sudo_audit import scan_sudo_config
    from lpe_sentinel.suid_sgid import is_linux_platform, scan_suid_sgid
    from lpe_sentinel.system_info import collect_system_info
except ImportError:
    import sensitive_permissions
    import sudo_audit
    from audit_summary import summarize_findings
    from models import Finding
    from reporting import build_report_data
    from sensitive_permissions import scan_sensitive_permissions
    from sudo_audit import scan_sudo_config
    from suid_sgid import is_linux_platform, scan_suid_sgid
    from system_info import collect_system_info

# Standard documented default inspection paths on Linux
DEFAULT_SUID_SEARCH_PATHS: tuple[str, ...] = (
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
)

DEFAULT_SENSITIVE_FILE_PATHS: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
)

DEFAULT_SUDO_FILE_PATHS: tuple[str, ...] = (
    "/etc/sudoers",
)

ALL_SCANNER_NAMES: tuple[str, ...] = (
    "suid_sgid",
    "sensitive_permissions",
    "sudo_audit",
)


class ScannerStatus:
    """Execution status values for an individual scanner run."""

    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


class AuditStatus:
    """Overall status values for a unified audit session."""

    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


@dataclass
class ScannerExecutionResult:
    """
    Detailed execution outcome for an individual scanner.

    Attributes:
        scanner_name: Identifier of the scanner (e.g. 'suid_sgid').
        status: Execution status ('COMPLETED', 'PARTIAL', 'SKIPPED', 'FAILED').
        findings_count: Number of findings discovered by this scanner.
        target_paths: All paths originally provided to this scanner.
        accessible_paths: Paths successfully accessed and evaluated.
        skipped_paths: Paths skipped due to missing files or permission errors.
        error: Error message if the scanner failed, or None.
        message: Informational message about the run, coverage, or failure reason.
    """

    scanner_name: str
    status: str
    findings_count: int = 0
    target_paths: List[str] = field(default_factory=list)
    accessible_paths: List[str] = field(default_factory=list)
    skipped_paths: List[str] = field(default_factory=list)
    error: Optional[str] = None
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class AuditConfig:
    """
    Configuration options for running a unified security audit.

    Attributes:
        suid_paths: Optional directory paths for SUID/SGID scanning.
                    If None, uses DEFAULT_SUID_SEARCH_PATHS.
        sensitive_file_paths: Optional file paths for sensitive permissions check.
                              If None, uses DEFAULT_SENSITIVE_FILE_PATHS.
        sudo_file_paths: Optional file paths for sudoers audit.
                         If None, uses DEFAULT_SUDO_FILE_PATHS.
        enabled_scanners: Tuple or list of scanner names to execute.
                          Defaults to ALL_SCANNER_NAMES.
        collect_sys_info: Whether to automatically collect host metadata.
    """

    suid_paths: Optional[Iterable[Union[str, Path]]] = None
    sensitive_file_paths: Optional[Iterable[Union[str, Path]]] = None
    sudo_file_paths: Optional[Iterable[Union[str, Path]]] = None
    enabled_scanners: Sequence[str] = ALL_SCANNER_NAMES
    collect_sys_info: bool = True


@dataclass
class AuditResult:
    """
    Comprehensive result of a unified security audit session.

    Attributes:
        status: Overall audit status ('COMPLETED', 'PARTIAL', 'FAILED').
        system_info: Host metadata dictionary.
        findings: List of deduplicated Finding objects discovered across all scanners.
        summary: Aggregated summary dictionary (from summarize_findings).
        scanner_results: Mapping of scanner name to ScannerExecutionResult.
        errors: List of error messages encountered during execution.
        timestamp: ISO 8601 UTC timestamp of audit execution.
    """

    status: str
    system_info: Dict[str, Any]
    findings: List[Finding]
    summary: Dict[str, Any]
    scanner_results: Dict[str, ScannerExecutionResult]
    errors: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def is_complete(self) -> bool:
        """Return True only if the audit completed all checks without errors, skips, or omissions."""
        return self.status == AuditStatus.COMPLETED

    def to_dict(self) -> Dict[str, Any]:
        """Serialize AuditResult to a JSON-compatible dictionary."""
        return {
            "status": self.status,
            "is_complete": self.is_complete,
            "timestamp": self.timestamp,
            "system_info": self.system_info,
            "summary": self.summary,
            "errors": list(self.errors),
            "scanner_results": {
                name: res.to_dict() for name, res in self.scanner_results.items()
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_report_data(self) -> Dict[str, Any]:
        """
        Generate a report dictionary conforming to the standard report schema.
        Can be validated by report_validation.validate_report_data and saved via save_report_to_file.
        """
        report = build_report_data(self.findings, system_info=self.system_info)
        report["audit_engine"] = {
            "status": self.status,
            "is_complete": self.is_complete,
            "errors": list(self.errors),
            "scanner_results": {
                name: res.to_dict() for name, res in self.scanner_results.items()
            },
        }
        return report


def _normalize_paths(
    paths: Optional[Iterable[Union[str, Path]]],
    default_paths: tuple[str, ...],
) -> List[str]:
    """Normalize input paths into a list of strings, falling back to defaults if None."""
    if paths is None:
        return list(default_paths)
    result: List[str] = []
    try:
        for p in paths:
            if p is not None:
                s = str(p).strip()
                if s:
                    result.append(s)
    except TypeError:
        return list(default_paths)
    return result


def _inspect_suid_paths(paths: List[str]) -> tuple[List[str], List[str]]:
    """
    Check accessibility of directory search paths for SUID/SGID scanning.
    Returns (accessible_paths, skipped_paths).
    """
    accessible: List[str] = []
    skipped: List[str] = []
    for p in paths:
        try:
            target = Path(p).resolve()
            if not target.exists():
                skipped.append(f"{p} (directory does not exist)")
            elif not target.is_dir():
                skipped.append(f"{p} (path is not a directory)")
            else:
                try:
                    os.scandir(str(target)).close()
                    accessible.append(str(target))
                except PermissionError:
                    skipped.append(f"{p} (permission denied)")
        except Exception as exc:
            skipped.append(f"{p} ({exc})")
    return accessible, skipped


def _inspect_sensitive_file_paths(paths: List[str]) -> tuple[List[str], List[str]]:
    """
    Check accessibility of file paths for sensitive permissions scanning.
    Returns (accessible_paths, skipped_paths).
    """
    accessible: List[str] = []
    skipped: List[str] = []
    stat_fn = getattr(sensitive_permissions, "_get_file_stat", os.lstat)

    for p in paths:
        try:
            st = stat_fn(p)
            if stat.S_ISLNK(st.st_mode):
                skipped.append(f"{p} (symbolic link skipped)")
            elif not stat.S_ISREG(st.st_mode):
                skipped.append(f"{p} (not a regular file)")
            else:
                accessible.append(os.path.abspath(p))
        except FileNotFoundError:
            skipped.append(f"{p} (file not found)")
        except PermissionError:
            skipped.append(f"{p} (permission denied)")
        except Exception as exc:
            skipped.append(f"{p} ({exc})")
    return accessible, skipped


def _inspect_sudo_file_paths(paths: List[str]) -> tuple[List[str], List[str]]:
    """
    Check accessibility and read permissions of sudo configuration files.
    Returns (accessible_paths, skipped_paths).
    """
    accessible: List[str] = []
    skipped: List[str] = []
    stat_fn = getattr(sudo_audit, "_get_file_stat", os.lstat)

    for p in paths:
        try:
            st = stat_fn(p)
            if stat.S_ISLNK(st.st_mode):
                skipped.append(f"{p} (symbolic link skipped)")
            elif not stat.S_ISREG(st.st_mode):
                skipped.append(f"{p} (not a regular file)")
            else:
                abs_path = os.path.abspath(p)
                # Verify read permissions without storing or logging rule content
                with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                    _ = f.read(1)
                accessible.append(abs_path)
        except FileNotFoundError:
            skipped.append(f"{p} (file not found)")
        except PermissionError:
            skipped.append(f"{p} (permission denied)")
        except Exception as exc:
            skipped.append(f"{p} ({exc})")
    return accessible, skipped


def run_unified_audit(
    config: Optional[AuditConfig] = None,
    suid_paths: Optional[Iterable[Union[str, Path]]] = None,
    sensitive_file_paths: Optional[Iterable[Union[str, Path]]] = None,
    sudo_file_paths: Optional[Iterable[Union[str, Path]]] = None,
    enabled_scanners: Optional[Sequence[str]] = None,
    collect_sys_info: bool = True,
    system_info: Optional[Dict[str, Any]] = None,
) -> AuditResult:
    """
    Execute all currently implemented security scanners in a single unified session.

    This function does NOT use interactive prompts. It collects host details, runs
    the selected scanners over configurable or default paths, isolates scanner failures,
    deduplicates findings, and calculates a summary report.

    Args:
        config: Optional AuditConfig instance. If provided, overrides individual kwargs.
        suid_paths: Directory paths for SUID/SGID scanning. Defaults to DEFAULT_SUID_SEARCH_PATHS.
        sensitive_file_paths: File paths for permission checking. Defaults to DEFAULT_SENSITIVE_FILE_PATHS.
        sudo_file_paths: File paths for sudoers audit. Defaults to DEFAULT_SUDO_FILE_PATHS.
        enabled_scanners: Subset of scanners to run. Defaults to ALL_SCANNER_NAMES.
        collect_sys_info: If True and system_info is None, collects host metadata.
        system_info: Optional pre-collected system information dictionary.

    Returns:
        AuditResult instance containing status, findings, summary, and scanner metrics.
    """
    if config is not None:
        suid_paths = config.suid_paths if config.suid_paths is not None else suid_paths
        sensitive_file_paths = (
            config.sensitive_file_paths
            if config.sensitive_file_paths is not None
            else sensitive_file_paths
        )
        sudo_file_paths = (
            config.sudo_file_paths
            if config.sudo_file_paths is not None
            else sudo_file_paths
        )
        if config.enabled_scanners is not None:
            enabled_scanners = config.enabled_scanners
        collect_sys_info = config.collect_sys_info

    selected_scanners = set(
        enabled_scanners if enabled_scanners is not None else ALL_SCANNER_NAMES
    )

    # Collect host metadata if requested
    if system_info is not None:
        sys_info = dict(system_info)
    elif collect_sys_info:
        try:
            sys_info = collect_system_info()
        except Exception as exc:
            sys_info = {"error": f"Failed to collect system info: {exc}"}
    else:
        sys_info = {}

    is_linux = is_linux_platform()
    current_os = platform.system()

    scanner_results: Dict[str, ScannerExecutionResult] = {}
    errors: List[str] = []
    raw_findings: List[Finding] = []

    # Handle explicit empty scanner selection
    if not selected_scanners:
        errors.append("No scanners were selected for execution.")
        summary = summarize_findings([])
        return AuditResult(
            status=AuditStatus.PARTIAL,
            system_info=sys_info,
            findings=[],
            summary=summary,
            scanner_results={},
            errors=errors,
        )

    # 1. SUID / SGID Scanner
    norm_suid_paths = _normalize_paths(suid_paths, DEFAULT_SUID_SEARCH_PATHS)
    if "suid_sgid" in selected_scanners:
        if not is_linux:
            scanner_results["suid_sgid"] = ScannerExecutionResult(
                scanner_name="suid_sgid",
                status=ScannerStatus.SKIPPED,
                findings_count=0,
                target_paths=norm_suid_paths,
                message=f"Scanner skipped: platform '{current_os}' is not Linux.",
            )
        else:
            accessible_dirs, skipped_dirs = _inspect_suid_paths(norm_suid_paths)
            try:
                findings = scan_suid_sgid(accessible_dirs)

                if not norm_suid_paths:
                    s_status = ScannerStatus.SKIPPED
                    msg = "No target paths were configured."
                elif len(skipped_dirs) == 0:
                    s_status = ScannerStatus.COMPLETED
                    msg = (
                        f"Scan completed with full coverage ({len(accessible_dirs)}/"
                        f"{len(norm_suid_paths)} paths inspected, {len(findings)} finding(s) discovered)."
                    )
                elif len(accessible_dirs) > 0:
                    s_status = ScannerStatus.PARTIAL
                    msg = (
                        f"Scan completed with partial coverage ({len(accessible_dirs)}/"
                        f"{len(norm_suid_paths)} paths inspected, {len(skipped_dirs)} skipped)."
                    )
                else:
                    s_status = ScannerStatus.PARTIAL
                    msg = (
                        f"Scan incomplete: all {len(skipped_dirs)} target directory "
                        "path(s) were inaccessible or missing."
                    )

                scanner_results["suid_sgid"] = ScannerExecutionResult(
                    scanner_name="suid_sgid",
                    status=s_status,
                    findings_count=len(findings),
                    target_paths=norm_suid_paths,
                    accessible_paths=accessible_dirs,
                    skipped_paths=skipped_dirs,
                    message=msg,
                )
                raw_findings.extend(findings)
            except Exception as exc:
                err_msg = f"Scanner 'suid_sgid' error: {exc}"
                errors.append(err_msg)
                scanner_results["suid_sgid"] = ScannerExecutionResult(
                    scanner_name="suid_sgid",
                    status=ScannerStatus.FAILED,
                    findings_count=0,
                    target_paths=norm_suid_paths,
                    accessible_paths=accessible_dirs,
                    skipped_paths=skipped_dirs,
                    error=err_msg,
                    message=err_msg,
                )

    # 2. Sensitive Permissions Scanner
    norm_perm_paths = _normalize_paths(
        sensitive_file_paths, DEFAULT_SENSITIVE_FILE_PATHS
    )
    if "sensitive_permissions" in selected_scanners:
        if not is_linux:
            scanner_results["sensitive_permissions"] = ScannerExecutionResult(
                scanner_name="sensitive_permissions",
                status=ScannerStatus.SKIPPED,
                findings_count=0,
                target_paths=norm_perm_paths,
                message=f"Scanner skipped: platform '{current_os}' is not Linux.",
            )
        else:
            accessible_files, skipped_files = _inspect_sensitive_file_paths(norm_perm_paths)
            try:
                findings = scan_sensitive_permissions(accessible_files)

                if not norm_perm_paths:
                    s_status = ScannerStatus.SKIPPED
                    msg = "No target paths were configured."
                elif len(skipped_files) == 0:
                    s_status = ScannerStatus.COMPLETED
                    msg = (
                        f"Scan completed with full coverage ({len(accessible_files)}/"
                        f"{len(norm_perm_paths)} paths inspected, {len(findings)} finding(s) discovered)."
                    )
                elif len(accessible_files) > 0:
                    s_status = ScannerStatus.PARTIAL
                    msg = (
                        f"Scan completed with partial coverage ({len(accessible_files)}/"
                        f"{len(norm_perm_paths)} paths inspected, {len(skipped_files)} skipped)."
                    )
                else:
                    s_status = ScannerStatus.PARTIAL
                    msg = (
                        f"Scan incomplete: all {len(skipped_files)} target file "
                        "path(s) were inaccessible or missing."
                    )

                scanner_results["sensitive_permissions"] = ScannerExecutionResult(
                    scanner_name="sensitive_permissions",
                    status=s_status,
                    findings_count=len(findings),
                    target_paths=norm_perm_paths,
                    accessible_paths=accessible_files,
                    skipped_paths=skipped_files,
                    message=msg,
                )
                raw_findings.extend(findings)
            except Exception as exc:
                err_msg = f"Scanner 'sensitive_permissions' error: {exc}"
                errors.append(err_msg)
                scanner_results["sensitive_permissions"] = ScannerExecutionResult(
                    scanner_name="sensitive_permissions",
                    status=ScannerStatus.FAILED,
                    findings_count=0,
                    target_paths=norm_perm_paths,
                    accessible_paths=accessible_files,
                    skipped_paths=skipped_files,
                    error=err_msg,
                    message=err_msg,
                )

    # 3. Sudo Configuration Scanner
    norm_sudo_paths = _normalize_paths(sudo_file_paths, DEFAULT_SUDO_FILE_PATHS)
    if "sudo_audit" in selected_scanners:
        if not is_linux:
            scanner_results["sudo_audit"] = ScannerExecutionResult(
                scanner_name="sudo_audit",
                status=ScannerStatus.SKIPPED,
                findings_count=0,
                target_paths=norm_sudo_paths,
                message=f"Scanner skipped: platform '{current_os}' is not Linux.",
            )
        else:
            accessible_sudo, skipped_sudo = _inspect_sudo_file_paths(norm_sudo_paths)
            try:
                findings = scan_sudo_config(accessible_sudo)

                if not norm_sudo_paths:
                    s_status = ScannerStatus.SKIPPED
                    msg = "No target paths were configured."
                elif len(skipped_sudo) == 0:
                    s_status = ScannerStatus.COMPLETED
                    msg = (
                        f"Scan completed with full coverage ({len(accessible_sudo)}/"
                        f"{len(norm_sudo_paths)} paths inspected, {len(findings)} finding(s) discovered)."
                    )
                elif len(accessible_sudo) > 0:
                    s_status = ScannerStatus.PARTIAL
                    msg = (
                        f"Scan completed with partial coverage ({len(accessible_sudo)}/"
                        f"{len(norm_sudo_paths)} paths inspected, {len(skipped_sudo)} skipped)."
                    )
                else:
                    s_status = ScannerStatus.PARTIAL
                    msg = (
                        f"Scan incomplete: all {len(skipped_sudo)} target file "
                        "path(s) were inaccessible or unreadable."
                    )

                scanner_results["sudo_audit"] = ScannerExecutionResult(
                    scanner_name="sudo_audit",
                    status=s_status,
                    findings_count=len(findings),
                    target_paths=norm_sudo_paths,
                    accessible_paths=accessible_sudo,
                    skipped_paths=skipped_sudo,
                    message=msg,
                )
                raw_findings.extend(findings)
            except Exception as exc:
                err_msg = f"Scanner 'sudo_audit' error: {exc}"
                errors.append(err_msg)
                scanner_results["sudo_audit"] = ScannerExecutionResult(
                    scanner_name="sudo_audit",
                    status=ScannerStatus.FAILED,
                    findings_count=0,
                    target_paths=norm_sudo_paths,
                    accessible_paths=accessible_sudo,
                    skipped_paths=skipped_sudo,
                    error=err_msg,
                    message=err_msg,
                )

    # Deduplicate findings while preserving order
    seen_keys = set()
    deduped_findings: List[Finding] = []
    for f in raw_findings:
        key = (f.finding_id, f.affected_resource, f.evidence)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped_findings.append(f)

    # Compute audit summary
    summary = summarize_findings(deduped_findings)

    # Calculate overall audit status
    statuses = [res.status for res in scanner_results.values()]
    if not statuses:
        overall_status = AuditStatus.PARTIAL
    elif all(s == ScannerStatus.COMPLETED for s in statuses):
        overall_status = AuditStatus.COMPLETED
    elif all(s == ScannerStatus.FAILED for s in statuses):
        overall_status = AuditStatus.FAILED
    else:
        # At least one scanner was partial, skipped, or failed
        overall_status = AuditStatus.PARTIAL

    return AuditResult(
        status=overall_status,
        system_info=sys_info,
        findings=deduped_findings,
        summary=summary,
        scanner_results=scanner_results,
        errors=errors,
    )
