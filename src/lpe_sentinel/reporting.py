"""
Security Audit Reporting Module for LPE Sentinel.

Generates and saves structured, JSON-formatted security audit reports
from collected Finding objects and optional system metadata.
Strictly read-only with atomic, collision-safe file writes.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from lpe_sentinel import __title__, __version__
    from lpe_sentinel.models import VALID_SEVERITIES, Finding
except ImportError:
    try:
        from __init__ import __title__, __version__
    except ImportError:
        __title__ = "lpe-sentinel"
        __version__ = "0.1.0"
    from models import VALID_SEVERITIES, Finding


def build_report_data(
    findings: Iterable[Any],
    system_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Construct a JSON-compatible dictionary containing report metadata,
    severity summaries, system details, and serialized findings.

    Args:
        findings: An iterable of Finding instances.
        system_info: Optional dictionary containing host system information.

    Returns:
        Structured report dictionary.

    Raises:
        TypeError: If an element in findings is not a Finding instance,
                   or if system_info is not a dict when provided.
    """
    if system_info is not None and not isinstance(system_info, dict):
        raise TypeError(
            f"system_info must be a dictionary or None, got: {type(system_info).__name__}"
        )

    # Initialize severity counts
    severity_counts = {sev: 0 for sev in VALID_SEVERITIES}
    serialized_findings: List[Dict[str, Any]] = []

    for item in findings:
        if not isinstance(item, Finding):
            raise TypeError(
                f"Expected all items in findings to be Finding instances, got: {type(item).__name__}"
            )
        serialized_findings.append(item.to_dict())
        norm_sev = item.severity.upper()
        if norm_sev in severity_counts:
            severity_counts[norm_sev] += 1
        else:
            severity_counts[norm_sev] = 1

    # Timestamp with explicit UTC timezone in ISO 8601 format
    generation_time = datetime.now(timezone.utc).isoformat()

    report: Dict[str, Any] = {
        "report_metadata": {
            "project_name": __title__,
            "version": __version__,
            "generated_at": generation_time,
            "format_version": "1.0",
        },
        "summary": {
            "total_findings": len(serialized_findings),
            "severity_counts": severity_counts,
        },
        "system_info": system_info if system_info is not None else {},
        "findings": serialized_findings,
    }

    return report


def save_report_to_file(
    report_data: Dict[str, Any],
    output_path: str | Path,
    overwrite: bool = False,
) -> Path:
    """
    Safely write report dictionary to a JSON file.

    Features:
      - Refuses to overwrite existing files unless overwrite=True.
      - Creates parent directories only when necessary.
      - Uses atomic write pattern (writes to temporary file, flushes/syncs,
        and replaces target) to prevent corrupted partial files.

    Args:
        report_data: Dictionary report structure (from build_report_data).
        output_path: Target destination file path.
        overwrite: If True, allows overwriting an existing file.

    Returns:
        Resolved Path of the saved report.

    Raises:
        FileExistsError: If target file already exists and overwrite is False.
        TypeError: If report_data is not a dictionary.
        OSError: If directory creation or file writing fails.
    """
    if not isinstance(report_data, dict):
        raise TypeError(
            f"report_data must be a dictionary, got: {type(report_data).__name__}"
        )

    dest_path = Path(output_path).resolve()

    if dest_path.exists() and not overwrite:
        raise FileExistsError(
            f"Report file already exists at '{dest_path}'. Specify overwrite=True to replace it."
        )

    # Ensure parent directory exists
    parent_dir = dest_path.parent
    parent_dir.mkdir(parents=True, exist_ok=True)

    # Serialize JSON with clean indentation
    json_content = json.dumps(report_data, indent=2, ensure_ascii=False)

    # Atomic write: write to a temporary file in the same parent directory, then rename/replace
    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=str(parent_dir),
            delete=False,
            encoding="utf-8",
            prefix=".tmp_report_",
            suffix=".json",
        ) as tf:
            temp_file = tf.name
            tf.write(json_content)
            tf.flush()
            os.fsync(tf.fileno())

        # Atomic replace
        os.replace(temp_file, str(dest_path))
        temp_file = None
    finally:
        # Clean up temporary file if write or replace failed
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass

    return dest_path
