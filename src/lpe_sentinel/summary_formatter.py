"""
Audit Summary Formatter Module for LPE Sentinel.

Formats in-memory audit summary dictionaries into human-readable,
plain-text representations suitable for terminal display and log files.
"""

from typing import Any, Dict

try:
    from lpe_sentinel.audit_summary import VALID_SCANNER_CATEGORIES
    from lpe_sentinel.models import VALID_SEVERITIES
except ImportError:
    from audit_summary import VALID_SCANNER_CATEGORIES
    from models import VALID_SEVERITIES


def format_audit_summary(summary: Dict[str, Any]) -> str:
    """
    Format a security audit summary dictionary into a clean, readable plain-text report.

    Args:
        summary: Dictionary returned by audit_summary.summarize_findings().

    Returns:
        A formatted plain-text string containing total counts, severity breakdown,
        unique resource metrics, and scanner category distributions.

    Raises:
        TypeError: If summary or any count values have incorrect data types
                   (e.g., non-dict input, boolean where int is expected).
        ValueError: If required fields or severity/category keys are missing,
                    or if any counts are negative.
    """
    if not isinstance(summary, dict):
        raise TypeError(f"Summary must be a dictionary, got: {type(summary).__name__}")

    # Validate required top-level fields
    required_fields = (
        "total_findings",
        "severity_counts",
        "unique_affected_resources",
        "findings_by_scanner_category",
    )
    for field_name in required_fields:
        if field_name not in summary:
            raise ValueError(f"Summary dictionary is missing required field: '{field_name}'")

    # Validate total_findings
    total_findings = summary["total_findings"]
    if isinstance(total_findings, bool) or not isinstance(total_findings, int):
        raise TypeError(
            f"Field 'total_findings' must be an integer, got: {type(total_findings).__name__}"
        )
    if total_findings < 0:
        raise ValueError(
            f"Field 'total_findings' must be non-negative, got: {total_findings}"
        )

    # Validate unique_affected_resources
    unique_resources = summary["unique_affected_resources"]
    if isinstance(unique_resources, bool) or not isinstance(unique_resources, int):
        raise TypeError(
            f"Field 'unique_affected_resources' must be an integer, got: {type(unique_resources).__name__}"
        )
    if unique_resources < 0:
        raise ValueError(
            f"Field 'unique_affected_resources' must be non-negative, got: {unique_resources}"
        )

    # Validate severity_counts
    severity_counts = summary["severity_counts"]
    if not isinstance(severity_counts, dict):
        raise TypeError(
            f"Field 'severity_counts' must be a dictionary, got: {type(severity_counts).__name__}"
        )

    for sev in VALID_SEVERITIES:
        if sev not in severity_counts:
            raise ValueError(f"Field 'severity_counts' is missing required severity: '{sev}'")
        cnt = severity_counts[sev]
        if isinstance(cnt, bool) or not isinstance(cnt, int):
            raise TypeError(
                f"Severity count for '{sev}' must be an integer, got: {type(cnt).__name__}"
            )
        if cnt < 0:
            raise ValueError(f"Severity count for '{sev}' must be non-negative, got: {cnt}")

    # Validate findings_by_scanner_category
    category_counts = summary["findings_by_scanner_category"]
    if not isinstance(category_counts, dict):
        raise TypeError(
            f"Field 'findings_by_scanner_category' must be a dictionary, got: {type(category_counts).__name__}"
        )

    for cat in VALID_SCANNER_CATEGORIES:
        if cat not in category_counts:
            raise ValueError(
                f"Field 'findings_by_scanner_category' is missing required category: '{cat}'"
            )
        cnt = category_counts[cat]
        if isinstance(cnt, bool) or not isinstance(cnt, int):
            raise TypeError(
                f"Category count for '{cat}' must be an integer, got: {type(cnt).__name__}"
            )
        if cnt < 0:
            raise ValueError(f"Category count for '{cat}' must be non-negative, got: {cnt}")

    # Build plain-text layout
    lines = [
        "=" * 50,
        "              AUDIT FINDINGS SUMMARY              ",
        "=" * 50,
        f"Total Findings            : {total_findings}",
        f"Unique Affected Resources : {unique_resources}",
        "",
        "Severity Breakdown:",
        f"  - CRITICAL : {severity_counts['CRITICAL']}",
        f"  - HIGH     : {severity_counts['HIGH']}",
        f"  - MEDIUM   : {severity_counts['MEDIUM']}",
        f"  - LOW      : {severity_counts['LOW']}",
        f"  - INFO     : {severity_counts['INFO']}",
        "",
        "Scanner Categories:",
        f"  - SUID     : {category_counts['SUID']}",
        f"  - SGID     : {category_counts['SGID']}",
        f"  - SUDO     : {category_counts['SUDO']}",
        f"  - PERM     : {category_counts['PERM']}",
        f"  - OTHER    : {category_counts['OTHER']}",
        "=" * 50,
    ]

    return "\n".join(lines)
