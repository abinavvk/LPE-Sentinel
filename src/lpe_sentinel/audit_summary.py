"""
Audit Summary Module for LPE Sentinel.

Provides lightweight, in-memory summary calculations for collections of Finding instances,
including severity distribution, scanner category classification, and unique resource counts.
"""

from typing import Any, Dict, Iterable

try:
    from lpe_sentinel.models import VALID_SEVERITIES, Finding
except ImportError:
    from models import VALID_SEVERITIES, Finding

VALID_SCANNER_CATEGORIES = ("SUID", "SGID", "SUDO", "PERM", "OTHER")


def classify_finding_id(finding_id: str) -> str:
    """
    Determine the scanner category from a finding ID string.

    Conventions:
      - 'SUID-<num>' -> 'SUID'
      - 'SGID-<num>' -> 'SGID'
      - 'SUDO-<num>' -> 'SUDO'
      - 'PERM-<num>' -> 'PERM'

    Ambiguity Resolution:
      The scanner suid_sgid.py produces 'SUID-SGID-001' when a file has both SUID
      and SGID permissions set. Because this composite identifier refers to both
      categories simultaneously, selecting either 'SUID' or 'SGID' would silently
      invent an arbitrary precedence rule. In accordance with project requirements
      ('For IDs that do not match these conventions, classify them as OTHER'),
      composite IDs and any non-standard finding IDs are classified as 'OTHER'.

    Args:
        finding_id: The finding identifier string (e.g., 'SUID-001').

    Returns:
        One of 'SUID', 'SGID', 'SUDO', 'PERM', or 'OTHER'.
    """
    if not isinstance(finding_id, str):
        return "OTHER"

    parts = finding_id.strip().split("-")
    if len(parts) == 2:
        prefix = parts[0].upper()
        if prefix in ("SUID", "SGID", "SUDO", "PERM"):
            return prefix

    return "OTHER"


def summarize_findings(findings: Iterable[Any]) -> Dict[str, Any]:
    """
    Compute summary metrics for an iterable of Finding objects.

    Args:
        findings: An iterable or generator of Finding instances.

    Returns:
        A dictionary containing:
          - 'total_findings': Total number of findings.
          - 'severity_counts': Dictionary mapping each severity to its count.
          - 'unique_affected_resources': Integer count of unique affected resources.
          - 'findings_by_scanner_category': Dictionary mapping each scanner category to its count.

    Raises:
        TypeError: If findings is not iterable or contains items that are not Finding instances.
    """
    try:
        iterator = iter(findings)
    except TypeError:
        raise TypeError(
            f"Expected findings to be an iterable, got: {type(findings).__name__}"
        )

    severity_counts: Dict[str, int] = {sev: 0 for sev in VALID_SEVERITIES}
    category_counts: Dict[str, int] = {cat: 0 for cat in VALID_SCANNER_CATEGORIES}
    unique_resources: set[str] = set()
    total_count = 0

    for item in iterator:
        if not isinstance(item, Finding):
            raise TypeError(
                f"Expected all items in findings to be Finding instances, got: {type(item).__name__}"
            )

        total_count += 1

        # Count severity
        norm_sev = item.severity.upper() if isinstance(item.severity, str) else ""
        if norm_sev in severity_counts:
            severity_counts[norm_sev] += 1
        else:
            severity_counts[norm_sev] = severity_counts.get(norm_sev, 0) + 1

        # Track unique affected resources
        unique_resources.add(item.affected_resource)

        # Classify scanner category
        category = classify_finding_id(item.finding_id)
        category_counts[category] += 1

    return {
        "total_findings": total_count,
        "severity_counts": severity_counts,
        "unique_affected_resources": len(unique_resources),
        "findings_by_scanner_category": category_counts,
    }
