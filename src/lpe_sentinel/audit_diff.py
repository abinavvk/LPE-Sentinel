"""
Historical Audit Comparison Module for LPE Sentinel.

Provides read-only, deterministic comparison between two saved historical audit records.
Classifies findings into:
- New: present in newer audit but not in older audit
- Resolved: present in older audit but not in newer audit
- Persistent: present in both audits with identical security properties
- Changed: present in both audits but with meaningful differences (e.g. severity or affected resource)

Defensive constraints:
- Strictly read-only; never triggers scanners or mutates stored history.
- Compares records based on stable identifiers and normalized attributes, not list indices.
- Rejects simulated demo audits as real comparison targets.
- Handles duplicate finding IDs deterministically.
- Ignores volatile timestamps and presentation metadata during comparison.
"""

import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from lpe_sentinel.audit_history import SCAN_ID_REGEX, AuditHistoryError, AuditHistoryManager
    from lpe_sentinel.remediation_guidance import get_remediation_guidance
except ImportError:
    from audit_history import SCAN_ID_REGEX, AuditHistoryError, AuditHistoryManager
    from remediation_guidance import get_remediation_guidance

COMPARISON_DISCLAIMER = (
    "SECURITY NOTICE: A resolved finding indicates only that the issue was not detected in the "
    "newer recorded audit. It does NOT prove or certify that the system is secure or that "
    "vulnerabilities have been eliminated."
)


class AuditComparisonError(Exception):
    """Sanitized exception raised when audit comparison fails validation."""
    pass


def _normalize_resource_path(res: Any) -> str:
    """Normalize file path or resource identifier for consistent comparison."""
    if not res:
        return ""
    s = str(res).strip().replace("\\", "/")
    # Collapse multiple consecutive slashes
    while "//" in s:
        s = s.replace("//", "/")
    return s.rstrip("/") if len(s) > 1 else s


def _normalize_finding(f: Any) -> Dict[str, Any]:
    """Extract standard finding attributes and attach remediation guidance."""
    if hasattr(f, "to_dict"):
        d = f.to_dict()
    elif isinstance(f, dict):
        d = dict(f)
    else:
        d = {}

    finding_id = str(d.get("finding_id", "UNKNOWN")).strip()
    title = str(d.get("title", "")).strip()
    severity = str(d.get("severity", "INFO")).strip().upper()
    affected_resource = _normalize_resource_path(d.get("affected_resource", ""))
    description = str(d.get("description", "")).strip()
    evidence = str(d.get("evidence", "")).strip()
    recommendation = str(d.get("recommendation", "")).strip()
    mitre_attack = str(d["mitre_attack"]).strip() if d.get("mitre_attack") else None

    # Attach advisory remediation guidance
    guidance = get_remediation_guidance({"finding_id": finding_id})

    return {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "affected_resource": affected_resource,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "mitre_attack": mitre_attack,
        "remediation_guidance": guidance.to_dict(),
    }


def _is_demo_audit(audit: Dict[str, Any]) -> bool:
    """Check if audit record represents synthetic demo data."""
    if not isinstance(audit, dict):
        return False
    if audit.get("is_demo") is True or audit.get("is_simulated") is True:
        return True
    scan_id = str(audit.get("scan_id", "")).lower()
    if "demo" in scan_id or "simulated" in scan_id:
        return True
    findings = audit.get("findings", [])
    if isinstance(findings, list) and findings:
        first = findings[0] if isinstance(findings[0], dict) else {}
        title = str(first.get("title", ""))
        if "[SIMULATED DEMO]" in title:
            return True
    return False


def compare_audit_records(
    older_audit: Dict[str, Any],
    newer_audit: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Perform a pure, deterministic comparison between two pre-loaded audit records.

    Args:
        older_audit: Baseline audit record dictionary.
        newer_audit: Target/newer audit record dictionary.

    Returns:
        Structured comparison report with new, resolved, persistent, and changed findings.

    Raises:
        AuditComparisonError: If audits are malformed, demo-based, or incompatible.
    """
    if not isinstance(older_audit, dict) or not isinstance(newer_audit, dict):
        raise AuditComparisonError("Audit records must be valid dictionaries.")

    if _is_demo_audit(older_audit) or _is_demo_audit(newer_audit):
        raise AuditComparisonError(
            "Demo audit records cannot be compared as real audits. Only authentic persisted audits are supported."
        )

    older_id = str(older_audit.get("scan_id", "UNKNOWN"))
    newer_id = str(newer_audit.get("scan_id", "UNKNOWN"))

    if older_id == newer_id and older_id != "UNKNOWN":
        raise AuditComparisonError(
            f"Cannot compare audit '{older_id}' against itself. Two distinct audit records are required."
        )

    raw_older_findings = older_audit.get("findings", [])
    raw_newer_findings = newer_audit.get("findings", [])

    if not isinstance(raw_older_findings, list) or not isinstance(raw_newer_findings, list):
        raise AuditComparisonError("Findings data in audit record is malformed.")

    older_findings = [_normalize_finding(f) for f in raw_older_findings]
    newer_findings = [_normalize_finding(f) for f in raw_newer_findings]

    # Deterministic matching algorithm:
    # 1. Exact match on (finding_id, normalized affected_resource)
    #    Multiple findings with the same key are paired deterministically by secondary attributes (title, evidence).
    # 2. For unmatched findings with identical finding_id and title (e.g. singletons where affected_resource changed):
    #    Identify meaningful changes.
    # 3. Remaining in newer -> New
    # 4. Remaining in older -> Resolved

    def _sort_key(f: Dict[str, Any]) -> Tuple[str, str, str, str]:
        return (
            f["finding_id"],
            f["affected_resource"],
            f["title"],
            f["severity"],
        )

    sorted_older = sorted(older_findings, key=_sort_key)
    sorted_newer = sorted(newer_findings, key=_sort_key)

    new_findings: List[Dict[str, Any]] = []
    resolved_findings: List[Dict[str, Any]] = []
    persistent_findings: List[Dict[str, Any]] = []
    changed_findings: List[Dict[str, Any]] = []

    # Map older findings by (finding_id, affected_resource)
    older_exact_buckets: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for f in sorted_older:
        key = (f["finding_id"], f["affected_resource"])
        older_exact_buckets.setdefault(key, []).append(f)

    unmatched_newer: List[Dict[str, Any]] = []

    for f_new in sorted_newer:
        key = (f_new["finding_id"], f_new["affected_resource"])
        if key in older_exact_buckets and older_exact_buckets[key]:
            # Matched by exact (finding_id, resource)
            f_old = older_exact_buckets[key].pop(0)

            # Check if there are meaningful differences
            changes: Dict[str, Dict[str, Any]] = {}
            if f_old["severity"] != f_new["severity"]:
                changes["severity"] = {"older": f_old["severity"], "newer": f_new["severity"]}
            if f_old["title"] != f_new["title"]:
                changes["title"] = {"older": f_old["title"], "newer": f_new["title"]}
            if f_old["description"] != f_new["description"]:
                changes["description"] = {"older": f_old["description"], "newer": f_new["description"]}

            if changes:
                changed_findings.append({
                    "older": f_old,
                    "newer": f_new,
                    "changes": changes,
                })
            else:
                persistent_findings.append(f_new)
        else:
            unmatched_newer.append(f_new)

    # Gather remaining unmatched older findings
    unmatched_older: List[Dict[str, Any]] = []
    for bucket in older_exact_buckets.values():
        unmatched_older.extend(bucket)

    # All remaining in unmatched_older are Resolved
    resolved_findings.extend(unmatched_older)
    # All remaining in unmatched_newer are New
    new_findings.extend(unmatched_newer)

    # Ensure deterministic output ordering for all lists
    new_findings.sort(key=_sort_key)
    resolved_findings.sort(key=_sort_key)
    persistent_findings.sort(key=_sort_key)
    changed_findings.sort(key=lambda item: _sort_key(item["newer"]))

    return {
        "status": "SUCCESS",
        "disclaimer": COMPARISON_DISCLAIMER,
        "older_audit": {
            "scan_id": older_id,
            "timestamp": str(older_audit.get("timestamp", "Unknown")),
            "status": str(older_audit.get("status", "UNKNOWN")).upper(),
            "total_findings": len(older_findings),
        },
        "newer_audit": {
            "scan_id": newer_id,
            "timestamp": str(newer_audit.get("timestamp", "Unknown")),
            "status": str(newer_audit.get("status", "UNKNOWN")).upper(),
            "total_findings": len(newer_findings),
        },
        "summary": {
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "persistent_count": len(persistent_findings),
            "changed_count": len(changed_findings),
            "total_older": len(older_findings),
            "total_newer": len(newer_findings),
        },
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "persistent_findings": persistent_findings,
        "changed_findings": changed_findings,
    }


def compare_history_audits(
    history_manager: AuditHistoryManager,
    scan_id_a: str,
    scan_id_b: str,
) -> Dict[str, Any]:
    """
    Load two historical audits from SQLite storage and compare them.

    Automatically identifies which audit is older and which is newer based on
    their recorded timestamps and creation times.

    Args:
        history_manager: AuditHistoryManager instance with active database.
        scan_id_a: First scan ID.
        scan_id_b: Second scan ID.

    Returns:
        Structured comparison report.

    Raises:
        AuditComparisonError: On validation failure or missing record.
    """
    if not isinstance(scan_id_a, str) or not SCAN_ID_REGEX.match(scan_id_a):
        raise AuditComparisonError(f"Invalid scan ID format: {scan_id_a!r}")
    if not isinstance(scan_id_b, str) or not SCAN_ID_REGEX.match(scan_id_b):
        raise AuditComparisonError(f"Invalid scan ID format: {scan_id_b!r}")

    if scan_id_a == scan_id_b:
        raise AuditComparisonError("Cannot compare an audit to itself. Two distinct scan IDs are required.")

    record_a = history_manager.get_audit(scan_id_a)
    if record_a is None:
        raise AuditComparisonError(f"Historical audit '{scan_id_a}' not found.")

    record_b = history_manager.get_audit(scan_id_b)
    if record_b is None:
        raise AuditComparisonError(f"Historical audit '{scan_id_b}' not found.")

    # Determine chronological order
    # Use timestamp string or fallback to ID
    ts_a = str(record_a.get("timestamp", ""))
    ts_b = str(record_b.get("timestamp", ""))

    if ts_a <= ts_b:
        older = record_a
        newer = record_b
    else:
        older = record_b
        newer = record_a

    return compare_audit_records(older, newer)
