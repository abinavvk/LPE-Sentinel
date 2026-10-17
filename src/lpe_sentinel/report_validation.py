"""
Report Validation Module for LPE Sentinel.

Provides read-only validation of JSON security audit report data structures
against the expected schema, Finding models, and summary calculations.
"""

from datetime import datetime
from typing import Any, Dict, List, NamedTuple

try:
    from lpe_sentinel.models import VALID_SEVERITIES
except ImportError:
    from models import VALID_SEVERITIES


class ValidationResult(NamedTuple):
    """
    Structured outcome of a report data validation check.

    Attributes:
        is_valid: True if report structure and all contents are valid, False otherwise.
        errors: List of human-readable explanations of validation errors.
    """

    is_valid: bool
    errors: List[str]


def validate_report_data(report_data: Any) -> ValidationResult:
    """
    Validate a security audit report data structure.

    Checks:
      - Top-level schema (report_metadata, summary, system_info, findings).
      - Metadata fields (project_name, version, format_version, ISO 8601 timestamp with tz).
      - System information dictionary type.
      - Findings list and each finding's schema, types, and valid severity.
      - Summary counts consistency with the actual findings list.

    Args:
        report_data: Deserialized JSON report data (expected to be a dictionary).

    Returns:
        ValidationResult with is_valid status and any collected error descriptions.
    """
    if not isinstance(report_data, dict):
        return ValidationResult(
            is_valid=False,
            errors=[
                f"Report data must be a dictionary, got: {type(report_data).__name__}"
            ],
        )

    errors: List[str] = []

    # 1. Top-level section presence
    required_sections = ("report_metadata", "summary", "system_info", "findings")
    for section in required_sections:
        if section not in report_data:
            errors.append(f"Missing required top-level section: '{section}'")

    # 2. Validate report_metadata
    if "report_metadata" in report_data:
        meta = report_data["report_metadata"]
        if not isinstance(meta, dict):
            errors.append(
                f"Section 'report_metadata' must be a dictionary, got: {type(meta).__name__}"
            )
        else:
            required_meta_strings = ("project_name", "version", "format_version")
            for field_name in required_meta_strings:
                if field_name not in meta:
                    errors.append(
                        f"Missing required metadata field: 'report_metadata.{field_name}'"
                    )
                else:
                    val = meta[field_name]
                    if not isinstance(val, str) or not val.strip():
                        errors.append(
                            f"Field 'report_metadata.{field_name}' must be a non-empty string, got: {val!r}"
                        )

            if "generated_at" not in meta:
                errors.append("Missing required metadata field: 'report_metadata.generated_at'")
            else:
                timestamp = meta["generated_at"]
                if not isinstance(timestamp, str) or not timestamp.strip():
                    errors.append(
                        f"Field 'report_metadata.generated_at' must be a non-empty string, got: {timestamp!r}"
                    )
                else:
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        if dt.tzinfo is None:
                            errors.append(
                                "Field 'report_metadata.generated_at' timestamp must include timezone information."
                            )
                    except Exception:
                        errors.append(
                            f"Field 'report_metadata.generated_at' is not a valid ISO 8601 timestamp: {timestamp!r}"
                        )

    # 3. Validate system_info
    if "system_info" in report_data:
        sys_info = report_data["system_info"]
        if not isinstance(sys_info, dict):
            errors.append(
                f"Section 'system_info' must be a dictionary, got: {type(sys_info).__name__}"
            )

    # 4. Validate findings list and items
    findings_valid_structure = True
    actual_findings_count = 0
    actual_severity_counts = {sev: 0 for sev in VALID_SEVERITIES}

    if "findings" in report_data:
        findings = report_data["findings"]
        if not isinstance(findings, list):
            errors.append(
                f"Section 'findings' must be a list, got: {type(findings).__name__}"
            )
            findings_valid_structure = False
        else:
            actual_findings_count = len(findings)
            required_finding_fields = (
                "finding_id",
                "title",
                "severity",
                "description",
                "evidence",
                "affected_resource",
                "recommendation",
            )
            for idx, item in enumerate(findings):
                if not isinstance(item, dict):
                    errors.append(
                        f"Finding at index {idx} must be a dictionary, got: {type(item).__name__}"
                    )
                    continue

                for field_name in required_finding_fields:
                    if field_name not in item:
                        errors.append(
                            f"Finding at index {idx} is missing required field: '{field_name}'"
                        )
                    elif field_name != "severity":
                        val = item[field_name]
                        if not isinstance(val, str) or not val.strip():
                            errors.append(
                                f"Finding at index {idx} field '{field_name}' must be a non-empty string, got: {val!r}"
                            )

                # Validate severity
                if "severity" in item:
                    sev_val = item["severity"]
                    if not isinstance(sev_val, str):
                        errors.append(
                            f"Finding at index {idx} field 'severity' must be a string, got: {type(sev_val).__name__}"
                        )
                    elif sev_val not in VALID_SEVERITIES:
                        errors.append(
                            f"Finding at index {idx} has invalid severity: {sev_val!r}. "
                            f"Must be one of: {', '.join(VALID_SEVERITIES)}"
                        )
                    else:
                        actual_severity_counts[sev_val] += 1

                # Validate optional mitre_attack
                if "mitre_attack" in item:
                    mitre_val = item["mitre_attack"]
                    if mitre_val is not None:
                        if not isinstance(mitre_val, str) or not mitre_val.strip():
                            errors.append(
                                f"Finding at index {idx} field 'mitre_attack' must be None or a non-empty string, got: {mitre_val!r}"
                            )

    # 5. Validate summary counts and consistency
    if "summary" in report_data:
        summary = report_data["summary"]
        if not isinstance(summary, dict):
            errors.append(
                f"Section 'summary' must be a dictionary, got: {type(summary).__name__}"
            )
        else:
            # Check total_findings
            if "total_findings" not in summary:
                errors.append("Missing required summary field: 'summary.total_findings'")
            else:
                total = summary["total_findings"]
                if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                    errors.append(
                        f"Field 'summary.total_findings' must be a non-negative integer, got: {total!r}"
                    )
                elif findings_valid_structure and total != actual_findings_count:
                    errors.append(
                        f"Summary total_findings ({total}) does not match actual findings count ({actual_findings_count})."
                    )

            # Check severity_counts
            if "severity_counts" not in summary:
                errors.append("Missing required summary field: 'summary.severity_counts'")
            else:
                sev_counts = summary["severity_counts"]
                if not isinstance(sev_counts, dict):
                    errors.append(
                        f"Field 'summary.severity_counts' must be a dictionary, got: {type(sev_counts).__name__}"
                    )
                else:
                    for sev in VALID_SEVERITIES:
                        if sev not in sev_counts:
                            errors.append(
                                f"Field 'summary.severity_counts' is missing count for severity: '{sev}'"
                            )
                        else:
                            count_val = sev_counts[sev]
                            if (
                                isinstance(count_val, bool)
                                or not isinstance(count_val, int)
                                or count_val < 0
                            ):
                                errors.append(
                                    f"Severity count for '{sev}' must be a non-negative integer, got: {count_val!r}"
                                )
                            elif (
                                findings_valid_structure
                                and count_val != actual_severity_counts[sev]
                            ):
                                errors.append(
                                    f"Summary severity_counts['{sev}'] ({count_val}) does not match actual findings count ({actual_severity_counts[sev]})."
                                )

    return ValidationResult(is_valid=len(errors) == 0, errors=errors)
