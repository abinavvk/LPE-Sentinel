"""
Data models for LPE Sentinel security audit findings.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

VALID_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass
class Finding:
    """
    Standard data model representing a single security audit finding.

    Attributes:
        finding_id: Stable identifier for the finding type (e.g., 'SUID-001').
        title: Short human-readable title.
        severity: Severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL).
        description: Explanation of the identified issue.
        evidence: Safe, concise supporting evidence (no secrets/passwords).
        affected_resource: The relevant file, path, or system configuration.
        recommendation: Remediation or mitigation guidance.
        mitre_attack: Optional MITRE ATT&CK technique reference (e.g., 'T1548.001').
    """

    finding_id: str
    title: str
    severity: str
    description: str
    evidence: str
    affected_resource: str
    recommendation: str
    mitre_attack: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate required fields and severity upon instantiation."""
        # Validate required string fields
        required_fields = {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "affected_resource": self.affected_resource,
            "recommendation": self.recommendation,
        }

        for field_name, value in required_fields.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Field '{field_name}' must be a non-empty string, got: {value!r}"
                )

        # Validate and normalize severity
        if not isinstance(self.severity, str):
            raise ValueError(
                f"Field 'severity' must be a string, got: {type(self.severity).__name__}"
            )

        normalized_severity = self.severity.strip().upper()
        if normalized_severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{self.severity}'. Must be one of: {', '.join(VALID_SEVERITIES)}"
            )

        self.severity = normalized_severity

        # Validate mitre_attack if provided
        if self.mitre_attack is not None:
            if not isinstance(self.mitre_attack, str) or not self.mitre_attack.strip():
                raise ValueError("Field 'mitre_attack' must be None or a non-empty string.")

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the Finding instance into a standard JSON-compatible dictionary.

        Returns:
            Dictionary containing all finding attributes.
        """
        return asdict(self)
