"""
Unit tests for Finding data model (models.py).
"""

import json
import sys
import unittest
from pathlib import Path

# Add 'src' to sys.path so tests can import lpe_sentinel modules
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lpe_sentinel.models import VALID_SEVERITIES, Finding


class TestFindingModel(unittest.TestCase):
    """Test suite for Finding data model creation, validation, and serialization."""

    def test_valid_finding_creation(self) -> None:
        """Verify that a valid Finding can be instantiated with all fields."""
        finding = Finding(
            finding_id="SUID-001",
            title="Standard SUID Binary Identified",
            severity="LOW",
            description="A binary was found with the SUID bit enabled.",
            evidence="Path: /usr/bin/passwd, Permissions: -rwsr-xr-x",
            affected_resource="/usr/bin/passwd",
            recommendation="Verify whether SUID permission is required for this binary.",
            mitre_attack="T1548.001",
        )

        self.assertEqual(finding.finding_id, "SUID-001")
        self.assertEqual(finding.title, "Standard SUID Binary Identified")
        self.assertEqual(finding.severity, "LOW")
        self.assertEqual(finding.affected_resource, "/usr/bin/passwd")
        self.assertEqual(finding.mitre_attack, "T1548.001")

    def test_default_optional_values(self) -> None:
        """Verify that mitre_attack defaults to None when not provided."""
        finding = Finding(
            finding_id="FILE-001",
            title="World-Writable Configuration File",
            severity="HIGH",
            description="A system configuration file is world-writable.",
            evidence="Permissions: -rw-rw-rw-",
            affected_resource="/etc/test.conf",
            recommendation="Restrict write access to root user only.",
        )

        self.assertIsNone(finding.mitre_attack)

    def test_severity_case_insensitivity(self) -> None:
        """Verify that lowercase/mixed severity strings are normalized to uppercase."""
        for sev in ("info", "low", "medium", "high", "critical"):
            finding = Finding(
                finding_id="TEST-001",
                title="Test Title",
                severity=sev,
                description="Test description",
                evidence="Safe evidence snippet",
                affected_resource="/test/resource",
                recommendation="Test recommendation",
            )
            self.assertEqual(finding.severity, sev.upper())

    def test_invalid_severity_raises_error(self) -> None:
        """Verify that invalid severity values raise a ValueError."""
        invalid_severities = ["FATAL", "URGENT", "DANGEROUS", "UNKNOWN", "", "123"]

        for invalid_sev in invalid_severities:
            with self.subTest(severity=invalid_sev):
                with self.assertRaises(ValueError) as ctx:
                    Finding(
                        finding_id="TEST-001",
                        title="Test Title",
                        severity=invalid_sev,
                        description="Test description",
                        evidence="Evidence text",
                        affected_resource="/test/path",
                        recommendation="Test recommendation",
                    )
                self.assertIn("Invalid severity", str(ctx.exception))

    def test_required_fields_validation(self) -> None:
        """Verify that empty or whitespace-only required fields raise a ValueError."""
        base_args = {
            "finding_id": "TEST-001",
            "title": "Test Title",
            "severity": "MEDIUM",
            "description": "Test description",
            "evidence": "Safe evidence",
            "affected_resource": "/etc/test",
            "recommendation": "Test recommendation",
        }

        required_string_fields = [
            "finding_id",
            "title",
            "description",
            "evidence",
            "affected_resource",
            "recommendation",
        ]

        # Test each required field when set to empty string or whitespace
        for field in required_string_fields:
            with self.subTest(empty_field=field):
                invalid_args = dict(base_args)
                invalid_args[field] = "   "
                with self.assertRaises(ValueError) as ctx:
                    Finding(**invalid_args)
                self.assertIn(f"Field '{field}' must be a non-empty string", str(ctx.exception))

    def test_to_dict_and_json_serialization(self) -> None:
        """Verify to_dict returns a JSON-serializable dictionary matching model values."""
        finding = Finding(
            finding_id="CRON-001",
            title="Insecure Cron Job Script",
            severity="CRITICAL",
            description="Cron job runs an insecurely permissioned script.",
            evidence="Cron entry: * * * * * root /opt/backup.sh (mode 0777)",
            affected_resource="/opt/backup.sh",
            recommendation="Change file permissions to 0750 or 0700 owned by root.",
            mitre_attack="T1053.003",
        )

        finding_dict = finding.to_dict()
        self.assertIsInstance(finding_dict, dict)
        self.assertEqual(finding_dict["finding_id"], "CRON-001")
        self.assertEqual(finding_dict["severity"], "CRITICAL")
        self.assertEqual(finding_dict["mitre_attack"], "T1053.003")

        # Must serialize cleanly using standard library json.dumps
        serialized = json.dumps(finding_dict)
        self.assertIsInstance(serialized, str)

        # Deserialize and verify round-trip integrity
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized, finding_dict)


if __name__ == "__main__":
    unittest.main()
