"""
Unit tests for the Audit Summary Formatter Module (summary_formatter.py).
"""

import copy
import sys
import unittest
from pathlib import Path

# Add 'src' to sys.path so tests can import lpe_sentinel modules
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lpe_sentinel.audit_summary import summarize_findings
from lpe_sentinel.models import Finding
from lpe_sentinel.summary_formatter import format_audit_summary


class TestSummaryFormatter(unittest.TestCase):
    """Test suite verifying plain-text formatting and validation of audit summaries."""

    def setUp(self) -> None:
        """Create a baseline valid summary dictionary for testing."""
        self.valid_summary = {
            "total_findings": 4,
            "severity_counts": {
                "INFO": 1,
                "LOW": 0,
                "MEDIUM": 1,
                "HIGH": 1,
                "CRITICAL": 1,
            },
            "unique_affected_resources": 3,
            "findings_by_scanner_category": {
                "SUID": 1,
                "SGID": 0,
                "SUDO": 1,
                "PERM": 1,
                "OTHER": 1,
            },
        }

    def test_valid_summary_formatting(self) -> None:
        """Verify that a valid summary formats into a readable plain-text report."""
        output = format_audit_summary(self.valid_summary)

        self.assertIsInstance(output, str)
        self.assertIn("AUDIT FINDINGS SUMMARY", output)
        self.assertIn("Total Findings            : 4", output)
        self.assertIn("Unique Affected Resources : 3", output)

        # Check all 5 severities appear with their counts
        self.assertIn("CRITICAL : 1", output)
        self.assertIn("HIGH     : 1", output)
        self.assertIn("MEDIUM   : 1", output)
        self.assertIn("LOW      : 0", output)
        self.assertIn("INFO     : 1", output)

        # Check all 5 scanner categories appear with their counts
        self.assertIn("SUID     : 1", output)
        self.assertIn("SGID     : 0", output)
        self.assertIn("SUDO     : 1", output)
        self.assertIn("PERM     : 1", output)
        self.assertIn("OTHER    : 1", output)

    def test_zero_findings_formatting(self) -> None:
        """Verify that a summary with zero findings formats and displays all zeros."""
        zero_summary = {
            "total_findings": 0,
            "severity_counts": {
                "INFO": 0,
                "LOW": 0,
                "MEDIUM": 0,
                "HIGH": 0,
                "CRITICAL": 0,
            },
            "unique_affected_resources": 0,
            "findings_by_scanner_category": {
                "SUID": 0,
                "SGID": 0,
                "SUDO": 0,
                "PERM": 0,
                "OTHER": 0,
            },
        }
        output = format_audit_summary(zero_summary)

        self.assertIn("Total Findings            : 0", output)
        self.assertIn("Unique Affected Resources : 0", output)
        self.assertIn("CRITICAL : 0", output)
        self.assertIn("INFO     : 0", output)
        self.assertIn("SUID     : 0", output)
        self.assertIn("OTHER    : 0", output)

    def test_missing_top_level_fields(self) -> None:
        """Verify ValueError is raised when any required top-level key is missing."""
        required_fields = [
            "total_findings",
            "severity_counts",
            "unique_affected_resources",
            "findings_by_scanner_category",
        ]
        for field_name in required_fields:
            with self.subTest(missing_field=field_name):
                summary_copy = copy.deepcopy(self.valid_summary)
                del summary_copy[field_name]
                with self.assertRaises(ValueError) as ctx:
                    format_audit_summary(summary_copy)
                self.assertIn(f"missing required field: '{field_name}'", str(ctx.exception))

    def test_wrong_input_types(self) -> None:
        """Verify TypeError is raised when input or its nested values have invalid types."""
        # Non-dict top-level input
        for bad_input in [None, "string", 123, [1, 2, 3], True]:
            with self.subTest(bad_input=bad_input):
                with self.assertRaises(TypeError):
                    format_audit_summary(bad_input)  # type: ignore

        # Wrong type for total_findings
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["total_findings"] = "4"
        with self.assertRaises(TypeError):
            format_audit_summary(summary_copy)

        # Wrong type for unique_affected_resources
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["unique_affected_resources"] = [3]
        with self.assertRaises(TypeError):
            format_audit_summary(summary_copy)

        # Wrong type for severity_counts
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["severity_counts"] = "not_a_dict"
        with self.assertRaises(TypeError):
            format_audit_summary(summary_copy)

        # Wrong type for findings_by_scanner_category
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["findings_by_scanner_category"] = [1, 2, 3]
        with self.assertRaises(TypeError):
            format_audit_summary(summary_copy)

    def test_boolean_counts_rejected(self) -> None:
        """Verify booleans are rejected as integers in all count fields."""
        # Boolean in total_findings
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["total_findings"] = True
        with self.assertRaises(TypeError):
            format_audit_summary(summary_copy)

        # Boolean in unique_affected_resources
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["unique_affected_resources"] = False
        with self.assertRaises(TypeError):
            format_audit_summary(summary_copy)

        # Boolean in severity_counts
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["severity_counts"]["HIGH"] = True
        with self.assertRaises(TypeError):
            format_audit_summary(summary_copy)

        # Boolean in findings_by_scanner_category
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["findings_by_scanner_category"]["PERM"] = False
        with self.assertRaises(TypeError):
            format_audit_summary(summary_copy)

    def test_negative_counts_rejected(self) -> None:
        """Verify ValueError is raised for negative numbers in any count field."""
        # Negative total_findings
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["total_findings"] = -1
        with self.assertRaises(ValueError):
            format_audit_summary(summary_copy)

        # Negative unique_affected_resources
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["unique_affected_resources"] = -5
        with self.assertRaises(ValueError):
            format_audit_summary(summary_copy)

        # Negative severity_counts
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["severity_counts"]["MEDIUM"] = -1
        with self.assertRaises(ValueError):
            format_audit_summary(summary_copy)

        # Negative findings_by_scanner_category
        summary_copy = copy.deepcopy(self.valid_summary)
        summary_copy["findings_by_scanner_category"]["SUID"] = -2
        with self.assertRaises(ValueError):
            format_audit_summary(summary_copy)

    def test_missing_severity_key(self) -> None:
        """Verify ValueError is raised when any of the 5 severities is missing."""
        for sev in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            with self.subTest(missing_sev=sev):
                summary_copy = copy.deepcopy(self.valid_summary)
                del summary_copy["severity_counts"][sev]
                with self.assertRaises(ValueError) as ctx:
                    format_audit_summary(summary_copy)
                self.assertIn(f"missing required severity: '{sev}'", str(ctx.exception))

    def test_missing_category_key(self) -> None:
        """Verify ValueError is raised when any of the 5 scanner categories is missing."""
        for cat in ["SUID", "SGID", "SUDO", "PERM", "OTHER"]:
            with self.subTest(missing_cat=cat):
                summary_copy = copy.deepcopy(self.valid_summary)
                del summary_copy["findings_by_scanner_category"][cat]
                with self.assertRaises(ValueError) as ctx:
                    format_audit_summary(summary_copy)
                self.assertIn(f"missing required category: '{cat}'", str(ctx.exception))

    def test_input_summary_immutability(self) -> None:
        """Verify that format_audit_summary does not mutate the passed summary dict."""
        summary_copy = copy.deepcopy(self.valid_summary)
        format_audit_summary(self.valid_summary)
        self.assertEqual(self.valid_summary, summary_copy)

    def test_integration_with_summarize_findings(self) -> None:
        """Verify output of summarize_findings formats cleanly without error."""
        finding1 = Finding(
            finding_id="SUID-001",
            title="SUID Test",
            severity="INFO",
            description="Test SUID.",
            evidence="Mode 0o4755",
            affected_resource="/bin/ping",
            recommendation="Review.",
        )
        finding2 = Finding(
            finding_id="SUDO-001",
            title="Sudo Test",
            severity="HIGH",
            description="Test Sudo.",
            evidence="NOPASSWD",
            affected_resource="/etc/sudoers",
            recommendation="Review.",
        )
        summary = summarize_findings([finding1, finding2])
        formatted = format_audit_summary(summary)

        self.assertIn("Total Findings            : 2", formatted)
        self.assertIn("Unique Affected Resources : 2", formatted)
        self.assertIn("INFO     : 1", formatted)
        self.assertIn("HIGH     : 1", formatted)
        self.assertIn("SUID     : 1", formatted)
        self.assertIn("SUDO     : 1", formatted)


if __name__ == "__main__":
    unittest.main()
