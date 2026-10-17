"""
Unit tests for the Audit Summary Module (audit_summary.py).
"""

import sys
import unittest
from pathlib import Path

# Add 'src' to sys.path so tests can import lpe_sentinel modules
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lpe_sentinel.audit_summary import classify_finding_id, summarize_findings
from lpe_sentinel.models import VALID_SEVERITIES, Finding


class TestAuditSummary(unittest.TestCase):
    """Test suite verifying summary calculations, category classification, and input handling."""

    def setUp(self) -> None:
        """Create sample findings for testing."""
        self.suid_finding = Finding(
            finding_id="SUID-001",
            title="SUID Executable",
            severity="INFO",
            description="File has SUID bit.",
            evidence="Mode 0o4755",
            affected_resource="/usr/bin/passwd",
            recommendation="Review.",
            mitre_attack="T1548.001",
        )

        self.sgid_finding = Finding(
            finding_id="SGID-001",
            title="SGID Executable",
            severity="LOW",
            description="File has SGID bit.",
            evidence="Mode 0o2755",
            affected_resource="/usr/bin/wall",
            recommendation="Review.",
            mitre_attack="T1548.001",
        )

        self.sudo_finding = Finding(
            finding_id="SUDO-001",
            title="Sudo NOPASSWD",
            severity="MEDIUM",
            description="Passwordless rule.",
            evidence="Line 1: NOPASSWD",
            affected_resource="/etc/sudoers",
            recommendation="Review.",
            mitre_attack="T1548.003",
        )

        self.perm_finding = Finding(
            finding_id="PERM-001",
            title="World-Writable File",
            severity="HIGH",
            description="File is world-writable.",
            evidence="Mode 0o666",
            affected_resource="/etc/cron.d/job",
            recommendation="Fix permissions.",
            mitre_attack="T1222.002",
        )

        self.critical_finding = Finding(
            finding_id="PERM-002",
            title="Critical Root File Writable",
            severity="CRITICAL",
            description="Critical root configuration writable by others.",
            evidence="Mode 0o777",
            affected_resource="/etc/shadow",
            recommendation="Restrict permissions immediately.",
        )

        self.composite_finding = Finding(
            finding_id="SUID-SGID-001",
            title="SUID and SGID Permissions",
            severity="INFO",
            description="File has both SUID and SGID.",
            evidence="Mode 0o6755",
            affected_resource="/usr/bin/dual",
            recommendation="Review.",
        )

    def test_empty_input(self) -> None:
        """Verify summary calculations for empty collections (list, tuple, set)."""
        for empty_iterable in [[], (), set()]:
            with self.subTest(empty_iterable=type(empty_iterable).__name__):
                summary = summarize_findings(empty_iterable)

                self.assertEqual(summary["total_findings"], 0)
                self.assertEqual(summary["unique_affected_resources"], 0)

                # Ensure all severities appear with count 0
                for sev in VALID_SEVERITIES:
                    self.assertIn(sev, summary["severity_counts"])
                    self.assertEqual(summary["severity_counts"][sev], 0)

                # Ensure all scanner categories appear with count 0
                for cat in ["SUID", "SGID", "SUDO", "PERM", "OTHER"]:
                    self.assertIn(cat, summary["findings_by_scanner_category"])
                    self.assertEqual(summary["findings_by_scanner_category"][cat], 0)

    def test_each_severity_count(self) -> None:
        """Verify that findings of each severity are counted accurately."""
        findings = [
            self.suid_finding,      # INFO
            self.sgid_finding,      # LOW
            self.sudo_finding,      # MEDIUM
            self.perm_finding,      # HIGH
            self.critical_finding,  # CRITICAL
        ]
        summary = summarize_findings(findings)

        self.assertEqual(summary["total_findings"], 5)
        self.assertEqual(summary["severity_counts"]["INFO"], 1)
        self.assertEqual(summary["severity_counts"]["LOW"], 1)
        self.assertEqual(summary["severity_counts"]["MEDIUM"], 1)
        self.assertEqual(summary["severity_counts"]["HIGH"], 1)
        self.assertEqual(summary["severity_counts"]["CRITICAL"], 1)

    def test_category_classification_direct_function(self) -> None:
        """Verify classify_finding_id correctly resolves standard and non-standard IDs."""
        self.assertEqual(classify_finding_id("SUID-001"), "SUID")
        self.assertEqual(classify_finding_id("SGID-002"), "SGID")
        self.assertEqual(classify_finding_id("SUDO-001"), "SUDO")
        self.assertEqual(classify_finding_id("PERM-002"), "PERM")

        # Ambiguous composite ID SUID-SGID-001 classified as OTHER
        self.assertEqual(classify_finding_id("SUID-SGID-001"), "OTHER")

        # Non-matching prefixes
        self.assertEqual(classify_finding_id("CUSTOM-001"), "OTHER")
        self.assertEqual(classify_finding_id("KERNEL-001"), "OTHER")
        self.assertEqual(classify_finding_id(""), "OTHER")
        self.assertEqual(classify_finding_id("INVALID"), "OTHER")
        self.assertEqual(classify_finding_id(None), "OTHER")  # type: ignore

    def test_category_counts_in_summary(self) -> None:
        """Verify findings_by_scanner_category groups findings into proper buckets."""
        custom_finding = Finding(
            finding_id="CUSTOM-001",
            title="Custom Check",
            severity="LOW",
            description="Custom check.",
            evidence="Manual audit",
            affected_resource="/opt/app",
            recommendation="Review.",
        )
        findings = [
            self.suid_finding,       # SUID
            self.sgid_finding,       # SGID
            self.sudo_finding,       # SUDO
            self.perm_finding,       # PERM
            self.composite_finding,  # OTHER (SUID-SGID)
            custom_finding,          # OTHER
        ]
        summary = summarize_findings(findings)

        cats = summary["findings_by_scanner_category"]
        self.assertEqual(cats["SUID"], 1)
        self.assertEqual(cats["SGID"], 1)
        self.assertEqual(cats["SUDO"], 1)
        self.assertEqual(cats["PERM"], 1)
        self.assertEqual(cats["OTHER"], 2)

    def test_duplicate_affected_resources(self) -> None:
        """Verify unique_affected_resources accurately deduplicates resource paths."""
        # 3 findings for /etc/passwd, 2 for /etc/cron.d/job
        f1 = Finding("SUID-001", "T1", "INFO", "D1", "E1", "/etc/passwd", "R1")
        f2 = Finding("PERM-001", "T2", "HIGH", "D2", "E2", "/etc/passwd", "R2")
        f3 = Finding("PERM-002", "T3", "LOW", "D3", "E3", "/etc/passwd", "R3")
        f4 = Finding("PERM-003", "T4", "HIGH", "D4", "E4", "/etc/cron.d/job", "R4")
        f5 = Finding("PERM-004", "T5", "MEDIUM", "D5", "E5", "/etc/cron.d/job", "R5")

        summary = summarize_findings([f1, f2, f3, f4, f5])

        self.assertEqual(summary["total_findings"], 5)
        self.assertEqual(summary["unique_affected_resources"], 2)

    def test_generator_input(self) -> None:
        """Verify summarize_findings handles ordinary generator inputs properly."""
        findings_gen = (f for f in [self.suid_finding, self.sudo_finding])
        summary = summarize_findings(findings_gen)

        self.assertEqual(summary["total_findings"], 2)
        self.assertEqual(summary["severity_counts"]["INFO"], 1)
        self.assertEqual(summary["severity_counts"]["MEDIUM"], 1)
        self.assertEqual(summary["unique_affected_resources"], 2)

    def test_empty_generator_input(self) -> None:
        """Verify summarize_findings handles empty generator expressions."""
        empty_gen = (f for f in [])
        summary = summarize_findings(empty_gen)

        self.assertEqual(summary["total_findings"], 0)
        self.assertEqual(summary["unique_affected_resources"], 0)

    def test_invalid_non_iterable_input(self) -> None:
        """Verify TypeError is raised when findings is not an iterable."""
        for bad_input in [None, 123, True, 3.14]:
            with self.subTest(bad_input=bad_input):
                with self.assertRaises(TypeError):
                    summarize_findings(bad_input)  # type: ignore

    def test_invalid_items_in_iterable(self) -> None:
        """Verify TypeError is raised when iterable contains non-Finding objects."""
        bad_iterables = [
            ["not_a_finding"],
            [self.suid_finding, {"finding_id": "FAKE"}],
            (123,),
        ]
        for bad_iter in bad_iterables:
            with self.subTest(bad_iter=bad_iter):
                with self.assertRaises(TypeError):
                    summarize_findings(bad_iter)  # type: ignore

    def test_input_findings_not_mutated(self) -> None:
        """Verify that summarize_findings does not alter the input list or findings."""
        findings_list = [self.suid_finding, self.perm_finding]
        original_len = len(findings_list)
        original_id = self.suid_finding.finding_id

        summarize_findings(findings_list)

        self.assertEqual(len(findings_list), original_len)
        self.assertEqual(self.suid_finding.finding_id, original_id)


if __name__ == "__main__":
    unittest.main()
