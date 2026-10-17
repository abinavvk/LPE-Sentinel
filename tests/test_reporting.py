"""
Unit tests for the Security Audit Reporting Module (reporting.py).
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

# Add 'src' to sys.path so tests can import lpe_sentinel modules
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import lpe_sentinel
from lpe_sentinel.models import Finding
from lpe_sentinel.reporting import build_report_data, save_report_to_file


class TestReporting(unittest.TestCase):
    """Test suite for building and safely saving JSON audit reports."""

    def setUp(self) -> None:
        """Create sample findings and temporary directory for file output testing."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.test_dir.name)

        self.sample_finding_1 = Finding(
            finding_id="SUID-001",
            title="SUID Permission Detected",
            severity="INFO",
            description="Binary has SUID bit enabled.",
            evidence="Permissions: -rwsr-xr-x (0o4755)",
            affected_resource="/usr/bin/passwd",
            recommendation="Review SUID privilege.",
            mitre_attack="T1548.001",
        )

        self.sample_finding_2 = Finding(
            finding_id="PERM-001",
            title="World-Writable File Permissions",
            severity="HIGH",
            description="Configuration file is world-writable.",
            evidence="Permissions: -rw-rw-rw- (0o666)",
            affected_resource="/etc/config.conf",
            recommendation="Remove world-write permissions.",
            mitre_attack="T1222.002",
        )

        self.sample_finding_3 = Finding(
            finding_id="SUDO-001",
            title="Sudo NOPASSWD Rule Detected",
            severity="MEDIUM",
            description="Sudo rule allows passwordless execution.",
            evidence="Line 5: Matched NOPASSWD tag",
            affected_resource="/etc/sudoers",
            recommendation="Enforce password authentication.",
            mitre_attack="T1548.003",
        )

        self.sample_system_info = {
            "os_name": "Linux",
            "os_release": "6.6.9",
            "hostname": "audit-node",
            "username": "auditor",
            "python_version": "3.11.8",
            "architecture": "x86_64",
            "platform_category": "Linux",
        }

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.test_dir.cleanup()

    def test_build_report_data_structure_and_metadata(self) -> None:
        """Verify report metadata, version, and structure match package information."""
        report = build_report_data([self.sample_finding_1], system_info=self.sample_system_info)

        self.assertIn("report_metadata", report)
        self.assertIn("summary", report)
        self.assertIn("system_info", report)
        self.assertIn("findings", report)

        meta = report["report_metadata"]
        self.assertEqual(meta["project_name"], lpe_sentinel.__title__)
        self.assertEqual(meta["version"], lpe_sentinel.__version__)
        self.assertEqual(meta["format_version"], "1.0")

    def test_timestamp_contains_timezone(self) -> None:
        """Verify generated timestamp is valid ISO 8601 with explicit timezone."""
        report = build_report_data([])
        timestamp_str = report["report_metadata"]["generated_at"]

        # Parse with datetime.fromisoformat to verify timezone presence
        dt = datetime.fromisoformat(timestamp_str)
        self.assertIsNotNone(dt.tzinfo, "Timestamp must include timezone information")

    def test_severity_counts_and_total(self) -> None:
        """Verify findings count and severity grouping."""
        findings = [self.sample_finding_1, self.sample_finding_2, self.sample_finding_3]
        report = build_report_data(findings)

        summary = report["summary"]
        self.assertEqual(summary["total_findings"], 3)
        counts = summary["severity_counts"]
        self.assertEqual(counts["INFO"], 1)
        self.assertEqual(counts["MEDIUM"], 1)
        self.assertEqual(counts["HIGH"], 1)
        self.assertEqual(counts["LOW"], 0)
        self.assertEqual(counts["CRITICAL"], 0)

    def test_empty_findings_report(self) -> None:
        """Verify report handles zero findings gracefully with zeroed severity counts."""
        report = build_report_data([])

        self.assertEqual(report["summary"]["total_findings"], 0)
        self.assertEqual(len(report["findings"]), 0)
        for count in report["summary"]["severity_counts"].values():
            self.assertEqual(count, 0)
        self.assertEqual(report["system_info"], {})

    def test_findings_serialization_integrity(self) -> None:
        """Verify findings are serialized using to_dict() and serialize cleanly to JSON."""
        findings = [self.sample_finding_1, self.sample_finding_2]
        report = build_report_data(findings, system_info=self.sample_system_info)

        # Test JSON round-trip
        json_str = json.dumps(report)
        deserialized = json.loads(json_str)

        self.assertEqual(len(deserialized["findings"]), 2)
        self.assertEqual(deserialized["findings"][0]["finding_id"], "SUID-001")
        self.assertEqual(deserialized["findings"][1]["finding_id"], "PERM-001")
        self.assertEqual(deserialized["system_info"]["hostname"], "audit-node")

    def test_invalid_input_validation(self) -> None:
        """Verify non-Finding items or invalid system_info types raise TypeError."""
        with self.assertRaises(TypeError):
            build_report_data(["not_a_finding"])  # type: ignore

        with self.assertRaises(TypeError):
            build_report_data([], system_info="not_a_dict")  # type: ignore

        with self.assertRaises(TypeError):
            save_report_to_file("not_a_dict_report", self.output_dir / "out.json")  # type: ignore

    def test_save_report_successful_write(self) -> None:
        """Verify report is successfully written to disk with auto-created parent directories."""
        report = build_report_data([self.sample_finding_1])
        nested_dest = self.output_dir / "nested" / "subdir" / "audit_report.json"

        saved_path = save_report_to_file(report, nested_dest)

        self.assertTrue(saved_path.exists())
        self.assertEqual(saved_path, nested_dest.resolve())

        # Read back and verify valid JSON
        with open(saved_path, "r", encoding="utf-8") as f:
            loaded_data = json.load(f)

        self.assertEqual(loaded_data["summary"]["total_findings"], 1)
        self.assertEqual(loaded_data["findings"][0]["finding_id"], "SUID-001")

    def test_save_report_refuses_to_overwrite_existing_by_default(self) -> None:
        """Verify FileExistsError is raised when destination exists and overwrite=False."""
        report = build_report_data([])
        existing_dest = self.output_dir / "existing_report.json"
        existing_dest.write_text('{"already": "exists"}', encoding="utf-8")

        with self.assertRaises(FileExistsError) as ctx:
            save_report_to_file(report, existing_dest, overwrite=False)

        self.assertIn("already exists", str(ctx.exception))
        # Ensure original file was not modified
        self.assertEqual(existing_dest.read_text(encoding="utf-8"), '{"already": "exists"}')

    def test_save_report_allows_explicit_overwrite(self) -> None:
        """Verify overwrite=True successfully updates an existing report file."""
        report = build_report_data([self.sample_finding_2])
        dest = self.output_dir / "overwrite_report.json"
        dest.write_text('{"old": "data"}', encoding="utf-8")

        saved_path = save_report_to_file(report, dest, overwrite=True)

        self.assertTrue(saved_path.exists())
        with open(saved_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["findings"][0]["finding_id"], "PERM-001")

    def test_atomic_write_cleans_up_on_failure(self) -> None:
        """Verify temporary files are cleaned up and target is not corrupted if write fails."""
        report = build_report_data([self.sample_finding_1])
        dest = self.output_dir / "target_never_created.json"

        # Simulate failure during os.replace
        with patch("os.replace", side_effect=OSError("Disk write simulated failure")):
            with self.assertRaises(OSError):
                save_report_to_file(report, dest)

        # Ensure destination file was never created
        self.assertFalse(dest.exists())

        # Ensure no leftover temporary files in output directory
        leftover_tmps = list(self.output_dir.glob(".tmp_report_*"))
        self.assertEqual(len(leftover_tmps), 0)


if __name__ == "__main__":
    unittest.main()
