"""
Integration tests for the LPE Sentinel report generation, persistence,
deserialization, and validation workflow.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Add 'src' to sys.path so tests can import lpe_sentinel modules
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lpe_sentinel.models import Finding
from lpe_sentinel.report_validation import ValidationResult, validate_report_data
from lpe_sentinel.reporting import build_report_data, save_report_to_file


def load_report_file(file_path: Path) -> tuple[bool, any, str]:
    """
    Helper to safely read and parse a JSON report file from disk.

    Returns:
        tuple of (success: bool, parsed_data: any, error_message: str)
    """
    try:
        content = file_path.read_text(encoding="utf-8")
        return True, json.loads(content), ""
    except json.JSONDecodeError as exc:
        return False, None, f"JSON decode error: {exc}"
    except OSError as exc:
        return False, None, f"Filesystem read error: {exc}"


class TestReportWorkflowIntegration(unittest.TestCase):
    """Integration test suite verifying end-to-end report build, save, load, and validate."""

    def setUp(self) -> None:
        """Set up temporary working directory and realistic sample findings."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.test_dir.name)

        self.suid_finding = Finding(
            finding_id="SUID-001",
            title="SUID Executable Detected",
            severity="INFO",
            description="A binary has the setuid permission bit enabled.",
            evidence="Permissions: -rwsr-xr-x (0o4755)",
            affected_resource="/usr/bin/passwd",
            recommendation="Review whether SUID is strictly required.",
            mitre_attack="T1548.001",
        )

        self.perm_finding = Finding(
            finding_id="PERM-001",
            title="World-Writable Configuration File",
            severity="HIGH",
            description="A sensitive file is writable by all local users.",
            evidence="Permissions: -rw-rw-rw- (0o666)",
            affected_resource="/etc/cron.d/audit_job",
            recommendation="Restrict permissions to root:root (0644).",
            mitre_attack="T1222.002",
        )

        self.sudo_finding = Finding(
            finding_id="SUDO-001",
            title="Sudo NOPASSWD Rule Detected",
            severity="MEDIUM",
            description="The sudoers configuration allows passwordless execution.",
            evidence="Line 12: Matched NOPASSWD tag",
            affected_resource="/etc/sudoers.d/admin",
            recommendation="Review and enforce password authentication.",
            mitre_attack="T1548.003",
        )

        self.system_info = {
            "os_name": "Linux",
            "os_release": "6.6.9-arch1-1",
            "hostname": "sentinel-target",
            "username": "auditor",
            "python_version": "3.11.8",
            "architecture": "x86_64",
            "platform_category": "Linux",
        }

    def tearDown(self) -> None:
        """Clean up temporary test directory."""
        self.test_dir.cleanup()

    def test_full_workflow_with_findings(self) -> None:
        """
        Test end-to-end workflow:
          1. Build report with realistic findings and system information.
          2. Save report to disk via save_report_to_file.
          3. Read saved JSON back from disk.
          4. Validate loaded data with validate_report_data.
          5. Verify exact data preservation across round-trip serialization.
        """
        findings = [self.suid_finding, self.perm_finding, self.sudo_finding]
        report_data = build_report_data(findings, system_info=self.system_info)

        report_file = self.temp_path / "reports" / "security_audit.json"
        saved_path = save_report_to_file(report_data, report_file, overwrite=False)

        self.assertTrue(saved_path.exists())
        self.assertEqual(saved_path, report_file.resolve())

        # Read back from disk
        success, loaded_data, err_msg = load_report_file(saved_path)
        self.assertTrue(success, f"Failed to load saved report: {err_msg}")

        # Validate deserialized data
        validation_result = validate_report_data(loaded_data)
        self.assertTrue(
            validation_result.is_valid,
            f"Validation unexpectedly failed: {validation_result.errors}",
        )
        self.assertEqual(validation_result.errors, [])

        # Verify data preservation
        self.assertEqual(loaded_data["summary"]["total_findings"], 3)
        self.assertEqual(loaded_data["summary"]["severity_counts"]["INFO"], 1)
        self.assertEqual(loaded_data["summary"]["severity_counts"]["HIGH"], 1)
        self.assertEqual(loaded_data["summary"]["severity_counts"]["MEDIUM"], 1)
        self.assertEqual(loaded_data["summary"]["severity_counts"]["LOW"], 0)
        self.assertEqual(loaded_data["summary"]["severity_counts"]["CRITICAL"], 0)

        # Verify finding fields in serialized output
        findings_by_id = {f["finding_id"]: f for f in loaded_data["findings"]}
        self.assertIn("SUID-001", findings_by_id)
        self.assertEqual(findings_by_id["SUID-001"]["affected_resource"], "/usr/bin/passwd")
        self.assertEqual(findings_by_id["SUID-001"]["evidence"], "Permissions: -rwsr-xr-x (0o4755)")
        self.assertEqual(findings_by_id["SUID-001"]["mitre_attack"], "T1548.001")

        self.assertIn("PERM-001", findings_by_id)
        self.assertEqual(findings_by_id["PERM-001"]["severity"], "HIGH")

        self.assertIn("SUDO-001", findings_by_id)
        self.assertEqual(findings_by_id["SUDO-001"]["severity"], "MEDIUM")

        # Verify system info
        self.assertEqual(loaded_data["system_info"]["hostname"], "sentinel-target")
        self.assertEqual(loaded_data["system_info"]["platform_category"], "Linux")

    def test_full_workflow_empty_report(self) -> None:
        """
        Verify that an empty report (0 findings) builds, writes, loads,
        and validates successfully.
        """
        empty_data = build_report_data([], system_info=self.system_info)
        report_file = self.temp_path / "empty_audit.json"

        saved_path = save_report_to_file(empty_data, report_file, overwrite=False)
        self.assertTrue(saved_path.exists())

        success, loaded_data, err_msg = load_report_file(saved_path)
        self.assertTrue(success, f"Failed to load empty report: {err_msg}")

        validation_result = validate_report_data(loaded_data)
        self.assertTrue(
            validation_result.is_valid,
            f"Empty report validation failed: {validation_result.errors}",
        )
        self.assertEqual(validation_result.errors, [])
        self.assertEqual(loaded_data["summary"]["total_findings"], 0)
        self.assertEqual(loaded_data["findings"], [])

    def test_saved_report_no_overwrite_protection(self) -> None:
        """
        Verify that save_report_to_file refuses to overwrite an existing saved report
        when overwrite=False, and that the original report file remains intact and valid.
        """
        first_report = build_report_data([self.suid_finding])
        target_path = self.temp_path / "protected_report.json"

        # Initial write
        save_report_to_file(first_report, target_path, overwrite=False)
        self.assertTrue(target_path.exists())

        # Attempt second write to same destination with overwrite=False
        second_report = build_report_data([self.perm_finding])
        with self.assertRaises(FileExistsError):
            save_report_to_file(second_report, target_path, overwrite=False)

        # Verify the original content remains unchanged and valid
        success, loaded_data, _ = load_report_file(target_path)
        self.assertTrue(success)
        self.assertEqual(loaded_data["summary"]["total_findings"], 1)
        self.assertEqual(loaded_data["findings"][0]["finding_id"], "SUID-001")

        val_result = validate_report_data(loaded_data)
        self.assertTrue(val_result.is_valid)

    def test_corrupted_json_report_structure_rejected_by_validator(self) -> None:
        """
        Verify that deliberately corrupted JSON reports (valid JSON syntax, but
        tampered schema or mismatched totals) are rejected by validate_report_data
        without raising unhandled exceptions.
        """
        report_data = build_report_data([self.suid_finding])
        report_file = self.temp_path / "tampered_report.json"
        save_report_to_file(report_data, report_file)

        # Read, corrupt structure, and rewrite
        content = json.loads(report_file.read_text(encoding="utf-8"))
        content["summary"]["total_findings"] = 999  # Mismatch
        content["findings"][0]["severity"] = "INVALID_SEVERITY"  # Invalid severity
        del content["report_metadata"]["version"]  # Missing required field

        report_file.write_text(json.dumps(content), encoding="utf-8")

        # Load tampered report
        success, loaded_data, _ = load_report_file(report_file)
        self.assertTrue(success)

        # Validate
        val_result = validate_report_data(loaded_data)
        self.assertFalse(val_result.is_valid)
        self.assertTrue(len(val_result.errors) >= 3)
        self.assertTrue(any("total_findings" in err for err in val_result.errors))
        self.assertTrue(any("INVALID_SEVERITY" in err for err in val_result.errors))
        self.assertTrue(any("report_metadata.version" in err for err in val_result.errors))

    def test_malformed_json_text_handled_separately(self) -> None:
        """
        Verify that malformed JSON text (syntax errors) is cleanly caught
        during parsing and never crashes the application workflow.
        """
        malformed_file = self.temp_path / "syntax_error.json"
        malformed_file.write_text('{"project": "lpe-sentinel", truncated...}', encoding="utf-8")

        # Reading with JSON parser detects syntax error
        success, loaded_data, err_msg = load_report_file(malformed_file)
        self.assertFalse(success)
        self.assertIn("JSON decode error", err_msg)
        self.assertIsNone(loaded_data)

    def test_non_dict_valid_json_rejected_by_validator(self) -> None:
        """
        Verify that valid JSON files representing non-dictionary payloads
        (e.g., list or integer) are safely rejected by validate_report_data.
        """
        list_json_file = self.temp_path / "array_report.json"
        list_json_file.write_text('[{"some": "data"}]', encoding="utf-8")

        success, loaded_data, _ = load_report_file(list_json_file)
        self.assertTrue(success)
        self.assertIsInstance(loaded_data, list)

        # Validator should cleanly reject non-dict
        val_result = validate_report_data(loaded_data)
        self.assertFalse(val_result.is_valid)
        self.assertTrue(any("must be a dictionary" in err for err in val_result.errors))


if __name__ == "__main__":
    unittest.main()
