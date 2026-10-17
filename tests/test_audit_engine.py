"""
Unit tests for the Unified Security Audit Orchestrator (audit_engine.py).
"""

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

# Add 'src' to sys.path so tests can import lpe_sentinel modules
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lpe_sentinel.audit_engine import (
    DEFAULT_SENSITIVE_FILE_PATHS,
    DEFAULT_SUDO_FILE_PATHS,
    DEFAULT_SUID_SEARCH_PATHS,
    AuditConfig,
    AuditResult,
    AuditStatus,
    ScannerExecutionResult,
    ScannerStatus,
    run_unified_audit,
)
from lpe_sentinel.models import Finding
from lpe_sentinel.report_validation import validate_report_data


class TestAuditEngine(unittest.TestCase):
    """Test suite for the unified audit orchestrator module."""

    def setUp(self) -> None:
        """Create isolated temporary directory and sample files for testing."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.test_dir.name)

        # Setup mock SUID directory and files
        self.suid_dir = self.root_path / "bin"
        self.suid_dir.mkdir()
        self.suid_file = self.suid_dir / "custom_suid.bin"
        self.suid_file.write_text("#!/bin/sh\necho test\n", encoding="utf-8")

        # Setup mock sensitive file
        self.sensitive_file = self.root_path / "dummy_passwd"
        self.sensitive_file.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")

        # Setup mock sudoers file
        self.sudoers_file = self.root_path / "dummy_sudoers"
        self.sudoers_file.write_text(
            "alice ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.test_dir.cleanup()

    def _mock_suid_stat(self, file_path: str) -> os.stat_result:
        """Simulate SUID bit on custom_suid.bin portably across test platforms."""
        real_st = os.lstat(file_path)
        if os.path.basename(file_path) == "custom_suid.bin":
            simulated_mode = real_st.st_mode | stat.S_ISUID
            return os.stat_result((simulated_mode, *tuple(real_st)[1:]))
        return real_st

    def _mock_world_writable_stat(self, file_path: str) -> os.stat_result:
        """Simulate world-writable permission bit portably across test platforms."""
        real_st = os.lstat(file_path)
        simulated_mode = real_st.st_mode | stat.S_IWOTH
        return os.stat_result((simulated_mode, *tuple(real_st)[1:]))

    def test_default_paths_defined(self) -> None:
        """Verify that default inspection paths are non-empty tuples of strings."""
        self.assertIsInstance(DEFAULT_SUID_SEARCH_PATHS, tuple)
        self.assertGreater(len(DEFAULT_SUID_SEARCH_PATHS), 0)
        self.assertTrue(all(isinstance(p, str) for p in DEFAULT_SUID_SEARCH_PATHS))

        self.assertIsInstance(DEFAULT_SENSITIVE_FILE_PATHS, tuple)
        self.assertGreater(len(DEFAULT_SENSITIVE_FILE_PATHS), 0)
        self.assertTrue(all(isinstance(p, str) for p in DEFAULT_SENSITIVE_FILE_PATHS))

        self.assertIsInstance(DEFAULT_SUDO_FILE_PATHS, tuple)
        self.assertGreater(len(DEFAULT_SUDO_FILE_PATHS), 0)
        self.assertTrue(all(isinstance(p, str) for p in DEFAULT_SENSITIVE_FILE_PATHS))

    def test_completed_audit_on_mocked_linux(self) -> None:
        """Verify that a full audit completes successfully and aggregates all scanner findings."""
        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid._get_file_stat", side_effect=self._mock_suid_stat), \
             patch("lpe_sentinel.sensitive_permissions._get_file_stat", side_effect=self._mock_world_writable_stat):

            result = run_unified_audit(
                suid_paths=[str(self.suid_dir)],
                sensitive_file_paths=[str(self.sensitive_file)],
                sudo_file_paths=[str(self.sudoers_file)],
            )

            self.assertIsInstance(result, AuditResult)
            self.assertEqual(result.status, AuditStatus.COMPLETED)
            self.assertTrue(result.is_complete)
            self.assertEqual(len(result.errors), 0)

            # Check individual scanner results
            self.assertEqual(len(result.scanner_results), 3)
            self.assertIn("suid_sgid", result.scanner_results)
            self.assertIn("sensitive_permissions", result.scanner_results)
            self.assertIn("sudo_audit", result.scanner_results)

            for name, s_res in result.scanner_results.items():
                self.assertEqual(s_res.status, ScannerStatus.COMPLETED)
                self.assertGreater(s_res.findings_count, 0)
                self.assertEqual(len(s_res.skipped_paths), 0)
                self.assertGreater(len(s_res.accessible_paths), 0)

            # Check finding aggregation
            self.assertGreater(len(result.findings), 0)
            finding_ids = {f.finding_id for f in result.findings}
            self.assertIn("SUID-001", finding_ids)
            self.assertIn("PERM-001", finding_ids)
            self.assertIn("SUDO-001", finding_ids)

            # Check summary computation
            self.assertEqual(result.summary["total_findings"], len(result.findings))
            self.assertIn("severity_counts", result.summary)
            self.assertIn("findings_by_scanner_category", result.summary)

    def test_empty_scanner_selection_returns_non_success(self) -> None:
        """Verify that passing enabled_scanners=[] returns PARTIAL and explains no scanners selected."""
        result = run_unified_audit(enabled_scanners=[])

        self.assertEqual(result.status, AuditStatus.PARTIAL)
        self.assertFalse(result.is_complete)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.summary["total_findings"], 0)
        self.assertEqual(len(result.scanner_results), 0)
        self.assertGreater(len(result.errors), 0)
        self.assertIn("No scanners were selected", result.errors[0])

    def test_unsupported_platform_marks_scanners_skipped_and_status_partial(self) -> None:
        """Verify that on non-Linux systems, scanners are marked SKIPPED and audit is PARTIAL."""
        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=False), \
             patch("platform.system", return_value="Windows"):

            result = run_unified_audit(
                suid_paths=[str(self.suid_dir)],
                sensitive_file_paths=[str(self.sensitive_file)],
                sudo_file_paths=[str(self.sudoers_file)],
            )

            self.assertEqual(result.status, AuditStatus.PARTIAL)
            self.assertFalse(result.is_complete)
            self.assertEqual(len(result.findings), 0)
            self.assertEqual(result.summary["total_findings"], 0)

            for name, s_res in result.scanner_results.items():
                self.assertEqual(s_res.status, ScannerStatus.SKIPPED)
                self.assertEqual(s_res.findings_count, 0)
                self.assertIn("skipped", s_res.message.lower())
                self.assertIn("Windows", s_res.message)

    def test_partial_status_when_one_scanner_fails(self) -> None:
        """Verify that an individual scanner failure leads to PARTIAL audit status and captures error."""
        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.audit_engine.scan_sudo_config", side_effect=RuntimeError("Simulated sudoers I/O failure")):

            result = run_unified_audit(
                suid_paths=[str(self.suid_dir)],
                sensitive_file_paths=[str(self.sensitive_file)],
                sudo_file_paths=[str(self.sudoers_file)],
            )

            self.assertEqual(result.status, AuditStatus.PARTIAL)
            self.assertFalse(result.is_complete)

            # Sudo scanner should be marked FAILED
            sudo_res = result.scanner_results["sudo_audit"]
            self.assertEqual(sudo_res.status, ScannerStatus.FAILED)
            self.assertIn("Simulated sudoers I/O failure", sudo_res.error)

            # Other scanners should have COMPLETED
            self.assertEqual(result.scanner_results["suid_sgid"].status, ScannerStatus.COMPLETED)
            self.assertEqual(result.scanner_results["sensitive_permissions"].status, ScannerStatus.COMPLETED)

            # Error should be recorded in audit errors list
            self.assertTrue(any("Simulated sudoers I/O failure" in err for err in result.errors))

    def test_failed_status_when_all_scanners_fail(self) -> None:
        """Verify that if all scanners fail with exceptions, the overall status is FAILED."""
        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.audit_engine.scan_suid_sgid", side_effect=RuntimeError("SUID error")), \
             patch("lpe_sentinel.audit_engine.scan_sensitive_permissions", side_effect=RuntimeError("Perm error")), \
             patch("lpe_sentinel.audit_engine.scan_sudo_config", side_effect=RuntimeError("Sudo error")):

            result = run_unified_audit()

            self.assertEqual(result.status, AuditStatus.FAILED)
            self.assertFalse(result.is_complete)
            self.assertEqual(len(result.findings), 0)
            self.assertEqual(len(result.errors), 3)

            for name, s_res in result.scanner_results.items():
                self.assertEqual(s_res.status, ScannerStatus.FAILED)
                self.assertIsNotNone(s_res.error)

    def test_finding_deduplication(self) -> None:
        """Verify that identical findings produced across scanners are deduplicated."""
        dup_finding = Finding(
            finding_id="SUID-001",
            title="Duplicate SUID Finding",
            severity="INFO",
            description="Test finding description",
            evidence="Mode: 0o4755",
            affected_resource="/bin/dup.bin",
            recommendation="chmod u-s /bin/dup.bin",
        )

        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.audit_engine.scan_suid_sgid", return_value=[dup_finding, dup_finding]), \
             patch("lpe_sentinel.audit_engine.scan_sensitive_permissions", return_value=[dup_finding]), \
             patch("lpe_sentinel.audit_engine.scan_sudo_config", return_value=[]):

            result = run_unified_audit(
                suid_paths=[str(self.suid_dir)],
                sensitive_file_paths=[str(self.sensitive_file)],
                sudo_file_paths=[str(self.sudoers_file)],
            )

            self.assertEqual(result.status, AuditStatus.COMPLETED)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.summary["total_findings"], 1)

    def test_missing_and_empty_paths_handled_safely_and_marked_partial(self) -> None:
        """Verify that non-existent paths execute safely and honestly report PARTIAL coverage."""
        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):

            non_existent_dir = self.root_path / "does_not_exist_dir"
            non_existent_file = self.root_path / "does_not_exist_file"

            result = run_unified_audit(
                suid_paths=[str(non_existent_dir), None, ""],
                sensitive_file_paths=[str(non_existent_file), ""],
                sudo_file_paths=[],
            )

            # Because target paths were missing, audit status must be PARTIAL (not COMPLETED)
            self.assertEqual(result.status, AuditStatus.PARTIAL)
            self.assertFalse(result.is_complete)
            self.assertEqual(len(result.findings), 0)

            # Check that missing paths are documented in skipped_paths
            suid_res = result.scanner_results["suid_sgid"]
            self.assertIn(str(non_existent_dir), " ".join(suid_res.skipped_paths))

            perm_res = result.scanner_results["sensitive_permissions"]
            self.assertIn(str(non_existent_file), " ".join(perm_res.skipped_paths))

    def test_incomplete_path_coverage_marks_status_partial(self) -> None:
        """Verify that a mix of accessible and inaccessible paths produces PARTIAL coverage status."""
        missing_file = self.root_path / "missing_sensitive_file"

        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):

            result = run_unified_audit(
                suid_paths=[str(self.suid_dir)],
                sensitive_file_paths=[str(self.sensitive_file), str(missing_file)],
                sudo_file_paths=[str(self.sudoers_file)],
            )

            self.assertEqual(result.status, AuditStatus.PARTIAL)
            self.assertFalse(result.is_complete)

            perm_res = result.scanner_results["sensitive_permissions"]
            self.assertEqual(perm_res.status, ScannerStatus.PARTIAL)
            self.assertEqual(len(perm_res.accessible_paths), 1)
            self.assertEqual(len(perm_res.skipped_paths), 1)
            self.assertIn(str(missing_file), perm_res.skipped_paths[0])
            self.assertIn("partial coverage", perm_res.message)

    def test_sudoers_permission_denied_marks_status_partial(self) -> None:
        """Verify that PermissionError reading sudoers is reported honestly as incomplete coverage."""
        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True), \
             patch("builtins.open", side_effect=PermissionError("Access denied to /etc/sudoers")):

            result = run_unified_audit(
                suid_paths=[str(self.suid_dir)],
                sensitive_file_paths=[str(self.sensitive_file)],
                sudo_file_paths=[str(self.sudoers_file)],
            )

            self.assertEqual(result.status, AuditStatus.PARTIAL)
            self.assertFalse(result.is_complete)

            sudo_res = result.scanner_results["sudo_audit"]
            self.assertEqual(sudo_res.status, ScannerStatus.PARTIAL)
            self.assertEqual(len(sudo_res.accessible_paths), 0)
            self.assertEqual(len(sudo_res.skipped_paths), 1)
            self.assertIn("permission denied", sudo_res.skipped_paths[0])

    def test_audit_config_class_usage(self) -> None:
        """Verify that passing an AuditConfig object correctly configures the audit run."""
        config = AuditConfig(
            suid_paths=[str(self.suid_dir)],
            sensitive_file_paths=[str(self.sensitive_file)],
            sudo_file_paths=[str(self.sudoers_file)],
            collect_sys_info=False,
            enabled_scanners=("suid_sgid", "sensitive_permissions"),
        )

        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True):

            result = run_unified_audit(config=config)

            self.assertEqual(result.status, AuditStatus.COMPLETED)
            self.assertEqual(result.system_info, {})
            self.assertIn("suid_sgid", result.scanner_results)
            self.assertIn("sensitive_permissions", result.scanner_results)
            self.assertNotIn("sudo_audit", result.scanner_results)

    def test_audit_result_serialization(self) -> None:
        """Verify that AuditResult.to_dict() produces a complete JSON-compatible structure."""
        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=False), \
             patch("platform.system", return_value="Windows"):

            result = run_unified_audit()
            serialized = result.to_dict()

            self.assertIsInstance(serialized, dict)
            self.assertEqual(serialized["status"], AuditStatus.PARTIAL)
            self.assertFalse(serialized["is_complete"])
            self.assertIn("timestamp", serialized)
            self.assertIn("system_info", serialized)
            self.assertIn("summary", serialized)
            self.assertIn("scanner_results", serialized)
            self.assertIn("findings", serialized)
            self.assertIn("errors", serialized)

    def test_to_report_data_schema_compliance(self) -> None:
        """Verify that AuditResult.to_report_data() satisfies report_validation.validate_report_data."""
        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):

            result = run_unified_audit(
                suid_paths=[str(self.suid_dir)],
                sensitive_file_paths=[str(self.sensitive_file)],
                sudo_file_paths=[str(self.sudoers_file)],
            )

            report_data = result.to_report_data()
            self.assertIsInstance(report_data, dict)

            # Must satisfy official schema validator
            val_result = validate_report_data(report_data)
            self.assertTrue(val_result.is_valid, f"Validation errors: {val_result.errors}")
            self.assertEqual(len(val_result.errors), 0)

            # Must contain engine execution metadata
            self.assertIn("audit_engine", report_data)
            self.assertEqual(report_data["audit_engine"]["status"], AuditStatus.COMPLETED)
            self.assertTrue(report_data["audit_engine"]["is_complete"])

    def test_system_info_collection_and_override(self) -> None:
        """Verify that custom system_info can be passed directly to the orchestrator."""
        custom_info = {
            "os_name": "Linux",
            "hostname": "kali-sentinel",
            "custom_field": "test_value",
        }

        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=False):
            result = run_unified_audit(system_info=custom_info)

            self.assertEqual(result.system_info, custom_info)
            self.assertEqual(result.system_info["hostname"], "kali-sentinel")

    def test_read_only_guarantee_no_file_mutations(self) -> None:
        """Verify that running the audit does not alter file content or create unintended files."""
        initial_suid_stat = os.stat(self.suid_file)
        initial_sensitive_stat = os.stat(self.sensitive_file)
        initial_sudoers_stat = os.stat(self.sudoers_file)

        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):

            run_unified_audit(
                suid_paths=[str(self.suid_dir)],
                sensitive_file_paths=[str(self.sensitive_file)],
                sudo_file_paths=[str(self.sudoers_file)],
            )

        # Confirm file modification times and sizes did not change
        post_suid_stat = os.stat(self.suid_file)
        post_sensitive_stat = os.stat(self.sensitive_file)
        post_sudoers_stat = os.stat(self.sudoers_file)

        self.assertEqual(initial_suid_stat.st_mtime, post_suid_stat.st_mtime)
        self.assertEqual(initial_suid_stat.st_size, post_suid_stat.st_size)
        self.assertEqual(initial_sensitive_stat.st_mtime, post_sensitive_stat.st_mtime)
        self.assertEqual(initial_sensitive_stat.st_size, post_sensitive_stat.st_size)
        self.assertEqual(initial_sudoers_stat.st_mtime, post_sudoers_stat.st_mtime)
        self.assertEqual(initial_sudoers_stat.st_size, post_sudoers_stat.st_size)


if __name__ == "__main__":
    unittest.main()
