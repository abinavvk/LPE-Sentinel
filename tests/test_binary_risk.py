"""
Unit tests for the Defensive SUID/SGID Binary Risk Assessment Module (binary_risk.py).
"""

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Add 'src' to sys.path so tests can import lpe_sentinel modules
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lpe_sentinel.audit_engine import AuditStatus, run_unified_audit
from lpe_sentinel.binary_risk import (
    REFERENCE_BINARY_CATALOG,
    BinaryRiskProfile,
    assess_binary_risk,
    get_binary_risk_profile,
    normalize_binary_name,
)
from lpe_sentinel.models import VALID_SEVERITIES, Finding
from lpe_sentinel.report_validation import validate_report_data
from lpe_sentinel.suid_sgid import scan_suid_sgid


class TestBinaryRisk(unittest.TestCase):
    """Test suite for binary risk assessment, reference catalog, and integration."""

    def setUp(self) -> None:
        """Create isolated temporary directory for file fixtures."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.test_dir.name)

        # Setup test binaries
        self.find_bin = self.root_path / "find"
        self.find_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

        self.bash_bin = self.root_path / "bash"
        self.bash_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

        self.safe_bin = self.root_path / "custom_safe_tool.bin"
        self.safe_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.test_dir.cleanup()

    def test_reference_catalog_integrity(self) -> None:
        """Verify that the bundled reference catalog contains valid, well-formed entries."""
        self.assertGreater(len(REFERENCE_BINARY_CATALOG), 15)

        required_tools = ("bash", "sh", "python", "perl", "find", "vim", "chmod", "cp", "dd", "tar")
        for tool in required_tools:
            self.assertIn(tool, REFERENCE_BINARY_CATALOG)

        for name, profile in REFERENCE_BINARY_CATALOG.items():
            self.assertIsInstance(profile, BinaryRiskProfile)
            self.assertEqual(profile.basename, name)
            self.assertIn(profile.risk_level, VALID_SEVERITIES)
            self.assertIn(profile.risk_level, ("HIGH", "MEDIUM", "LOW"))
            self.assertTrue(bool(profile.category.strip()))
            self.assertTrue(bool(profile.review_reason.strip()))
            self.assertTrue(bool(profile.admin_recommendation.strip()))

    def test_normalize_binary_name(self) -> None:
        """Verify that executable names are extracted cleanly from varied path formats."""
        self.assertEqual(normalize_binary_name("/usr/bin/find"), "find")
        self.assertEqual(normalize_binary_name("/usr/bin/find/"), "find")
        self.assertEqual(normalize_binary_name("C:\\Program Files\\Tools\\bash.exe"), "bash.exe")
        self.assertEqual(normalize_binary_name("  /bin/BASH  "), "bash")
        self.assertEqual(normalize_binary_name("python"), "python")
        self.assertEqual(normalize_binary_name(""), "")
        self.assertEqual(normalize_binary_name(None), "")  # type: ignore

    def test_versioned_suffix_normalization(self) -> None:
        """Verify that versioned binary names resolve to their canonical catalog profile."""
        profile_py = get_binary_risk_profile("/usr/bin/python3.11")
        self.assertIsNotNone(profile_py)
        self.assertEqual(profile_py.basename, "python3")

        profile_ruby = get_binary_risk_profile("/usr/local/bin/ruby3.2")
        self.assertIsNotNone(profile_ruby)
        self.assertEqual(profile_ruby.basename, "ruby")

    def test_supported_versioned_executable_families(self) -> None:
        """Verify that explicitly supported versioned families match canonical profiles."""
        cases = [
            ("python3.11", "python3"),
            ("python3.12", "python3"),
            ("python3.11.4", "python3"),
            ("python2.7", "python"),
            ("ruby3.2", "ruby"),
            ("php8.1", "php"),
            ("lua5.4", "lua"),
            ("perl5.36", "perl"),
            ("node18", "node"),
            ("/usr/bin/python3.10", "python3"),
            ("/usr/local/bin/ruby3.0", "ruby"),
        ]
        for bin_name, expected_basename in cases:
            profile = get_binary_risk_profile(bin_name)
            self.assertIsNotNone(profile, f"Failed to match supported versioned executable: {bin_name}")
            self.assertEqual(
                profile.basename,
                expected_basename,
                f"Binary {bin_name} matched {profile.basename}, expected {expected_basename}",
            )

    def test_non_matching_custom_names_with_trailing_digits(self) -> None:
        """Verify that custom names with trailing digits do not match catalog utilities."""
        custom_non_matches = [
            "cp1",
            "cp2",
            "dd1",
            "dd2",
            "find1",
            "find2",
            "sed1",
            "sed2",
            "chmod1",
            "chown2",
            "tar1",
            "tar2",
            "nano1",
            "vim2",
            "env1",
            "bash2",
            "sh1",
            "/usr/bin/cp1",
            "/usr/local/bin/dd2",
            "/opt/tools/find1",
        ]
        for name in custom_non_matches:
            self.assertIsNone(
                get_binary_risk_profile(name),
                f"Custom name '{name}' should not match any catalog profile",
            )
            # Ensure assess_binary_risk also yields None even with SUID bit set
            finding = assess_binary_risk(name, is_suid=True, is_sgid=False)
            self.assertIsNone(
                finding,
                f"assess_binary_risk should return None for custom binary '{name}'",
            )

    def test_known_match_suid(self) -> None:
        """Verify that an SUID match generates a Finding with SUID-002 and appropriate severity."""
        st_mode = stat.S_IFREG | 0o4755 | stat.S_ISUID
        finding = assess_binary_risk(str(self.find_bin), st_mode=st_mode, is_suid=True, is_sgid=False)

        self.assertIsNotNone(finding)
        self.assertIsInstance(finding, Finding)
        self.assertEqual(finding.finding_id, "SUID-002")
        self.assertEqual(finding.severity, "MEDIUM")
        self.assertIn("find", finding.title)
        self.assertIn("Search & Execution", finding.description)
        self.assertIn("warrants security review", finding.description)
        self.assertIn("chmod u-s", finding.recommendation)
        self.assertEqual(finding.mitre_attack, "T1548.001")
        self.assertEqual(finding.affected_resource, str(self.find_bin.resolve()))

    def test_known_match_sgid(self) -> None:
        """Verify that an SGID-only match generates an SGID-002 finding."""
        st_mode = stat.S_IFREG | 0o2755 | stat.S_ISGID
        finding = assess_binary_risk(str(self.bash_bin), st_mode=st_mode, is_suid=False, is_sgid=True)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.finding_id, "SGID-002")
        self.assertEqual(finding.severity, "HIGH")
        self.assertIn("SGID", finding.title)
        self.assertIn("chmod g-s", finding.recommendation)

    def test_non_match_returns_none(self) -> None:
        """Verify that binaries not in the reference catalog return None."""
        st_mode = stat.S_IFREG | 0o4755 | stat.S_ISUID
        finding = assess_binary_risk(str(self.safe_bin), st_mode=st_mode, is_suid=True, is_sgid=False)
        self.assertIsNone(finding)

    def test_no_suid_or_sgid_returns_none(self) -> None:
        """Verify that even a cataloged tool returns None if special bits are not set."""
        st_mode = stat.S_IFREG | 0o0755
        finding = assess_binary_risk(str(self.bash_bin), st_mode=st_mode, is_suid=False, is_sgid=False)
        self.assertIsNone(finding)

    def test_empty_and_invalid_inputs(self) -> None:
        """Verify that None, empty string, and non-string inputs are handled safely."""
        self.assertIsNone(assess_binary_risk("", is_suid=True))
        self.assertIsNone(assess_binary_risk("   ", is_suid=True))
        self.assertIsNone(get_binary_risk_profile(""))
        self.assertIsNone(get_binary_risk_profile("   "))

    def test_integration_with_scan_suid_sgid(self) -> None:
        """Verify that scan_suid_sgid yields both SUID-001 (discovery) and SUID-002 (risk) on matches."""
        def mock_stat_dispatcher(path: str) -> os.stat_result:
            real_st = os.lstat(path)
            if os.path.basename(path) == "find":
                simulated_mode = real_st.st_mode | stat.S_ISUID
                return os.stat_result((simulated_mode, *tuple(real_st)[1:]))
            return real_st

        with patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid._get_file_stat", side_effect=mock_stat_dispatcher):

            findings = scan_suid_sgid([str(self.root_path)])

            # Should have SUID-001 (standard discovery) and SUID-002 (catalog risk) for find
            finding_ids = [f.finding_id for f in findings]
            self.assertIn("SUID-001", finding_ids)
            self.assertIn("SUID-002", finding_ids)

            # Finding for safe_bin should NOT have SUID-002
            safe_findings = [f for f in findings if f.affected_resource == str(self.safe_bin.resolve())]
            self.assertEqual(len(safe_findings), 0)

            # Verify risk finding details
            risk_finding = next(f for f in findings if f.finding_id == "SUID-002")
            self.assertEqual(risk_finding.severity, "MEDIUM")
            self.assertIn("warrants security review", risk_finding.description)

    def test_unified_audit_integration_and_deduplication(self) -> None:
        """Verify that run_unified_audit aggregates catalog findings and summary metrics cleanly."""
        def mock_stat_dispatcher(path: str) -> os.stat_result:
            real_st = os.lstat(path)
            if os.path.basename(path) == "find":
                simulated_mode = real_st.st_mode | stat.S_ISUID
                return os.stat_result((simulated_mode, *tuple(real_st)[1:]))
            return real_st

        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid._get_file_stat", side_effect=mock_stat_dispatcher):

            result = run_unified_audit(
                suid_paths=[str(self.root_path)],
                enabled_scanners=["suid_sgid"],
            )

            self.assertEqual(result.status, AuditStatus.COMPLETED)
            self.assertTrue(result.is_complete)

            # Both SUID-001 and SUID-002 should be recorded
            finding_ids = [f.finding_id for f in result.findings]
            self.assertIn("SUID-001", finding_ids)
            self.assertIn("SUID-002", finding_ids)

            # Check summary calculations
            self.assertEqual(result.summary["total_findings"], len(result.findings))
            self.assertEqual(result.summary["findings_by_scanner_category"]["SUID"], len(result.findings))

    def test_report_validation_compatibility(self) -> None:
        """Verify that reports containing binary risk findings pass official schema validation."""
        def mock_stat_dispatcher(path: str) -> os.stat_result:
            real_st = os.lstat(path)
            if os.path.basename(path) == "bash":
                simulated_mode = real_st.st_mode | stat.S_ISUID
                return os.stat_result((simulated_mode, *tuple(real_st)[1:]))
            return real_st

        with patch("lpe_sentinel.audit_engine.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid._get_file_stat", side_effect=mock_stat_dispatcher):

            result = run_unified_audit(
                suid_paths=[str(self.root_path)],
                enabled_scanners=["suid_sgid"],
            )

            report_data = result.to_report_data()
            val_res = validate_report_data(report_data)
            self.assertTrue(val_res.is_valid, f"Validation errors: {val_res.errors}")
            self.assertEqual(len(val_res.errors), 0)

    def test_read_only_guarantee_no_modifications(self) -> None:
        """Verify that risk assessment performs zero file modifications."""
        before_stat = os.stat(self.find_bin)

        st_mode = stat.S_IFREG | 0o4755 | stat.S_ISUID
        _ = assess_binary_risk(str(self.find_bin), st_mode=st_mode, is_suid=True)

        after_stat = os.stat(self.find_bin)
        self.assertEqual(before_stat.st_mtime, after_stat.st_mtime)
        self.assertEqual(before_stat.st_size, after_stat.st_size)


if __name__ == "__main__":
    unittest.main()
