"""
Unit tests for the SUID/SGID file permission scanner (suid_sgid.py).
"""

import os
import stat
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

# Add 'src' to sys.path so tests can import lpe_sentinel modules
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lpe_sentinel.models import Finding
from lpe_sentinel.suid_sgid import is_linux_platform, scan_suid_sgid


class TestSuidSgidScanner(unittest.TestCase):
    """Test suite for SUID/SGID scanning, permission detection, and platform safety."""

    def setUp(self) -> None:
        """Create isolated temporary directories and files for testing."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.test_dir.name)

        # Create target inspection directory
        self.target_dir = self.root_path / "target_bin"
        self.target_dir.mkdir()

        # Create normal file (no special bits)
        self.normal_file = self.target_dir / "normal.bin"
        self.normal_file.write_text("#!/bin/sh\necho hello\n")

        # Create SUID candidate file
        self.suid_file = self.target_dir / "suid.bin"
        self.suid_file.write_text("#!/bin/sh\necho suid\n")

        # Create SGID candidate file
        self.sgid_file = self.target_dir / "sgid.bin"
        self.sgid_file.write_text("#!/bin/sh\necho sgid\n")

        # Create both SUID+SGID candidate file
        self.both_file = self.target_dir / "both.bin"
        self.both_file.write_text("#!/bin/sh\necho both\n")

        # Create outside directory that should NOT be inspected
        self.outside_dir = self.root_path / "outside_bin"
        self.outside_dir.mkdir()
        self.outside_suid = self.outside_dir / "outside_suid.bin"
        self.outside_suid.write_text("#!/bin/sh\necho outside\n")

    def tearDown(self) -> None:
        """Clean up temporary directories."""
        self.test_dir.cleanup()

    def _mock_stat_dispatcher(self, file_path: str) -> os.stat_result:
        """Helper to simulate SUID/SGID bits portably across Windows & Linux test environments."""
        real_st = os.lstat(file_path)
        filename = os.path.basename(file_path)

        if filename == "suid.bin" or filename == "outside_suid.bin":
            simulated_mode = real_st.st_mode | stat.S_ISUID
            return os.stat_result((simulated_mode, *tuple(real_st)[1:]))
        elif filename == "sgid.bin":
            simulated_mode = real_st.st_mode | stat.S_ISGID
            return os.stat_result((simulated_mode, *tuple(real_st)[1:]))
        elif filename == "both.bin":
            simulated_mode = real_st.st_mode | stat.S_ISUID | stat.S_ISGID
            return os.stat_result((simulated_mode, *tuple(real_st)[1:]))

        return real_st

    def test_unsupported_platform_behavior(self) -> None:
        """Verify that running on Windows/macOS issues an explicit warning and returns empty."""
        with patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=False), \
             patch("platform.system", return_value="Windows"):

            with warnings.catch_warnings(record=True) as captured_warnings:
                warnings.simplefilter("always")
                findings = scan_suid_sgid([str(self.target_dir)])

                self.assertEqual(findings, [])
                self.assertTrue(len(captured_warnings) >= 1)
                self.assertIn("only supported on Linux", str(captured_warnings[0].message))

    def test_normal_file_without_special_bits_not_reported(self) -> None:
        """Verify that standard files without SUID/SGID bits are ignored."""
        with patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid._get_file_stat", side_effect=os.lstat):

            findings = scan_suid_sgid([str(self.target_dir)])
            reported_paths = [f.affected_resource for f in findings]

            self.assertNotIn(str(self.normal_file.resolve()), reported_paths)

    def test_suid_file_detected(self) -> None:
        """Verify that a file with SUID bit set is detected with Finding model."""
        with patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid._get_file_stat", side_effect=self._mock_stat_dispatcher):

            findings = scan_suid_sgid([str(self.target_dir)])
            suid_findings = [f for f in findings if f.finding_id == "SUID-001"]

            self.assertEqual(len(suid_findings), 1)
            finding = suid_findings[0]

            self.assertIsInstance(finding, Finding)
            self.assertEqual(finding.severity, "INFO")
            self.assertEqual(finding.affected_resource, str(self.suid_file.resolve()))
            self.assertIn("SUID Permission Detected", finding.title)
            self.assertIn("chmod u-s", finding.recommendation)
            self.assertEqual(finding.mitre_attack, "T1548.001")
            self.assertNotIn("echo", finding.evidence)  # Never leak file contents

    def test_sgid_file_detected(self) -> None:
        """Verify that a file with SGID bit set is detected with Finding model."""
        with patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid._get_file_stat", side_effect=self._mock_stat_dispatcher):

            findings = scan_suid_sgid([str(self.target_dir)])
            sgid_findings = [f for f in findings if f.finding_id == "SGID-001"]

            self.assertEqual(len(sgid_findings), 1)
            finding = sgid_findings[0]

            self.assertIsInstance(finding, Finding)
            self.assertEqual(finding.severity, "INFO")
            self.assertEqual(finding.affected_resource, str(self.sgid_file.resolve()))
            self.assertIn("SGID Permission Detected", finding.title)
            self.assertIn("chmod g-s", finding.recommendation)
            self.assertEqual(finding.mitre_attack, "T1548.001")

    def test_both_suid_and_sgid_detected(self) -> None:
        """Verify that a file with both SUID and SGID is detected with combined finding ID."""
        with patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid._get_file_stat", side_effect=self._mock_stat_dispatcher):

            findings = scan_suid_sgid([str(self.target_dir)])
            both_findings = [f for f in findings if f.finding_id == "SUID-SGID-001"]

            self.assertEqual(len(both_findings), 1)
            finding = both_findings[0]
            self.assertEqual(finding.affected_resource, str(self.both_file.resolve()))
            self.assertIn("SUID and SGID Permissions Detected", finding.title)
            self.assertIn("chmod ug-s", finding.recommendation)

    def test_no_files_outside_search_paths_inspected(self) -> None:
        """Verify that the scanner does not inspect files outside the given search paths."""
        with patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.suid_sgid._get_file_stat", side_effect=self._mock_stat_dispatcher):

            # Explicitly supply ONLY target_dir, excluding outside_dir
            findings = scan_suid_sgid([str(self.target_dir)])
            reported_paths = [f.affected_resource for f in findings]

            self.assertNotIn(str(self.outside_suid.resolve()), reported_paths)

    def test_missing_and_invalid_paths_handled_safely(self) -> None:
        """Verify missing paths, non-directory files, and invalid paths do not crash."""
        with patch("lpe_sentinel.suid_sgid.is_linux_platform", return_value=True):
            invalid_paths = [
                "/non/existent/path/for/sure/12345",
                str(self.normal_file),  # A file, not a directory
                12345,                  # Non-string invalid type
            ]
            findings = scan_suid_sgid(invalid_paths)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
