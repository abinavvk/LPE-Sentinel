"""
Unit tests for Sensitive File Permissions Scanner (sensitive_permissions.py).
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
from lpe_sentinel.sensitive_permissions import (
    is_linux_platform,
    scan_sensitive_permissions,
)


class TestSensitivePermissionsScanner(unittest.TestCase):
    """Test suite for sensitive file permissions scanning and platform safety."""

    def setUp(self) -> None:
        """Create temporary test files for permission auditing."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.test_dir.name)

        # 1. Normal secure file (read/write owner, read-only group and others: 0o644)
        self.normal_file = self.root_path / "normal.conf"
        self.normal_file.write_text("PARAM=SECURE\n")

        # 2. Group-writable file (0o664)
        self.group_writable_file = self.root_path / "group_writable.conf"
        self.group_writable_file.write_text("PARAM=GROUP_EDITABLE\n")

        # 3. World-writable file (0o666)
        self.world_writable_file = self.root_path / "world_writable.conf"
        self.world_writable_file.write_text("PARAM=WORLD_EDITABLE\n")

        # 4. Unsupplied file that is also world-writable
        self.unsupplied_file = self.root_path / "unsupplied.conf"
        self.unsupplied_file.write_text("SECRET=DO_NOT_INSPECT\n")

    def tearDown(self) -> None:
        """Clean up temporary test files."""
        self.test_dir.cleanup()

    def _mock_stat_dispatcher(self, file_path: str) -> os.stat_result:
        """Portably simulate POSIX permission modes across Windows & Linux."""
        real_st = os.lstat(file_path)
        filename = os.path.basename(file_path)

        if filename in ("world_writable.conf", "unsupplied.conf"):
            # S_IFREG + mode 0o666 (world & group writable)
            simulated_mode = stat.S_IFREG | 0o666
            return os.stat_result((simulated_mode, *tuple(real_st)[1:]))
        elif filename == "group_writable.conf":
            # S_IFREG + mode 0o664 (group writable only)
            simulated_mode = stat.S_IFREG | 0o664
            return os.stat_result((simulated_mode, *tuple(real_st)[1:]))
        elif filename == "normal.conf":
            # S_IFREG + mode 0o644 (read-only for group/others)
            simulated_mode = stat.S_IFREG | 0o644
            return os.stat_result((simulated_mode, *tuple(real_st)[1:]))
        elif filename == "symlink_test.conf":
            # S_IFLNK (symbolic link)
            simulated_mode = stat.S_IFLNK | 0o777
            return os.stat_result((simulated_mode, *tuple(real_st)[1:]))

        return real_st

    def test_unsupported_platform_behavior(self) -> None:
        """Verify that running on Windows/macOS returns empty and issues a warning."""
        with patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=False), \
             patch("platform.system", return_value="Windows"):

            with warnings.catch_warnings(record=True) as captured_warnings:
                warnings.simplefilter("always")
                findings = scan_sensitive_permissions([str(self.world_writable_file)])

                self.assertEqual(findings, [])
                self.assertTrue(len(captured_warnings) >= 1)
                self.assertIn("only supported on Linux", str(captured_warnings[0].message))

    def test_normal_file_is_not_reported(self) -> None:
        """Verify that a normal non-group/world writable file generates no finding."""
        with patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions._get_file_stat", side_effect=self._mock_stat_dispatcher):

            findings = scan_sensitive_permissions([str(self.normal_file)])
            self.assertEqual(findings, [])

    def test_group_writable_file_detected(self) -> None:
        """Verify group-writable file generates PERM-002 with MEDIUM severity."""
        with patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions._get_file_stat", side_effect=self._mock_stat_dispatcher):

            findings = scan_sensitive_permissions([str(self.group_writable_file)])

            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertIsInstance(finding, Finding)
            self.assertEqual(finding.finding_id, "PERM-002")
            self.assertEqual(finding.severity, "MEDIUM")
            self.assertIn("Group-Writable", finding.title)
            self.assertEqual(finding.affected_resource, str(self.group_writable_file.resolve()))
            self.assertIn("chmod g-w", finding.recommendation)
            self.assertEqual(finding.mitre_attack, "T1222.002")
            self.assertNotIn("PARAM=", finding.evidence)  # No file content in evidence

    def test_world_writable_file_detected(self) -> None:
        """Verify world-writable file generates PERM-001 with HIGH severity."""
        with patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions._get_file_stat", side_effect=self._mock_stat_dispatcher):

            findings = scan_sensitive_permissions([str(self.world_writable_file)])

            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertIsInstance(finding, Finding)
            self.assertEqual(finding.finding_id, "PERM-001")
            self.assertEqual(finding.severity, "HIGH")
            self.assertIn("World-Writable", finding.title)
            self.assertEqual(finding.affected_resource, str(self.world_writable_file.resolve()))
            self.assertIn("chmod o-w", finding.recommendation)
            self.assertEqual(finding.mitre_attack, "T1222.002")
            self.assertNotIn("PARAM=", finding.evidence)  # No file content in evidence

    def test_symlink_is_not_followed(self) -> None:
        """Verify that symbolic links are skipped without following target files."""
        symlink_path = self.root_path / "symlink_test.conf"
        # We don't need real symlink; _mock_stat_dispatcher flags this filename as S_IFLNK
        symlink_path.write_text("DUMMY")

        with patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions._get_file_stat", side_effect=self._mock_stat_dispatcher):

            findings = scan_sensitive_permissions([str(symlink_path)])
            self.assertEqual(findings, [])

    def test_restriction_to_supplied_paths(self) -> None:
        """Verify files not in the supplied target_paths list are never inspected or reported."""
        with patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.sensitive_permissions._get_file_stat", side_effect=self._mock_stat_dispatcher):

            # Only provide world_writable_file, deliberately omit unsupplied_file
            findings = scan_sensitive_permissions([str(self.world_writable_file)])
            reported_paths = [f.affected_resource for f in findings]

            self.assertIn(str(self.world_writable_file.resolve()), reported_paths)
            self.assertNotIn(str(self.unsupplied_file.resolve()), reported_paths)

    def test_missing_and_inaccessible_paths_handled_safely(self) -> None:
        """Verify non-existent files and invalid entries do not crash the scanner."""
        with patch("lpe_sentinel.sensitive_permissions.is_linux_platform", return_value=True):
            invalid_paths = [
                "/non/existent/config/file.conf",
                str(self.root_path),  # Directory, not a regular file
                "",
                None,
                12345,
            ]
            findings = scan_sensitive_permissions(invalid_paths)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
