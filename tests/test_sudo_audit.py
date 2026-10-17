"""
Unit tests for Sudo Configuration Auditor (sudo_audit.py).
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
from lpe_sentinel.sudo_audit import (
    is_linux_platform,
    scan_sudo_config,
)


class TestSudoAuditScanner(unittest.TestCase):
    """Test suite for sudoers configuration inspection and platform safety."""

    def setUp(self) -> None:
        """Create temporary test directories and sudoers configuration files."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.test_dir.name)

        # 1. Clean file with only safe specific rules, comments, and blank lines
        self.clean_file = self.root_path / "sudoers_clean"
        self.clean_file.write_text(
            "# /etc/sudoers sample file\n"
            "# Defaults specification\n"
            "Defaults env_reset\n\n"
            "# User privilege specification\n"
            "operator ALL=(root) /usr/bin/apt-get update\n"
            "backup_user ALL=(root) /usr/local/bin/backup\n"
        )

        # 2. File with NOPASSWD pattern
        self.nopasswd_file = self.root_path / "sudoers_nopasswd"
        self.nopasswd_file.write_text(
            "# NOPASSWD test\n"
            "secret_agent ALL=(root) NOPASSWD: /usr/bin/cat\n"
        )

        # 3. File with ALL command pattern
        self.all_cmd_file = self.root_path / "sudoers_all"
        self.all_cmd_file.write_text(
            "# ALL commands test\n"
            "admin_user ALL=(ALL:ALL) ALL\n"
        )

        # 4. File with Wildcard pattern
        self.wildcard_file = self.root_path / "sudoers_wildcard"
        self.wildcard_file.write_text(
            "# Wildcard test\n"
            "deployer ALL=(root) /opt/scripts/*.sh\n"
        )

        # 5. Combined risk file
        self.combined_file = self.root_path / "sudoers_combined"
        self.combined_file.write_text(
            "# Combined NOPASSWD and ALL\n"
            "super_dev ALL=(ALL) NOPASSWD: ALL\n"
        )

    def tearDown(self) -> None:
        """Clean up temporary test files."""
        self.test_dir.cleanup()

    def test_unsupported_platform_behavior(self) -> None:
        """Verify that running on Windows/macOS returns empty and issues a warning."""
        with patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=False), \
             patch("platform.system", return_value="Windows"):

            with warnings.catch_warnings(record=True) as captured_warnings:
                warnings.simplefilter("always")
                findings = scan_sudo_config([str(self.all_cmd_file)])

                self.assertEqual(findings, [])
                self.assertTrue(len(captured_warnings) >= 1)
                self.assertIn("only supported on Linux", str(captured_warnings[0].message))

    def test_clean_file_comments_and_blanks_ignored(self) -> None:
        """Verify comments, blank lines, and safe specific commands produce no findings."""
        with patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):
            findings = scan_sudo_config([str(self.clean_file)])
            self.assertEqual(findings, [])

    def test_nopasswd_pattern_detected(self) -> None:
        """Verify NOPASSWD rule generates SUDO-001 finding."""
        with patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):
            findings = scan_sudo_config([str(self.nopasswd_file)])

            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.finding_id, "SUDO-001")
            self.assertEqual(f.severity, "MEDIUM")
            self.assertIn("NOPASSWD", f.title)
            self.assertEqual(f.affected_resource, str(self.nopasswd_file.resolve()))
            self.assertEqual(f.evidence, "Line 2: Matched NOPASSWD tag")
            self.assertEqual(f.mitre_attack, "T1548.003")

    def test_all_command_pattern_detected(self) -> None:
        """Verify unrestricted ALL command rule generates SUDO-002 finding."""
        with patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):
            findings = scan_sudo_config([str(self.all_cmd_file)])

            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.finding_id, "SUDO-002")
            self.assertEqual(f.severity, "MEDIUM")
            self.assertIn("Unrestricted Sudo ALL", f.title)
            self.assertEqual(f.affected_resource, str(self.all_cmd_file.resolve()))
            self.assertEqual(f.evidence, "Line 2: Matched unrestricted ALL command specification")
            self.assertEqual(f.mitre_attack, "T1548.003")

    def test_wildcard_pattern_detected(self) -> None:
        """Verify wildcard command rule generates SUDO-003 finding."""
        with patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):
            findings = scan_sudo_config([str(self.wildcard_file)])

            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.finding_id, "SUDO-003")
            self.assertEqual(f.severity, "LOW")
            self.assertIn("Wildcard Pattern", f.title)
            self.assertEqual(f.affected_resource, str(self.wildcard_file.resolve()))
            self.assertEqual(f.evidence, "Line 2: Matched wildcard (*) command specification")
            self.assertEqual(f.mitre_attack, "T1548.003")

    def test_combined_rule_generates_both_findings(self) -> None:
        """Verify a line with both NOPASSWD and ALL generates SUDO-001 and SUDO-002."""
        with patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):
            findings = scan_sudo_config([str(self.combined_file)])

            self.assertEqual(len(findings), 2)
            finding_ids = {f.finding_id for f in findings}
            self.assertEqual(finding_ids, {"SUDO-001", "SUDO-002"})

    def test_safe_evidence_does_not_leak_usernames_or_rules(self) -> None:
        """Verify evidence never includes full rule contents or sensitive usernames."""
        with patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):
            findings = scan_sudo_config([str(self.nopasswd_file), str(self.all_cmd_file)])

            for f in findings:
                # Sensitive usernames in test files
                self.assertNotIn("secret_agent", f.evidence)
                self.assertNotIn("admin_user", f.evidence)
                # Full sudoers syntax characters
                self.assertNotIn("ALL=(", f.evidence)

    def test_multiple_files_audited_independently(self) -> None:
        """Verify multiple configuration files are audited together."""
        with patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):
            findings = scan_sudo_config([str(self.nopasswd_file), str(self.wildcard_file)])

            self.assertEqual(len(findings), 2)
            resources = {f.affected_resource for f in findings}
            self.assertIn(str(self.nopasswd_file.resolve()), resources)
            self.assertIn(str(self.wildcard_file.resolve()), resources)

    def test_missing_and_invalid_entries_handled_safely(self) -> None:
        """Verify non-existent files, directories, None, and non-strings do not crash."""
        with patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True):
            invalid_entries = [
                "/non/existent/sudoers.d/custom",
                str(self.root_path),  # Directory, not a regular file
                "",
                None,
                99999,
            ]
            findings = scan_sudo_config(invalid_entries)
            self.assertEqual(findings, [])

    def test_unreadable_file_handled_safely(self) -> None:
        """Verify PermissionError during file open is handled safely."""
        with patch("lpe_sentinel.sudo_audit.is_linux_platform", return_value=True), \
             patch("builtins.open", side_effect=PermissionError("Permission denied")):

            findings = scan_sudo_config([str(self.all_cmd_file)])
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
