"""
Unit tests for the LPE Sentinel starter application and CLI.
"""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

# Add 'src' to sys.path so tests can import lpe_sentinel without requiring package installation
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import lpe_sentinel
from lpe_sentinel import main as main_module


class TestStarterApplication(unittest.TestCase):
    """Test suite verifying the starter application foundation and CLI menu."""

    def test_package_version(self) -> None:
        """Verify that the package version in __init__.py is 0.1.0."""
        self.assertEqual(lpe_sentinel.__version__, "0.1.0")

    def test_import_does_not_execute_cli(self) -> None:
        """Verify that importing main_module does not run main() automatically."""
        self.assertTrue(callable(main_module.main))

    def test_main_output(self) -> None:
        """Verify that main() prints the project name, version 0.1.0, and status message."""
        captured_output = io.StringIO()
        with patch("builtins.input", return_value="4"):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()

        # 1. Project name
        self.assertIn("LPE Sentinel", output)
        # 2. Version 0.1.0
        self.assertIn("0.1.0", output)
        # 3. Development-status message
        self.assertIn("Toolkit is currently under development", output)

    def test_menu_display(self) -> None:
        """Verify that the main menu displays all required options."""
        captured_output = io.StringIO()
        with redirect_stdout(captured_output):
            main_module.print_menu()

        output = captured_output.getvalue()
        self.assertIn("[1] System Information", output)
        self.assertIn("[2] Security Audit", output)
        self.assertIn("[3] Generate Report", output)
        self.assertIn("[4] Exit", output)

    def test_system_info_option_1_cli(self) -> None:
        """Verify option 1 invokes system information display and returns to menu."""
        captured_output = io.StringIO()
        with patch("builtins.input", side_effect=["1", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("SYSTEM INFORMATION", output)
        self.assertIn("Platform Category", output)
        self.assertIn("Operating System", output)

    def test_generate_report_empty_path(self) -> None:
        """Verify report generator rejects empty path and returns to main menu."""
        captured_output = io.StringIO()
        with patch("builtins.input", side_effect=["3", "", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("SECURITY REPORT GENERATION", output)
        self.assertIn("No report path provided. Report generation cancelled.", output)
        self.assertIn("Exiting LPE Sentinel", output)

    def test_generate_report_cancel_on_eof(self) -> None:
        """Verify report generator handles EOFError during path prompt gracefully."""
        captured_output = io.StringIO()
        with patch("builtins.input", side_effect=["3", EOFError, "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("Report generation cancelled. Returning to main menu.", output)
        self.assertIn("Exiting LPE Sentinel", output)

    def test_generate_report_empty_session(self) -> None:
        """Verify generating a report when no scans have been run creates a valid 0-finding report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dest_file = Path(tmpdir) / "empty-report.json"
            captured_output = io.StringIO()
            with patch("builtins.input", side_effect=["3", str(dest_file), "4"]):
                with redirect_stdout(captured_output):
                    main_module.main()

            output = captured_output.getvalue()
            self.assertIn("Session Findings Collected: 0", output)
            self.assertIn("No findings have been recorded in this session.", output)
            self.assertIn("Security report generated successfully", output)
            self.assertIn(str(dest_file), output)
            self.assertTrue(dest_file.exists())

            with open(dest_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["summary"]["total_findings"], 0)
            self.assertEqual(data["findings"], [])
            self.assertIn("report_metadata", data)
            self.assertIn("system_info", data)

    def test_generate_report_with_findings(self) -> None:
        """Verify generating a report includes findings collected during a scan."""
        from lpe_sentinel.models import Finding

        mock_finding = Finding(
            finding_id="SUID-001",
            title="SUID Executable Detected",
            severity="INFO",
            description="A binary has SUID set.",
            evidence="Permissions: -rwsr-xr-x (0o4755)",
            affected_resource="/usr/bin/passwd",
            recommendation="Verify requirement.",
            mitre_attack="T1548.001",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_file = Path(tmpdir) / "findings-report.json"
            captured_output = io.StringIO()
            with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.main.scan_suid_sgid", return_value=[mock_finding]), \
                 patch("builtins.input", side_effect=[
                     "2", "1", "/usr/bin", "4",  # Run SUID scan -> exit submenu
                     "3", str(dest_file),         # Generate report
                     "4"                          # Exit
                 ]):
                with redirect_stdout(captured_output):
                    main_module.main()

            output = captured_output.getvalue()
            self.assertIn("Security report generated successfully", output)
            self.assertIn("Total findings recorded: 1", output)
            self.assertTrue(dest_file.exists())

            with open(dest_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["summary"]["total_findings"], 1)
            self.assertEqual(data["findings"][0]["finding_id"], "SUID-001")
            self.assertEqual(data["findings"][0]["affected_resource"], "/usr/bin/passwd")

    def test_generate_report_retains_findings_from_multiple_scans(self) -> None:
        """Verify session retains findings across multiple distinct scanner runs."""
        from lpe_sentinel.models import Finding

        suid_finding = Finding(
            finding_id="SUID-001",
            title="SUID Executable",
            severity="INFO",
            description="SUID binary.",
            evidence="Mode 0o4755",
            affected_resource="/usr/bin/passwd",
            recommendation="Review.",
        )
        perm_finding = Finding(
            finding_id="PERM-001",
            title="World-Writable File",
            severity="HIGH",
            description="Writable file.",
            evidence="Mode 0o666",
            affected_resource="/etc/cron.d/job",
            recommendation="Fix perms.",
        )
        sudo_finding = Finding(
            finding_id="SUDO-001",
            title="Sudo NOPASSWD",
            severity="MEDIUM",
            description="Passwordless rule.",
            evidence="Line 1: NOPASSWD",
            affected_resource="/etc/sudoers",
            recommendation="Review sudoers.",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_file = Path(tmpdir) / "multi-scan-report.json"
            captured_output = io.StringIO()
            with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.main.scan_suid_sgid", return_value=[suid_finding]), \
                 patch("lpe_sentinel.main.scan_sensitive_permissions", return_value=[perm_finding]), \
                 patch("lpe_sentinel.main.scan_sudo_config", return_value=[sudo_finding]), \
                 patch("builtins.input", side_effect=[
                     "2", "1", "/usr/bin",            # Scan 1: SUID
                     "2", "/etc/cron.d/job",          # Scan 2: Sensitive perms
                     "3", "/etc/sudoers",             # Scan 3: Sudo config
                     "4",                             # Return to main menu
                     "3", str(dest_file),             # Generate report
                     "4"                              # Exit
                 ]):
                with redirect_stdout(captured_output):
                    main_module.main()

            output = captured_output.getvalue()
            self.assertIn("Total findings recorded: 3", output)
            self.assertTrue(dest_file.exists())

            with open(dest_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["summary"]["total_findings"], 3)
            ids = [f["finding_id"] for f in data["findings"]]
            self.assertIn("SUID-001", ids)
            self.assertIn("PERM-001", ids)
            self.assertIn("SUDO-001", ids)

    def test_generate_report_deduplicates_repeated_scans(self) -> None:
        """Verify identical findings from running the same scan twice are not duplicated."""
        from lpe_sentinel.models import Finding

        suid_finding = Finding(
            finding_id="SUID-001",
            title="SUID Executable",
            severity="INFO",
            description="SUID binary.",
            evidence="Mode 0o4755",
            affected_resource="/usr/bin/passwd",
            recommendation="Review.",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_file = Path(tmpdir) / "dedup-report.json"
            captured_output = io.StringIO()
            with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.main.scan_suid_sgid", return_value=[suid_finding]), \
                 patch("builtins.input", side_effect=[
                     "2", "1", "/usr/bin",            # Scan 1: SUID
                     "1", "/usr/bin",                 # Scan 2: SUID again (same findings)
                     "4",                             # Return to main menu
                     "3", str(dest_file),             # Generate report
                     "4"                              # Exit
                 ]):
                with redirect_stdout(captured_output):
                    main_module.main()

            output = captured_output.getvalue()
            self.assertIn("Total findings recorded: 1", output)
            with open(dest_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["summary"]["total_findings"], 1)

    def test_generate_report_existing_destination_protection(self) -> None:
        """Verify report generator refuses to overwrite an existing destination file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            existing_file = Path(tmpdir) / "preexisting.json"
            existing_file.write_text('{"original": "data"}', encoding="utf-8")

            captured_output = io.StringIO()
            with patch("builtins.input", side_effect=["3", str(existing_file), "4"]):
                with redirect_stdout(captured_output):
                    main_module.main()

            output = captured_output.getvalue()
            self.assertIn("Report file already exists", output)
            self.assertIn("Overwriting existing reports is not permitted by default", output)
            # Verify original content was not overwritten
            self.assertEqual(existing_file.read_text(encoding="utf-8"), '{"original": "data"}')

    def test_generate_report_write_failure_handling(self) -> None:
        """Verify write errors (e.g. disk or permission error) are caught cleanly without crashing."""
        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.save_report_to_file", side_effect=OSError("Disk write error")), \
             patch("builtins.input", side_effect=["3", "/fake/path/report.json", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("Failed to save report: Disk write error", output)
        self.assertIn("Exiting LPE Sentinel", output)

    def test_security_audit_submenu_display_and_return(self) -> None:
        """Verify option 2 displays the security audit submenu and option 4 returns cleanly."""
        captured_output = io.StringIO()
        # Option 2 (Security Audit) -> Submenu Option 4 (Return) -> Main Option 4 (Exit)
        with patch("builtins.input", side_effect=["2", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("SECURITY AUDIT", output)
        self.assertIn("[1] Scan directories for SUID/SGID files", output)
        self.assertIn("[2] Check explicitly selected files for risky write permissions", output)
        self.assertIn("[3] Audit explicitly selected sudo configuration files", output)
        self.assertIn("[4] Return to main menu", output)
        self.assertIn("Returning to main menu", output)

    def test_security_audit_submenu_invalid_choice(self) -> None:
        """Verify invalid submenu choices are handled gracefully without crashing."""
        captured_output = io.StringIO()
        # Option 2 -> Invalid "99" -> Submenu Option 4 -> Main Option 4
        with patch("builtins.input", side_effect=["2", "99", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("Invalid option: '99'", output)

    def test_suid_sgid_submenu_empty_path_input(self) -> None:
        """Verify SUID/SGID scanner rejects empty directory input and returns to submenu."""
        captured_output = io.StringIO()
        # Option 2 -> Submenu Option 1 -> empty string -> Submenu Option 4 -> Main Option 4
        with patch("builtins.input", side_effect=["2", "1", "", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("SUID / SGID FILE PERMISSION SCAN", output)
        self.assertIn("No directories provided. Audit cancelled. Returning to submenu.", output)

    def test_suid_sgid_submenu_unsupported_platform(self) -> None:
        """Verify SUID/SGID scanner displays unsupported platform warning on Windows/macOS."""
        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=False), \
             patch("platform.system", return_value="Windows"), \
             patch("builtins.input", side_effect=["2", "1", "/usr/bin;/bin", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("SUID/SGID scanning is only supported on Linux operating systems", output)
        self.assertIn("Current platform is 'Windows'", output)
        self.assertNotIn("Audit completed", output)

    def test_suid_sgid_submenu_no_findings_message(self) -> None:
        """Verify SUID/SGID scanner message when no files are found in accessible paths."""
        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.main.scan_suid_sgid", return_value=[]), \
             patch("builtins.input", side_effect=["2", "1", "/tmp/safe_dir", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("No SUID/SGID files were detected within the selected accessible paths", output)
        self.assertIn("does not guarantee that the overall system is secure", output)

    def test_suid_sgid_submenu_displays_findings(self) -> None:
        """Verify SUID/SGID scanner displays finding details when files are detected."""
        from lpe_sentinel.models import Finding

        mock_finding = Finding(
            finding_id="SUID-001",
            title="SUID Permission Detected",
            severity="INFO",
            description="The file has SUID enabled.",
            evidence="Permissions: -rwsr-xr-x (0o4755)",
            affected_resource="/usr/bin/passwd",
            recommendation="Verify whether SUID is required.",
            mitre_attack="T1548.001",
        )

        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.main.scan_suid_sgid", return_value=[mock_finding]) as mock_scan, \
             patch("builtins.input", side_effect=["2", "1", "/usr/bin; /usr/local/bin", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        mock_scan.assert_called_once_with(["/usr/bin", "/usr/local/bin"])
        output = captured_output.getvalue()
        self.assertIn("Audit completed: 1 finding(s) discovered", output)
        self.assertIn("SUID-001", output)
        self.assertIn("SUID Permission Detected", output)
        self.assertIn("/usr/bin/passwd", output)
        self.assertIn("Permissions: -rwsr-xr-x (0o4755)", output)
        self.assertIn("Verify whether SUID is required", output)

    def test_sensitive_permissions_submenu_empty_path_input(self) -> None:
        """Verify sensitive permissions scanner rejects empty input and returns to submenu."""
        captured_output = io.StringIO()
        # Option 2 -> Submenu Option 2 -> empty string -> Submenu Option 4 -> Main Option 4
        with patch("builtins.input", side_effect=["2", "2", "", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("RISKY FILE WRITE PERMISSIONS SCAN", output)
        self.assertIn("No file paths provided. Audit cancelled. Returning to submenu.", output)

    def test_sensitive_permissions_submenu_unsupported_platform(self) -> None:
        """Verify sensitive permissions scanner displays unsupported platform warning on Windows/macOS."""
        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=False), \
             patch("platform.system", return_value="Windows"), \
             patch("builtins.input", side_effect=["2", "2", "/etc/shadow;/etc/passwd", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("Sensitive file permission scanning is only supported on Linux operating systems", output)
        self.assertIn("Current platform is 'Windows'", output)
        self.assertNotIn("Audit completed", output)

    def test_sensitive_permissions_submenu_no_findings_message(self) -> None:
        """Verify sensitive permissions message when no matching issues are detected."""
        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.main.scan_sensitive_permissions", return_value=[]), \
             patch("builtins.input", side_effect=["2", "2", "/etc/safe.conf", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("No matching permission issues were detected among the selected accessible files", output)
        self.assertIn("does not guarantee that the overall system is secure", output)

    def test_sensitive_permissions_submenu_displays_findings(self) -> None:
        """Verify sensitive permissions scanner displays finding details and preliminary notice."""
        from lpe_sentinel.models import Finding

        mock_finding = Finding(
            finding_id="PERM-001",
            title="World-Writable File Permissions",
            severity="HIGH",
            description="The file is writable by any user.",
            evidence="Permissions: -rw-rw-rw- (0o666)",
            affected_resource="/etc/test.conf",
            recommendation="Remove world-write permissions.",
            mitre_attack="T1222.002",
        )

        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.main.scan_sensitive_permissions", return_value=[mock_finding]) as mock_scan, \
             patch("builtins.input", side_effect=["2", "2", "/etc/test.conf; /etc/test2.conf", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        mock_scan.assert_called_once_with(["/etc/test.conf", "/etc/test2.conf"])
        output = captured_output.getvalue()
        self.assertIn("preliminary permission-risk indicators", output)
        self.assertIn("Audit completed: 1 finding(s) discovered", output)
        self.assertIn("PERM-001", output)
        self.assertIn("HIGH", output)
        self.assertIn("World-Writable File Permissions", output)
        self.assertIn("/etc/test.conf", output)
        self.assertIn("Permissions: -rw-rw-rw- (0o666)", output)
        self.assertIn("Remove world-write permissions", output)

    def test_sudo_audit_submenu_empty_path_input(self) -> None:
        """Verify sudo audit scanner rejects empty input and returns to submenu."""
        captured_output = io.StringIO()
        # Option 2 -> Submenu Option 3 -> empty string -> Submenu Option 4 -> Main Option 4
        with patch("builtins.input", side_effect=["2", "3", "", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("SUDO CONFIGURATION SECURITY AUDIT", output)
        self.assertIn("No configuration files provided. Audit cancelled. Returning to submenu.", output)

    def test_sudo_audit_submenu_unsupported_platform(self) -> None:
        """Verify sudo audit scanner displays unsupported platform warning on Windows/macOS."""
        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=False), \
             patch("platform.system", return_value="Windows"), \
             patch("builtins.input", side_effect=["2", "3", "/etc/sudoers", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("Sudo configuration auditing is only supported on Linux operating systems", output)
        self.assertIn("Current platform is 'Windows'", output)
        self.assertNotIn("Audit completed", output)

    def test_sudo_audit_submenu_no_findings_message(self) -> None:
        """Verify sudo audit scanner message when no matching issues are detected."""
        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.main.scan_sudo_config", return_value=[]), \
             patch("builtins.input", side_effect=["2", "3", "/etc/sudoers_clean", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("No sudo configuration risk patterns detected in the selected accessible files", output)
        self.assertIn("does not guarantee that the overall system is secure", output)

    def test_sudo_audit_submenu_displays_findings(self) -> None:
        """Verify sudo audit scanner displays finding details and preliminary notice."""
        from lpe_sentinel.models import Finding

        mock_finding = Finding(
            finding_id="SUDO-001",
            title="Sudo NOPASSWD Rule Detected",
            severity="MEDIUM",
            description="The rule contains NOPASSWD.",
            evidence="Line 2: Matched NOPASSWD tag",
            affected_resource="/etc/sudoers",
            recommendation="Review passwordless sudo rules.",
            mitre_attack="T1548.003",
        )

        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.main.scan_sudo_config", return_value=[mock_finding]) as mock_scan, \
             patch("builtins.input", side_effect=["2", "3", "/etc/sudoers; /etc/sudoers.d/admin", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        mock_scan.assert_called_once_with(["/etc/sudoers", "/etc/sudoers.d/admin"])
        output = captured_output.getvalue()
        self.assertIn("preliminary indicators, not proof of a vulnerability", output)
        self.assertIn("Audit completed: 1 finding(s) discovered", output)
        self.assertIn("SUDO-001", output)
        self.assertIn("MEDIUM", output)
        self.assertIn("Sudo NOPASSWD Rule Detected", output)
        self.assertIn("/etc/sudoers", output)
        self.assertIn("Line 2: Matched NOPASSWD tag", output)
        self.assertIn("Review passwordless sudo rules", output)

    def test_clean_exit_option_4(self) -> None:
        """Verify option 4 exits cleanly with an exit message."""
        captured_output = io.StringIO()
        with patch("builtins.input", return_value="4"):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("Exiting LPE Sentinel", output)

    def test_invalid_input_handling(self) -> None:
        """Verify invalid menu inputs are handled gracefully without crashing."""
        captured_output = io.StringIO()
        # Feed an invalid option first, then option 4 to exit
        with patch("builtins.input", side_effect=["99", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("Invalid option: '99'", output)
        self.assertIn("Exiting LPE Sentinel", output)

    def test_eof_handling(self) -> None:
        """Verify that EOFError (e.g. Ctrl+D / closed input stream) exits cleanly."""
        captured_output = io.StringIO()
        with patch("builtins.input", side_effect=EOFError):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("Exiting LPE Sentinel", output)

    def test_audit_submenu_completed_scan_zero_findings_displays_summary(self) -> None:
        """Verify completed scan with zero findings displays audit summary with 0 totals."""
        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.main.scan_suid_sgid", return_value=[]), \
             patch("builtins.input", side_effect=["2", "1", "/tmp/safe_dir", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("No SUID/SGID files were detected", output)
        self.assertIn("AUDIT FINDINGS SUMMARY", output)
        self.assertIn("Total Findings            : 0", output)
        self.assertIn("SUID     : 0", output)

    def test_audit_submenu_completed_scan_with_findings_displays_summary(self) -> None:
        """Verify completed scan with findings displays audit summary reflecting discovered counts."""
        from lpe_sentinel.models import Finding

        mock_finding = Finding(
            finding_id="SUID-001",
            title="SUID Permission Detected",
            severity="INFO",
            description="The file has SUID enabled.",
            evidence="Permissions: -rwsr-xr-x (0o4755)",
            affected_resource="/usr/bin/passwd",
            recommendation="Verify requirement.",
            mitre_attack="T1548.001",
        )

        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.main.scan_suid_sgid", return_value=[mock_finding]), \
             patch("builtins.input", side_effect=["2", "1", "/usr/bin", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("Audit completed: 1 finding(s) discovered", output)
        self.assertIn("AUDIT FINDINGS SUMMARY", output)
        self.assertIn("Total Findings            : 1", output)
        self.assertIn("INFO     : 1", output)
        self.assertIn("SUID     : 1", output)

    def test_audit_submenu_accumulates_findings_from_multiple_scans_in_summary(self) -> None:
        """Verify audit summary accumulates findings across multiple scans in the same session."""
        from lpe_sentinel.models import Finding

        suid_finding = Finding(
            finding_id="SUID-001",
            title="SUID Binary",
            severity="INFO",
            description="SUID set.",
            evidence="Mode 0o4755",
            affected_resource="/usr/bin/passwd",
            recommendation="Review.",
        )
        perm_finding = Finding(
            finding_id="PERM-001",
            title="World Writable",
            severity="HIGH",
            description="Writable.",
            evidence="Mode 0o666",
            affected_resource="/etc/cron.d/job",
            recommendation="Fix.",
        )

        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.main.scan_suid_sgid", return_value=[suid_finding]), \
             patch("lpe_sentinel.main.scan_sensitive_permissions", return_value=[perm_finding]), \
             patch("builtins.input", side_effect=[
                 "2", "1", "/usr/bin",            # Scan 1: SUID
                 "2", "/etc/cron.d/job",          # Scan 2: Sensitive perms
                 "4", "4"                         # Exit submenu -> exit main
             ]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("Total Findings            : 2", output)
        self.assertIn("SUID     : 1", output)
        self.assertIn("PERM     : 1", output)
        self.assertIn("HIGH     : 1", output)
        self.assertIn("INFO     : 1", output)

    def test_audit_submenu_unsupported_scan_does_not_display_summary(self) -> None:
        """Verify unsupported scans do not display an audit summary to avoid misleading clean results."""
        captured_output = io.StringIO()
        with patch("lpe_sentinel.main.is_linux_platform", return_value=False), \
             patch("platform.system", return_value="Windows"), \
             patch("builtins.input", side_effect=["2", "1", "/usr/bin", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("Current platform is 'Windows'. No audit performed.", output)
        self.assertNotIn("AUDIT FINDINGS SUMMARY", output)

    def test_audit_submenu_cancelled_input_does_not_display_summary(self) -> None:
        """Verify cancelled scan input does not display an audit summary."""
        captured_output = io.StringIO()
        with patch("builtins.input", side_effect=["2", "1", "", "4", "4"]):
            with redirect_stdout(captured_output):
                main_module.main()

        output = captured_output.getvalue()
        self.assertIn("No directories provided. Audit cancelled.", output)
        self.assertNotIn("AUDIT FINDINGS SUMMARY", output)


if __name__ == "__main__":
    unittest.main()
