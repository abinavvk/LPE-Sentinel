"""
Unit tests for the System Information module (system_info.py).
"""

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

# Add 'src' to sys.path so tests can import lpe_sentinel modules
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lpe_sentinel.system_info import (
    collect_system_info,
    display_system_info,
    get_platform_category,
)


class TestSystemInfo(unittest.TestCase):
    """Test suite for collecting and displaying host system information."""

    def test_collect_system_info_keys(self) -> None:
        """Verify that collect_system_info returns all required keys with non-empty values."""
        info = collect_system_info()

        self.assertIsInstance(info, dict)
        expected_keys = {
            "os_name",
            "os_release",
            "hostname",
            "username",
            "python_version",
            "architecture",
            "platform_category",
        }
        for key in expected_keys:
            self.assertIn(key, info)
            self.assertTrue(len(str(info[key])) > 0)

    def test_platform_category_classification(self) -> None:
        """Verify platform category resolution for various operating system names."""
        test_cases = [
            ("Windows", "Windows"),
            ("Windows NT", "Windows"),
            ("Linux", "Linux"),
            ("linux", "Linux"),
            ("Darwin", "macOS"),
            ("macOS", "macOS"),
            ("FreeBSD", "Other"),
            ("SunOS", "Other"),
            ("", "Other"),
        ]
        for os_name, expected_category in test_cases:
            with self.subTest(os_name=os_name):
                self.assertEqual(get_platform_category(os_name), expected_category)

    def test_mocked_linux_environment(self) -> None:
        """Verify collect_system_info output with mocked Linux environment details."""
        with patch("platform.system", return_value="Linux"), \
             patch("platform.release", return_value="6.6.9-kali1-amd64"), \
             patch("socket.gethostname", return_value="kali-sec-box"), \
             patch("getpass.getuser", return_value="auditor"), \
             patch("platform.python_version", return_value="3.11.8"), \
             patch("platform.machine", return_value="x86_64"):

            info = collect_system_info()

            self.assertEqual(info["os_name"], "Linux")
            self.assertEqual(info["os_release"], "6.6.9-kali1-amd64")
            self.assertEqual(info["hostname"], "kali-sec-box")
            self.assertEqual(info["username"], "auditor")
            self.assertEqual(info["python_version"], "3.11.8")
            self.assertEqual(info["architecture"], "x86_64")
            self.assertEqual(info["platform_category"], "Linux")

    def test_safe_username_fallback(self) -> None:
        """Verify fallback behavior when getpass.getuser() raises an exception."""
        with patch("getpass.getuser", side_effect=Exception("User context unavailable")), \
             patch.dict("os.environ", {"USER": "fallback_user"}):
            info = collect_system_info()
            self.assertEqual(info["username"], "fallback_user")

        with patch("getpass.getuser", side_effect=Exception("User context unavailable")), \
             patch.dict("os.environ", {}, clear=True):
            info = collect_system_info()
            self.assertEqual(info["username"], "Unknown")

    def test_graceful_handling_on_collector_exceptions(self) -> None:
        """Verify that individual collection errors do not crash collect_system_info."""
        with patch("platform.system", side_effect=RuntimeError("System lookup failed")), \
             patch("socket.gethostname", side_effect=OSError("Hostname lookup failed")), \
             patch("platform.release", side_effect=Exception("Release lookup failed")):

            info = collect_system_info()

            self.assertEqual(info["os_name"], "Unavailable")
            self.assertEqual(info["hostname"], "Unavailable")
            self.assertEqual(info["os_release"], "Unavailable")
            self.assertEqual(info["platform_category"], "Other")

    def test_display_system_info_output(self) -> None:
        """Verify that display_system_info formats and prints all fields to stdout."""
        sample_info = {
            "os_name": "Linux",
            "os_release": "6.6.9",
            "hostname": "test-box",
            "username": "student",
            "python_version": "3.11.0",
            "architecture": "x86_64",
            "platform_category": "Linux",
        }

        captured_output = io.StringIO()
        with redirect_stdout(captured_output):
            display_system_info(sample_info)

        output = captured_output.getvalue()
        self.assertIn("SYSTEM INFORMATION", output)
        self.assertIn("Linux", output)
        self.assertIn("test-box", output)
        self.assertIn("student", output)
        self.assertIn("x86_64", output)
        self.assertIn("3.11.0", output)


if __name__ == "__main__":
    unittest.main()
