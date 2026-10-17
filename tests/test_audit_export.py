"""
Unit and Integration Tests for Audit Report Export (Task 5E).

Tests JSON, CSV, and HTML report generators, API export endpoints, header security,
sanitization, formula/HTML injection defense, and non-execution of real scanners.
"""

import csv
import io
import json
import os
import re
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import sys
from http import HTTPStatus
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add 'src' to sys.path so tests can import lpe_sentinel modules
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lpe_sentinel.audit_history import AuditHistoryManager
from lpe_sentinel.export import (
    generate_csv_export,
    generate_html_export,
    generate_json_export,
)
from lpe_sentinel.web.server import create_web_server
from lpe_sentinel.web.templates import render_dashboard_html


class TestAuditExportGenerators(unittest.TestCase):
    """Unit tests for standalone export generators."""

    def setUp(self) -> None:
        self.sample_audit = {
            "scan_id": "scan_20261017_180000_1234abcd",
            "timestamp": "2026-10-17T18:00:00Z",
            "status": "COMPLETED",
            "is_complete": True,
            "duration_ms": 150.25,
            "summary": {
                "critical": 1,
                "high": 1,
                "medium": 0,
                "low": 1,
                "info": 0,
                "total": 3,
            },
            "system_info": {
                "os_name": "Linux",
                "release": "6.6.9-kali1-amd64",
                "architecture": "x86_64",
                "platform_category": "Linux",
            },
            "scanner_results": {
                "suid_sgid": {"status": "COMPLETED", "findings_count": 2, "error": None},
                "binary_risk": {"status": "COMPLETED", "findings_count": 1, "error": None},
            },
            "findings": [
                {
                    "finding_id": "SUID-001",
                    "title": "Setuid binary detected",
                    "severity": "CRITICAL",
                    "affected_resource": "/usr/bin/vuln_bin",
                    "mitre_attack": "T1548.001",
                    "description": "Binary has setuid root bit set and insecure permissions.",
                    "evidence": "Permissions: -rwsr-xr-x (mode 4755)",
                    "recommendation": "Remove setuid bit with chmod u-s /usr/bin/vuln_bin",
                },
                {
                    "finding_id": "SUID-002",
                    "title": "Elevated helper binary",
                    "severity": "HIGH",
                    "affected_resource": "/usr/lib/helper",
                    "mitre_attack": "T1548.001",
                    "description": "Helper executed with elevated privileges.",
                    "evidence": "Permissions: -rwsr-xr-x",
                    "recommendation": "Restrict execution.",
                },
                {
                    "finding_id": "BIN-001",
                    "title": "Writable binary directory",
                    "severity": "LOW",
                    "affected_resource": "/opt/custom/bin",
                    "mitre_attack": None,
                    "description": "Directory is world-writable.",
                    "evidence": "mode 777",
                    "recommendation": "chmod 755 /opt/custom/bin",
                },
            ],
        }

    def test_json_export_structure_and_types(self) -> None:
        """Verify JSON export produces valid JSON matching the stable report schema."""
        out = generate_json_export(self.sample_audit)
        self.assertIsInstance(out, str)
        data = json.loads(out)

        self.assertIn("report_metadata", data)
        self.assertEqual(data["report_metadata"]["format_version"], "1.0")
        self.assertEqual(data["report_metadata"]["report_type"], "LPE_SENTINEL_SECURITY_AUDIT")
        self.assertIn("generated_at", data["report_metadata"])

        audit = data["audit"]
        self.assertEqual(audit["scan_id"], "scan_20261017_180000_1234abcd")
        self.assertEqual(audit["status"], "COMPLETED")
        self.assertTrue(audit["is_complete"])
        self.assertEqual(audit["duration_ms"], 150.25)
        self.assertEqual(audit["summary"]["critical"], 1)
        self.assertEqual(audit["summary"]["total"], 3)
        self.assertEqual(len(audit["findings"]), 3)
        self.assertEqual(audit["findings"][0]["finding_id"], "SUID-001")
        self.assertEqual(audit["findings"][0]["mitre_attack"], "T1548.001")

    def test_json_export_empty_findings(self) -> None:
        """Verify JSON export handles zero findings cleanly."""
        audit_empty = {
            "scan_id": "scan_20261017_180000_empty000",
            "timestamp": "2026-10-17T18:00:00Z",
            "status": "COMPLETED",
            "is_complete": True,
            "findings": [],
            "summary": {"total": 0},
        }
        out = generate_json_export(audit_empty)
        data = json.loads(out)
        self.assertEqual(data["audit"]["findings_count"], 0)
        self.assertEqual(data["audit"]["findings"], [])

    def test_csv_export_format_and_headers(self) -> None:
        """Verify CSV export writes correct header columns and one row per finding."""
        out = generate_csv_export(self.sample_audit)
        reader = list(csv.reader(io.StringIO(out)))

        # Header row
        self.assertEqual(len(reader), 4)  # 1 header + 3 findings
        expected_headers = [
            "scan_id",
            "finding_id",
            "severity",
            "title",
            "affected_resource",
            "mitre_attack",
            "description",
            "evidence",
            "recommendation",
            "remediation_why_it_matters",
            "remediation_investigation",
            "remediation_recommendation",
            "remediation_validation",
        ]
        self.assertEqual(reader[0], expected_headers)

        # Finding rows
        self.assertEqual(reader[1][0], "scan_20261017_180000_1234abcd")
        self.assertEqual(reader[1][1], "SUID-001")
        self.assertEqual(reader[1][2], "CRITICAL")
        self.assertEqual(reader[1][3], "Setuid binary detected")
        self.assertEqual(reader[1][4], "/usr/bin/vuln_bin")
        self.assertEqual(reader[1][5], "T1548.001")

        # Row 3 without MITRE ATT&CK
        self.assertEqual(reader[3][1], "BIN-001")
        self.assertEqual(reader[3][5], "")

    def test_csv_export_empty_findings(self) -> None:
        """Verify CSV export produces a complete header row when there are no findings."""
        audit_empty = {
            "scan_id": "scan_20261017_180000_empty000",
            "findings": [],
        }
        out = generate_csv_export(audit_empty)
        reader = list(csv.reader(io.StringIO(out)))
        self.assertEqual(len(reader), 1)
        self.assertEqual(reader[0][0], "scan_id")
        self.assertEqual(reader[0][1], "finding_id")

    def test_csv_export_formula_injection_defense(self) -> None:
        """Verify spreadsheet formula injection prefixes (=, +, -, @) are sanitized, including with whitespace/control characters."""
        malicious_audit = {
            "scan_id": "scan_20261017_180000_test1234",
            "findings": [
                {
                    "finding_id": "=cmd|' /C calc'!A0",
                    "title": "   +2+5+cmd|' /C calc'!A0",
                    "severity": "HIGH",
                    "affected_resource": "\t@calc.exe",
                    "description": " \r\n-10-5",
                    "evidence": "\tTAB_INJECT",
                    "recommendation": "\r=1+1",
                },
                {
                    "finding_id": "SAFE-001",
                    "title": "Ordinary Title",
                    "severity": "LOW",
                    "affected_resource": "/etc/shadow",
                    "description": "-1",
                    "evidence": "-42.5",
                    "recommendation": "Normal guidance",
                }
            ],
        }
        out = generate_csv_export(malicious_audit)
        reader = list(csv.reader(io.StringIO(out)))
        row1 = reader[1]
        row2 = reader[2]

        # Cells starting with risky prefixes (even with leading spaces or control chars) must be prepended with single-quote
        self.assertTrue(row1[1].startswith("'="), f"Row 1 Col 1 failed: {row1[1]}")
        self.assertTrue(row1[2].startswith("HIGH"))
        self.assertTrue(row1[3].startswith("'   +"), f"Row 1 Col 3 failed: {row1[3]}")
        self.assertTrue(row1[4].startswith("'\t@"), f"Row 1 Col 4 failed: {row1[4]}")
        self.assertTrue(row1[6].startswith("' \r\n-"), f"Row 1 Col 6 failed: {row1[6]}")
        self.assertTrue(row1[7].startswith("'\t"), f"Row 1 Col 7 failed: {row1[7]}")
        self.assertTrue(row1[8].startswith("'\r="), f"Row 1 Col 8 failed: {row1[8]}")

        # Legitimate negative numbers should remain unquoted
        self.assertEqual(row2[6], "-1")
        self.assertEqual(row2[7], "-42.5")

    def test_html_export_structure_and_metadata(self) -> None:
        """Verify HTML report includes DOCTYPE, scan metadata, metrics, and findings."""
        html_out = generate_html_export(self.sample_audit)
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("LPE-Sentinel Security Audit Report", html_out)
        self.assertIn("scan_20261017_180000_1234abcd", html_out)
        self.assertIn("6.6.9-kali1-amd64", html_out)
        self.assertIn("SUID-001", html_out)
        self.assertIn("/usr/bin/vuln_bin", html_out)
        self.assertIn("@media print", html_out)
        self.assertIn("page-break-inside: avoid", html_out)

    def test_html_export_empty_findings(self) -> None:
        """Verify HTML report cleanly indicates clean posture when findings are empty."""
        audit_empty = {
            "scan_id": "scan_20261017_180000_empty000",
            "timestamp": "2026-10-17T18:00:00Z",
            "status": "COMPLETED",
            "findings": [],
            "summary": {"total": 0},
        }
        html_out = generate_html_export(audit_empty)
        self.assertIn("Clean Security Posture — No Findings Recorded", html_out)
        self.assertNotIn("SUID-001", html_out)

    def test_html_export_xss_and_injection_defense(self) -> None:
        """Verify HTML/script payloads are escaped and never rendered executable."""
        xss_payload = "<script>alert('pwned')</script>"
        attr_payload = '" onfocus="alert(1)'
        malicious_audit = {
            "scan_id": "scan_20261017_180000_sec00001",
            "findings": [
                {
                    "finding_id": "INJ-001",
                    "title": xss_payload,
                    "severity": "CRITICAL",
                    "affected_resource": attr_payload,
                    "description": "<img src=x onerror=alert(2)>",
                    "evidence": "<svg onload=alert(3)>",
                    "recommendation": "<b>Sanitize</b>",
                }
            ],
        }
        html_out = generate_html_export(malicious_audit)
        # Raw tags must not exist
        self.assertNotIn("<script>alert('pwned')</script>", html_out)
        self.assertNotIn("<img src=x onerror=alert(2)>", html_out)
        self.assertNotIn("<svg onload=alert(3)>", html_out)
        # Must be escaped HTML entities
        self.assertIn("&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;", html_out)
        self.assertIn("&lt;img src=x onerror=alert(2)&gt;", html_out)


class TestAuditExportAPIIntegration(unittest.TestCase):
    """Integration tests for web server export endpoints."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_api_export.db")
        self.server = create_web_server(host="127.0.0.1", port=0, db_path=self.db_path)
        self.thread = threading.Thread(target=self.server.start, daemon=True)
        self.thread.start()
        time.sleep(0.3)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

        # Seed a test audit record in history
        self.sample_audit = {
            "status": "COMPLETED",
            "is_complete": True,
            "summary": {
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 1,
            },
            "findings": [
                {
                    "finding_id": "TEST-001",
                    "title": "Persistent Test Finding",
                    "severity": "CRITICAL",
                    "affected_resource": "/bin/test_bin",
                    "description": "Test description",
                    "evidence": "Mode: 4755",
                    "recommendation": "Fix permission",
                    "mitre_attack": "T1548",
                }
            ],
            "scanners": {
                "suid_sgid": {"status": "COMPLETED", "findings_count": 1, "error": None}
            },
        }
        self.scan_id = self.server.history_manager.save_audit(self.sample_audit, duration_ms=45.5)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2.0)
        time.sleep(0.05)
        self.temp_dir.cleanup()

    def test_export_json_endpoint_200_and_headers(self) -> None:
        """Verify GET /api/history/<scan_id>/export/json returns 200 with valid headers and payload."""
        url = f"{self.base_url}/api/history/{self.scan_id}/export/json"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertEqual(resp.headers.get("Content-Type"), "application/json; charset=utf-8")
            self.assertEqual(
                resp.headers.get("Content-Disposition"),
                f'attachment; filename="lpe_audit_{self.scan_id}.json"',
            )
            body = resp.read()
            data = json.loads(body.decode("utf-8"))
            self.assertEqual(data["audit"]["scan_id"], self.scan_id)
            self.assertEqual(len(data["audit"]["findings"]), 1)
            self.assertEqual(data["audit"]["findings"][0]["finding_id"], "TEST-001")

    def test_export_csv_endpoint_200_and_headers(self) -> None:
        """Verify GET /api/history/<scan_id>/export/csv returns 200 with text/csv content."""
        url = f"{self.base_url}/api/history/{self.scan_id}/export/csv"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertEqual(resp.headers.get("Content-Type"), "text/csv; charset=utf-8")
            self.assertEqual(
                resp.headers.get("Content-Disposition"),
                f'attachment; filename="lpe_audit_{self.scan_id}.csv"',
            )
            body = resp.read().decode("utf-8")
            rows = list(csv.reader(io.StringIO(body)))
            self.assertEqual(len(rows), 2)  # 1 header + 1 finding
            self.assertEqual(rows[1][0], self.scan_id)
            self.assertEqual(rows[1][1], "TEST-001")

    def test_export_html_endpoint_200_and_headers(self) -> None:
        """Verify GET /api/history/<scan_id>/export/html returns 200 with text/html report."""
        url = f"{self.base_url}/api/history/{self.scan_id}/export/html"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertEqual(resp.headers.get("Content-Type"), "text/html; charset=utf-8")
            self.assertEqual(
                resp.headers.get("Content-Disposition"),
                f'attachment; filename="lpe_audit_{self.scan_id}.html"',
            )
            body = resp.read().decode("utf-8")
            self.assertIn("<!DOCTYPE html>", body)
            self.assertIn(self.scan_id, body)
            self.assertIn("TEST-001", body)

    def test_export_head_requests(self) -> None:
        """Verify HEAD requests to export endpoints return headers with no body."""
        for fmt in ("json", "csv", "html"):
            url = f"{self.base_url}/api/history/{self.scan_id}/export/{fmt}"
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, HTTPStatus.OK)
                self.assertIsNotNone(resp.headers.get("Content-Type"))
                self.assertIsNotNone(resp.headers.get("Content-Disposition"))
                self.assertGreater(int(resp.headers.get("Content-Length", 0)), 0)
                body = resp.read()
                self.assertEqual(len(body), 0)

    def test_export_unknown_scan_id_returns_404(self) -> None:
        """Verify unknown scan ID returns 404 Not Found."""
        unknown_id = "scan_19990101_000000_deadbeef"
        url = f"{self.base_url}/api/history/{unknown_id}/export/json"
        req = urllib.request.Request(url)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.NOT_FOUND)
        body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(body["status"], "NOT_FOUND")

    def test_export_malformed_scan_id_returns_400(self) -> None:
        """Verify invalid scan ID format returns 400 Bad Request."""
        invalid_ids = ["bad$id", "short", "x" * 100, "../escape", "scan with spaces"]
        for bad_id in invalid_ids:
            url = f"{self.base_url}/api/history/{urllib.parse.quote(bad_id)}/export/json"
            req = urllib.request.Request(url)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=3.0)
            self.assertIn(ctx.exception.code, (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND))

    def test_export_unsupported_format_returns_400(self) -> None:
        """Verify unsupported format like XML or PDF returns 400 Bad Request."""
        for bad_fmt in ("xml", "pdf", "yaml", "exe"):
            url = f"{self.base_url}/api/history/{self.scan_id}/export/{bad_fmt}"
            req = urllib.request.Request(url)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=3.0)
            self.assertEqual(ctx.exception.code, HTTPStatus.BAD_REQUEST)
            body = json.loads(ctx.exception.read().decode("utf-8"))
            self.assertIn("Unsupported export format", body["error"])

    def test_export_post_method_not_allowed(self) -> None:
        """Verify POST requests to export endpoints return 405 Method Not Allowed."""
        url = f"{self.base_url}/api/history/{self.scan_id}/export/json"
        req = urllib.request.Request(url, data=b"{}", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.METHOD_NOT_ALLOWED)

    def test_exporting_history_never_triggers_scanners(self) -> None:
        """Verify export requests strictly read from DB and never invoke scanners."""
        with patch("lpe_sentinel.web.server.run_unified_audit") as mock_audit:
            for fmt in ("json", "csv", "html"):
                url = f"{self.base_url}/api/history/{self.scan_id}/export/{fmt}"
                with urllib.request.urlopen(url, timeout=3.0) as resp:
                    self.assertEqual(resp.status, HTTPStatus.OK)
            mock_audit.assert_not_called()

    def test_demo_data_is_never_exportable_via_history_endpoints(self) -> None:
        """Verify simulated demo data is never queryable or exportable as a real audit."""
        # Demo data does not write to DB
        demo_id = "demo_scan_id_nonexistent"
        url = f"{self.base_url}/api/history/{demo_id}/export/json"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(url, timeout=3.0)
        self.assertIn(ctx.exception.code, (HTTPStatus.NOT_FOUND, HTTPStatus.BAD_REQUEST))

    def test_dashboard_contains_export_ui_integration(self) -> None:
        """Verify dashboard HTML includes export actions for banner and history items."""
        html = render_dashboard_html()
        self.assertIn("history-export-actions", html)
        self.assertIn("history-export-json", html)
        self.assertIn("history-export-csv", html)
        self.assertIn("history-export-html", html)
        self.assertIn("history-item-export-group", html)


if __name__ == "__main__":
    unittest.main()
