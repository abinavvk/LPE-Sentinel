"""
Comprehensive Test Suite for LPE-Sentinel Task 5D: Persistent Audit History with SQLite.

Tests cover:
- Database initialization and round-trip persistence
- Completed, partial, and failed status serialization
- Parameterized queries and invalid/malicious scan IDs (SQL injection safety)
- List limit validation and retention pruning behavior
- Unknown scan ID (404) and malformed ID (400)
- Database unavailable/corrupted scenarios without server crash or path leak
- Live audit persistence integration and graceful degradation when persistence fails
- Demo results are never persisted
- History endpoints never trigger scanners
- Dashboard HTML and JS integration for historical viewing
"""

import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http import HTTPStatus
from pathlib import Path

# Add 'src' to sys.path so tests can import lpe_sentinel modules
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from unittest.mock import MagicMock, patch

from lpe_sentinel.audit_engine import AuditResult, AuditStatus
from lpe_sentinel.audit_history import (
    DEFAULT_LIST_LIMIT,
    MAX_LIST_LIMIT,
    SCAN_ID_REGEX,
    AuditHistoryError,
    AuditHistoryManager,
    extract_severity_summary,
    sanitize_findings_data,
    sanitize_scanner_results_data,
    sanitize_system_info_data,
)
from lpe_sentinel.models import Finding
from lpe_sentinel.web.server import LpeSentinelWebHandler, create_web_server
from lpe_sentinel.web.templates import render_dashboard_html


class TestAuditHistoryUnit(unittest.TestCase):
    """Unit tests for AuditHistoryManager and SQLite persistence."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_history.db")
        self.mgr = AuditHistoryManager(db_path=self.db_path, max_records=5)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_database_initialization_and_schema(self) -> None:
        """Verify database and audit_history table and index are created properly."""
        self.mgr.init_db()
        self.assertTrue(os.path.exists(self.db_path))

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_history'"
            )
            self.assertIsNotNone(cursor.fetchone())
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_audit_history_created_at'"
            )
            self.assertIsNotNone(cursor.fetchone())
        finally:
            conn.close()

    def test_save_and_get_roundtrip_completed_audit(self) -> None:
        """Verify full round-trip persistence and retrieval for COMPLETED audit."""
        mock_finding = Finding(
            finding_id="SUID-001",
            title="Writable SUID binary",
            severity="HIGH",
            description="Found SUID binary with world-writable permissions",
            evidence="mode 04777 /usr/bin/test_bin",
            affected_resource="/usr/bin/test_bin",
            recommendation="chmod 04755 /usr/bin/test_bin",
            mitre_attack="T1548.001",
        )
        mock_audit = AuditResult(
            status=AuditStatus.COMPLETED,
            system_info={"os_name": "Linux", "release": "6.6", "architecture": "x86_64", "platform_category": "Linux"},
            findings=[mock_finding],
            summary={"total_findings": 1, "severity_counts": {"HIGH": 1, "CRITICAL": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
            scanner_results={"suid_sgid": MagicMock(to_dict=lambda: {"scanner_name": "suid_sgid", "status": "COMPLETED", "findings_count": 1})},
            errors=[],
            timestamp="2026-10-17T12:00:00Z",
        )

        scan_id = self.mgr.save_audit(mock_audit, duration_ms=123.45)
        self.assertTrue(scan_id.startswith("audit-"))
        self.assertEqual(self.mgr.count_audits(), 1)

        # Retrieve full record
        record = self.mgr.get_audit(scan_id)
        self.assertIsNotNone(record)
        self.assertEqual(record["scan_id"], scan_id)
        self.assertEqual(record["status"], "COMPLETED")
        self.assertTrue(record["is_complete"])
        self.assertTrue(record["is_historical"])
        self.assertFalse(record["is_demo"])
        self.assertEqual(record["duration_ms"], 123.45)
        self.assertEqual(record["summary"]["high"], 1)
        self.assertEqual(record["summary"]["total"], 1)
        self.assertEqual(len(record["findings"]), 1)
        self.assertEqual(record["findings"][0]["finding_id"], "SUID-001")
        self.assertEqual(record["findings"][0]["mitre_attack"], "T1548.001")
        self.assertEqual(record["system_info"]["os_name"], "Linux")

    def test_save_and_get_partial_and_failed_statuses(self) -> None:
        """Verify serialization and retrieval of PARTIAL and FAILED audits."""
        # 1. PARTIAL audit
        audit_partial = {
            "status": "PARTIAL",
            "is_complete": False,
            "timestamp": "2026-10-17T13:00:00Z",
            "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "findings": [],
            "scanner_results": {"sudo_audit": {"status": "PARTIAL", "findings_count": 0}},
            "errors": ["Permission denied on /etc/sudoers"],
        }
        id_part = self.mgr.save_audit(audit_partial, duration_ms=50.0)
        rec_part = self.mgr.get_audit(id_part)
        self.assertEqual(rec_part["status"], "PARTIAL")
        self.assertFalse(rec_part["is_complete"])
        self.assertEqual(rec_part["errors"], ["Permission denied on /etc/sudoers"])

        # 2. FAILED audit
        audit_failed = {
            "status": "FAILED",
            "is_complete": False,
            "timestamp": "2026-10-17T14:00:00Z",
            "summary": {"total_findings": 0},
            "findings": [],
            "scanner_results": {},
            "errors": ["Scan aborted due to fatal error"],
        }
        id_fail = self.mgr.save_audit(audit_failed, duration_ms=10.0)
        rec_fail = self.mgr.get_audit(id_fail)
        self.assertEqual(rec_fail["status"], "FAILED")
        self.assertFalse(rec_fail["is_complete"])

    def test_data_sanitization_does_not_leak_secrets(self) -> None:
        """Verify sanitizers omit sensitive passwords, tokens, and arbitrary objects."""
        raw_sys = {
            "os_name": "Linux",
            "release": "6.6",
            "architecture": "x86_64",
            "platform_category": "Linux",
            "username": "secret_user",
            "password": "secret_password",
            "env_vars": {"TOKEN": "super_secret_token"},
        }
        sanitized_sys = sanitize_system_info_data(raw_sys)
        self.assertNotIn("username", sanitized_sys)
        self.assertNotIn("password", sanitized_sys)
        self.assertNotIn("env_vars", sanitized_sys)
        self.assertEqual(sanitized_sys["os_name"], "Linux")

        raw_finding = {
            "finding_id": "TEST-001",
            "title": "Title",
            "severity": "info",
            "description": "Desc",
            "evidence": "Evidence",
            "affected_resource": "/path",
            "recommendation": "Rec",
            "mitre_attack": "T1000",
            "raw_stacktrace": "Traceback ... secret token: 12345",
        }
        sanitized_finding = sanitize_findings_data([raw_finding])[0]
        self.assertNotIn("raw_stacktrace", sanitized_finding)
        self.assertEqual(sanitized_finding["severity"], "INFO")

    def test_parameterized_queries_and_sql_injection_defense(self) -> None:
        """Verify SQL injection payloads in IDs or fields cannot compromise database."""
        # Malicious custom scan ID rejected by validation
        malicious_id = "audit-1'; DROP TABLE audit_history; --"
        with self.assertRaises(ValueError):
            self.mgr.save_audit({"status": "COMPLETED"}, scan_id=malicious_id)

        with self.assertRaises(ValueError):
            self.mgr.get_audit(malicious_id)

        # SQL payload inside finding title or evidence is stored safely via parameterization
        safe_injection_payload = "test_bin'; DELETE FROM audit_history; --"
        mock_audit = {
            "status": "COMPLETED",
            "findings": [{
                "finding_id": "INJ-001",
                "title": safe_injection_payload,
                "severity": "LOW",
                "description": safe_injection_payload,
                "evidence": safe_injection_payload,
                "affected_resource": safe_injection_payload,
                "recommendation": safe_injection_payload,
            }],
        }
        valid_id = self.mgr.save_audit(mock_audit)
        rec = self.mgr.get_audit(valid_id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["findings"][0]["title"], safe_injection_payload)
        # Table must still exist and be intact
        self.assertEqual(self.mgr.count_audits(), 1)

    def test_invalid_scan_ids_rejected(self) -> None:
        """Verify malformed scan IDs are rejected by get_audit."""
        invalid_ids = ["", "short", "bad spaces", "../traversal", "x" * 100, "invalid$char"]
        for bad_id in invalid_ids:
            with self.assertRaises(ValueError):
                self.mgr.get_audit(bad_id)

    def test_retention_limit_pruning(self) -> None:
        """Verify older audit records are automatically pruned beyond max_records."""
        mgr = AuditHistoryManager(db_path=self.db_path, max_records=3)
        scan_ids = []
        for i in range(5):
            sid = mgr.save_audit({"status": "COMPLETED", "summary": {"total_findings": i}})
            scan_ids.append(sid)
            time.sleep(0.01)

        # Only the 3 newest audits should remain
        self.assertEqual(mgr.count_audits(), 3)
        self.assertIsNone(mgr.get_audit(scan_ids[0]))
        self.assertIsNone(mgr.get_audit(scan_ids[1]))
        self.assertIsNotNone(mgr.get_audit(scan_ids[2]))
        self.assertIsNotNone(mgr.get_audit(scan_ids[3]))
        self.assertIsNotNone(mgr.get_audit(scan_ids[4]))

    def test_list_audits_limit_and_bounds(self) -> None:
        """Verify list_audits respects bounds and default limits."""
        for i in range(4):
            self.mgr.save_audit({"status": "COMPLETED", "summary": {"total_findings": i}})

        items_default = self.mgr.list_audits()
        self.assertEqual(len(items_default), 4)

        items_bounded = self.mgr.list_audits(limit=2)
        self.assertEqual(len(items_bounded), 2)

    def test_get_unknown_scan_id_returns_none(self) -> None:
        """Verify valid but nonexistent scan ID returns None."""
        self.assertIsNone(self.mgr.get_audit("audit-nonexistent123"))

    def test_corrupt_data_handling(self) -> None:
        """Verify corrupt JSON in database causes AuditHistoryError without crashing."""
        sid = self.mgr.save_audit({"status": "COMPLETED"})
        # Corrupt the record directly in SQLite
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("UPDATE audit_history SET findings_json='NOT_JSON{' WHERE scan_id=?", (sid,))
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(AuditHistoryError):
            self.mgr.get_audit(sid)

    def test_database_error_handling_sanitized_message(self) -> None:
        """Verify database errors don't leak full paths and raise AuditHistoryError."""
        # Using a regular file as a parent directory causes an OSError on both Windows and Linux
        file_path = os.path.join(self.temp_dir.name, "not_a_dir.txt")
        with open(file_path, "w") as f:
            f.write("test")
        bad_path = os.path.join(file_path, "sub_dir", "test.db")
        bad_mgr = AuditHistoryManager(db_path=bad_path)
        with self.assertRaises(AuditHistoryError) as ctx:
            bad_mgr.init_db()
        self.assertNotIn(bad_path, str(ctx.exception))


class TestAuditHistoryAPIIntegration(unittest.TestCase):
    """Integration tests for web server history endpoints and live audit integration."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_api_history.db")
        self.server = create_web_server(host="127.0.0.1", port=0, db_path=self.db_path)
        self.thread = threading.Thread(target=self.server.start, daemon=True)
        self.thread.start()
        time.sleep(0.3)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

        # Fetch CSRF token for live audit POST calls
        with urllib.request.urlopen(f"{self.base_url}/api/csrf-token", timeout=3.0) as resp:
            self.csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2.0)
        time.sleep(0.05)
        self.temp_dir.cleanup()

    def test_api_history_empty_list(self) -> None:
        """Verify GET /api/history on empty database returns empty history array."""
        req = urllib.request.Request(f"{self.base_url}/api/history")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "OK")
            self.assertEqual(data["count"], 0)
            self.assertEqual(data["limit"], DEFAULT_LIST_LIMIT)
            self.assertEqual(data["history"], [])

    def test_api_history_list_with_records_and_limit_param(self) -> None:
        """Verify GET /api/history?limit=N returns correct records."""
        # Insert 3 records directly through manager
        for i in range(3):
            self.server.history_manager.save_audit({
                "status": "COMPLETED",
                "summary": {"total_findings": i, "critical": 0, "high": i, "medium": 0, "low": 0, "info": 0},
            })

        req = urllib.request.Request(f"{self.base_url}/api/history?limit=2")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "OK")
            self.assertEqual(data["count"], 2)
            self.assertEqual(data["limit"], 2)
            self.assertEqual(len(data["history"]), 2)

    def test_api_history_invalid_limit_returns_400(self) -> None:
        """Verify non-integer or out-of-range limit parameter returns 400 Bad Request."""
        bad_urls = [
            f"{self.base_url}/api/history?limit=abc",
            f"{self.base_url}/api/history?limit=0",
            f"{self.base_url}/api/history?limit=9999",
            f"{self.base_url}/api/history?limit=-5",
        ]
        for url in bad_urls:
            req = urllib.request.Request(url)
            try:
                urllib.request.urlopen(req, timeout=3.0)
                self.fail(f"Expected 400 for {url}")
            except urllib.error.HTTPError as err:
                self.assertEqual(err.code, HTTPStatus.BAD_REQUEST)
                err_data = json.loads(err.read().decode("utf-8"))
                self.assertEqual(err_data["status"], "BAD_REQUEST")

    def test_api_history_get_existing_item(self) -> None:
        """Verify GET /api/history/<scan_id> returns 200 with full audit record."""
        sid = self.server.history_manager.save_audit({
            "status": "COMPLETED",
            "summary": {"total_findings": 1, "high": 1},
            "findings": [{
                "finding_id": "SUID-001",
                "title": "SUID Test",
                "severity": "HIGH",
                "description": "Desc",
                "evidence": "Evidence",
                "affected_resource": "/bin/test",
                "recommendation": "Rec",
            }],
        })

        req = urllib.request.Request(f"{self.base_url}/api/history/{sid}")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "OK")
            self.assertEqual(data["scan_id"], sid)
            self.assertEqual(len(data["audit"]["findings"]), 1)
            self.assertEqual(data["audit"]["findings"][0]["finding_id"], "SUID-001")

    def test_api_history_get_unknown_id_returns_404(self) -> None:
        """Verify GET /api/history/<unknown_id> returns 404 Not Found."""
        req = urllib.request.Request(f"{self.base_url}/api/history/audit-unknown1234567")
        try:
            urllib.request.urlopen(req, timeout=3.0)
            self.fail("Expected 404 Not Found")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, HTTPStatus.NOT_FOUND)
            err_data = json.loads(err.read().decode("utf-8"))
            self.assertEqual(err_data["status"], "NOT_FOUND")

    def test_api_history_malformed_id_returns_400(self) -> None:
        """Verify GET /api/history/<malformed_id> returns 400 Bad Request."""
        malformed_urls = [
            f"{self.base_url}/api/history/bad!id",
            f"{self.base_url}/api/history/short",
            f"{self.base_url}/api/history/test%20spaces",
        ]
        for url in malformed_urls:
            req = urllib.request.Request(url)
            try:
                urllib.request.urlopen(req, timeout=3.0)
                self.fail(f"Expected 400 for {url}")
            except urllib.error.HTTPError as err:
                self.assertEqual(err.code, HTTPStatus.BAD_REQUEST)
                err_data = json.loads(err.read().decode("utf-8"))
                self.assertEqual(err_data["status"], "BAD_REQUEST")

    def test_api_history_post_method_not_allowed(self) -> None:
        """Verify history endpoints reject POST, PUT, DELETE."""
        req = urllib.request.Request(
            f"{self.base_url}/api/history",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=3.0)
            self.fail("Expected 405 Method Not Allowed")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, HTTPStatus.METHOD_NOT_ALLOWED)

    def test_live_audit_persists_to_history_and_returns_scan_id(self) -> None:
        """Verify POST /api/run-audit saves result to SQLite and includes scan_id."""
        mock_res = MagicMock(spec=AuditResult)
        mock_res.status = "COMPLETED"
        mock_res.is_complete = True
        mock_res.timestamp = "2026-10-17T00:00:00Z"
        mock_res.summary = {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1}
        mock_res.system_info = {"platform_category": "Linux", "os_name": "Linux", "os_release": "6.6"}
        mock_res.scanner_results = {}
        mock_res.errors = []
        mock_res.findings = [
            MagicMock(to_dict=lambda: {
                "finding_id": "SUID-001",
                "title": "SUID Binary Found",
                "severity": "HIGH",
                "description": "Found SUID binary",
                "evidence": "mode 4755",
                "affected_resource": "/usr/bin/test_bin",
                "recommendation": "Review permissions",
            })
        ]

        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_res):
            req = urllib.request.Request(
                f"{self.base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": self.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, HTTPStatus.OK)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["status"], "COMPLETED")
                self.assertTrue(data["history_saved"])
                self.assertIsNotNone(data["scan_id"])
                saved_scan_id = data["scan_id"]

        # Verify saved record can be fetched from /api/history/<scan_id>
        req_hist = urllib.request.Request(f"{self.base_url}/api/history/{saved_scan_id}")
        with urllib.request.urlopen(req_hist, timeout=3.0) as resp_hist:
            self.assertEqual(resp_hist.status, HTTPStatus.OK)
            hist_data = json.loads(resp_hist.read().decode("utf-8"))
            self.assertEqual(hist_data["scan_id"], saved_scan_id)
            self.assertEqual(hist_data["audit"]["status"], "COMPLETED")
            self.assertEqual(len(hist_data["audit"]["findings"]), 1)

    def test_live_audit_succeeds_even_if_history_persistence_fails(self) -> None:
        """
        Verify graceful degradation: if database persistence raises an error,
        POST /api/run-audit still returns 200 with the full audit result, indicating
        history could not be saved without leaking exception details.
        """
        mock_res = MagicMock(spec=AuditResult)
        mock_res.status = "COMPLETED"
        mock_res.is_complete = True
        mock_res.timestamp = "2026-10-17T00:00:00Z"
        mock_res.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        mock_res.system_info = {"platform_category": "Linux"}
        mock_res.scanner_results = {}
        mock_res.errors = []
        mock_res.findings = []

        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_res), \
             patch.object(self.server.history_manager, "save_audit", side_effect=sqlite3.OperationalError("disk I/O error")):
            req = urllib.request.Request(
                f"{self.base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": self.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, HTTPStatus.OK)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["status"], "COMPLETED")
                self.assertFalse(data["history_saved"])
                self.assertIsNone(data["scan_id"])
                self.assertIn("persistence to history database failed", data.get("history_error", ""))
                # Verify internal error details not exposed
                self.assertNotIn("disk I/O error", data.get("history_error", ""))

    def test_demo_audit_is_never_persisted_to_history(self) -> None:
        """Verify calling GET /api/demo-audit does not save anything to history."""
        initial_count = self.server.history_manager.count_audits()
        req = urllib.request.Request(f"{self.base_url}/api/demo-audit")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(data.get("is_demo"))

        self.assertEqual(self.server.history_manager.count_audits(), initial_count)

    def test_history_endpoints_never_trigger_scanners(self) -> None:
        """Verify accessing history endpoints does not execute run_unified_audit."""
        with patch("lpe_sentinel.web.server.run_unified_audit") as mock_run:
            urllib.request.urlopen(f"{self.base_url}/api/history", timeout=3.0)
            mock_run.assert_not_called()

            try:
                urllib.request.urlopen(f"{self.base_url}/api/history/audit-nonexistent123", timeout=3.0)
            except urllib.error.HTTPError:
                pass
            mock_run.assert_not_called()

    def test_dashboard_contains_history_ui_integration(self) -> None:
        """Verify render_dashboard_html() incorporates Recent Audits UI and functions."""
        html = render_dashboard_html()
        self.assertIn('id="history-banner"', html)
        self.assertIn('id="history-section"', html)
        self.assertIn('id="history-list"', html)
        self.assertIn('id="history-count-pill"', html)
        self.assertIn('onclick="loadRecentAudits()"', html)
        self.assertIn("loadRecentAudits", html)
        self.assertIn("viewHistoryAudit", html)
        self.assertIn("showHistoryBanner", html)
        self.assertIn("hideHistoryBanner", html)
        self.assertIn("active-history", html)


if __name__ == "__main__":
    unittest.main()
