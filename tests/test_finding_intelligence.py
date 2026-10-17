"""
Comprehensive Test Suite for Task 5F — Finding Intelligence and Historical Comparison.

Covers:
- Advisory remediation guidance module (known categories, unknown generic fallback, immutability, safety)
- Deterministic audit comparison engine (new, resolved, persistent, changed classifications)
- Attribute normalization, duplicate finding IDs, metadata/timestamp/order invariance
- Demo record exclusion and invalid/missing scan ID handling
- Dashboard UI integration for filtering, sorting, empty states, and reset
- API endpoints for historical comparison (GET, query params, path params, error cases)
- Safety: read-only comparison, no scanner invocation, no exploit payloads, no secret leaks
"""

import copy
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch

# Ensure src/ is on sys.path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lpe_sentinel.audit_diff import (
    COMPARISON_DISCLAIMER,
    AuditComparisonError,
    compare_audit_records,
    compare_history_audits,
)
from lpe_sentinel.audit_history import AuditHistoryManager
from lpe_sentinel.export import (
    generate_csv_export,
    generate_html_export,
    generate_json_export,
)
from lpe_sentinel.models import Finding
from lpe_sentinel.remediation_guidance import (
    RemediationGuidance,
    get_remediation_guidance,
)
from lpe_sentinel.web.server import create_web_server
from lpe_sentinel.web.templates import render_dashboard_html


class TestRemediationGuidanceModule(unittest.TestCase):
    """Unit tests for the Advisory Remediation Guidance module."""

    def test_known_categories_coverage(self) -> None:
        """Verify vetted guidance for all primary supported finding types."""
        test_ids = [
            ("SUID-001", "SUID / SGID Executables"),
            ("SUID-002", "SUID / SGID Executables"),
            ("SGID-001", "SUID / SGID Executables"),
            ("SGID-002", "SUID / SGID Executables"),
            ("PERM-001", "File & Directory Permissions"),
            ("PERM-002", "File & Directory Permissions"),
            ("SUDO-001", "Sudo Configuration"),
            ("SUDO-002", "Sudo Configuration"),
            ("SUDO-003", "Sudo Configuration"),
        ]

        for finding_id, expected_category in test_ids:
            with self.subTest(finding_id=finding_id):
                guidance = get_remediation_guidance({"finding_id": finding_id})
                self.assertIsInstance(guidance, RemediationGuidance)
                self.assertEqual(guidance.category, expected_category)
                self.assertTrue(len(guidance.why_it_matters) > 20)
                self.assertTrue(len(guidance.investigation_steps) >= 1)
                self.assertTrue(len(guidance.remediation_steps) >= 1)
                self.assertTrue(len(guidance.validation_steps) >= 1)

    def test_unknown_category_safe_fallback(self) -> None:
        """Verify unknown finding IDs receive safe generic review guidance without guessing."""
        unknown_ids = ["CUSTOM-999", "UNKNOWN", "KERNEL-CVE-2024", "RANDOM-CHECK"]
        for u_id in unknown_ids:
            with self.subTest(finding_id=u_id):
                guidance = get_remediation_guidance({"finding_id": u_id})
                self.assertEqual(guidance.category, "General Security Review")
                self.assertIn("baseline", guidance.why_it_matters.lower())
                self.assertIn("least privilege", " ".join(guidance.remediation_steps).lower())
                self.assertTrue(len(guidance.validation_steps) >= 1)

    def test_guidance_from_finding_dataclass(self) -> None:
        """Verify guidance works seamlessly with Finding dataclass instances."""
        finding = Finding(
            finding_id="SUID-001",
            title="Setuid executable found",
            severity="INFO",
            description="Found setuid bit",
            evidence="mode 0o104755",
            affected_resource="/bin/sample",
            recommendation="Review rights",
        )
        guidance = get_remediation_guidance(finding)
        self.assertEqual(guidance.finding_id, "SUID-001")
        self.assertEqual(guidance.category, "SUID / SGID Executables")

    def test_guidance_does_not_alter_original_finding_or_severity(self) -> None:
        """Verify guidance generation never alters the finding dictionary or severity."""
        raw_finding = {
            "finding_id": "PERM-001",
            "title": "World writable file",
            "severity": "HIGH",
            "affected_resource": "/etc/custom.conf",
            "evidence": "0o666",
            "description": "Anyone can write",
            "recommendation": "chmod 644",
        }
        original_copy = copy.deepcopy(raw_finding)
        guidance = get_remediation_guidance(raw_finding)

        # Finding dict must remain completely untouched
        self.assertEqual(raw_finding, original_copy)
        self.assertEqual(raw_finding["severity"], "HIGH")

    def test_guidance_contains_no_exploit_or_privesc_instructions(self) -> None:
        """Confirm guidance contains purely defensive advice and no exploit hints."""
        dangerous_terms = ["payload", "exploit", "gtfobins", "sh -i", "/bin/sh -p", "spawn shell", "privilege escalation script"]
        for fid in ["SUID-001", "SUID-002", "PERM-001", "SUDO-001", "SUDO-002", "SUDO-003"]:
            g = get_remediation_guidance({"finding_id": fid})
            full_text = (
                g.why_it_matters + " " +
                " ".join(g.investigation_steps) + " " +
                " ".join(g.remediation_steps) + " " +
                " ".join(g.validation_steps)
            ).lower()
            for term in dangerous_terms:
                self.assertNotIn(term, full_text, f"Dangerous term '{term}' found in guidance for {fid}")


class TestAuditComparisonEngine(unittest.TestCase):
    """Unit tests for the Historical Audit Comparison Engine."""

    def setUp(self) -> None:
        self.base_older = {
            "scan_id": "scan_20261017_100000_aaaa1111",
            "timestamp": "2026-10-17T10:00:00Z",
            "status": "COMPLETED",
            "findings": [
                {
                    "finding_id": "SUID-001",
                    "title": "Setuid binary detected",
                    "severity": "INFO",
                    "affected_resource": "/usr/bin/passwd",
                    "description": "Standard passwd binary",
                },
                {
                    "finding_id": "PERM-001",
                    "title": "World-Writable Sensitive File",
                    "severity": "HIGH",
                    "affected_resource": "/etc/shadow",
                    "description": "Shadow file is world-writable",
                },
                {
                    "finding_id": "SUDO-001",
                    "title": "Sudo NOPASSWD Rule",
                    "severity": "MEDIUM",
                    "affected_resource": "/etc/sudoers.d/admin",
                    "description": "Passwordless rule for backup",
                },
            ],
        }

    def test_new_resolved_persistent_classification(self) -> None:
        """Verify findings are correctly categorized as New, Resolved, or Persistent."""
        # Newer audit:
        # - /etc/shadow is fixed (Resolved)
        # - /usr/bin/passwd is still present with same properties (Persistent)
        # - /etc/sudoers.d/admin is still present (Persistent)
        # - /etc/cron.d/job is newly introduced (New)
        newer = {
            "scan_id": "scan_20261017_120000_bbbb2222",
            "timestamp": "2026-10-17T12:00:00Z",
            "status": "COMPLETED",
            "findings": [
                {
                    "finding_id": "SUID-001",
                    "title": "Setuid binary detected",
                    "severity": "INFO",
                    "affected_resource": "/usr/bin/passwd",
                    "description": "Standard passwd binary",
                },
                {
                    "finding_id": "SUDO-001",
                    "title": "Sudo NOPASSWD Rule",
                    "severity": "MEDIUM",
                    "affected_resource": "/etc/sudoers.d/admin",
                    "description": "Passwordless rule for backup",
                },
                {
                    "finding_id": "PERM-001",
                    "title": "World-Writable Sensitive File",
                    "severity": "HIGH",
                    "affected_resource": "/etc/cron.d/job",
                    "description": "Cron job world writable",
                },
            ],
        }

        diff = compare_audit_records(self.base_older, newer)
        self.assertEqual(diff["status"], "SUCCESS")
        self.assertEqual(diff["summary"]["new_count"], 1)
        self.assertEqual(diff["summary"]["resolved_count"], 1)
        self.assertEqual(diff["summary"]["persistent_count"], 2)
        self.assertEqual(diff["summary"]["changed_count"], 0)

        # Check resolved finding (/etc/shadow)
        self.assertEqual(diff["resolved_findings"][0]["affected_resource"], "/etc/shadow")
        # Check new finding (/etc/cron.d/job)
        self.assertEqual(diff["new_findings"][0]["affected_resource"], "/etc/cron.d/job")
        # Check persistent findings
        persistent_resources = {f["affected_resource"] for f in diff["persistent_findings"]}
        self.assertEqual(persistent_resources, {"/usr/bin/passwd", "/etc/sudoers.d/admin"})
        # Check disclaimer
        self.assertIn("does NOT prove or certify that the system is secure", diff["disclaimer"])

    def test_changed_finding_classification_severity_and_resource(self) -> None:
        """Verify findings with identical ID/resource but modified severity are categorized as Changed."""
        newer = {
            "scan_id": "scan_20261017_140000_cccc3333",
            "timestamp": "2026-10-17T14:00:00Z",
            "status": "COMPLETED",
            "findings": [
                # Severity elevated from INFO to HIGH
                {
                    "finding_id": "SUID-001",
                    "title": "Setuid binary detected",
                    "severity": "HIGH",
                    "affected_resource": "/usr/bin/passwd",
                    "description": "Standard passwd binary",
                },
                # Identical
                {
                    "finding_id": "PERM-001",
                    "title": "World-Writable Sensitive File",
                    "severity": "HIGH",
                    "affected_resource": "/etc/shadow",
                    "description": "Shadow file is world-writable",
                },
                # Identical
                {
                    "finding_id": "SUDO-001",
                    "title": "Sudo NOPASSWD Rule",
                    "severity": "MEDIUM",
                    "affected_resource": "/etc/sudoers.d/admin",
                    "description": "Passwordless rule for backup",
                },
            ],
        }

        diff = compare_audit_records(self.base_older, newer)
        self.assertEqual(diff["summary"]["changed_count"], 1)
        self.assertEqual(diff["summary"]["persistent_count"], 2)
        self.assertEqual(diff["summary"]["new_count"], 0)
        self.assertEqual(diff["summary"]["resolved_count"], 0)

        changed_item = diff["changed_findings"][0]
        self.assertEqual(changed_item["newer"]["finding_id"], "SUID-001")
        self.assertIn("severity", changed_item["changes"])
        self.assertEqual(changed_item["changes"]["severity"]["older"], "INFO")
        self.assertEqual(changed_item["changes"]["severity"]["newer"], "HIGH")

    def test_comparison_ignores_reordering_and_metadata_differences(self) -> None:
        """Verify findings are marked Persistent even when reordered or having different timestamps."""
        # Reverse order, slightly different timestamps on scan
        newer = {
            "scan_id": "scan_20261017_150000_dddd4444",
            "timestamp": "2026-10-17T15:00:00Z",
            "status": "COMPLETED",
            "findings": list(reversed(self.base_older["findings"])),
        }

        diff = compare_audit_records(self.base_older, newer)
        self.assertEqual(diff["summary"]["persistent_count"], 3)
        self.assertEqual(diff["summary"]["changed_count"], 0)
        self.assertEqual(diff["summary"]["new_count"], 0)
        self.assertEqual(diff["summary"]["resolved_count"], 0)

    def test_duplicate_finding_ids_handled_deterministically(self) -> None:
        """Verify multiple findings with identical finding_id are deterministically handled."""
        older = {
            "scan_id": "scan_20261017_160000_eeee5555",
            "timestamp": "2026-10-17T16:00:00Z",
            "status": "COMPLETED",
            "findings": [
                {"finding_id": "SUID-001", "title": "A", "severity": "INFO", "affected_resource": "/bin/tool1"},
                {"finding_id": "SUID-001", "title": "B", "severity": "INFO", "affected_resource": "/bin/tool2"},
                {"finding_id": "SUID-001", "title": "C", "severity": "INFO", "affected_resource": "/bin/tool3"},
            ],
        }
        # Newer keeps tool1 and tool3, removes tool2, adds tool4
        newer = {
            "scan_id": "scan_20261017_170000_ffff6666",
            "timestamp": "2026-10-17T17:00:00Z",
            "status": "COMPLETED",
            "findings": [
                {"finding_id": "SUID-001", "title": "C", "severity": "INFO", "affected_resource": "/bin/tool3"},
                {"finding_id": "SUID-001", "title": "D", "severity": "INFO", "affected_resource": "/bin/tool4"},
                {"finding_id": "SUID-001", "title": "A", "severity": "INFO", "affected_resource": "/bin/tool1"},
            ],
        }

        diff = compare_audit_records(older, newer)
        self.assertEqual(diff["summary"]["persistent_count"], 2)  # tool1, tool3
        self.assertEqual(diff["summary"]["resolved_count"], 1)    # tool2
        self.assertEqual(diff["summary"]["new_count"], 1)         # tool4
        self.assertEqual(diff["summary"]["changed_count"], 0)

    def test_demo_record_rejection(self) -> None:
        """Verify simulated demo audits cannot be compared as real audits."""
        demo_audit = {
            "scan_id": "scan_demo_synthetic_1234",
            "is_demo": True,
            "findings": [{"finding_id": "SUID-001", "title": "[SIMULATED DEMO] Test"}],
        }
        with self.assertRaises(AuditComparisonError) as ctx:
            compare_audit_records(self.base_older, demo_audit)
        self.assertIn("demo", str(ctx.exception).lower())

        with self.assertRaises(AuditComparisonError) as ctx:
            compare_audit_records(demo_audit, self.base_older)
        self.assertIn("demo", str(ctx.exception).lower())

    def test_compare_scan_against_itself_rejected(self) -> None:
        """Verify comparing a scan against itself raises a clean error."""
        with self.assertRaises(AuditComparisonError) as ctx:
            compare_audit_records(self.base_older, self.base_older)
        self.assertIn("cannot compare", str(ctx.exception).lower())


class TestExportRemediationGuidanceIntegration(unittest.TestCase):
    """Verify remediation guidance appears consistently in JSON, CSV, and HTML exports."""

    def setUp(self) -> None:
        self.sample_audit = {
            "scan_id": "scan_20261017_190000_aabb1122",
            "timestamp": "2026-10-17T19:00:00Z",
            "status": "COMPLETED",
            "is_complete": True,
            "duration_ms": 120.5,
            "summary": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 1, "total": 3},
            "findings": [
                {
                    "finding_id": "SUID-001",
                    "title": "Setuid binary detected",
                    "severity": "INFO",
                    "affected_resource": "/usr/bin/passwd",
                    "description": "Valid setuid binary",
                    "evidence": "mode 0o104755",
                    "recommendation": "Review rights",
                },
                {
                    "finding_id": "PERM-001",
                    "title": "World-Writable Sensitive File",
                    "severity": "HIGH",
                    "affected_resource": "/etc/shadow",
                    "description": "Shadow is world writable",
                    "evidence": "mode 0o666",
                    "recommendation": "chmod 640",
                },
                {
                    "finding_id": "CUSTOM-099",
                    "title": "Custom configuration check",
                    "severity": "MEDIUM",
                    "affected_resource": "/opt/app.conf",
                    "description": "Non-standard configuration",
                    "evidence": "line 42",
                    "recommendation": "Review manual",
                },
            ],
        }

    def test_json_export_contains_remediation_guidance(self) -> None:
        """Verify JSON export contains structured remediation_guidance in each finding."""
        raw_json = generate_json_export(self.sample_audit)
        parsed = json.loads(raw_json)

        findings = parsed["audit"]["findings"]
        self.assertEqual(len(findings), 3)

        for f in findings:
            self.assertIn("remediation_guidance", f)
            g = f["remediation_guidance"]
            self.assertIn("why_it_matters", g)
            self.assertIn("investigation_steps", g)
            self.assertIn("remediation_steps", g)
            self.assertIn("validation_steps", g)
            self.assertTrue(len(g["why_it_matters"]) > 10)

    def test_csv_export_contains_remediation_columns(self) -> None:
        """Verify CSV export contains documented remediation columns with formula defense."""
        raw_csv = generate_csv_export(self.sample_audit)
        import csv
        reader = list(csv.reader(io.StringIO(raw_csv)))

        # Header check
        headers = reader[0]
        self.assertIn("remediation_why_it_matters", headers)
        self.assertIn("remediation_investigation", headers)
        self.assertIn("remediation_recommendation", headers)
        self.assertIn("remediation_validation", headers)

        # Row check
        self.assertEqual(len(reader), 4)  # 1 header + 3 findings
        for row in reader[1:]:
            self.assertEqual(len(row), len(headers))
            # Column 9 is remediation_why_it_matters
            self.assertTrue(len(row[9]) > 10)

    def test_csv_formula_injection_defense_on_remediation_fields(self) -> None:
        """Verify spreadsheet formula injection prefixes (=, +, -, @) are sanitized."""
        malicious_audit = {
            "scan_id": "scan_test_clean",
            "findings": [
                {
                    "finding_id": "=cmd|' /C calc'!A0",
                    "title": "+2+5+cmd",
                    "severity": "HIGH",
                    "affected_resource": "@malicious",
                    "description": "\tTabInjected",
                }
            ],
        }
        raw_csv = generate_csv_export(malicious_audit)
        import csv
        reader = list(csv.reader(io.StringIO(raw_csv)))
        row = reader[1]
        self.assertTrue(row[1].startswith("'="))
        self.assertTrue(row[3].startswith("'+"))
        self.assertTrue(row[4].startswith("'@"))
        self.assertTrue(row[6].startswith("'\t"))

    def test_html_export_contains_guidance_and_escapes_xss(self) -> None:
        """Verify HTML export includes guidance block and defensively escapes XSS vectors."""
        xss_audit = {
            "scan_id": "<script>alert('xss')</script>",
            "findings": [
                {
                    "finding_id": "SUID-001",
                    "title": "<img src=x onerror=alert(1)>",
                    "severity": "HIGH",
                    "affected_resource": "/path/<script>",
                    "description": "Normal description",
                }
            ],
        }
        raw_html = generate_html_export(xss_audit)
        self.assertNotIn("<script>alert('xss')</script>", raw_html)
        self.assertNotIn("<img src=x onerror=alert(1)>", raw_html)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", raw_html)
        self.assertIn("Advisory Remediation Guidance", raw_html)
        self.assertIn("Why It Matters", raw_html)
        self.assertIn("Validation Steps", raw_html)


class TestDashboardUIFiltersAndSorting(unittest.TestCase):
    """Unit tests verifying dashboard template controls for filtering, sorting, and comparison."""

    def test_dashboard_html_contains_filter_controls(self) -> None:
        """Verify dashboard HTML contains severity, source, keyword search, and reset buttons."""
        html_doc = render_dashboard_html()

        # Severity filters
        self.assertIn('data-filter="CRITICAL"', html_doc)
        self.assertIn('data-filter="HIGH"', html_doc)
        self.assertIn('data-filter="INFO"', html_doc)

        # Source filter dropdown
        self.assertIn('id="filter-source"', html_doc)
        self.assertIn('value="suid_sgid"', html_doc)
        self.assertIn('value="sensitive_permissions"', html_doc)
        self.assertIn('value="sudo_audit"', html_doc)

        # Sort dropdown
        self.assertIn('id="sort-findings"', html_doc)
        self.assertIn('value="SEVERITY"', html_doc)
        self.assertIn('value="TITLE_ASC"', html_doc)
        self.assertIn('value="SOURCE_ASC"', html_doc)

        # Reset button
        self.assertIn('id="btn-reset-filters"', html_doc)
        self.assertIn('resetAllFilters()', html_doc)

        # Search box
        self.assertIn('id="search-input"', html_doc)

    def test_dashboard_html_contains_comparison_section(self) -> None:
        """Verify dashboard HTML contains Historical Audit Comparison section and disclaimer."""
        html_doc = render_dashboard_html()
        self.assertIn('id="comparison-section"', html_doc)
        self.assertIn('id="compare-select-older"', html_doc)
        self.assertIn('id="compare-select-newer"', html_doc)
        self.assertIn('id="btn-run-compare"', html_doc)
        self.assertIn('id="comparison-results"', html_doc)
        self.assertIn('A resolved finding indicates only that the finding was not present', html_doc)
        self.assertIn('id="comparison-table"', html_doc)


class TestComparisonAPIEndpoints(unittest.TestCase):
    """Integration tests for GET /api/history/compare endpoint."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.test_dir = tempfile.mkdtemp(prefix="lpe_test_diff_api_")
        cls.db_path = os.path.join(cls.test_dir, "history_test.db")
        cls.history_mgr = AuditHistoryManager(db_path=cls.db_path)
        cls.history_mgr.init_db()

        # Seed two authentic historical audits
        cls.scan_older = cls.history_mgr.save_audit(
            {
                "status": "COMPLETED",
                "timestamp": "2026-10-17T10:00:00Z",
                "is_complete": True,
                "findings": [
                    {"finding_id": "SUID-001", "title": "SUID tool", "severity": "INFO", "affected_resource": "/bin/suid1"},
                    {"finding_id": "PERM-001", "title": "Perm issue", "severity": "HIGH", "affected_resource": "/etc/file1"},
                ],
                "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 1, "total": 2},
                "scanners": {"suid_sgid": {"status": "COMPLETED"}},
            },
            duration_ms=50.0,
        )

        cls.scan_newer = cls.history_mgr.save_audit(
            {
                "status": "COMPLETED",
                "timestamp": "2026-10-17T12:00:00Z",
                "is_complete": True,
                "findings": [
                    {"finding_id": "SUID-001", "title": "SUID tool", "severity": "HIGH", "affected_resource": "/bin/suid1"},  # Changed
                    {"finding_id": "SUDO-001", "title": "Sudo issue", "severity": "MEDIUM", "affected_resource": "/etc/sudoers"},  # New
                ],
                "summary": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0, "total": 2},
                "scanners": {"suid_sgid": {"status": "COMPLETED"}},
            },
            duration_ms=60.0,
        )

        cls.server = create_web_server(
            host="127.0.0.1",
            port=0,
            history_manager=cls.history_mgr,
        )
        cls.thread = Thread(target=cls.server.start, daemon=True)
        cls.thread.start()
        time.sleep(0.3)
        cls.host = "127.0.0.1"
        cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "server"):
            cls.server.shutdown()
        if hasattr(cls, "thread"):
            cls.thread.join(timeout=2.0)
        time.sleep(0.05)
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def _get(self, path: str) -> Tuple[int, Dict[str, Any]]:
        conn = HTTPConnection(self.host, self.port, timeout=5)
        conn.request("GET", path)
        res = conn.getresponse()
        data = res.read().decode("utf-8")
        status = res.status
        conn.close()
        try:
            parsed = json.loads(data)
        except Exception:
            parsed = {"raw": data}
        return status, parsed

    def test_api_history_compare_query_params(self) -> None:
        """Verify GET /api/history/compare?older=...&newer=... returns 200 and accurate diff."""
        status, body = self._get(f"/api/history/compare?older={self.scan_older}&newer={self.scan_newer}")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(body["status"], "SUCCESS")
        self.assertIn("disclaimer", body)
        self.assertEqual(body["summary"]["new_count"], 1)       # SUDO-001
        self.assertEqual(body["summary"]["resolved_count"], 1)  # PERM-001
        self.assertEqual(body["summary"]["changed_count"], 1)   # SUID-001 (INFO -> HIGH)
        self.assertEqual(body["summary"]["persistent_count"], 0)

    def test_api_history_compare_path_params(self) -> None:
        """Verify GET /api/history/compare/<id1>/<id2> works identically."""
        status, body = self._get(f"/api/history/compare/{self.scan_older}/{self.scan_newer}")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(body["status"], "SUCCESS")
        self.assertEqual(body["summary"]["changed_count"], 1)

    def test_api_history_compare_missing_params_returns_400(self) -> None:
        """Verify missing parameters return sanitized 400 error."""
        status, body = self._get("/api/history/compare")
        self.assertEqual(status, HTTPStatus.BAD_REQUEST)
        self.assertIn("error", body)

    def test_api_history_compare_identical_ids_returns_400(self) -> None:
        """Verify comparing identical scan IDs returns 400."""
        status, body = self._get(f"/api/history/compare?older={self.scan_older}&newer={self.scan_older}")
        self.assertEqual(status, HTTPStatus.BAD_REQUEST)
        self.assertIn("cannot compare", body["error"].lower())

    def test_api_history_compare_unknown_id_returns_404(self) -> None:
        """Verify non-existent scan ID returns 404."""
        unknown_id = "scan_20261017_999999_deadbeef"
        status, body = self._get(f"/api/history/compare?older={self.scan_older}&newer={unknown_id}")
        self.assertEqual(status, HTTPStatus.NOT_FOUND)
        self.assertIn("not found", body["error"].lower())

    def test_api_history_compare_never_triggers_scanners(self) -> None:
        """Verify historical comparison NEVER triggers any live scanner module."""
        with patch("lpe_sentinel.web.server.run_unified_audit") as mock_audit:
            status, _ = self._get(f"/api/history/compare?older={self.scan_older}&newer={self.scan_newer}")
            self.assertEqual(status, HTTPStatus.OK)
            mock_audit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
