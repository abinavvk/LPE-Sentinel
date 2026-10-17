"""
Unit tests for LPE-Sentinel Web Application Foundation (Task 4A).

Verifies the HTTP server, dashboard routes, API endpoints, explicit demo labeling,
and argument parser using only the Python standard library.
"""

import io
import json
import os
import sys
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

from lpe_sentinel.audit_engine import (
    AuditResult,
    AuditStatus,
    ScannerExecutionResult,
    ScannerStatus,
)
from lpe_sentinel.models import Finding
from lpe_sentinel.web.demo_data import (
    DEMO_DISCLAIMER,
    get_demo_audit_payload,
    get_demo_findings,
)
from lpe_sentinel.web.server import (
    LpeSentinelWebHandler,
    LpeSentinelWebServer,
    create_web_server,
)
from lpe_sentinel.web.templates import render_dashboard_html
from lpe_sentinel.web_app import parse_args


class TestWebApp(unittest.TestCase):
    """Test suite for the web dashboard server, routes, and demo data."""

    def _get_csrf_token(self) -> str:
        """Fetch valid CSRF token from /api/csrf-token."""
        req = urllib.request.Request(f"{self.base_url}/api/csrf-token")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["csrf_token"]

    @classmethod
    def setUpClass(cls) -> None:
        """Start a background test instance of the web server on an ephemeral port."""
        cls.server = LpeSentinelWebServer(host="127.0.0.1", port=0)
        cls.server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.server_thread.start()

        # Wait briefly for socket binding
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if cls.server.httpd is not None:
                break
            time.sleep(0.05)

        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        """Shut down the background test server cleanly."""
        cls.server.shutdown()
        cls.server_thread.join(timeout=2.0)

    def test_server_started_on_valid_port(self) -> None:
        """Verify that server successfully bound to an ephemeral port."""
        self.assertGreater(self.port, 0)
        self.assertNotEqual(self.port, 8080)

    def test_dashboard_html_route(self) -> None:
        """Verify that GET / returns 200 OK with responsive dashboard HTML and branding."""
        req = urllib.request.Request(f"{self.base_url}/")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))

            html = resp.read().decode("utf-8")
            self.assertIn("LPE-Sentinel", html)
            self.assertIn("Linux Privilege Escalation", html)
            self.assertIn("DEMO MODE ACTIVE", html)
            self.assertIn("SIMULATED AUDIT DATA", html)
            self.assertIn("Total Findings", html)
            self.assertIn("Critical", html)
            self.assertIn("High", html)
            self.assertIn("Medium", html)
            self.assertIn("Low", html)
            self.assertIn("Info", html)
            self.assertIn("findings-table", html)
            self.assertIn("Load Demo Audit", html)
            self.assertIn("Run Unified Audit", html)

    def test_api_status_route(self) -> None:
        """Verify that GET /api/status returns server metadata and capabilities."""
        req = urllib.request.Request(f"{self.base_url}/api/status")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertIn("application/json", resp.headers.get("Content-Type", ""))

            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data.get("status"), "ACTIVE")
            self.assertIn("version", data)
            self.assertIn("system_info", data)
            self.assertTrue(data.get("capabilities", {}).get("demo_mode"))
            self.assertFalse(data.get("capabilities", {}).get("live_audit"))

    def test_api_demo_audit_route(self) -> None:
        """Verify that GET /api/demo-audit returns explicitly labeled simulated data."""
        req = urllib.request.Request(f"{self.base_url}/api/demo-audit")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertIn("application/json", resp.headers.get("Content-Type", ""))

            data = json.loads(resp.read().decode("utf-8"))
            # Must be clearly flagged as demo
            self.assertTrue(data.get("is_demo"))
            self.assertIn("SIMULATED DEMO DATA", data.get("demo_watermark", ""))
            self.assertIn("DO NOT represent an active or live scan", data.get("disclaimer", ""))

            # Findings must exist and be visibly simulated
            findings = data.get("findings", [])
            self.assertGreater(len(findings), 0)
            for f in findings:
                self.assertIn("[SIMULATED DEMO]", f["title"])
                self.assertIn("[SIMULATED DEMO]", f["description"])
                self.assertTrue(f["affected_resource"].startswith("/demo/"))

            # Summary must be present and consistent
            summary = data.get("summary", {})
            self.assertEqual(summary.get("total_findings"), len(findings))
            self.assertIn("severity_counts", summary)

    def test_api_run_audit_post_missing_csrf_rejected_with_403(self) -> None:
        """Verify that POST /api/run-audit without CSRF token is rejected with 403 Forbidden."""
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.FORBIDDEN)
        data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("CSRF token", data.get("error", ""))
        ctx.exception.close()

    def test_invalid_routes_return_404(self) -> None:
        """Verify that non-existent paths return 404 Not Found."""
        req = urllib.request.Request(f"{self.base_url}/api/non_existent_route")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.NOT_FOUND)
        ctx.exception.close()

    def test_demo_findings_generator_integrity(self) -> None:
        """Verify that demo findings are valid instances of the Finding data model."""
        findings = get_demo_findings()
        self.assertGreaterEqual(len(findings), 4)

        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertTrue(f.finding_id.startswith(("SUID-", "PERM-", "SUDO-")))
            self.assertIn(f.severity, ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"))
            self.assertIn("[SIMULATED DEMO]", f.title)

        payload = get_demo_audit_payload()
        self.assertTrue(payload["is_demo"])
        self.assertEqual(len(payload["findings"]), len(findings))

    def test_security_headers_present_on_all_responses(self) -> None:
        """Verify that X-Content-Type-Options, X-Frame-Options, CSP, and Cache-Control are sent."""
        routes = ["/", "/api/status", "/api/demo-audit"]
        for route in routes:
            req = urllib.request.Request(f"{self.base_url}{route}")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
                self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
                csp = resp.headers.get("Content-Security-Policy", "")
                self.assertIn("default-src 'self'", csp)
                self.assertIn("frame-ancestors 'none'", csp)
                cache_control = resp.headers.get("Cache-Control", "")
                self.assertIn("no-store", cache_control)

    def test_head_method_support(self) -> None:
        """Verify that HEAD requests return status 200 with headers and empty body."""
        req = urllib.request.Request(f"{self.base_url}/", method="HEAD")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            body = resp.read()
            self.assertEqual(len(body), 0)

    def test_unsupported_methods_return_405(self) -> None:
        """Verify that unsupported HTTP methods like PUT or DELETE return 405 Method Not Allowed."""
        for method in ("PUT", "DELETE", "PATCH"):
            req = urllib.request.Request(
                f"{self.base_url}/api/status",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method=method,
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=3.0)
            self.assertEqual(ctx.exception.code, HTTPStatus.METHOD_NOT_ALLOWED)
            ctx.exception.close()

    def test_api_status_information_minimization(self) -> None:
        """Verify that /api/status does not expose sensitive local usernames across HTTP."""
        req = urllib.request.Request(f"{self.base_url}/api/status")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode("utf-8"))

            sys_info = data.get("system_info", {})
            self.assertNotIn("username", sys_info, "Local username must not be exposed over /api/status")
            self.assertIn("os_name", sys_info)
            self.assertIn("platform_category", sys_info)
            self.assertIn("is_linux", sys_info)
            self.assertIn("architecture", sys_info)

    def test_post_run_audit_drains_request_body_safely(self) -> None:
        """Verify that POST /api/run-audit drains the request body without execution or socket hanging."""
        csrf_token = self._get_csrf_token()
        sample_payload = json.dumps({"target": "all", "force": True, "padding": "x" * 1024, "csrf_token": csrf_token}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=sample_payload,
            headers={"Content-Type": "application/json", "Content-Length": str(len(sample_payload)), "X-CSRF-Token": csrf_token},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.BAD_REQUEST)
        data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("Forbidden parameter", data.get("error", ""))
        ctx.exception.close()

    def test_malformed_content_length_returns_400_and_closes_connection(self) -> None:
        """Verify that non-integer Content-Length returns 400 Bad Request and sends Connection: close."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3.0)
        try:
            conn.request("POST", "/api/run-audit", body=b"test", headers={"Content-Length": "invalid_non_int"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.BAD_REQUEST)
            self.assertEqual(resp.headers.get("Connection"), "close")
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("Malformed Content-Length", data.get("error", ""))
        finally:
            conn.close()

    def test_negative_content_length_returns_400_and_closes_connection(self) -> None:
        """Verify that negative Content-Length returns 400 Bad Request and sends Connection: close."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3.0)
        try:
            conn.request("POST", "/api/run-audit", body=b"", headers={"Content-Length": "-1"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.BAD_REQUEST)
            self.assertEqual(resp.headers.get("Connection"), "close")
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("Negative Content-Length", data.get("error", ""))
        finally:
            conn.close()

    def test_oversized_content_length_returns_413_and_closes_connection(self) -> None:
        """Verify that Content-Length exceeding 64KB returns 413 Payload Too Large and closes connection."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3.0)
        try:
            conn.request("POST", "/api/run-audit", body=b"", headers={"Content-Length": "70000"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            self.assertEqual(resp.headers.get("Connection"), "close")
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("Payload Too Large", data.get("error", ""))
        finally:
            conn.close()

    def test_chunked_transfer_encoding_returns_501_and_closes_connection(self) -> None:
        """Verify that chunked upload requests return 501 Not Implemented and close connection."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3.0)
        try:
            conn.request("POST", "/api/run-audit", body=b"0\r\n\r\n", headers={"Transfer-Encoding": "chunked"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.NOT_IMPLEMENTED)
            self.assertEqual(resp.headers.get("Connection"), "close")
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("Chunked transfer encoding is not supported", data.get("error", ""))
        finally:
            conn.close()

    def test_incomplete_request_body_returns_400_and_closes_connection(self) -> None:
        """Verify that sending fewer bytes than Content-Length returns 400 and closes connection."""
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        try:
            s.connect(("127.0.0.1", self.port))
            # Claim 50 bytes, but send only 4 and shut down write side
            payload = b"POST /api/run-audit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 50\r\n\r\n1234"
            s.sendall(payload)
            s.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
            resp_data = b"".join(chunks).decode("utf-8", errors="replace")
            self.assertIn("400 Bad Request", resp_data)
            self.assertIn("Incomplete request body", resp_data)
        finally:
            s.close()

    def test_post_missing_content_length_allowed_with_empty_body(self) -> None:
        """Verify that a POST request with no Content-Length safely defaults to empty body."""
        import socket
        csrf_token = self._get_csrf_token()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        try:
            s.connect(("127.0.0.1", self.port))
            payload = (
                f"POST /api/run-audit HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\n"
                f"Content-Type: application/json\r\n"
                f"X-CSRF-Token: {csrf_token}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")
            s.sendall(payload)
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
            resp_data = b"".join(chunks).decode("utf-8", errors="replace")
            self.assertIn("HTTP/1.", resp_data)
            self.assertTrue("200 OK" in resp_data or "400 Bad Request" in resp_data)
        finally:
            s.close()

    def test_hardened_csp_directives(self) -> None:
        """Verify that Content-Security-Policy contains object-src none, base-uri self, and frame-ancestors none."""
        req = urllib.request.Request(f"{self.base_url}/")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            csp = resp.headers.get("Content-Security-Policy", "")
            self.assertIn("object-src 'none'", csp)
            self.assertIn("base-uri 'self'", csp)
            self.assertIn("form-action 'self'", csp)
            self.assertIn("frame-ancestors 'none'", csp)

    def test_path_normalization_and_trailing_slashes(self) -> None:
        """Verify that path normalization collapses redundant slashes and handles trailing slashes."""
        paths = ["/api/status/", "//api/status", "/index.html"]
        for p in paths:
            req = urllib.request.Request(f"{self.base_url}{p}")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, HTTPStatus.OK)

    def test_demo_audit_explicit_simulation_flags(self) -> None:
        """Verify that GET /api/demo-audit explicitly marks the payload and all findings as simulated/demo."""
        req = urllib.request.Request(f"{self.base_url}/api/demo-audit")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(data.get("is_demo"))
            self.assertTrue(data.get("is_simulated"))
            self.assertEqual(data.get("status"), "COMPLETED (DEMO SIMULATION)")
            self.assertIn("SIMULATED DEMO DATA", data.get("demo_watermark", ""))

            findings = data.get("findings", [])
            self.assertGreater(len(findings), 0)
            for f in findings:
                self.assertTrue(f.get("is_demo"), f"Finding {f.get('finding_id')} must have is_demo=True")
                self.assertTrue(f.get("is_simulated"), f"Finding {f.get('finding_id')} must have is_simulated=True")
                self.assertIn("[SIMULATED DEMO]", f.get("title", ""))

    def test_post_run_audit_unsupported_platform_contract(self) -> None:
        """Verify that POST /api/run-audit returns explicit UNSUPPORTED_PLATFORM contract on non-Linux."""
        csrf_token = self._get_csrf_token()
        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=False):
            req = urllib.request.Request(
                f"{self.base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=3.0)
            self.assertEqual(ctx.exception.code, HTTPStatus.BAD_REQUEST)
            data = json.loads(ctx.exception.read().decode("utf-8"))
            self.assertEqual(data.get("status"), "UNSUPPORTED_PLATFORM")
            self.assertFalse(data.get("is_complete"))
            self.assertFalse(data.get("live_audit"))
            self.assertFalse(data.get("is_demo"))
            self.assertFalse(data.get("is_simulated"))
            self.assertEqual(data.get("findings"), [])
            self.assertIn("only supported on Linux", data.get("error", ""))
            ctx.exception.close()

    def test_csrf_token_endpoint(self) -> None:
        """Verify that GET /api/csrf-token returns unpredictable hex string."""
        token = self._get_csrf_token()
        self.assertIsInstance(token, str)
        self.assertEqual(len(token), 64)

    def test_post_run_audit_invalid_csrf_token_returns_403(self) -> None:
        """Verify that invalid CSRF token returns 403 Forbidden."""
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=b"{}",
            headers={"Content-Type": "application/json", "X-CSRF-Token": "bad_token_12345"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.FORBIDDEN)
        ctx.exception.close()

    def test_post_run_audit_invalid_origin_returns_403(self) -> None:
        """Verify that cross-origin POST request returns 403 Forbidden."""
        csrf_token = self._get_csrf_token()
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf_token,
                "Origin": "http://attacker-controlled-site.com",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.FORBIDDEN)
        ctx.exception.close()

    def test_post_run_audit_invalid_content_type_returns_415(self) -> None:
        """Verify that non-JSON Content-Type returns 415 Unsupported Media Type."""
        csrf_token = self._get_csrf_token()
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=b"raw plain text",
            headers={"Content-Type": "text/plain", "X-CSRF-Token": csrf_token},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        ctx.exception.close()

    def test_post_run_audit_malformed_json_returns_400(self) -> None:
        """Verify that invalid JSON syntax in request body returns 400 Bad Request."""
        csrf_token = self._get_csrf_token()
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=b"{\"unclosed_json: true",
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.BAD_REQUEST)
        data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("Malformed JSON", data.get("error", ""))
        ctx.exception.close()

    def test_post_run_audit_client_supplied_paths_rejected(self) -> None:
        """Verify that client-supplied paths are rejected with 400 Bad Request."""
        csrf_token = self._get_csrf_token()
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=json.dumps({"paths": ["/etc/shadow"]}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.BAD_REQUEST)
        data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("Forbidden parameter", data.get("error", ""))
        self.assertIn("paths", data.get("error", ""))
        ctx.exception.close()

    def test_post_run_audit_command_parameter_rejected(self) -> None:
        """Verify that shell command parameters are rejected with 400 Bad Request."""
        csrf_token = self._get_csrf_token()
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=json.dumps({"command": "whoami"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.BAD_REQUEST)
        data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("Forbidden parameter", data.get("error", ""))
        ctx.exception.close()

    def test_post_run_audit_invalid_scanner_name_rejected(self) -> None:
        """Verify that unknown scanner names in enabled_scanners return 400 Bad Request."""
        csrf_token = self._get_csrf_token()
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=json.dumps({"enabled_scanners": ["suid_sgid", "non_existent_scanner"]}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.BAD_REQUEST)
        data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("Invalid scanner name", data.get("error", ""))
        ctx.exception.close()

    def test_post_run_audit_empty_scanner_list_rejected(self) -> None:
        """Verify that empty enabled_scanners list returns 400 Bad Request."""
        csrf_token = self._get_csrf_token()
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=json.dumps({"enabled_scanners": []}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.BAD_REQUEST)
        data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("non-empty", data.get("error", ""))
        ctx.exception.close()

    def test_post_run_audit_concurrency_lock_returns_409(self) -> None:
        """Verify that a second concurrent audit request returns 409 Conflict."""
        csrf_token = self._get_csrf_token()
        lock = self.server.audit_lock
        lock.acquire()
        try:
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True):
                req = urllib.request.Request(
                    f"{self.base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req, timeout=3.0)
                self.assertEqual(ctx.exception.code, HTTPStatus.CONFLICT)
                data = json.loads(ctx.exception.read().decode("utf-8"))
                self.assertEqual(data.get("status"), "BUSY")
                self.assertIn("already in progress", data.get("error", ""))
                ctx.exception.close()
        finally:
            lock.release()

    def test_post_run_audit_engine_exception_returns_500(self) -> None:
        """Verify that unexpected engine exceptions return 500 Internal Server Error."""
        csrf_token = self._get_csrf_token()
        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.web.server.run_unified_audit", side_effect=RuntimeError("Engine failure")):
            req = urllib.request.Request(
                f"{self.base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=3.0)
            self.assertEqual(ctx.exception.code, HTTPStatus.INTERNAL_SERVER_ERROR)
            data = json.loads(ctx.exception.read().decode("utf-8"))
            self.assertEqual(data.get("status"), "FAILED")
            self.assertIn("Internal error during audit execution", data.get("error", ""))
            ctx.exception.close()

    def test_post_run_audit_completed_live_result(self) -> None:
        """Verify that completed live audit serializes findings and coverage metadata accurately."""
        csrf_token = self._get_csrf_token()
        mock_finding = Finding(
            finding_id="SUID-001",
            title="SUID Test Binary",
            severity="INFO",
            description="Test SUID description",
            evidence="Mode 0o4755",
            affected_resource="/bin/test_tool",
            recommendation="Review.",
            mitre_attack="T1548.001",
        )
        mock_result = AuditResult(
            status="COMPLETED",
            system_info={"os_name": "Linux", "platform_category": "Linux"},
            findings=[mock_finding],
            summary={"total_findings": 1, "severity_counts": {"INFO": 1, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}},
            scanner_results={
                "suid_sgid": ScannerExecutionResult(
                    scanner_name="suid_sgid",
                    status="COMPLETED",
                    findings_count=1,
                    target_paths=["/bin"],
                    accessible_paths=["/bin"],
                    skipped_paths=[],
                    message="Full coverage",
                )
            },
            errors=[],
        )
        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_result) as mock_engine:
            req = urllib.request.Request(
                f"{self.base_url}/api/run-audit",
                data=json.dumps({"enabled_scanners": ["suid_sgid"]}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, HTTPStatus.OK)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data.get("status"), "COMPLETED")
                self.assertTrue(data.get("is_complete"))
                self.assertTrue(data.get("live_audit"))
                self.assertFalse(data.get("is_demo"))
                self.assertFalse(data.get("is_simulated"))
                self.assertEqual(len(data.get("findings", [])), 1)
                self.assertEqual(data["findings"][0]["finding_id"], "SUID-001")
                mock_engine.assert_called_once_with(
                    enabled_scanners=("suid_sgid",),
                    collect_sys_info=True,
                )

    def test_post_run_audit_partial_live_result(self) -> None:
        """Verify that partial live audit sets is_complete=False and status=PARTIAL."""
        csrf_token = self._get_csrf_token()
        mock_result = AuditResult(
            status="PARTIAL",
            system_info={"os_name": "Linux", "platform_category": "Linux"},
            findings=[],
            summary={"total_findings": 0, "severity_counts": {}},
            scanner_results={},
            errors=["Skipped inaccessible directory"],
        )
        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_result):
            req = urllib.request.Request(
                f"{self.base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, HTTPStatus.OK)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data.get("status"), "PARTIAL")
                self.assertFalse(data.get("is_complete"))
                self.assertTrue(data.get("live_audit"))

    def test_post_run_audit_failed_live_result(self) -> None:
        """Verify that failed live audit sets is_complete=False and status=FAILED."""
        csrf_token = self._get_csrf_token()
        mock_result = AuditResult(
            status="FAILED",
            system_info={"os_name": "Linux", "platform_category": "Linux"},
            findings=[],
            summary={"total_findings": 0, "severity_counts": {}},
            scanner_results={},
            errors=["All scanners failed"],
        )
        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_result):
            req = urllib.request.Request(
                f"{self.base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, HTTPStatus.OK)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data.get("status"), "FAILED")
                self.assertFalse(data.get("is_complete"))
                self.assertTrue(data.get("live_audit"))

    def test_post_run_audit_engine_receives_only_predefined_paths_and_no_binary_execution(self) -> None:
        """Verify that engine receives only server-controlled defaults and no subprocess execution occurs."""
        csrf_token = self._get_csrf_token()
        mock_result = AuditResult(
            status="COMPLETED",
            system_info={"os_name": "Linux", "platform_category": "Linux"},
            findings=[],
            summary={"total_findings": 0, "severity_counts": {}},
            scanner_results={},
            errors=[],
        )
        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_result) as mock_engine, \
             patch("subprocess.Popen") as mock_popen, \
             patch("os.system") as mock_system:
            req = urllib.request.Request(
                f"{self.base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, HTTPStatus.OK)
            mock_engine.assert_called_once()
            called_kwargs = mock_engine.call_args[1]
            self.assertNotIn("suid_paths", called_kwargs)
            self.assertNotIn("sensitive_file_paths", called_kwargs)
            self.assertNotIn("sudo_file_paths", called_kwargs)
            mock_popen.assert_not_called()
            mock_system.assert_not_called()

    def test_get_run_audit_returns_405_method_not_allowed(self) -> None:
        """Verify that GET /api/run-audit returns 405 Method Not Allowed."""
        req = urllib.request.Request(f"{self.base_url}/api/run-audit")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.METHOD_NOT_ALLOWED)
        ctx.exception.close()

    def test_unrouted_findings_and_summary_return_404(self) -> None:
        """Verify that GET /api/findings and GET /api/summary return 404 to avoid phantom live results."""
        for path in ("/api/findings", "/api/summary"):
            req = urllib.request.Request(f"{self.base_url}{path}")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=3.0)
            self.assertEqual(ctx.exception.code, HTTPStatus.NOT_FOUND)
            ctx.exception.close()

    def test_status_capabilities_explicitly_disables_live_audit(self) -> None:
        """Verify that /api/status capabilities advertise live_audit=False and demo_mode=True."""
        req = urllib.request.Request(f"{self.base_url}/api/status")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode("utf-8"))
            capabilities = data.get("capabilities", {})
            self.assertFalse(capabilities.get("live_audit"))
            self.assertTrue(capabilities.get("demo_mode"))

    def test_cli_argument_parser(self) -> None:
        """Verify that parse_args handles custom host and port flags."""
        args = parse_args(["--host", "0.0.0.0", "--port", "9090", "--allow-non-loopback"])
        self.assertEqual(args.host, "0.0.0.0")
        self.assertEqual(args.port, 9090)
        self.assertTrue(args.allow_non_loopback)
        self.assertFalse(args.open_browser)

        default_args = parse_args([])
        self.assertEqual(default_args.host, "127.0.0.1")
        self.assertFalse(default_args.allow_non_loopback)

    def test_non_loopback_binding_guards(self) -> None:
        """Verify loopback host detection and refusal when non-loopback is passed without opt-in."""
        from lpe_sentinel.web_app import is_loopback_host, main

        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertFalse(is_loopback_host("0.0.0.0"))
        self.assertFalse(is_loopback_host("192.168.1.100"))

        # Refusal without --allow-non-loopback
        with patch("sys.argv", ["web_app.py", "--host", "0.0.0.0"]):
            with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                with self.assertRaises(SystemExit) as cm:
                    main()
                self.assertEqual(cm.exception.code, 1)
                self.assertIn("SECURITY REFUSAL: Non-loopback host '0.0.0.0'", mock_stderr.getvalue())
                self.assertIn("--allow-non-loopback", mock_stderr.getvalue())

        # Permitted with --allow-non-loopback (mocking server to prevent real socket bind)
        with patch("sys.argv", ["web_app.py", "--host", "0.0.0.0", "--allow-non-loopback"]):
            with patch("lpe_sentinel.web_app.LpeSentinelWebServer") as mock_server:
                mock_server.return_value.start = MagicMock()
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    main()
                    self.assertIn("SECURITY WARNING: Binding to non-loopback address '0.0.0.0'", mock_stderr.getvalue())
                    mock_server.assert_called_once()
    # ------------------------------------------------------------------
    # Task 5B-2: Live-Audit Controller Security Verification Tests
    # ------------------------------------------------------------------

    def test_csrf_token_process_lifetime_behavior(self) -> None:
        """Verify that CSRF token is bound to process lifetime and identical across requests."""
        token1 = self._get_csrf_token()
        token2 = self._get_csrf_token()
        self.assertEqual(token1, token2)
        self.assertEqual(len(token1), 64)

    def test_post_run_audit_origin_null_rejected(self) -> None:
        """Verify that Origin: 'null' is rejected with 403 Forbidden."""
        csrf_token = self._get_csrf_token()
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf_token,
                "Origin": "null",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.FORBIDDEN)
        ctx.exception.close()

    def test_post_run_audit_origin_port_mismatch_rejected(self) -> None:
        """Verify that loopback Origin with mismatched port is rejected with 403 Forbidden."""
        csrf_token = self._get_csrf_token()
        foreign_port = (self.port + 1) if self.port < 65535 else (self.port - 1)
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf_token,
                "Origin": f"http://127.0.0.1:{foreign_port}",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.FORBIDDEN)
        ctx.exception.close()

    def test_post_run_audit_referer_cross_origin_rejected(self) -> None:
        """Verify that cross-origin Referer is rejected with 403 Forbidden."""
        csrf_token = self._get_csrf_token()
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf_token,
                "Referer": "http://evil-attacker.org/attack.html",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.FORBIDDEN)
        ctx.exception.close()

    def test_post_run_audit_malformed_origin_rejected(self) -> None:
        """Verify that malformed Origin header is rejected with 403 Forbidden."""
        csrf_token = self._get_csrf_token()
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf_token,
                "Origin": ":::malformed-uri:::",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.FORBIDDEN)
        ctx.exception.close()

    def test_post_run_audit_valid_origin_and_referer_accepted(self) -> None:
        """Verify that matching loopback Origin and Referer are accepted."""
        csrf_token = self._get_csrf_token()
        mock_result = MagicMock(spec=AuditResult)
        mock_result.status = "COMPLETED"
        mock_result.is_complete = True
        mock_result.timestamp = "2026-10-17T00:00:00Z"
        mock_result.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        mock_result.system_info = {"platform_category": "Linux"}
        mock_result.scanner_results = {}
        mock_result.errors = []
        mock_result.findings = []

        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_result):
            req = urllib.request.Request(
                f"{self.base_url}/api/run-audit",
                data=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrf_token,
                    "Origin": f"http://127.0.0.1:{self.port}",
                    "Referer": f"http://127.0.0.1:{self.port}/index.html",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, HTTPStatus.OK)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data.get("status"), "COMPLETED")

    def test_post_run_audit_absent_origin_without_csrf_rejected(self) -> None:
        """Verify that absent Origin/Referer does NOT bypass CSRF protection."""
        req = urllib.request.Request(
            f"{self.base_url}/api/run-audit",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.FORBIDDEN)
        ctx.exception.close()

    def test_overlapping_requests_concurrent_rejection_with_409_busy(self) -> None:
        """
        Verify real HTTP-level concurrency behavior with ThreadingHTTPServer:
        The first request enters the engine and holds the audit lock.
        The second overlapping request is rejected promptly with 409 Conflict (BUSY).
        The audit engine is invoked exactly once.
        """
        csrf_token = self._get_csrf_token()
        engine_started = threading.Event()
        engine_release = threading.Event()
        engine_call_count = 0
        call_lock = threading.Lock()
        results = []

        def slow_engine(*args, **kwargs):
            nonlocal engine_call_count
            with call_lock:
                engine_call_count += 1
            engine_started.set()
            engine_release.wait(timeout=5.0)
            mock_res = MagicMock(spec=AuditResult)
            mock_res.status = "COMPLETED"
            mock_res.is_complete = True
            mock_res.timestamp = "2026-10-17T00:00:00Z"
            mock_res.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
            mock_res.system_info = {"platform_category": "Linux"}
            mock_res.scanner_results = {}
            mock_res.errors = []
            mock_res.findings = []
            return mock_res

        def send_request(req_id: int):
            req = urllib.request.Request(
                f"{self.base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    results.append((req_id, resp.status, data.get("status")))
            except urllib.error.HTTPError as exc:
                data = json.loads(exc.read().decode("utf-8"))
                results.append((req_id, exc.code, data.get("status")))
                exc.close()

        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.web.server.run_unified_audit", side_effect=slow_engine):
            # Start Request 1 in thread
            t1 = threading.Thread(target=send_request, args=(1,), daemon=True)
            t1.start()
            self.assertTrue(engine_started.wait(timeout=2.0), "Engine did not start in time for request 1")

            # Start Request 2 in thread while Request 1 is still actively blocked in the engine
            t2 = threading.Thread(target=send_request, args=(2,), daemon=True)
            t2.start()

            # Request 2 should finish promptly with 409 Conflict without waiting for engine_release
            t2.join(timeout=2.0)
            self.assertFalse(t2.is_alive(), "Request 2 did not return promptly")

            # At this point, Request 2 must already be in results with 409 BUSY, while Request 1 is still blocked
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0], (2, HTTPStatus.CONFLICT, "BUSY"))

            # Now release Request 1 and wait for completion
            engine_release.set()
            t1.join(timeout=3.0)
            self.assertFalse(t1.is_alive(), "Request 1 did not complete in time")

        # Verify final results: Request 2 got 409 BUSY, Request 1 got 200 COMPLETED
        self.assertEqual(len(results), 2)
        sorted_results = sorted(results, key=lambda x: x[0])
        self.assertEqual(sorted_results[0], (1, HTTPStatus.OK, "COMPLETED"))
        self.assertEqual(sorted_results[1], (2, HTTPStatus.CONFLICT, "BUSY"))

        # Crucial check: Verify engine was invoked exactly once!
        self.assertEqual(engine_call_count, 1)

    def test_invalid_requests_never_invoke_audit_engine(self) -> None:
        """Verify that malformed or unauthorized requests never trigger the audit engine."""
        csrf_token = self._get_csrf_token()

        invalid_cases = [
            ("missing_csrf", {"Content-Type": "application/json"}, b"{}"),
            ("invalid_csrf", {"Content-Type": "application/json", "X-CSRF-Token": "bad_token"}, b"{}"),
            ("cross_origin", {"Content-Type": "application/json", "X-CSRF-Token": csrf_token, "Origin": "http://evil.com"}, b"{}"),
            ("bad_content_type", {"Content-Type": "text/html", "X-CSRF-Token": csrf_token}, b"{}"),
            ("malformed_json", {"Content-Type": "application/json", "X-CSRF-Token": csrf_token}, b"not-json"),
            ("unknown_param", {"Content-Type": "application/json", "X-CSRF-Token": csrf_token}, b'{"arbitrary": 123}'),
            ("client_path", {"Content-Type": "application/json", "X-CSRF-Token": csrf_token}, b'{"paths": ["/tmp"]}'),
            ("client_cmd", {"Content-Type": "application/json", "X-CSRF-Token": csrf_token}, b'{"command": "whoami"}'),
            ("bad_scanner", {"Content-Type": "application/json", "X-CSRF-Token": csrf_token}, b'{"enabled_scanners": ["hack"]}'),
            ("empty_scanner", {"Content-Type": "application/json", "X-CSRF-Token": csrf_token}, b'{"enabled_scanners": []}'),
        ]

        with patch("lpe_sentinel.web.server.run_unified_audit") as mock_audit:
            for name, headers, body in invalid_cases:
                with self.subTest(case=name):
                    req = urllib.request.Request(
                        f"{self.base_url}/api/run-audit",
                        data=body,
                        headers=headers,
                        method="POST",
                    )
                    with self.assertRaises(urllib.error.HTTPError) as ctx:
                        urllib.request.urlopen(req, timeout=3.0)
                    ctx.exception.close()
                    mock_audit.assert_not_called()

    def test_engine_exception_does_not_disclose_internal_paths_or_tracebacks(self) -> None:
        """Verify that engine exceptions sanitize errors and never disclose host paths or tracebacks."""
        csrf_token = self._get_csrf_token()
        sensitive_path = "/home/secret_user/confidential/.hidden_token"
        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.web.server.run_unified_audit", side_effect=OSError(f"Permission denied: {sensitive_path}")):
            req = urllib.request.Request(
                f"{self.base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=3.0)
            self.assertEqual(ctx.exception.code, HTTPStatus.INTERNAL_SERVER_ERROR)
            data = json.loads(ctx.exception.read().decode("utf-8"))
            self.assertEqual(data.get("status"), "FAILED")
            self.assertFalse(data.get("is_complete"))
            err_text = data.get("error", "")
            self.assertNotIn(sensitive_path, err_text)
            self.assertNotIn("Traceback", err_text)
            self.assertNotIn("File \"", err_text)
            self.assertIn("Internal error during audit execution (OSError)", err_text)
            ctx.exception.close()


    # ------------------------------------------------------------------
    # Task 5B-4: Shutdown and Final Lifecycle Regression Tests
    # ------------------------------------------------------------------

    def test_server_shutdown_while_audit_in_progress(self) -> None:
        """
        Verify server shutdown while an audit request is actively blocked in the engine:
        - Shutdown terminates the listening socket and unblocks promptly.
        - The active audit thread safely releases its own lock upon completion.
        - No duplicate scan occurs and no new connections are accepted.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        time.sleep(0.3)
        self.assertIsNotNone(server.httpd)

        port = server.server_port
        base_url = f"http://127.0.0.1:{port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        engine_started = threading.Event()
        engine_release = threading.Event()
        engine_call_count = 0

        def slow_engine(*args, **kwargs):
            nonlocal engine_call_count
            engine_call_count += 1
            engine_started.set()
            engine_release.wait(timeout=5.0)
            mock_res = MagicMock(spec=AuditResult)
            mock_res.status = "COMPLETED"
            mock_res.is_complete = True
            mock_res.timestamp = "2026-10-17T00:00:00Z"
            mock_res.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
            mock_res.system_info = {"platform_category": "Linux"}
            mock_res.scanner_results = {}
            mock_res.errors = []
            mock_res.findings = []
            return mock_res

        def send_audit():
            req = urllib.request.Request(
                f"{base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    resp.read()
            except Exception:
                pass

        with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
             patch("lpe_sentinel.web.server.run_unified_audit", side_effect=slow_engine):
            req_thread = threading.Thread(target=send_audit, daemon=True)
            req_thread.start()

            self.assertTrue(engine_started.wait(timeout=2.0), "Audit did not start in time")
            self.assertTrue(server.audit_lock.locked(), "Audit lock should be locked while running")

            # Shutdown while request is blocked
            shutdown_start = time.time()
            server.shutdown()
            shutdown_duration = time.time() - shutdown_start

            # Shutdown should unblock promptly
            self.assertLess(shutdown_duration, 2.0)
            self.assertIsNone(server.httpd)

            # Audit lock is still held by the active worker thread
            self.assertTrue(server.audit_lock.locked())

            # New requests to this port are rejected (connection refused / failed)
            with self.assertRaises(Exception):
                urllib.request.urlopen(f"{base_url}/api/status", timeout=1.0)

            # Release engine and wait for worker thread to exit
            engine_release.set()
            req_thread.join(timeout=3.0)
            self.assertFalse(req_thread.is_alive())

            # Now the lock has been safely released
            self.assertFalse(server.audit_lock.locked())
            self.assertEqual(engine_call_count, 1)

    def test_server_shutdown_idempotent_and_thread_safe(self) -> None:
        """Verify repeated and concurrent shutdown calls do not raise errors."""
        server = create_web_server(host="127.0.0.1", port=0)
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        time.sleep(0.3)

        # Call shutdown multiple times in sequence
        server.shutdown()
        self.assertIsNone(server.httpd)
        server.shutdown()
        server.shutdown()

        # Concurrent shutdown calls
        threads = [threading.Thread(target=server.shutdown, daemon=True) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=1.0)
        self.assertIsNone(server.httpd)

    def test_server_startup_failure_clean_state(self) -> None:
        """Verify startup failure on port collision raises OSError and leaves clean state."""
        server = create_web_server(host="127.0.0.1", port=8080)
        with patch("lpe_sentinel.web.server.ThreadingHTTPServer", side_effect=OSError("Address already in use")):
            with self.assertRaises(OSError):
                server.start()

        self.assertIsNone(server.httpd)
        server.shutdown()  # Must not error


    # ------------------------------------------------------------------
    # Task 5B-5: Shutdown Locking and Lifecycle Review Tests
    # ------------------------------------------------------------------

    def test_server_restart_unsupported_raises_runtime_error(self) -> None:
        """Verify that attempting to restart an already-stopped server instance raises RuntimeError."""
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)
        self.assertTrue(server.is_serving)

        server.shutdown()
        self.assertFalse(server.is_serving)

        # Calling start again on the stopped instance must raise RuntimeError
        with self.assertRaises(RuntimeError) as ctx:
            server.start()
        self.assertIn("not supported", str(ctx.exception))

    def test_server_start_while_running_raises_runtime_error(self) -> None:
        """Verify that calling start() while the server is already active raises RuntimeError."""
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)
        self.assertTrue(server.is_serving)

        try:
            with self.assertRaises(RuntimeError) as ctx:
                server.start()
            self.assertIn("already running", str(ctx.exception))
        finally:
            server.shutdown()

    def test_server_lifecycle_properties_and_wait_for_audit(self) -> None:
        """Verify is_serving, is_audit_active, and wait_for_audit accurately reflect state."""
        server = create_web_server(host="127.0.0.1", port=0)
        self.assertFalse(server.is_serving)
        self.assertFalse(server.is_audit_active)
        self.assertTrue(server.wait_for_audit())

        # Simulate audit lock held and idle event cleared
        server.audit_lock.acquire()
        server._audit_idle_event.clear()
        self.assertTrue(server.is_audit_active)
        # wait_for_audit with 0 timeout returns False because audit is active
        self.assertFalse(server.wait_for_audit(timeout=0.01))

        # Release lock and set idle event
        server._audit_idle_event.set()
        server.audit_lock.release()
        self.assertFalse(server.is_audit_active)
        self.assertTrue(server.wait_for_audit(timeout=0.1))

    def test_audit_lock_retained_on_client_disconnect_and_engine_exception(self) -> None:
        """Verify that audit lock is held throughout scan and released cleanly on engine exception."""
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        engine_started = threading.Event()
        engine_fail = threading.Event()

        def failing_engine(*args, **kwargs):
            engine_started.set()
            engine_fail.wait(timeout=5.0)
            raise RuntimeError("Fatal hardware failure during audit")

        def send_request():
            req = urllib.request.Request(
                f"{base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    resp.read()
            except Exception:
                pass

        try:
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", side_effect=failing_engine):
                req_thread = threading.Thread(target=send_request, daemon=True)
                req_thread.start()

                self.assertTrue(engine_started.wait(timeout=2.0))
                self.assertTrue(server.is_audit_active)

                # Unblock engine to trigger exception
                engine_fail.set()
                req_thread.join(timeout=3.0)

                # Verify lock is cleanly released after exception
                self.assertFalse(server.is_audit_active)
                self.assertTrue(server.wait_for_audit(timeout=0.1))
        finally:
            server.shutdown()

    # ------------------------------------------------------------------
    # Task 5B-6: Audit Completion Synchronization Review Tests
    # ------------------------------------------------------------------

    def test_wait_for_audit_blocks_until_completion_and_does_not_return_early(self) -> None:
        """
        Verify that wait_for_audit() blocks until an active audit finishes and does NOT return early.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        engine_started = threading.Event()
        engine_release = threading.Event()
        wait_result = []

        def slow_engine(*args, **kwargs):
            engine_started.set()
            engine_release.wait(timeout=5.0)
            mock_res = MagicMock(spec=AuditResult)
            mock_res.status = "COMPLETED"
            mock_res.is_complete = True
            mock_res.timestamp = "2026-10-17T00:00:00Z"
            mock_res.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
            mock_res.system_info = {"platform_category": "Linux"}
            mock_res.scanner_results = {}
            mock_res.errors = []
            mock_res.findings = []
            return mock_res

        def send_request():
            req = urllib.request.Request(
                f"{base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    resp.read()
            except Exception:
                pass

        def wait_worker():
            res = server.wait_for_audit(timeout=5.0)
            wait_result.append(res)

        try:
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", side_effect=slow_engine):
                req_thread = threading.Thread(target=send_request, daemon=True)
                req_thread.start()
                self.assertTrue(engine_started.wait(timeout=2.0))

                # Start waiting thread while engine is still blocked
                wait_thread = threading.Thread(target=wait_worker, daemon=True)
                wait_thread.start()

                # Verify wait_thread has NOT returned early
                time.sleep(0.3)
                self.assertTrue(wait_thread.is_alive())
                self.assertEqual(len(wait_result), 0)

                # Now release engine and confirm wait_thread completes with True
                engine_release.set()
                wait_thread.join(timeout=3.0)
                self.assertFalse(wait_thread.is_alive())
                self.assertEqual(wait_result, [True])
                req_thread.join(timeout=3.0)
        finally:
            server.shutdown()

    def test_wait_for_audit_does_not_cause_false_409_busy(self) -> None:
        """
        Verify that calling wait_for_audit() concurrently does NOT lock-steal or falsely reject
        an incoming POST /api/run-audit request with 409 BUSY.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        mock_res = MagicMock(spec=AuditResult)
        mock_res.status = "COMPLETED"
        mock_res.is_complete = True
        mock_res.timestamp = "2026-10-17T00:00:00Z"
        mock_res.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        mock_res.system_info = {"platform_category": "Linux"}
        mock_res.scanner_results = {}
        mock_res.errors = []
        mock_res.findings = []

        # Multiple background threads calling wait_for_audit repeatedly
        keep_waiting = True
        def continuous_waiter():
            while keep_waiting:
                server.wait_for_audit(timeout=0.01)

        waiters = [threading.Thread(target=continuous_waiter, daemon=True) for _ in range(5)]
        for w in waiters:
            w.start()

        try:
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_res):
                # Send audit request while multiple threads call wait_for_audit
                req = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    self.assertEqual(resp.status, HTTPStatus.OK)
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(data.get("status"), "COMPLETED")
        finally:
            keep_waiting = False
            for w in waiters:
                w.join(timeout=1.0)
            server.shutdown()

    def test_wait_for_audit_deterministic_timeout(self) -> None:
        """
        Verify that wait_for_audit(timeout) returns False on timeout without busy-waiting,
        and returns True after audit completes.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        engine_started = threading.Event()
        engine_release = threading.Event()

        def slow_engine(*args, **kwargs):
            engine_started.set()
            engine_release.wait(timeout=5.0)
            mock_res = MagicMock(spec=AuditResult)
            mock_res.status = "COMPLETED"
            mock_res.is_complete = True
            mock_res.timestamp = "2026-10-17T00:00:00Z"
            mock_res.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
            mock_res.system_info = {"platform_category": "Linux"}
            mock_res.scanner_results = {}
            mock_res.errors = []
            mock_res.findings = []
            return mock_res

        def send_request():
            req = urllib.request.Request(
                f"{base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    resp.read()
            except Exception:
                pass

        try:
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", side_effect=slow_engine):
                req_thread = threading.Thread(target=send_request, daemon=True)
                req_thread.start()
                self.assertTrue(engine_started.wait(timeout=2.0))

                # Test timeout: should return False within ~0.1s
                t0 = time.time()
                self.assertFalse(server.wait_for_audit(timeout=0.1))
                duration = time.time() - t0
                self.assertLess(duration, 0.5)

                # Release engine and wait with sufficient timeout
                engine_release.set()
                self.assertTrue(server.wait_for_audit(timeout=3.0))
                req_thread.join(timeout=2.0)
        finally:
            server.shutdown()

    # ------------------------------------------------------------------
    # Task 5B-7: Audit State Atomicity Review Tests
    # ------------------------------------------------------------------

    def test_audit_startup_atomicity_prevents_premature_wait_completion(self) -> None:
        """
        Verify that during audit startup, wait_for_audit() cannot interleave between
        audit_lock.acquire() and _audit_idle_event.clear() and falsely return True.
        """
        server = create_web_server(host="127.0.0.1", port=0)

        original_clear = server._audit_idle_event.clear
        clear_reached = threading.Event()
        observer_attempted = threading.Event()
        observer_result = []

        def hooked_clear():
            clear_reached.set()
            # Wait until observer thread has initiated wait_for_audit
            # (which will block on _audit_state_lock)
            observer_attempted.wait(timeout=2.0)
            original_clear()

        server._audit_idle_event.clear = hooked_clear

        def observer_worker():
            observer_attempted.set()
            res = server.wait_for_audit(timeout=0.05)
            observer_result.append(res)

        # Thread 1 starts acquire_audit
        t1 = threading.Thread(target=server.acquire_audit, daemon=True)
        t1.start()

        # Thread 1 enters hooked_clear (lock acquired, clear not yet done)
        self.assertTrue(clear_reached.wait(timeout=2.0))

        # Thread 2 (observer) calls wait_for_audit()
        t2 = threading.Thread(target=observer_worker, daemon=True)
        t2.start()

        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        # Because _audit_state_lock enforces atomicity, observer could NOT observe
        # a split state where audit was acquired but wait_for_audit returned True.
        # The observer properly observed an active audit and timed out (False).
        self.assertEqual(observer_result, [False])
        self.assertTrue(server.is_audit_active)

        server.release_audit()
        self.assertFalse(server.is_audit_active)
        self.assertTrue(server.wait_for_audit(timeout=0.1))

    def test_audit_cleanup_atomicity_prevents_stale_lock_observation(self) -> None:
        """
        Verify that during audit cleanup, an observer cannot see _audit_idle_event set
        while audit_lock remains held (preventing false 409 rejections or inconsistent state).
        """
        server = create_web_server(host="127.0.0.1", port=0)
        self.assertTrue(server.acquire_audit())
        self.assertTrue(server.is_audit_active)

        original_event_set = server._audit_idle_event.set
        set_reached = threading.Event()
        observer_attempted = threading.Event()
        observer_states = []

        def hooked_set():
            set_reached.set()
            # Observer tries to acquire audit and check state while in cleanup
            observer_attempted.wait(timeout=2.0)
            original_event_set()

        server._audit_idle_event.set = hooked_set

        def observer_worker():
            observer_attempted.set()
            # Observer checks is_audit_active and attempts acquire_audit
            active = server.is_audit_active
            acquired = server.acquire_audit()
            observer_states.append((active, acquired))
            if acquired:
                server.release_audit()

        # Thread 1 starts release_audit
        t1 = threading.Thread(target=server.release_audit, daemon=True)
        t1.start()

        # Thread 1 enters hooked_set (inside _audit_state_lock, before lock released)
        self.assertTrue(set_reached.wait(timeout=2.0))

        # Thread 2 attempts to observe state and acquire audit
        t2 = threading.Thread(target=observer_worker, daemon=True)
        t2.start()

        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        # Thread 2 was blocked by _audit_state_lock until release completed fully.
        # Once it ran, it observed active == False and acquired == True.
        # It never observed stale active==True or had acquire_audit falsely fail.
        self.assertEqual(observer_states, [(False, True)])
        self.assertFalse(server.is_audit_active)

    def test_atomic_acquire_and_release_methods_lifecycle(self) -> None:
        """
        Verify acquire_audit and release_audit enforce mutual exclusion atomically across threads.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        self.assertFalse(server.is_audit_active)
        self.assertTrue(server.wait_for_audit(timeout=0.01))

        # Multiple concurrent acquire_audit calls: exactly one must win
        results = []
        barrier = threading.Barrier(5)

        def worker():
            barrier.wait()
            results.append(server.acquire_audit())

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2.0)

        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 4)
        self.assertTrue(server.is_audit_active)
        self.assertFalse(server.wait_for_audit(timeout=0.01))

        server.release_audit()
        self.assertFalse(server.is_audit_active)
        self.assertTrue(server.wait_for_audit(timeout=0.01))

    def test_immediate_post_run_audit_after_wait_for_audit_succeeds_without_409(self) -> None:
        """
        Verify that an HTTP POST /api/run-audit sent immediately after wait_for_audit()
        returns True succeeds and never encounters a residual 409 BUSY from cleanup lag.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        mock_res = MagicMock(spec=AuditResult)
        mock_res.status = "COMPLETED"
        mock_res.is_complete = True
        mock_res.timestamp = "2026-10-17T00:00:00Z"
        mock_res.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        mock_res.system_info = {"platform_category": "Linux"}
        mock_res.scanner_results = {}
        mock_res.errors = []
        mock_res.findings = []

        try:
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_res):
                # Run first audit
                req1 = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(req1, timeout=3.0) as resp:
                    self.assertEqual(resp.status, HTTPStatus.OK)

                # Wait for audit (returns True immediately since audit finished)
                self.assertTrue(server.wait_for_audit(timeout=1.0))

                # Immediately run second audit: must succeed with 200 OK without 409
                req2 = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(req2, timeout=3.0) as resp:
                    self.assertEqual(resp.status, HTTPStatus.OK)
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(data.get("status"), "COMPLETED")
        finally:
            server.shutdown()

    # ------------------------------------------------------------------
    # Task 5B-8: Live Audit Controller Integration Readiness Review Tests
    # ------------------------------------------------------------------

    def test_audit_serialization_for_completed_partial_failed_and_exception(self) -> None:
        """
        Verify the backend serializes actual AuditResult findings, scanner statuses,
        coverage metadata, and sanitized system information correctly for COMPLETED,
        PARTIAL, FAILED, and engine-exception cases.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        try:
            # 1. Test PARTIAL status
            mock_partial = MagicMock(spec=AuditResult)
            mock_partial.status = "PARTIAL"
            mock_partial.is_complete = False
            mock_partial.timestamp = "2026-10-17T12:00:00Z"
            mock_partial.summary = {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1}
            mock_partial.system_info = {"platform_category": "Linux", "os_name": "Linux", "os_release": "6.6"}
            mock_partial.scanner_results = {
                "suid_sgid": MagicMock(to_dict=lambda: {
                    "scanner_name": "suid_sgid",
                    "status": "COMPLETED",
                    "findings_count": 1,
                    "target_paths": ["/usr/bin"],
                    "accessible_paths": ["/usr/bin"],
                    "skipped_paths": [],
                    "error": None,
                    "message": None,
                }),
                "sudo_audit": MagicMock(to_dict=lambda: {
                    "scanner_name": "sudo_audit",
                    "status": "PARTIAL",
                    "findings_count": 0,
                    "target_paths": ["/etc/sudoers"],
                    "accessible_paths": [],
                    "skipped_paths": ["/etc/sudoers"],
                    "error": "Permission denied",
                    "message": "Permission denied reading /etc/sudoers",
                }),
            }
            mock_partial.errors = ["Permission denied reading /etc/sudoers"]
            mock_partial.findings = [
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
                 patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_partial):
                req = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    self.assertEqual(resp.status, HTTPStatus.OK)
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(data["status"], "PARTIAL")
                    self.assertFalse(data["is_complete"])
                    self.assertFalse(data["is_demo"])
                    self.assertFalse(data["is_simulated"])
                    self.assertTrue(data["live_audit"])
                    self.assertEqual(len(data["findings"]), 1)
                    self.assertEqual(data["findings"][0]["finding_id"], "SUID-001")
                    self.assertIn("suid_sgid", data["scanner_results"])
                    self.assertIn("sudo_audit", data["scanner_results"])
                    self.assertEqual(data["scanner_results"]["sudo_audit"]["status"], "PARTIAL")
                    self.assertEqual(data["scanner_results"]["sudo_audit"]["skipped_paths"], ["/etc/sudoers"])

            # 2. Test FAILED status from engine
            mock_failed = MagicMock(spec=AuditResult)
            mock_failed.status = "FAILED"
            mock_failed.is_complete = False
            mock_failed.timestamp = "2026-10-17T12:00:00Z"
            mock_failed.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
            mock_failed.system_info = {"platform_category": "Linux"}
            mock_failed.scanner_results = {}
            mock_failed.errors = ["All scanners failed"]
            mock_failed.findings = []

            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_failed):
                req = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    self.assertEqual(resp.status, HTTPStatus.OK)
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(data["status"], "FAILED")
                    self.assertFalse(data["is_complete"])
                    self.assertFalse(data["is_demo"])
                    self.assertTrue(data["live_audit"])

            # 3. Test engine exception handling
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", side_effect=RuntimeError("Engine exploded")):
                req = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                try:
                    urllib.request.urlopen(req, timeout=3.0)
                    self.fail("Expected HTTPError 500")
                except urllib.error.HTTPError as err:
                    self.assertEqual(err.code, HTTPStatus.INTERNAL_SERVER_ERROR)
                    err_data = json.loads(err.read().decode("utf-8"))
                    self.assertEqual(err_data["status"], "FAILED")
                    self.assertFalse(err_data["is_complete"])
                    self.assertFalse(err_data["is_demo"])
                    self.assertTrue(err_data["live_audit"])
                    self.assertIn("RuntimeError", err_data["error"])

                self.assertTrue(server.wait_for_audit(timeout=2.0))

                # Confirm subsequent request can proceed after engine exception
                mock_recover = MagicMock(spec=AuditResult)
                mock_recover.status = "COMPLETED"
                mock_recover.is_complete = True
                mock_recover.timestamp = "2026-10-17T12:00:00Z"
                mock_recover.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
                mock_recover.system_info = {"platform_category": "Linux"}
                mock_recover.scanner_results = {}
                mock_recover.errors = []
                mock_recover.findings = []

                with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                     patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_recover):
                    req_recover = urllib.request.Request(
                        f"{base_url}/api/run-audit",
                        data=b"{}",
                        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                        method="POST",
                    )
                    with urllib.request.urlopen(req_recover, timeout=3.0) as resp:
                        self.assertEqual(resp.status, HTTPStatus.OK)
                        recover_data = json.loads(resp.read().decode("utf-8"))
                        self.assertEqual(recover_data["status"], "COMPLETED")
        finally:
            server.shutdown()

    def test_run_audit_rejects_paths_commands_and_unknown_scanners(self) -> None:
        """
        Verify that POST /api/run-audit rejects requests supplying custom paths, commands,
        or unknown scanner names with HTTP 400 Bad Request.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        try:
            # 1. Custom path injection
            for bad_payload in [
                {"path": "/custom/path"},
                {"target_path": "/etc/shadow"},
                {"command": "whoami"},
                {"exec": "cat /etc/passwd"},
                {"cwd": "/root"},
            ]:
                req = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=json.dumps(bad_payload).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                try:
                    urllib.request.urlopen(req, timeout=3.0)
                    self.fail(f"Expected HTTP 400 for payload: {bad_payload}")
                except urllib.error.HTTPError as err:
                    self.assertEqual(err.code, HTTPStatus.BAD_REQUEST)
                    err_data = json.loads(err.read().decode("utf-8"))
                    self.assertIn("Forbidden parameter", err_data["error"])

            # 2. Unknown scanner name
            bad_scanner_payload = {"enabled_scanners": ["suid_sgid", "arbitrary_custom_scanner"]}
            req = urllib.request.Request(
                f"{base_url}/api/run-audit",
                data=json.dumps(bad_scanner_payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=3.0)
                self.fail("Expected HTTP 400 for invalid scanner name")
            except urllib.error.HTTPError as err:
                self.assertEqual(err.code, HTTPStatus.BAD_REQUEST)
                err_data = json.loads(err.read().decode("utf-8"))
                self.assertIn("Invalid scanner name", err_data["error"])
        finally:
            server.shutdown()

    def test_demo_and_live_audit_responses_never_masquerade(self) -> None:
        """
        Confirm demo responses remain explicitly simulated and live responses never masquerade as demo results.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            # 1. Fetch Demo Audit
            with urllib.request.urlopen(f"{base_url}/api/demo-audit", timeout=3.0) as resp:
                demo_data = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(demo_data.get("is_demo"))
                self.assertTrue(demo_data.get("is_simulated"))
                self.assertIn("DEMO", demo_data.get("status", ""))
                self.assertIn("SIMULATED DEMO DATA", demo_data.get("demo_watermark", ""))

            # 2. Fetch Live Audit (mocked Linux execution)
            with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
                csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

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
                 patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_res):
                req = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    live_data = json.loads(resp.read().decode("utf-8"))
                    self.assertFalse(live_data.get("is_demo"))
                    self.assertFalse(live_data.get("is_simulated"))
                    self.assertTrue(live_data.get("live_audit"))
                    self.assertNotIn("DEMO", live_data.get("status", ""))
        finally:
            server.shutdown()

    # ------------------------------------------------------------------
    # Task 5B-9: Pre-Integration Security Gate Tests
    # ------------------------------------------------------------------

    def test_origin_validation_security_gate(self) -> None:
        """
        Verify Origin and Referer validation:
        - Origin: null -> 403 Forbidden
        - Origin: external domain -> 403 Forbidden
        - Origin: loopback mismatched port -> 403 Forbidden
        - Origin: loopback matching port -> 200 OK
        - Missing Origin/Referer -> 200 OK (CLI/direct clients)
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        mock_res = MagicMock(spec=AuditResult)
        mock_res.status = "COMPLETED"
        mock_res.is_complete = True
        mock_res.timestamp = "2026-10-17T00:00:00Z"
        mock_res.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        mock_res.system_info = {"platform_category": "Linux"}
        mock_res.scanner_results = {}
        mock_res.errors = []
        mock_res.findings = []

        try:
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_res):

                # 1. Origin: null (sandboxed iframe / data: URI)
                req_null = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token, "Origin": "null"},
                    method="POST",
                )
                try:
                    urllib.request.urlopen(req_null, timeout=3.0)
                    self.fail("Expected 403 Forbidden for Origin: null")
                except urllib.error.HTTPError as err:
                    self.assertEqual(err.code, HTTPStatus.FORBIDDEN)

                # 2. Origin: external domain
                req_ext = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token, "Origin": "http://evil.com"},
                    method="POST",
                )
                try:
                    urllib.request.urlopen(req_ext, timeout=3.0)
                    self.fail("Expected 403 Forbidden for external Origin")
                except urllib.error.HTTPError as err:
                    self.assertEqual(err.code, HTTPStatus.FORBIDDEN)

                # 3. Origin: loopback mismatched port
                req_bad_port = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token, "Origin": "http://127.0.0.1:54321"},
                    method="POST",
                )
                try:
                    urllib.request.urlopen(req_bad_port, timeout=3.0)
                    self.fail("Expected 403 Forbidden for mismatched loopback port")
                except urllib.error.HTTPError as err:
                    self.assertEqual(err.code, HTTPStatus.FORBIDDEN)

                # 4. Origin: matching loopback server port -> 200 OK
                req_valid = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token, "Origin": base_url},
                    method="POST",
                )
                with urllib.request.urlopen(req_valid, timeout=3.0) as resp:
                    self.assertEqual(resp.status, HTTPStatus.OK)

                self.assertTrue(server.wait_for_audit(timeout=2.0))

                # 5. Missing Origin and Referer (direct CLI/API client) -> 200 OK
                req_cli = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(req_cli, timeout=3.0) as resp:
                    self.assertEqual(resp.status, HTTPStatus.OK)
        finally:
            server.shutdown()

    def test_csrf_token_secrecy_and_no_cors_headers(self) -> None:
        """
        Verify that no permissive CORS headers are emitted, CSRF token is not leaked
        in other endpoints, and security headers are enforced.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            # 1. Fetch CSRF token
            with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
                token_data = json.loads(resp.read().decode("utf-8"))
                secret_token = token_data["csrf_token"]
                self.assertIsNone(resp.headers.get("Access-Control-Allow-Origin"))
                self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
                self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")

            # 2. Check /api/status does not leak CSRF token
            with urllib.request.urlopen(f"{base_url}/api/status", timeout=3.0) as resp:
                status_raw = resp.read().decode("utf-8")
                self.assertNotIn(secret_token, status_raw)
                self.assertIsNone(resp.headers.get("Access-Control-Allow-Origin"))

            # 3. Check /api/demo-audit does not leak CSRF token
            with urllib.request.urlopen(f"{base_url}/api/demo-audit", timeout=3.0) as resp:
                demo_raw = resp.read().decode("utf-8")
                self.assertNotIn(secret_token, demo_raw)
                self.assertIsNone(resp.headers.get("Access-Control-Allow-Origin"))
        finally:
            server.shutdown()

    def test_client_disconnect_during_audit_releases_state_atomically(self) -> None:
        """
        Verify that client disconnect during audit response writing triggers cleanup
        and leaves the server completely idle and ready for subsequent audits.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        mock_res = MagicMock(spec=AuditResult)
        mock_res.status = "COMPLETED"
        mock_res.is_complete = True
        mock_res.timestamp = "2026-10-17T00:00:00Z"
        mock_res.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        mock_res.system_info = {"platform_category": "Linux"}
        mock_res.scanner_results = {}
        mock_res.errors = []
        mock_res.findings = []

        try:
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_res), \
                 patch.object(LpeSentinelWebHandler, "_send_json_response", side_effect=BrokenPipeError("Client disconnected")):
                req = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                try:
                    urllib.request.urlopen(req, timeout=3.0)
                except Exception:
                    pass

            # Outside the BrokenPipeError mock: _send_json_response is now real again
            # Confirm server state is cleanly idle
            self.assertTrue(server.wait_for_audit(timeout=1.5))
            self.assertFalse(server.is_audit_active)
            self.assertFalse(server.audit_lock.locked())

            # Confirm subsequent mocked audit request can proceed successfully
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_res):
                req_next = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(req_next, timeout=3.0) as resp_next:
                    self.assertEqual(resp_next.status, HTTPStatus.OK)
                    data_next = json.loads(resp_next.read().decode("utf-8"))
                    self.assertEqual(data_next["status"], "COMPLETED")
        finally:
            server.shutdown()

    # ------------------------------------------------------------------
    # Task 5C-1: Connect Dashboard to Live Audit API Tests
    # ------------------------------------------------------------------

    def test_dashboard_html_contains_live_audit_integration(self) -> None:
        """
        Verify that render_dashboard_html() connects the Run Unified Audit button to
        runUnifiedAudit(), includes the live-banner, scanner-status-pills, and JavaScript workflow.
        """
        req = urllib.request.Request(f"{self.base_url}/")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, HTTPStatus.OK)
            html = resp.read().decode("utf-8")

            # Button connection
            self.assertIn('id="btn-run-audit"', html)
            self.assertIn('onclick="runUnifiedAudit()"', html)

            # Live banner markup
            self.assertIn('id="live-banner"', html)
            self.assertIn('id="live-banner-title"', html)
            self.assertIn('id="live-banner-desc"', html)
            self.assertIn('id="scanner-status-pills"', html)

            # JavaScript functions
            self.assertIn("async function runUnifiedAudit()", html)
            self.assertIn("fetch('/api/csrf-token')", html)
            self.assertIn("fetch('/api/run-audit'", html)
            self.assertIn("'X-CSRF-Token': csrfToken", html)
            self.assertIn("enabled_scanners", html)
            self.assertIn("showLiveBanner", html)
            self.assertIn("hideLiveBanner", html)
            self.assertIn("setSessionStatus", html)

    def test_frontend_api_workflow_end_to_end_mocked_success(self) -> None:
        """
        Verify the exact frontend HTTP workflow for successful live audit:
        1. Fetch CSRF token from GET /api/csrf-token
        2. Submit POST /api/run-audit with X-CSRF-Token and enabled_scanners
        3. Receive 200 OK with full AuditResult payload
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"

        # 1. Frontend fetches CSRF token
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        mock_res = MagicMock(spec=AuditResult)
        mock_res.status = "COMPLETED"
        mock_res.is_complete = True
        mock_res.timestamp = "2026-10-17T00:00:00Z"
        mock_res.summary = {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1}
        mock_res.system_info = {"platform_category": "Linux", "os_name": "Linux", "os_release": "6.6"}
        mock_res.scanner_results = {
            "suid_sgid": MagicMock(to_dict=lambda: {
                "scanner_name": "suid_sgid",
                "status": "COMPLETED",
                "findings_count": 1,
                "target_paths": ["/usr/bin"],
                "accessible_paths": ["/usr/bin"],
                "skipped_paths": [],
                "error": None,
                "message": None,
            }),
            "sensitive_permissions": MagicMock(to_dict=lambda: {
                "scanner_name": "sensitive_permissions",
                "status": "COMPLETED",
                "findings_count": 0,
                "target_paths": ["/etc/passwd"],
                "accessible_paths": ["/etc/passwd"],
                "skipped_paths": [],
                "error": None,
                "message": None,
            }),
            "sudo_audit": MagicMock(to_dict=lambda: {
                "scanner_name": "sudo_audit",
                "status": "COMPLETED",
                "findings_count": 0,
                "target_paths": ["/etc/sudoers"],
                "accessible_paths": ["/etc/sudoers"],
                "skipped_paths": [],
                "error": None,
                "message": None,
            }),
        }
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

        try:
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_res) as mock_engine:
                # 2. Frontend submits POST /api/run-audit
                req = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=json.dumps({
                        "enabled_scanners": ["suid_sgid", "sensitive_permissions", "sudo_audit"]
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    self.assertEqual(resp.status, HTTPStatus.OK)
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(data["status"], "COMPLETED")
                    self.assertTrue(data["is_complete"])
                    self.assertTrue(data["live_audit"])
                    self.assertFalse(data["is_demo"])
                    self.assertEqual(len(data["findings"]), 1)
                    self.assertIn("suid_sgid", data["scanner_results"])

                # Verify mock engine called with server-controlled defaults
                mock_engine.assert_called_once_with(
                    enabled_scanners=("suid_sgid", "sensitive_permissions", "sudo_audit"),
                    collect_sys_info=True,
                )
        finally:
            server.shutdown()

    def test_frontend_api_workflow_end_to_end_mocked_partial(self) -> None:
        """
        Verify frontend workflow when scan returns PARTIAL coverage.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        mock_res = MagicMock(spec=AuditResult)
        mock_res.status = "PARTIAL"
        mock_res.is_complete = False
        mock_res.timestamp = "2026-10-17T00:00:00Z"
        mock_res.summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        mock_res.system_info = {"platform_category": "Linux"}
        mock_res.scanner_results = {
            "sudo_audit": MagicMock(to_dict=lambda: {
                "scanner_name": "sudo_audit",
                "status": "PARTIAL",
                "findings_count": 0,
                "target_paths": ["/etc/sudoers"],
                "accessible_paths": [],
                "skipped_paths": ["/etc/sudoers"],
                "error": "Permission denied",
                "message": "Permission denied reading /etc/sudoers",
            })
        }
        mock_res.errors = ["Permission denied reading /etc/sudoers"]
        mock_res.findings = []

        try:
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True), \
                 patch("lpe_sentinel.web.server.run_unified_audit", return_value=mock_res):
                req = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=json.dumps({"enabled_scanners": ["sudo_audit"]}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    self.assertEqual(resp.status, HTTPStatus.OK)
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(data["status"], "PARTIAL")
                    self.assertFalse(data["is_complete"])
                    self.assertTrue(data["live_audit"])
        finally:
            server.shutdown()

    def test_frontend_api_workflow_end_to_end_409_busy(self) -> None:
        """
        Verify frontend workflow receives HTTP 409 Conflict with status BUSY when another audit is in progress.
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
            csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

        # Simulate audit lock held
        self.assertTrue(server.acquire_audit())
        try:
            with patch("lpe_sentinel.web.server.is_linux_platform", return_value=True):
                req = urllib.request.Request(
                    f"{base_url}/api/run-audit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                    method="POST",
                )
                try:
                    urllib.request.urlopen(req, timeout=3.0)
                    self.fail("Expected HTTP 409 Conflict")
                except urllib.error.HTTPError as err:
                    self.assertEqual(err.code, HTTPStatus.CONFLICT)
                    err_data = json.loads(err.read().decode("utf-8"))
                    self.assertEqual(err_data.get("status"), "BUSY")
                    self.assertIn("already in progress", err_data.get("error", ""))
        finally:
            server.release_audit()
            server.shutdown()

    def test_frontend_api_workflow_end_to_end_csrf_and_malformed_errors(self) -> None:
        """
        Verify frontend error handling for CSRF rejection (403) and malformed JSON (400).
        """
        server = create_web_server(host="127.0.0.1", port=0)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            # 1. CSRF rejection: missing header and body token
            req_no_csrf = urllib.request.Request(
                f"{base_url}/api/run-audit",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(req_no_csrf, timeout=3.0)
                self.fail("Expected 403 Forbidden")
            except urllib.error.HTTPError as err:
                self.assertEqual(err.code, HTTPStatus.FORBIDDEN)

            # 2. Malformed JSON payload
            with urllib.request.urlopen(f"{base_url}/api/csrf-token", timeout=3.0) as resp:
                csrf_token = json.loads(resp.read().decode("utf-8"))["csrf_token"]

            req_bad_json = urllib.request.Request(
                f"{base_url}/api/run-audit",
                data=b"NOT_VALID_JSON{{{",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token},
                method="POST",
            )
            try:
                urllib.request.urlopen(req_bad_json, timeout=3.0)
                self.fail("Expected 400 Bad Request")
            except urllib.error.HTTPError as err:
                self.assertEqual(err.code, HTTPStatus.BAD_REQUEST)
                err_data = json.loads(err.read().decode("utf-8"))
                self.assertIn("Malformed JSON", err_data.get("error", ""))
        finally:
            server.shutdown()

    def test_templates_stale_data_prevention_and_error_handling(self) -> None:
        """
        Verify that render_dashboard_html() incorporates all required frontend safety mechanisms:
        - Prevents re-entrant submissions via isAuditRunning flag
        - Immediately clears prior banners, findings, and counters to prevent stale data display
        - Explicitly distinguishes and handles FAILED audit status from PARTIAL/COMPLETED
        - Handles 409 BUSY, 403 CSRF, 400 UNSUPPORTED, 500 / network failures, and malformed JSON
        - Guarantees button restoration in finally block
        """
        html = render_dashboard_html()

        # Re-entrancy protection
        self.assertIn("let isAuditRunning = false;", html)
        self.assertIn("if (isAuditRunning || (btn && btn.disabled)) return;", html)
        self.assertIn("isAuditRunning = true;", html)
        self.assertIn("isAuditRunning = false;", html)

        # Stale data prevention on audit start
        self.assertIn("hideLiveBanner();", html)
        self.assertIn("currentFindings = [];", html)
        self.assertIn("renderFindingsTable();", html)
        self.assertIn("updateSummaryCounts({ total_findings: 0", html)

        # Explicit FAILED status handling
        self.assertIn("if (data.status === 'FAILED')", html)
        self.assertIn("'AUDIT FAILED'", html)

        # Specific status handlers
        self.assertIn("res.status === 409", html)
        self.assertIn("'AUDIT BUSY'", html)
        self.assertIn("res.status === 403", html)
        self.assertIn("'CSRF / FORBIDDEN'", html)
        self.assertIn("res.status === 400 && data.status === 'UNSUPPORTED_PLATFORM'", html)
        self.assertIn("'UNSUPPORTED PLATFORM'", html)
        self.assertIn("catch (jsonErr)", html)
        self.assertIn("'MALFORMED RESPONSE'", html)
        self.assertIn("catch (networkErr)", html)
        self.assertIn("'NETWORK ERROR'", html)

        # Safe button restoration
        self.assertIn("btn.disabled = false;", html)
        self.assertIn("btn.removeAttribute('aria-busy');", html)
        self.assertIn("btn.innerHTML = originalBtnHtml;", html)


if __name__ == "__main__":
    unittest.main()
