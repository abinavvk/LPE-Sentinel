"""
Tests for LPE-Sentinel Vercel Serverless Integration (Stage 1).

Verifies:
1. vercel.json configuration validity and routing.
2. api/index.py status payload identifying the environment as hosted serverless.
3. Dashboard rendering through the serverless entry point.
4. Security headers on all serverless responses.
5. Rejection of unhandled routes and mutation methods.
"""

import io
import json
import os
import sys
import unittest
from http import HTTPStatus
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure src and api are importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
API_DIR = PROJECT_ROOT / "api"

for d in (SRC_DIR, API_DIR, PROJECT_ROOT):
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))

from api.index import get_hosted_status_payload, handler


class DummyWfile(io.BytesIO):
    """Mock wfile for BaseHTTPRequestHandler."""
    pass


class TestVercelIntegrationStage1(unittest.TestCase):
    """Test suite for Vercel serverless entry point and configuration."""

    def test_vercel_json_configuration(self) -> None:
        """Verify vercel.json exists, is valid JSON, and routes traffic to api/index.py."""
        vercel_config_path = PROJECT_ROOT / "vercel.json"
        self.assertTrue(vercel_config_path.exists(), "vercel.json must exist")
        with open(vercel_config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        self.assertEqual(config.get("version"), 2)
        rewrites = config.get("rewrites", [])
        self.assertTrue(any(r.get("destination") == "/api/index.py" for r in rewrites))

    def test_hosted_status_payload_structure_and_safety(self) -> None:
        """Verify status payload identifies as hosted and omits secrets or raw host paths."""
        with patch.dict(os.environ, {"VERCEL_REGION": "sfo1", "SECRET_KEY": "supersecret"}):
            status = get_hosted_status_payload()

        self.assertEqual(status["status"], "ACTIVE")
        self.assertEqual(status["service"], "LPE-Sentinel Cloud Portal")
        self.assertTrue(status["deployment"]["is_hosted"])
        self.assertEqual(status["deployment"]["platform"], "vercel")
        self.assertEqual(status["deployment"]["region"], "sfo1")
        self.assertFalse(status["capabilities"]["live_audit"])
        self.assertIn("notice", status)

        # Confirm no internal environment secrets or user paths are leaked
        serialized = json.dumps(status)
        self.assertNotIn("supersecret", serialized)
        self.assertNotIn("Users", serialized)

    def _invoke_handler(self, method: str, path: str) -> tuple[int, dict, bytes]:
        """Helper to invoke the Vercel BaseHTTPRequestHandler in memory."""
        mock_request = MagicMock()
        mock_client_address = ("127.0.0.1", 12345)
        mock_server = MagicMock()

        inst = handler.__new__(handler)
        inst.request = mock_request
        inst.client_address = mock_client_address
        inst.server = mock_server
        inst.command = method
        inst.path = path
        inst.request_version = "HTTP/1.1"
        inst.headers = {}
        inst.rfile = io.BytesIO()
        inst.wfile = io.BytesIO()
        inst.close_connection = False

        headers_sent = {}
        response_code = [200]

        def fake_send_response(code, message=None):
            response_code[0] = int(code)

        def fake_send_header(k, v):
            headers_sent[k.lower()] = v

        def fake_end_headers():
            pass

        inst.send_response = fake_send_response
        inst.send_header = fake_send_header
        inst.end_headers = fake_end_headers

        if method == "GET":
            inst.do_GET()
        elif method == "HEAD":
            inst.do_HEAD()
        elif method == "POST":
            inst.do_POST()

        body = inst.wfile.getvalue()
        return response_code[0], headers_sent, body

    def test_serverless_api_status_endpoint(self) -> None:
        """Verify GET /api/status returns 200, hosted metadata, and security headers."""
        code, headers, body = self._invoke_handler("GET", "/api/status")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("x-frame-options"), "DENY")
        self.assertIn("default-src 'self'", headers.get("content-security-policy", ""))

        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "ACTIVE")
        self.assertTrue(data["deployment"]["is_hosted"])

    def test_serverless_dashboard_endpoint(self) -> None:
        """Verify GET / renders the full HTML dashboard with security headers."""
        code, headers, body = self._invoke_handler("GET", "/")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn("<!DOCTYPE html>", body.decode("utf-8"))
        self.assertIn("LPE-Sentinel", body.decode("utf-8"))

    def test_serverless_unhandled_route_returns_404(self) -> None:
        """Verify unknown path returns 404 JSON."""
        code, headers, body = self._invoke_handler("GET", "/api/nonexistent")
        self.assertEqual(code, HTTPStatus.NOT_FOUND)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "NOT_FOUND")

    def test_serverless_demo_audit_endpoint(self) -> None:
        """Verify GET /api/demo-audit returns 200, simulated demo findings, watermarks, and security headers."""
        code, headers, body = self._invoke_handler("GET", "/api/demo-audit")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("x-frame-options"), "DENY")

        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data.get("is_demo"))
        self.assertTrue(data.get("is_simulated"))
        self.assertIn("SIMULATED DEMO DATA", data.get("demo_watermark", ""))
        self.assertIn("disclaimer", data)

        findings = data.get("findings", [])
        self.assertGreater(len(findings), 0)
        # Every finding title must be explicitly marked as simulated
        for f in findings:
            self.assertTrue(f.get("is_simulated"))
            self.assertIn("[SIMULATED DEMO]", f.get("title", ""))
            # Ensure no local machine paths or secrets are leaked
            self.assertNotIn("Users", f.get("affected_resource", ""))

    def test_serverless_demo_audit_unsupported_methods(self) -> None:
        """Verify non-GET requests to /api/demo-audit are rejected with 405 Method Not Allowed."""
        code, headers, body = self._invoke_handler("POST", "/api/demo-audit")
        self.assertEqual(code, HTTPStatus.METHOD_NOT_ALLOWED)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("status"), "METHOD_NOT_ALLOWED")

    def test_serverless_demo_audit_head_request(self) -> None:
        """Verify HEAD /api/demo-audit returns headers only without body."""
        code, headers, body = self._invoke_handler("HEAD", "/api/demo-audit")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
    def test_vercel_forwarded_headers_resolution(self) -> None:
        """Verify routing honors x-forwarded-uri and x-matched-path injected by Vercel edge proxy."""
        # Simulated scenario: Vercel internally set self.path="/api/index.py", but client requested "/api/status"
        inst = handler.__new__(handler)
        inst.command = "GET"
        inst.path = "/api/index.py"
        inst.headers = {"x-forwarded-uri": "/api/status"}
        inst.rfile = io.BytesIO()
        inst.wfile = io.BytesIO()
        inst.close_connection = False

        response_code = [200]
        headers_sent = {}
        inst.send_response = lambda code, msg=None: response_code.__setitem__(0, int(code))
        inst.send_header = lambda k, v: headers_sent.__setitem__(k.lower(), v)
        inst.end_headers = lambda: None

        inst.do_GET()
        self.assertEqual(response_code[0], HTTPStatus.OK)
        data = json.loads(inst.wfile.getvalue().decode("utf-8"))
        self.assertEqual(data["status"], "ACTIVE")
        self.assertEqual(data["service"], "LPE-Sentinel Cloud Portal")


if __name__ == "__main__":
    unittest.main()
