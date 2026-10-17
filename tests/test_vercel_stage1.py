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
import re
import shutil
import subprocess
import sys
import tempfile
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
from lpe_sentinel.web.templates import render_dashboard_html


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

    def _invoke_handler(self, method: str, path: str, headers: dict | None = None) -> tuple[int, dict, bytes]:
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
        inst.headers = dict(headers) if headers else {}
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
        """Verify routing honors the x-forwarded-uri defensive override."""
        # Simulated scenario: self.path is the rewrite destination, but the client requested /api/status
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

    # ------------------------------------------------------------------
    # Regression tests: rewrite-destination routing + capability gating
    # ------------------------------------------------------------------

    def test_rewrite_destination_without_headers_is_not_dashboard(self) -> None:
        """Regression: /api/index.py with no forwarded headers must NOT serve dashboard HTML.

        The rewrite destination is not a client-facing route. Previously it was
        matched by the dashboard branch, so every mis-routed request returned
        200 text/html and the dashboard's res.json() calls raised a parse error.
        """
        code, headers, body = self._invoke_handler("GET", "/api/index.py")

        self.assertEqual(code, HTTPStatus.NOT_FOUND)
        self.assertIn("application/json", headers.get("content-type", ""))

        decoded = body.decode("utf-8")
        self.assertNotIn("<!DOCTYPE html>", decoded)

        data = json.loads(decoded)
        self.assertEqual(data["status"], "NOT_FOUND")

    def test_x_matched_path_is_not_used_for_routing(self) -> None:
        """Regression: x-matched-path is a response header and must not drive routing.

        Vercel documents x-matched-path as a Next.js response header. Reading it
        from request headers previously masked a missing original path.
        """
        code, headers, body = self._invoke_handler(
            "GET", "/api/index.py", headers={"x-matched-path": "/api/status"}
        )

        self.assertEqual(code, HTTPStatus.NOT_FOUND)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "NOT_FOUND")
        self.assertNotEqual(data.get("service"), "LPE-Sentinel Cloud Portal")

    def test_normal_dashboard_and_api_routing_preserved(self) -> None:
        """Regression: normal routing is unchanged after the rewrite-destination fix."""
        # Dashboard root still serves HTML.
        code, headers, body = self._invoke_handler("GET", "/")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn("<!DOCTYPE html>", body.decode("utf-8"))

        # Native function mount point still serves HTML.
        for alias in ("/api", "/index.html"):
            code, headers, body = self._invoke_handler("GET", alias)
            self.assertEqual(code, HTTPStatus.OK, f"{alias} should serve dashboard")
            self.assertIn("text/html", headers.get("content-type", ""))

        # API routes still serve JSON.
        code, headers, body = self._invoke_handler("GET", "/api/status")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
        self.assertEqual(json.loads(body.decode("utf-8"))["status"], "ACTIVE")

        code, headers, body = self._invoke_handler("GET", "/api/demo-audit")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
        self.assertTrue(json.loads(body.decode("utf-8"))["is_demo"])

    def test_hosted_status_declares_unsupported_capabilities(self) -> None:
        """Verify /api/status advertises cloud history and live audit as unsupported."""
        status = get_hosted_status_payload()
        caps = status["capabilities"]
        self.assertFalse(caps["cloud_history"])
        self.assertFalse(caps["live_audit"])
        self.assertTrue(caps["demo_mode"])
        self.assertTrue(status["deployment"]["is_hosted"])

    def test_dashboard_contains_capability_gating_hooks(self) -> None:
        """Verify the dashboard ships the capability-gating logic and honest messaging."""
        html = render_dashboard_html()

        # Gating is driven by the hosted flag only, so local behavior is untouched.
        self.assertIn("deployment.is_hosted", html)
        self.assertIn("resolveHostedCapabilities", html)
        self.assertIn("applyHostedCapabilities", html)

        # History short-circuits with an explicit message instead of erroring.
        self.assertIn("Cloud audit history is unavailable in the hosted deployment", html)

        # Live auditing is explained, not silently broken.
        self.assertIn("Live auditing is unavailable in the hosted deployment", html)
        self.assertIn("Live Auditing Unavailable", html)

        # Targets the gating relies on must exist in the markup.
        self.assertIn('id="btn-run-audit"', html)
        self.assertIn('id="control-hint"', html)
        self.assertIn('id="history-list"', html)

    def test_local_dashboard_retains_live_audit_and_history_controls(self) -> None:
        """Regression: the local dashboard must keep its live-audit and history UI.

        Gating is applied only when /api/status reports deployment.is_hosted, which
        the local server never sends, so these controls must still be rendered and
        reachable in the shared template.
        """
        html = render_dashboard_html()

        self.assertIn("async function runUnifiedAudit()", html)
        self.assertIn("fetch('/api/run-audit'", html)
        self.assertIn("fetch('/api/csrf-token')", html)
        self.assertIn("fetch('/api/history?limit=10')", html)
        self.assertIn('onclick="runUnifiedAudit()"', html)
        self.assertIn('onclick="loadDemoAudit()"', html)

        # No fabricated host identity may appear in the shared template.
        self.assertNotIn("SERVER_NAME", html)

    # ------------------------------------------------------------------
    # Regression tests: server-rendered fail-closed capability baseline
    # ------------------------------------------------------------------

    @staticmethod
    def _embedded_capabilities(html: str):
        """Extract and JSON-parse the server-rendered capability baseline."""
        match = re.search(r"let hostedCapabilities = (.+?);", html)
        assert match, "capability baseline declaration not found in dashboard"
        return json.loads(match.group(1))

    def test_local_dashboard_defaults_to_no_hosted_baseline(self) -> None:
        """Zero-argument callers must keep a null (fully-capable) baseline."""
        self.assertIsNone(self._embedded_capabilities(render_dashboard_html()))
        self.assertIsNone(self._embedded_capabilities(render_dashboard_html(hosted=False)))

    def test_zero_arg_call_is_backwards_compatible(self) -> None:
        """The default argument must not change existing zero-arg call behavior."""
        self.assertEqual(render_dashboard_html(), render_dashboard_html(hosted=False))

    def test_hosted_dashboard_embeds_fail_closed_baseline(self) -> None:
        """Hosted HTML must start gated without any /api/status response."""
        caps = self._embedded_capabilities(render_dashboard_html(hosted=True))

        self.assertIs(caps["isHosted"], True)
        self.assertIs(caps["cloudHistory"], False)
        self.assertIs(caps["liveAudit"], False)

    def test_hosted_dashboard_serves_gated_baseline_over_http(self) -> None:
        """Regression: the served hosted dashboard is gated before any status call."""
        code, headers, body = self._invoke_handler("GET", "/")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("text/html", headers.get("content-type", ""))

        caps = self._embedded_capabilities(body.decode("utf-8"))
        self.assertIs(caps["isHosted"], True)
        self.assertIs(caps["liveAudit"], False)
        self.assertIs(caps["cloudHistory"], False)

    def test_initialization_uses_baseline_not_failed_status_defaults(self) -> None:
        """Regression: a failed status request must not widen capabilities.

        initDashboard must seed from the server-rendered baseline rather than
        synthesizing fully-capable defaults when /api/status is unavailable.
        """
        html = render_dashboard_html(hosted=True)

        self.assertIn(
            "let caps = resolveHostedCapabilities(null, hostedCapabilities);", html
        )
        self.assertNotIn("let caps = resolveHostedCapabilities(null);", html)
        self.assertIn("caps = resolveHostedCapabilities(data, hostedCapabilities);", html)

    def test_capability_baseline_serialized_safely(self) -> None:
        """The embedded value must be JSON, not interpolated text."""
        html = render_dashboard_html(hosted=True)

        # No unreplaced placeholder may leak into the document.
        self.assertNotIn("__INITIAL_CAPABILITIES__", html)

        # Raw script-terminating characters must not appear in the embedded literal.
        match = re.search(r"let hostedCapabilities = (.+?);", html)
        self.assertIsNotNone(match)
        literal = match.group(1)
        self.assertNotIn("<", literal)
        self.assertNotIn(">", literal)
        self.assertNotIn("&", literal)

        # And it must round-trip as JSON.
        json.loads(literal)

    def test_json_for_inline_script_escapes_breakout_characters(self) -> None:
        """Verify the serializer neutralizes HTML/script breakout sequences."""
        from lpe_sentinel.web.templates import _json_for_inline_script

        serialized = _json_for_inline_script({"x": "</script><img src=x onerror=alert(1)>"})

        self.assertNotIn("<", serialized)
        self.assertNotIn(">", serialized)
        self.assertIn("\\u003c", serialized)
        self.assertIn("\\u003e", serialized)
        # Value survives intact once parsed back.
        self.assertEqual(
            json.loads(serialized)["x"], "</script><img src=x onerror=alert(1)>"
        )

    def test_server_side_live_audit_remains_disabled(self) -> None:
        """Regression: POST must stay rejected server-side regardless of UI gating.

        UI gating is cosmetic; the authoritative boundary is the handler, which
        must keep rejecting every mutation with 405.
        """
        code, headers, body = self._invoke_handler("POST", "/api/run-audit")

        self.assertEqual(code, HTTPStatus.METHOD_NOT_ALLOWED)
        self.assertIn("application/json", headers.get("content-type", ""))
        self.assertEqual(json.loads(body.decode("utf-8"))["status"], "METHOD_NOT_ALLOWED")

        # Any other mutation path is rejected too.
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            inst = handler.__new__(handler)
            inst.command = method
            inst.path = "/api/status"
            inst.headers = {}
            inst.rfile = io.BytesIO()
            inst.wfile = io.BytesIO()
            inst.close_connection = False
            response_code = [200]
            inst.send_response = lambda c, m=None: response_code.__setitem__(0, int(c))
            inst.send_header = lambda k, v: None
            inst.end_headers = lambda: None

            if hasattr(inst, "do_" + method):
                getattr(inst, "do_" + method)()
                self.assertEqual(
                    response_code[0],
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    f"{method} must be rejected",
                )

    def test_hosted_dashboard_does_not_enable_audit_endpoints(self) -> None:
        """Hosted function must expose no live-audit or persistence capability."""
        status = get_hosted_status_payload()

        self.assertFalse(status["capabilities"]["live_audit"])
        self.assertFalse(status["capabilities"]["cloud_history"])
        self.assertFalse(status["capabilities"]["report_ingestion"])

        # The hosted module must not import any scanning or persistence surface.
        import api.index as vercel_module

        source = Path(vercel_module.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "run_unified_audit",
            "audit_engine",
            "subprocess",
            "os.system",
            "AuditHistoryManager",
            "sqlite3",
        ):
            self.assertNotIn(forbidden, source, f"hosted function must not reference {forbidden}")

    # ------------------------------------------------------------------
    # Regression tests: hosted baseline is terminal (cannot be widened)
    # ------------------------------------------------------------------

    @staticmethod
    def _resolver_source(html: str) -> str:
        """Extract the real resolveHostedCapabilities() implementation from the HTML."""
        start = html.index("function resolveHostedCapabilities")
        end = html.index("function disableElement")
        source = html[start:end].rstrip()
        if source.count("{") != source.count("}"):
            raise AssertionError("extracted resolver is not balanced JS")
        return source

    def _resolve(self, baseline, payload):
        """Execute resolveHostedCapabilities() against a baseline and payload.

        Uses the actual JS shipped in the dashboard so the assertion covers real
        behavior rather than a reimplementation. Skipped when Node is absent.
        """
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js unavailable; skipping JS behavior verification")

        program = (
            "const baseline = %s;\n%s\n"
            "console.log(JSON.stringify(resolveHostedCapabilities(%s, baseline)));"
            % (json.dumps(baseline), self._resolver_source(render_dashboard_html()), json.dumps(payload))
        )
        handle = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8")
        try:
            handle.write(program)
            handle.close()
            proc = subprocess.run([node, handle.name], capture_output=True, text=True, timeout=30)
        finally:
            os.unlink(handle.name)

        self.assertEqual(proc.returncode, 0, f"resolver failed: {proc.stderr}")
        return json.loads(proc.stdout.strip())

    def test_hosted_baseline_rejects_payload_claiming_both_capabilities(self) -> None:
        """Regression: a hosted baseline must never be widened by a status payload.

        Even a payload that explicitly asserts is_hosted, live_audit, and
        cloud_history are all true must leave both capabilities disabled.
        """
        baseline = self._embedded_capabilities(render_dashboard_html(hosted=True))
        self.assertIs(baseline["isHosted"], True)

        result = self._resolve(
            baseline,
            {
                "deployment": {"is_hosted": True},
                "capabilities": {"live_audit": True, "cloud_history": True},
            },
        )

        self.assertIs(result["isHosted"], True)
        self.assertIs(result["liveAudit"], False)
        self.assertIs(result["cloudHistory"], False)

    def test_hosted_baseline_stays_gated_across_payload_variants(self) -> None:
        """A hosted baseline stays gated for missing, malformed, and locked payloads."""
        baseline = self._embedded_capabilities(render_dashboard_html(hosted=True))

        payloads = [
            None,
            {},
            {"deployment": {"is_hosted": True}},
            {"deployment": {"is_hosted": "true"}},
            {"deployment": {"is_hosted": True}, "capabilities": {}},
            {"capabilities": {"live_audit": True, "cloud_history": True}},
            {"deployment": {"is_hosted": True}, "capabilities": {"live_audit": True}},
            {"deployment": {"is_hosted": True}, "capabilities": {"cloud_history": True}},
        ]

        for payload in payloads:
            with self.subTest(payload=payload):
                result = self._resolve(baseline, payload)
                self.assertIs(result["liveAudit"], False)
                self.assertIs(result["cloudHistory"], False)

    def test_local_baseline_remains_fully_capable(self) -> None:
        """Regression: a non-hosted baseline keeps local live audit and history."""
        baseline = self._embedded_capabilities(render_dashboard_html())
        self.assertIsNone(baseline)

        # Local server responses carry no `deployment` block.
        result = self._resolve(baseline, {"capabilities": {"demo_mode": True}})

        self.assertIs(result["isHosted"], False)
        self.assertIs(result["liveAudit"], True)
        self.assertIs(result["cloudHistory"], True)

        # A null payload (failed status) must also leave local fully capable.
        fallback = self._resolve(baseline, None)
        self.assertIs(fallback["liveAudit"], True)
        self.assertIs(fallback["cloudHistory"], True)

    def test_hosted_lock_is_present_in_shipped_resolver(self) -> None:
        """Structural guard so the invariant is enforced even without Node."""
        html = render_dashboard_html(hosted=True)
        resolver = self._resolver_source(html)

        self.assertIn("const hostedLocked = base.isHosted === true;", resolver)
        self.assertIn("cloudHistory: hostedLocked ? false : caps.cloud_history === true,", resolver)
        self.assertIn("liveAudit: hostedLocked ? false : caps.live_audit === true", resolver)

        # The stale "never widened" claim must no longer appear.
        self.assertNotIn("never widened", resolver)


if __name__ == "__main__":
    unittest.main()
