"""
Tests for LPE-Sentinel Vercel Serverless Integration (native function routing).

Routing model under test
------------------------
Vercel exposes the resolved rewrite destination to a function as its request
path. A single catch-all destination therefore cannot distinguish routes, so
this deployment uses Vercel's documented file-based function mapping instead:

    api/index.py      -> /api              (dashboard)
    api/status.py     -> /api/status       (status JSON)
    api/demo-audit.py -> /api/demo-audit   (simulated demo JSON)
    api/history.py    -> /api/history      (intentional JSON 404)

Verifies:
1. vercel.json routing declares no catch-all.
2. Each native function serves exactly its own endpoint.
3. The dashboard arrives with fail-closed hosted capabilities baked in.
4. Security headers are present on every hosted response.
5. Every mutation verb is rejected with 405.
6. No handler depends on recovering the original URL after a rewrite.
7. Hosted code exposes no scanning, shell, or persistence surface.
"""

import importlib.util
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

from lpe_sentinel.web.hosted import get_hosted_status_payload
from lpe_sentinel.web.templates import render_dashboard_html

# Native route -> api function file, per Vercel's documented file-based mapping.
API_FUNCTIONS = {
    "/api": "index.py",
    "/api/status": "status.py",
    "/api/demo-audit": "demo-audit.py",
    "/api/history": "history.py",
}


def _load_api_module(filename: str):
    """Import an api/*.py entry point by path (api/ is not a package)."""
    module_name = "api_entry_" + re.sub(r"\W", "_", filename)
    spec = importlib.util.spec_from_file_location(module_name, API_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class DummyWfile(io.BytesIO):
    """Mock wfile for BaseHTTPRequestHandler."""
    pass


class TestVercelNativeRouting(unittest.TestCase):
    """Routing, response shape, and hosted safety properties."""

    @classmethod
    def setUpClass(cls) -> None:
        # Keyed by entry-point filename, which is how tests address the modules.
        cls.modules = {name: _load_api_module(name) for name in API_FUNCTIONS.values()}

    # -- helpers --------------------------------------------------------

    def _invoke(self, filename: str, method: str, path: str, headers: dict | None = None):
        """Invoke a hosted handler in memory and capture its response."""
        module = self.modules[filename]
        inst = module.handler.__new__(module.handler)
        inst.command = method
        inst.path = path
        inst.headers = dict(headers) if headers else {}
        inst.rfile = io.BytesIO()
        inst.wfile = io.BytesIO()
        inst.close_connection = False

        response_code = [200]
        headers_sent = {}

        def fake_send_response(code, message=None):
            response_code[0] = int(code)

        def fake_send_header(key, value):
            headers_sent[key.lower()] = value

        def fake_end_headers():
            pass

        inst.send_response = fake_send_response
        inst.send_header = fake_send_header
        inst.end_headers = fake_end_headers

        getattr(inst, "do_" + method)()
        return response_code[0], headers_sent, inst.wfile.getvalue()

    @staticmethod
    def _assert_security_headers(testcase: unittest.TestCase, headers: dict) -> None:
        testcase.assertEqual(headers.get("x-content-type-options"), "nosniff")
        testcase.assertEqual(headers.get("x-frame-options"), "DENY")
        testcase.assertIn("default-src 'self'", headers.get("content-security-policy", ""))
        testcase.assertIn("no-store", headers.get("cache-control", ""))

    # -- configuration --------------------------------------------------

    def test_vercel_json_has_no_catch_all_rewrite(self) -> None:
        """The catch-all rewrite is the root cause of the hosted routing bug."""
        config = json.loads((PROJECT_ROOT / "vercel.json").read_text(encoding="utf-8"))

        self.assertEqual(config.get("version"), 2)
        rewrites = config.get("rewrites", [])
        self.assertTrue(rewrites, "expected rewrites for / and /index.html")

        sources = [r.get("source") for r in rewrites]
        destinations = [r.get("destination") for r in rewrites]

        # No catch-all: it would funnel every request to one indistinguishable path.
        self.assertNotIn("/(.*)", sources)
        for dest in destinations:
            self.assertNotIn("index.py", str(dest), "destinations must use native route paths")

        # Only the dashboard aliases are rewritten, and only to the dashboard route.
        self.assertEqual(sorted(sources), sorted(["/", "/index.html"]))
        self.assertEqual(destinations, ["/api", "/api"])

    def test_every_native_function_file_exists(self) -> None:
        """Each documented route has its own entry point."""
        for route, filename in API_FUNCTIONS.items():
            with self.subTest(route=route):
                path = API_DIR / filename
                self.assertTrue(path.exists(), f"missing entry point for {route}")
                self.assertIn("class handler", path.read_text(encoding="utf-8"))

    # -- dashboard ------------------------------------------------------

    def test_dashboard_route_serves_hosted_html(self) -> None:
        for path in ("/api", "/", "/index.html"):
            with self.subTest(path=path):
                code, headers, body = self._invoke("index.py", "GET", path)
                self.assertEqual(code, HTTPStatus.OK)
                self.assertIn("text/html", headers.get("content-type", ""))
                decoded = body.decode("utf-8")
                self.assertIn("<!DOCTYPE html>", decoded)
                self.assertIn("LPE-Sentinel", decoded)
                self._assert_security_headers(self, headers)

    def test_dashboard_route_rejects_other_paths(self) -> None:
        """The dashboard function must not answer other endpoints."""
        for path in ("/api/status", "/api/demo-audit", "/api/index.py", "/api/../etc"):
            with self.subTest(path=path):
                code, headers, body = self._invoke("index.py", "GET", path)
                self.assertEqual(code, HTTPStatus.NOT_FOUND)
                self.assertIn("application/json", headers.get("content-type", ""))
                self.assertEqual(json.loads(body.decode("utf-8"))["status"], "NOT_FOUND")

    def test_rewrite_destination_is_not_dashboard(self) -> None:
        """Regression: /api/index.py must never serve the dashboard.

        This path is what a catch-all rewrite produced, and serving HTML for it
        silently broke every JSON endpoint on the hosted deployment.
        """
        code, headers, body = self._invoke("index.py", "GET", "/api/index.py")
        self.assertEqual(code, HTTPStatus.NOT_FOUND)
        self.assertNotIn("<!DOCTYPE html>", body.decode("utf-8"))

    # -- status ---------------------------------------------------------

    def test_status_route_serves_cloud_portal_json(self) -> None:
        code, headers, body = self._invoke("status.py", "GET", "/api/status")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
        self._assert_security_headers(self, headers)

        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "ACTIVE")
        self.assertEqual(data["service"], "LPE-Sentinel Cloud Portal")
        self.assertTrue(data["deployment"]["is_hosted"])
        self.assertIn("notice", data)

    def test_status_route_does_not_depend_on_request_path(self) -> None:
        """The function serves its own route regardless of the observed path.

        Proves routing is performed by native function selection, not by
        inspecting a path that a rewrite may have rewritten.
        """
        for path in ("/api/status", "/api", "/", "/api/demo-audit"):
            with self.subTest(path=path):
                code, _, body = self._invoke("status.py", "GET", path)
                self.assertEqual(code, HTTPStatus.OK)
                self.assertEqual(
                    json.loads(body.decode("utf-8"))["service"], "LPE-Sentinel Cloud Portal"
                )

    def test_status_payload_omits_secrets_and_paths(self) -> None:
        with patch.dict(os.environ, {"VERCEL_REGION": "sfo1", "SECRET_KEY": "supersecret"}):
            status = get_hosted_status_payload()
        serialized = json.dumps(status)
        self.assertNotIn("supersecret", serialized)
        self.assertNotIn("Users", serialized)
        self.assertEqual(status["deployment"]["region"], "sfo1")

    def test_status_capabilities_declare_unsupported_features(self) -> None:
        caps = get_hosted_status_payload()["capabilities"]
        self.assertTrue(caps["demo_mode"])
        self.assertFalse(caps["live_audit"])
        self.assertFalse(caps["cloud_history"])
        self.assertFalse(caps["report_ingestion"])

    # -- demo audit -----------------------------------------------------

    def test_demo_audit_route_serves_watermarked_simulated_findings(self) -> None:
        code, headers, body = self._invoke("demo-audit.py", "GET", "/api/demo-audit")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
        self._assert_security_headers(self, headers)

        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data["is_demo"])
        self.assertTrue(data["is_simulated"])
        self.assertIn("SIMULATED DEMO DATA", data["demo_watermark"])
        self.assertIn("disclaimer", data)

        findings = data["findings"]
        self.assertGreater(len(findings), 0)
        for finding in findings:
            self.assertTrue(finding.get("is_simulated"))
            self.assertIn("[SIMULATED DEMO]", finding.get("title", ""))
            self.assertNotIn("Users", finding.get("affected_resource", ""))

    def test_demo_audit_head_returns_headers_without_body(self) -> None:
        code, headers, body = self._invoke("demo-audit.py", "HEAD", "/api/demo-audit")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
        self.assertEqual(body, b"")

    # -- history and unknown routes -------------------------------------

    def test_history_route_returns_intentional_json_404(self) -> None:
        code, headers, body = self._invoke("history.py", "GET", "/api/history")
        self.assertEqual(code, HTTPStatus.NOT_FOUND)
        self.assertIn("application/json", headers.get("content-type", ""))
        self._assert_security_headers(self, headers)
        self.assertEqual(json.loads(body.decode("utf-8"))["status"], "NOT_FOUND")

    # -- method rejection -----------------------------------------------

    def test_every_hosted_route_rejects_mutations(self) -> None:
        """No hosted endpoint may mutate state or trigger an audit."""
        for route, filename in API_FUNCTIONS.items():
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                with self.subTest(route=route, method=method):
                    code, headers, body = self._invoke(filename, method, route)
                    self.assertEqual(code, HTTPStatus.METHOD_NOT_ALLOWED)
                    self.assertIn("application/json", headers.get("content-type", ""))
                    self.assertEqual(
                        json.loads(body.decode("utf-8"))["status"], "METHOD_NOT_ALLOWED"
                    )

    # -- no original-path recovery --------------------------------------

    def test_no_handler_recovers_original_url_from_rewrite(self) -> None:
        """Guards the root cause: nothing may depend on reconstructing the URL.

        Vercel supplies the resolved rewrite destination as the request path and
        sends neither of these headers, so relying on them silently breaks all
        routing.
        """
        sources = {p.name: p.read_text(encoding="utf-8") for p in API_DIR.glob("*.py")}
        sources["hosted.py"] = (SRC_DIR / "lpe_sentinel" / "web" / "hosted.py").read_text(
            encoding="utf-8"
        )

        for name, text in sources.items():
            with self.subTest(module=name):
                self.assertNotIn("x-forwarded-uri", text)
                self.assertNotIn("x-matched-path", text)

    def test_hosted_code_exposes_no_scanning_or_persistence_surface(self) -> None:
        """Hosted deployment must never reach scanners, shells, or SQLite."""
        sources = {p.name: p.read_text(encoding="utf-8") for p in API_DIR.glob("*.py")}
        sources["hosted.py"] = (SRC_DIR / "lpe_sentinel" / "web" / "hosted.py").read_text(
            encoding="utf-8"
        )

        forbidden = (
            "run_unified_audit",
            "audit_engine",
            "suid_sgid",
            "sensitive_permissions",
            "sudo_audit",
            "subprocess",
            "os.system",
            "popen",
            "eval(",
            "exec(",
            "sqlite3",
            "AuditHistoryManager",
            "audit_history",
        )
        for name, text in sources.items():
            for token in forbidden:
                with self.subTest(module=name, token=token):
                    self.assertNotIn(token, text, f"{name} must not reference {token}")


class TestHostedCapabilityGating(unittest.TestCase):
    """Server-rendered fail-closed capability gating in the shared dashboard."""

    @staticmethod
    def _embedded_capabilities(html: str):
        """Extract and JSON-parse the server-rendered capability baseline."""
        match = re.search(r"let hostedCapabilities = (.+?);", html)
        assert match, "capability baseline declaration not found in dashboard"
        return json.loads(match.group(1))

    @staticmethod
    def _resolver_source(html: str) -> str:
        """Extract the real resolveHostedCapabilities() implementation."""
        start = html.index("function resolveHostedCapabilities")
        end = html.index("function disableElement")
        source = html[start:end].rstrip()
        if source.count("{") != source.count("}"):
            raise AssertionError("extracted resolver is not balanced JS")
        return source

    def _resolve(self, baseline, payload):
        """Execute resolveHostedCapabilities() against a baseline and payload."""
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

    # -- baseline -------------------------------------------------------

    def test_local_dashboard_defaults_to_no_hosted_baseline(self) -> None:
        self.assertIsNone(self._embedded_capabilities(render_dashboard_html()))
        self.assertIsNone(self._embedded_capabilities(render_dashboard_html(hosted=False)))

    def test_zero_arg_call_is_backwards_compatible(self) -> None:
        self.assertEqual(render_dashboard_html(), render_dashboard_html(hosted=False))

    def test_hosted_dashboard_embeds_fail_closed_baseline(self) -> None:
        caps = self._embedded_capabilities(render_dashboard_html(hosted=True))
        self.assertIs(caps["isHosted"], True)
        self.assertIs(caps["cloudHistory"], False)
        self.assertIs(caps["liveAudit"], False)

    # -- invariant ------------------------------------------------------

    def test_hosted_baseline_rejects_payload_claiming_both_capabilities(self) -> None:
        baseline = self._embedded_capabilities(render_dashboard_html(hosted=True))
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
        baseline = self._embedded_capabilities(render_dashboard_html())
        result = self._resolve(baseline, {"capabilities": {"demo_mode": True}})
        self.assertIs(result["isHosted"], False)
        self.assertIs(result["liveAudit"], True)
        self.assertIs(result["cloudHistory"], True)

        fallback = self._resolve(baseline, None)
        self.assertIs(fallback["liveAudit"], True)
        self.assertIs(fallback["cloudHistory"], True)

    def test_hosted_lock_is_present_in_shipped_resolver(self) -> None:
        resolver = self._resolver_source(render_dashboard_html(hosted=True))
        self.assertIn("const hostedLocked = base.isHosted === true;", resolver)
        self.assertIn("cloudHistory: hostedLocked ? false : caps.cloud_history === true,", resolver)
        self.assertIn("liveAudit: hostedLocked ? false : caps.live_audit === true", resolver)
        self.assertNotIn("never widened", resolver)

    # -- initialization -------------------------------------------------

    def test_initialization_uses_baseline_not_failed_status_defaults(self) -> None:
        html = render_dashboard_html(hosted=True)
        self.assertIn("let caps = resolveHostedCapabilities(null, hostedCapabilities);", html)
        self.assertNotIn("let caps = resolveHostedCapabilities(null);", html)
        self.assertIn("caps = resolveHostedCapabilities(data, hostedCapabilities);", html)

    # -- safe serialization ---------------------------------------------

    def test_capability_baseline_serialized_safely(self) -> None:
        html = render_dashboard_html(hosted=True)
        self.assertNotIn("__INITIAL_CAPABILITIES__", html)

        match = re.search(r"let hostedCapabilities = (.+?);", html)
        self.assertIsNotNone(match)
        literal = match.group(1)
        self.assertNotIn("<", literal)
        self.assertNotIn(">", literal)
        self.assertNotIn("&", literal)
        json.loads(literal)

    def test_json_for_inline_script_escapes_breakout_characters(self) -> None:
        from lpe_sentinel.web.templates import _json_for_inline_script

        serialized = _json_for_inline_script({"x": "</script><img src=x onerror=alert(1)>"})
        self.assertNotIn("<", serialized)
        self.assertNotIn(">", serialized)
        self.assertIn("\\u003c", serialized)
        self.assertIn("\\u003e", serialized)
        self.assertEqual(
            json.loads(serialized)["x"], "</script><img src=x onerror=alert(1)>"
        )

    # -- local preservation ----------------------------------------------

    def test_local_dashboard_retains_live_audit_and_history_controls(self) -> None:
        html = render_dashboard_html()
        self.assertIn("async function runUnifiedAudit()", html)
        self.assertIn("fetch('/api/run-audit'", html)
        self.assertIn("fetch('/api/csrf-token')", html)
        self.assertIn("fetch('/api/history?limit=10')", html)
        self.assertIn('onclick="runUnifiedAudit()"', html)
        self.assertIn('onclick="loadDemoAudit()"', html)
        self.assertNotIn("SERVER_NAME", html)

    def test_dashboard_contains_capability_gating_hooks(self) -> None:
        html = render_dashboard_html()
        self.assertIn("deployment.is_hosted", html)
        self.assertIn("resolveHostedCapabilities", html)
        self.assertIn("applyHostedCapabilities", html)
        self.assertIn("Cloud audit history is unavailable in the hosted deployment", html)
        self.assertIn("Live auditing is unavailable in the hosted deployment", html)
        self.assertIn("Live Auditing Unavailable", html)
        self.assertIn('id="btn-run-audit"', html)
        self.assertIn('id="control-hint"', html)
        self.assertIn('id="history-list"', html)


if __name__ == "__main__":
    unittest.main()
