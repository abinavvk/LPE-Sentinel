"""
Tests for LPE-Sentinel Vercel Serverless Integration (single entry point).

Routing model under test
------------------------
Verified against a live Vercel preview deployment: the project is detected as
`framework: python`, Vercel builds a single Python Lambda, and additional
`api/*.py` files do not become separately deployed routes. All requests reach
one entry point carrying the ORIGINAL client request path.

Therefore routing is performed by dispatching on the observed request path.

Verifies:
1. vercel.json declares no catch-all rewrite.
2. Exactly one api/ entry point exists.
3. Every documented route returns the correct status, content type, and body.
4. Security headers are present on every hosted response.
5. Every mutation verb is rejected with 405.
6. Demo findings are explicitly labelled as simulated.
7. No handler depends on reconstructing the URL from a rewrite destination.
8. Hosted code exposes no scanning, shell, or persistence surface.
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
from unittest.mock import patch

# Ensure src and api are importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
API_DIR = PROJECT_ROOT / "api"

for d in (SRC_DIR, API_DIR, PROJECT_ROOT):
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))

from api.index import handler
from lpe_sentinel.web.hosted import (
    DEMO_AUDIT_PATH,
    HISTORY_PATH,
    HISTORY_UNAVAILABLE_REASON,
    STATUS_PATH,
    get_hosted_status_payload,
)
from lpe_sentinel.web.templates import render_dashboard_html


class DummyWfile(io.BytesIO):
    """Mock wfile for BaseHTTPRequestHandler."""
    pass


class TestVercelHostedRouting(unittest.TestCase):
    """Routing, response shape, and hosted safety properties."""

    # -- helpers --------------------------------------------------------

    def _invoke(self, method: str, path: str, headers: dict | None = None):
        """Invoke the hosted handler in memory and capture its response."""
        inst = handler.__new__(handler)
        inst.command = method
        inst.path = path
        inst.headers = dict(headers) if headers else {}
        inst.rfile = io.BytesIO()
        inst.wfile = io.BytesIO()
        inst.close_connection = False

        response_code = [200]
        headers_sent = {}

        inst.send_response = lambda code, message=None: response_code.__setitem__(0, int(code))
        inst.send_header = lambda key, value: headers_sent.__setitem__(key.lower(), value)
        inst.end_headers = lambda: None

        getattr(inst, "do_" + method)()
        return response_code[0], headers_sent, inst.wfile.getvalue()

    def _assert_security_headers(self, headers: dict) -> None:
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("x-frame-options"), "DENY")
        self.assertIn("default-src 'self'", headers.get("content-security-policy", ""))
        self.assertIn("no-store", headers.get("cache-control", ""))

    # -- configuration --------------------------------------------------

    def test_vercel_json_has_no_catch_all_rewrite(self) -> None:
        """A catch-all collapses every request onto one indistinguishable path."""
        config = json.loads((PROJECT_ROOT / "vercel.json").read_text(encoding="utf-8"))

        self.assertEqual(config.get("version"), 2)
        rewrites = config.get("rewrites", [])
        sources = [r.get("source") for r in rewrites]
        destinations = [str(r.get("destination")) for r in rewrites]

        self.assertNotIn("/(.*)", sources)
        for dest in destinations:
            self.assertNotIn("index.py", dest, "destinations must use route paths")

        # Only the dashboard aliases are rewritten.
        self.assertEqual(sorted(sources), sorted(["/", "/index.html"]))
        self.assertEqual(destinations, ["/api", "/api"])

    def test_single_api_entry_point(self) -> None:
        """Only one api/*.py may exist: extra files do not become separate routes."""
        entry_points = sorted(p.name for p in API_DIR.glob("*.py"))
        self.assertEqual(entry_points, ["index.py"])

    # -- dashboard ------------------------------------------------------

    def test_dashboard_routes_serve_hosted_html(self) -> None:
        for path in ("/", "/index.html", "/api"):
            with self.subTest(path=path):
                code, headers, body = self._invoke("GET", path)
                self.assertEqual(code, HTTPStatus.OK)
                self.assertIn("text/html", headers.get("content-type", ""))
                decoded = body.decode("utf-8")
                self.assertIn("<!DOCTYPE html>", decoded)
                self.assertIn("LPE-Sentinel", decoded)
                self._assert_security_headers(headers)

    def test_dashboard_html_embeds_fail_closed_hosted_capabilities(self) -> None:
        _, _, body = self._invoke("GET", "/api")
        match = re.search(r"let hostedCapabilities = (.+?);", body.decode("utf-8"))
        self.assertIsNotNone(match)
        caps = json.loads(match.group(1))
        self.assertIs(caps["isHosted"], True)
        self.assertIs(caps["liveAudit"], False)
        self.assertIs(caps["cloudHistory"], False)

    def test_dashboard_trailing_slash_is_normalized(self) -> None:
        for path in ("/api/", "/index.html/"):
            with self.subTest(path=path):
                code, headers, _ = self._invoke("GET", path)
                self.assertEqual(code, HTTPStatus.OK)
                self.assertIn("text/html", headers.get("content-type", ""))

    # -- status ---------------------------------------------------------

    def test_status_route_serves_cloud_portal_json(self) -> None:
        code, headers, body = self._invoke("GET", STATUS_PATH)
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
        self._assert_security_headers(headers)

        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "ACTIVE")
        self.assertEqual(data["service"], "LPE-Sentinel Cloud Portal")
        self.assertTrue(data["deployment"]["is_hosted"])
        self.assertIn("notice", data)

    def test_status_route_ignores_query_string(self) -> None:
        """Query parameters must not break path-based routing."""
        code, _, body = self._invoke("GET", STATUS_PATH + "?x=1")
        self.assertEqual(code, HTTPStatus.OK)
        self.assertEqual(json.loads(body.decode("utf-8"))["service"], "LPE-Sentinel Cloud Portal")

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
        code, headers, body = self._invoke("GET", DEMO_AUDIT_PATH)
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
        self._assert_security_headers(headers)

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

    def test_demo_audit_does_not_claim_to_scan_the_visitor(self) -> None:
        """Hosted demo must not imply it scanned the visitor's machine."""
        _, _, body = self._invoke("GET", DEMO_AUDIT_PATH)
        data = json.loads(body.decode("utf-8"))
        blob = json.dumps(data).lower()

        # The disclaimer must state the data is synthetic and not a live scan.
        self.assertIn("synthetic", data["disclaimer"].lower())
        self.assertIn("do not", data["disclaimer"].lower())

        # No claim about scanning the visitor's own machine.
        for phrase in ("your computer", "your machine", "your host", "your system", "scanned your"):
            self.assertNotIn(phrase, blob, f"demo payload must not mention '{phrase}'")

        # Any platform reference (e.g. a simulated kernel release string) must
        # be explicitly qualified as simulated or demo, never presented as a
        # real host that was scanned.
        for match in re.finditer(r"kali|linux|windows", blob):
            window = blob[max(0, match.start() - 48): match.end() + 48]
            self.assertTrue(
                "simulat" in window or "demo" in window,
                f"unqualified platform claim near: {window!r}",
            )

    def test_demo_audit_head_returns_headers_without_body(self) -> None:
        code, headers, body = self._invoke("HEAD", DEMO_AUDIT_PATH)
        self.assertEqual(code, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
        self.assertEqual(body, b"")

    # -- history and unknown routes -------------------------------------

    def test_history_route_returns_intentional_json_404(self) -> None:
        code, headers, body = self._invoke("GET", HISTORY_PATH)
        self.assertEqual(code, HTTPStatus.NOT_FOUND)
        self.assertIn("application/json", headers.get("content-type", ""))
        self._assert_security_headers(headers)

        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "NOT_FOUND")
        self.assertEqual(data["error"], HISTORY_UNAVAILABLE_REASON)
        self.assertIn("not implemented", data["error"])

    def test_unknown_routes_return_consistent_json_404(self) -> None:
        for path in ("/nope", "/api/unknown", "/api/status/extra", "/api/index.py", "/api/../etc"):
            with self.subTest(path=path):
                code, headers, body = self._invoke("GET", path)
                self.assertEqual(code, HTTPStatus.NOT_FOUND)
                self.assertIn("application/json", headers.get("content-type", ""))
                self._assert_security_headers(headers)
                self.assertEqual(json.loads(body.decode("utf-8"))["status"], "NOT_FOUND")

    def test_rewrite_destination_path_is_not_dashboard(self) -> None:
        """Regression: the old catch-all destination must not serve the dashboard.

        Serving HTML here silently broke every JSON endpoint on the hosted
        deployment, because each one received HTML where JSON was expected.
        """
        code, headers, body = self._invoke("GET", "/api/index.py")
        self.assertEqual(code, HTTPStatus.NOT_FOUND)
        self.assertNotIn("<!DOCTYPE html>", body.decode("utf-8"))

    # -- method rejection -----------------------------------------------

    def test_every_route_rejects_mutations(self) -> None:
        """No hosted route may mutate state or trigger an audit."""
        routes = ("/", "/api", STATUS_PATH, DEMO_AUDIT_PATH, HISTORY_PATH, "/unknown")
        for route in routes:
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                with self.subTest(route=route, method=method):
                    code, headers, body = self._invoke(method, route)
                    self.assertEqual(code, HTTPStatus.METHOD_NOT_ALLOWED)
                    self.assertIn("application/json", headers.get("content-type", ""))
                    self.assertEqual(
                        json.loads(body.decode("utf-8"))["status"], "METHOD_NOT_ALLOWED"
                    )

    # -- no original-path recovery --------------------------------------

    def test_no_handler_recovers_original_url_from_rewrite(self) -> None:
        """Guards the original root cause.

        Routing now legitimately reads the request path, but it must never try to
        reconstruct the URL from headers or rewrite destinations.
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
