"""
Vercel Serverless Function Handler for LPE-Sentinel.

Provides a standalone, zero-dependency WSGI/BaseHTTPRequestHandler adapter
compatible with Vercel's Python runtime. Exposes:
- GET /              -> Self-contained security audit web dashboard
- GET /api/status    -> Health & serverless deployment status (identifies as hosted environment)
"""

import json
import os
import platform
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

# Ensure src/ is on sys.path for importing lpe_sentinel
ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from lpe_sentinel import __version__
    from lpe_sentinel.web.demo_data import get_demo_audit_payload
    from lpe_sentinel.web.templates import render_dashboard_html
except ImportError as err:
    raise RuntimeError(
        f"LPE-Sentinel Vercel deployment error: Failed to import package components from {SRC_DIR}. "
        f"Ensure repository source tree is intact. Details: {err}"
    ) from err


def get_hosted_status_payload() -> dict:
    """
    Construct safe, minimized status metadata identifying the Vercel hosted environment.
    Never exposes internal filesystem paths, credentials, or arbitrary environment variables.
    """
    return {
        "status": "ACTIVE",
        "service": "LPE-Sentinel Cloud Portal",
        "version": str(__version__),
        "deployment": {
            "environment": "hosted_serverless",
            "platform": "vercel",
            "region": os.environ.get("VERCEL_REGION", "unknown"),
            "is_hosted": True,
        },
        "system_info": {
            "os_name": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "platform_category": "Serverless Container",
            "is_linux": platform.system().lower() == "linux",
        },
        "capabilities": {
            "demo_mode": True,
            "live_audit": False,
            "report_ingestion": False,  # Stage 3
            "cloud_history": False,     # Stage 2
        },
        "notice": (
            "Hosted Vercel environment: live host auditing is disabled on serverless functions. "
            "Use simulated demo mode or run the CLI locally on your target Linux machine."
        ),
    }


class handler(BaseHTTPRequestHandler):
    """
    Vercel Python Serverless HTTP Request Handler.
    Conforms to the Vercel BaseHTTPRequestHandler specification.
    """

    server_version = f"LPE-Sentinel-Vercel/{__version__}"

    def _send_security_headers(self) -> None:
        """Inject robust HTTP security headers."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
            ),
        )
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")

    def _send_json_response(self, data: dict, status: HTTPStatus = HTTPStatus.OK, is_head: bool = False) -> None:
        """Helper to write a JSON response with security headers."""
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()
        if not is_head:
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        """Handle incoming HEAD request."""
        self._dispatch(is_head=True)

    def do_GET(self) -> None:
        """Handle incoming GET request."""
        self._dispatch(is_head=False)

    def _dispatch(self, is_head: bool = False) -> None:
        """Route incoming request paths."""
        # Path recovery:
        # Vercel documents that a top-level `rewrites` entry "selects which service
        # handles a request, and the service receives the original path" - only an
        # explicit `request.path` transform (unused here) changes the path the
        # runtime observes. `self.path` is therefore authoritative.
        #
        # `x-matched-path` is deliberately NOT consulted: Vercel documents it as a
        # Next.js *response* header, so reading it from request headers cannot be
        # correct and it previously masked mis-routed requests.
        #
        # `x-forwarded-uri` is retained as a defensive override only. Its presence
        # is not guaranteed by Vercel's documented request headers, so remaining
        # uncertainty is confined to which value wins when both are present; any
        # value it yields that is not a real client path now falls through to an
        # honest 404 rather than silently serving the dashboard.
        raw_uri = self.headers.get("x-forwarded-uri") or self.path
        parsed_url = urlparse(raw_uri)
        path = parsed_url.path.strip()

        # Normalize trailing slashes
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]

        # Note: `/api/index.py` is intentionally absent. It is the rewrite
        # destination, not a client-facing route. Matching it here made every
        # mis-routed request return 200 dashboard HTML instead of an error.
        if path in ("", "/", "/index.html", "/api"):
            # hosted=True bakes the serverless capability defaults into the HTML,
            # so the UI stays gated even if /api/status never completes.
            html_content = render_dashboard_html(hosted=True)
            body = html_content.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._send_security_headers()
            self.end_headers()
            if not is_head:
                self.wfile.write(body)

        elif path == "/api/status":
            payload = get_hosted_status_payload()
            self._send_json_response(payload, status=HTTPStatus.OK, is_head=is_head)

        elif path == "/api/demo-audit":
            payload = get_demo_audit_payload()
            self._send_json_response(payload, status=HTTPStatus.OK, is_head=is_head)

        else:
            self._send_json_response(
                {"status": "NOT_FOUND", "error": f"Endpoint '{path}' not found on Vercel deployment"},
                status=HTTPStatus.NOT_FOUND,
                is_head=is_head,
            )

    def do_POST(self) -> None:
        """Handle POST request (currently read-only for Stage 1)."""
        self._send_json_response(
            {
                "status": "METHOD_NOT_ALLOWED",
                "error": "Mutation endpoints are disabled in Stage 1 hosted deployment.",
            },
            status=HTTPStatus.METHOD_NOT_ALLOWED,
        )
