"""
Shared hosted (serverless) HTTP handling for the LPE-Sentinel Vercel deployment.

Deployment-adapter code only. Nothing here exposes live host auditing, shell
execution, SQLite persistence, report ingestion, or automatic remediation:
the hosted deployment is strictly read-only and serves simulated demo findings
only. Local CLI, scanner, and SQLite history behavior are unaffected.

Routing model
-------------
Vercel exposes the *resolved rewrite destination* to the function as the request
path (CLI release notes, vercel@58.9.3: "Expose the resolved rewrite destination
as the request path observed by Python framework applications"). A single
catch-all destination therefore cannot distinguish between routes, because every
request arrives carrying the same path value.

This deployment consequently uses Vercel's documented file-based function
mapping, where each endpoint is its own function and no rewrite rewrites it:

    api/index.py      -> /api              (dashboard)
    api/status.py     -> /api/status       (status JSON)
    api/demo-audit.py -> /api/demo-audit   (simulated demo JSON)
    api/history.py    -> /api/history      (intentional JSON 404)

Because each endpoint is selected by native route matching, no handler needs to
recover the client's original URL from a rewrite destination.
"""

import json
import os
import platform
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

from lpe_sentinel import __version__
from lpe_sentinel.web.demo_data import get_demo_audit_payload
from lpe_sentinel.web.templates import render_dashboard_html

# Routes that serve the hosted dashboard when handled by the /api function.
# Both the native path and the rewrite destination are accepted so the
# dashboard renders regardless of which value the platform supplies.
DASHBOARD_PATHS = ("", "/", "/index.html", "/api")


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


class HostedHandlerBase(BaseHTTPRequestHandler):
    """
    Base handler shared by every hosted Vercel function entry point.

    Subclasses implement `_route()`. Mutation verbs are rejected here so no
    hosted endpoint can ever mutate state or trigger an audit.
    """

    server_version = f"LPE-Sentinel-Vercel/{__version__}"

    # -- request helpers ------------------------------------------------

    def normalized_path(self) -> str:
        """Return the request path with any query string and trailing slash removed."""
        path = urlparse(self.path).path.strip()
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]
        return path

    # -- response helpers -----------------------------------------------

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

    def _write(self, body: bytes, content_type: str, status: HTTPStatus, is_head: bool) -> None:
        """Write a complete response with security headers."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()
        if not is_head:
            self.wfile.write(body)

    def _send_json_response(
        self,
        data: dict,
        status: HTTPStatus = HTTPStatus.OK,
        is_head: bool = False,
    ) -> None:
        """Write a JSON response with security headers."""
        self._write(
            json.dumps(data, indent=2).encode("utf-8"),
            "application/json; charset=utf-8",
            status,
            is_head,
        )

    # -- response builders ----------------------------------------------

    def send_dashboard(self, is_head: bool = False) -> None:
        """Serve the hosted dashboard with fail-closed capability defaults baked in."""
        body = render_dashboard_html(hosted=True).encode("utf-8")
        self._write(body, "text/html; charset=utf-8", HTTPStatus.OK, is_head)

    def send_status(self, is_head: bool = False) -> None:
        """Serve hosted deployment status metadata."""
        self._send_json_response(get_hosted_status_payload(), status=HTTPStatus.OK, is_head=is_head)

    def send_demo_audit(self, is_head: bool = False) -> None:
        """Serve simulated demo findings, explicitly watermarked as simulated."""
        self._send_json_response(get_demo_audit_payload(), status=HTTPStatus.OK, is_head=is_head)

    def send_not_found(self, path: str, is_head: bool = False) -> None:
        """Serve an intentional JSON 404 for unsupported hosted routes."""
        self._send_json_response(
            {
                "status": "NOT_FOUND",
                "error": f"Endpoint '{path}' not available on the Vercel deployment",
            },
            status=HTTPStatus.NOT_FOUND,
            is_head=is_head,
        )

    def send_method_not_allowed(self) -> None:
        """Reject every mutation verb. Hosted deployment is read-only."""
        self._send_json_response(
            {
                "status": "METHOD_NOT_ALLOWED",
                "error": "Mutation endpoints are disabled in the hosted deployment.",
            },
            status=HTTPStatus.METHOD_NOT_ALLOWED,
        )

    # -- verb handling ---------------------------------------------------

    def _route(self, is_head: bool = False) -> None:
        """Dispatch a safe request. Subclasses must implement this."""
        raise NotImplementedError

    def do_GET(self) -> None:
        """Handle GET."""
        self._route(is_head=False)

    def do_HEAD(self) -> None:
        """Handle HEAD."""
        self._route(is_head=True)

    def do_POST(self) -> None:
        """Reject POST."""
        self.send_method_not_allowed()

    def do_PUT(self) -> None:
        """Reject PUT."""
        self.send_method_not_allowed()

    def do_PATCH(self) -> None:
        """Reject PATCH."""
        self.send_method_not_allowed()

    def do_DELETE(self) -> None:
        """Reject DELETE."""
        self.send_method_not_allowed()
