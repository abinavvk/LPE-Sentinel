"""
Defensive HTTP Web Server and Handler for LPE Sentinel.

Built using the Python standard library `http.server`. Requires zero third-party
dependencies and runs portably across both Windows and Linux environments.
"""

import hmac
import json
import platform
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

try:
    from lpe_sentinel import __version__
    from lpe_sentinel.audit_engine import ALL_SCANNER_NAMES, AuditResult, run_unified_audit
    from lpe_sentinel.audit_history import (
        DEFAULT_LIST_LIMIT,
        MAX_LIST_LIMIT,
        SCAN_ID_REGEX,
        AuditHistoryError,
        AuditHistoryManager,
    )
    from lpe_sentinel.export import (
        generate_csv_export,
        generate_html_export,
        generate_json_export,
    )
    from lpe_sentinel.audit_diff import AuditComparisonError, compare_history_audits
    from lpe_sentinel.suid_sgid import is_linux_platform
    from lpe_sentinel.system_info import collect_system_info
    from lpe_sentinel.web.demo_data import get_demo_audit_payload
    from lpe_sentinel.web.templates import render_dashboard_html
except ImportError:
    from __version__ import __version__
    from audit_diff import AuditComparisonError, compare_history_audits
    from audit_engine import ALL_SCANNER_NAMES, AuditResult, run_unified_audit
    from audit_history import (
        DEFAULT_LIST_LIMIT,
        MAX_LIST_LIMIT,
        SCAN_ID_REGEX,
        AuditHistoryError,
        AuditHistoryManager,
    )
    from export import (
        generate_csv_export,
        generate_html_export,
        generate_json_export,
    )
    from suid_sgid import is_linux_platform
    from system_info import collect_system_info
    from web.demo_data import get_demo_audit_payload
    from web.templates import render_dashboard_html

# Maximum allowable request body size (64 KB) to protect against buffer exhaustion
MAX_REQUEST_BODY_BYTES = 65536


class LpeSentinelWebHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler serving dashboard HTML and JSON API endpoints.
    """

    server_version = "LPE-Sentinel-Web/" + str(__version__)

    def _get_normalized_path(self) -> str:
        """Parse, clean, and normalize the request URI path."""
        raw_path = urlparse(self.path).path.strip()
        # Collapse multiple consecutive slashes
        while "//" in raw_path:
            raw_path = raw_path.replace("//", "/")
        # Strip trailing slash unless root
        if len(raw_path) > 1 and raw_path.endswith("/"):
            raw_path = raw_path[:-1]
        return raw_path or "/"

    def _parse_and_drain_request_body(self) -> Tuple[bool, Optional[bytes], Optional[str], HTTPStatus]:
        """
        Validate Content-Length and safely drain the request body.

        Protects against Keep-Alive desynchronization, negative/malformed lengths,
        unsupported transfer encodings, and buffer exhaustion.

        Returns:
            (is_valid, body_bytes, error_message, http_status)
        """
        # Reject chunked transfer encoding as incoming bodies are not chunk-parsed
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in transfer_encoding:
            self.close_connection = True
            return (
                False,
                None,
                "Chunked transfer encoding is not supported for uploads",
                HTTPStatus.NOT_IMPLEMENTED,
            )

        content_len_header = self.headers.get("Content-Length")
        if content_len_header is None:
            return (True, b"", None, HTTPStatus.OK)

        # Validate Content-Length integer format
        try:
            content_len = int(content_len_header.strip())
        except ValueError:
            self.close_connection = True
            return (
                False,
                None,
                f"Malformed Content-Length header: {content_len_header!r}",
                HTTPStatus.BAD_REQUEST,
            )

        # Reject negative Content-Length
        if content_len < 0:
            self.close_connection = True
            return (
                False,
                None,
                "Negative Content-Length header is not permitted",
                HTTPStatus.BAD_REQUEST,
            )

        # Reject oversized payloads and close connection to prevent Keep-Alive desync
        if content_len > MAX_REQUEST_BODY_BYTES:
            self.close_connection = True
            return (
                False,
                None,
                f"Payload Too Large: maximum allowed body is {MAX_REQUEST_BODY_BYTES} bytes",
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )

        # Drain exact body bytes safely
        try:
            body = self.rfile.read(content_len)
            if len(body) < content_len:
                self.close_connection = True
                return (
                    False,
                    None,
                    "Incomplete request body: premature client connection close",
                    HTTPStatus.BAD_REQUEST,
                )
            return (True, body, None, HTTPStatus.OK)
        except OSError as exc:
            self.close_connection = True
            return (
                False,
                None,
                f"I/O error reading request body: {exc}",
                HTTPStatus.BAD_REQUEST,
            )

    def do_GET(self) -> None:
        """Handle incoming GET requests."""
        self._dispatch_route(is_head=False)

    def do_HEAD(self) -> None:
        """Handle incoming HEAD requests (headers only, no body)."""
        self._dispatch_route(is_head=True)

    def _validate_origin(self) -> bool:
        """
        Validate Origin and Referer headers against local loopback address and bound server port.
        Returns True if valid or absent (for direct HTTP clients), False if foreign origin or mismatched port.
        """
        server_port = getattr(self.server, "server_address", (None, None))[1]
        for header_name in ("Origin", "Referer"):
            val = self.headers.get(header_name)
            if val:
                try:
                    parsed = urlparse(val)
                    if parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                        return False
                    effective_port = parsed.port if parsed.port is not None else (
                        80 if parsed.scheme == "http" else (443 if parsed.scheme == "https" else None)
                    )
                    if effective_port is not None and server_port is not None:
                        if effective_port != server_port:
                            return False
                except Exception:
                    return False
        return True

    def _validate_csrf_token(self, body_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        Validate unpredictable CSRF token from request headers or body against server token.
        """
        server_token = getattr(self.server, "csrf_token", None)
        if not server_token:
            return True

        client_token = (
            self.headers.get("X-CSRF-Token")
            or self.headers.get("X-Sentinel-CSRF-Token")
        )
        if not client_token and isinstance(body_data, dict):
            client_token = body_data.get("csrf_token")

        if not client_token or not isinstance(client_token, str):
            return False

        return hmac.compare_digest(client_token.strip(), server_token)

    def _handle_api_run_audit(self, body_bytes: bytes) -> None:
        """
        Secure backend controller for POST /api/run-audit.

        Enforces Content-Type, Origin checks, CSRF validation, parameter allow-listing,
        platform gating, concurrency locking, and execution of run_unified_audit.
        """
        # 1. Content-Type validation
        content_type = self.headers.get("Content-Type", "")
        if "application/json" not in content_type.lower():
            self._send_json_response(
                {"error": "Content-Type must be application/json", "status": "BAD_REQUEST"},
                status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            )
            return

        # 2. Origin & Referer validation
        if not self._validate_origin():
            self._send_json_response(
                {"error": "Forbidden: Cross-origin request blocked", "status": "FORBIDDEN"},
                status=HTTPStatus.FORBIDDEN,
            )
            return

        # 3. Parse JSON body (if provided)
        body_data: Dict[str, Any] = {}
        if body_bytes.strip():
            try:
                parsed = json.loads(body_bytes.decode("utf-8"))
                if not isinstance(parsed, dict):
                    self._send_json_response(
                        {"error": "Request body must be a JSON object", "status": "BAD_REQUEST"},
                        status=HTTPStatus.BAD_REQUEST,
                    )
                    return
                body_data = parsed
            except Exception:
                self._send_json_response(
                    {"error": "Malformed JSON in request body", "status": "BAD_REQUEST"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

        # 4. CSRF token validation
        if not self._validate_csrf_token(body_data):
            self._send_json_response(
                {"error": "Forbidden: Invalid or missing CSRF token", "status": "FORBIDDEN"},
                status=HTTPStatus.FORBIDDEN,
            )
            return

        # 5. Schema validation: reject unknown, custom, or client-controlled paths/commands
        allowed_keys = {"enabled_scanners", "csrf_token"}
        forbidden_keys = set(body_data.keys()) - allowed_keys
        if forbidden_keys:
            bad_key = sorted(forbidden_keys)[0]
            self._send_json_response(
                {
                    "error": f"Forbidden parameter: client-controlled path or parameter '{bad_key}' is not permitted",
                    "status": "BAD_REQUEST",
                },
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        # 6. Validate enabled_scanners against predefined catalog
        if "enabled_scanners" in body_data:
            scanners = body_data["enabled_scanners"]
            if not isinstance(scanners, (list, tuple)) or not scanners:
                self._send_json_response(
                    {"error": "enabled_scanners must be a non-empty list of scanner names", "status": "BAD_REQUEST"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            for s in scanners:
                if not isinstance(s, str) or s not in ALL_SCANNER_NAMES:
                    self._send_json_response(
                        {
                            "error": f"Invalid scanner name '{s}'. Allowed: {list(ALL_SCANNER_NAMES)}",
                            "status": "BAD_REQUEST",
                        },
                        status=HTTPStatus.BAD_REQUEST,
                    )
                    return
            selected_scanners = tuple(scanners)
        else:
            selected_scanners = ALL_SCANNER_NAMES

        # 7. Platform Gate: strictly Linux only
        if not is_linux_platform():
            current_os = platform.system()
            self._send_json_response(
                {
                    "status": "UNSUPPORTED_PLATFORM",
                    "is_complete": False,
                    "is_demo": False,
                    "is_simulated": False,
                    "live_audit": False,
                    "error": (
                        f"Live security auditing is only supported on Linux hosts (e.g. Kali Linux). "
                        f"Host platform '{current_os}' is not supported."
                    ),
                    "findings": [],
                },
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        # 8. Concurrency lock: atomically acquire audit lock
        acquire_fn = getattr(self.server, "acquire_audit", None)
        audit_lock = getattr(self.server, "audit_lock", None)
        audit_idle_event = getattr(self.server, "_audit_idle_event", None)
        audit_state_lock = getattr(self.server, "_audit_state_lock", None)

        if acquire_fn is not None:
            acquired = acquire_fn()
        elif audit_state_lock is not None and audit_lock is not None:
            with audit_state_lock:
                acquired = audit_lock.acquire(blocking=False)
                if acquired and audit_idle_event is not None:
                    audit_idle_event.clear()
        elif audit_lock is not None:
            acquired = audit_lock.acquire(blocking=False)
            if acquired and audit_idle_event is not None:
                audit_idle_event.clear()
        else:
            acquired = False

        if not acquired:
            self._send_json_response(
                {
                    "error": "An audit is already in progress. Concurrent audits are prohibited.",
                    "status": "BUSY",
                    "is_complete": False,
                },
                status=HTTPStatus.CONFLICT,
            )
            return

        # 9. Execute Unified Audit with server-controlled defaults
        t_start = time.monotonic()
        try:
            audit_res = run_unified_audit(
                enabled_scanners=selected_scanners,
                collect_sys_info=True,
            )
            duration_ms = round((time.monotonic() - t_start) * 1000.0, 2)
            sanitized_sys_info = {
                "os_name": audit_res.system_info.get("os_name", "Unknown"),
                "release": audit_res.system_info.get("os_release", "Unknown"),
                "architecture": audit_res.system_info.get("architecture", "Unknown"),
                "platform_category": audit_res.system_info.get("platform_category", "Unknown"),
                "is_linux": audit_res.system_info.get("platform_category") == "Linux",
            }
            payload = {
                "status": audit_res.status,
                "is_complete": audit_res.is_complete,
                "is_demo": False,
                "is_simulated": False,
                "live_audit": True,
                "timestamp": audit_res.timestamp,
                "duration_ms": duration_ms,
                "summary": audit_res.summary,
                "system_info": sanitized_sys_info,
                "scanner_results": {k: v.to_dict() for k, v in audit_res.scanner_results.items()},
                "errors": list(audit_res.errors),
                "findings": [f.to_dict() for f in audit_res.findings],
            }

            # Attempt persistence to SQLite history database
            history_manager = getattr(self.server, "history_manager", None)
            if history_manager is not None:
                try:
                    saved_scan_id = history_manager.save_audit(
                        audit_res,
                        duration_ms=duration_ms,
                        sanitized_sys_info=sanitized_sys_info,
                    )
                    payload["scan_id"] = saved_scan_id
                    payload["history_saved"] = True
                except Exception:
                    payload["scan_id"] = None
                    payload["history_saved"] = False
                    payload["history_error"] = "Audit completed, but persistence to history database failed"
            else:
                payload["scan_id"] = None
                payload["history_saved"] = False

            self._send_json_response(payload, status=HTTPStatus.OK)
        except Exception as exc:
            exc_type = type(exc).__name__
            self._send_json_response(
                {
                    "status": "FAILED",
                    "is_complete": False,
                    "is_demo": False,
                    "is_simulated": False,
                    "live_audit": True,
                    "error": f"Internal error during audit execution ({exc_type})",
                    "findings": [],
                },
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )
        finally:
            if acquired:
                release_fn = getattr(self.server, "release_audit", None)
                if release_fn is not None:
                    release_fn()
                elif audit_state_lock is not None and audit_lock is not None:
                    with audit_state_lock:
                        if audit_idle_event is not None:
                            audit_idle_event.set()
                        if audit_lock.locked():
                            audit_lock.release()
                elif audit_lock is not None and audit_lock.locked():
                    if audit_idle_event is not None:
                        audit_idle_event.set()
                    audit_lock.release()

    def do_POST(self) -> None:
        """Handle incoming POST requests with robust body and connection management."""
        is_valid, body, error_msg, err_status = self._parse_and_drain_request_body()
        if not is_valid:
            self._send_json_response(
                {"error": error_msg or "Bad Request"},
                status=err_status,
            )
            return

        path = self._get_normalized_path()

        if path == "/api/run-audit":
            self._handle_api_run_audit(body or b"")
        elif path == "/api/history" or path.startswith("/api/history/"):
            self._send_json_response(
                {"error": "Method Not Allowed: history endpoints are read-only", "path": path},
                status=HTTPStatus.METHOD_NOT_ALLOWED,
            )
        else:
            self._send_json_response(
                {"error": "Endpoint not found or method not allowed", "path": path},
                status=HTTPStatus.NOT_FOUND,
            )

    def do_PUT(self) -> None:
        """Reject unsupported PUT method."""
        self._send_method_not_allowed()

    def do_DELETE(self) -> None:
        """Reject unsupported DELETE method."""
        self._send_method_not_allowed()

    def do_PATCH(self) -> None:
        """Reject unsupported PATCH method."""
        self._send_method_not_allowed()

    def _send_method_not_allowed(self) -> None:
        """Return 405 Method Not Allowed response and drain body."""
        _ = self._parse_and_drain_request_body()
        self._send_json_response(
            {"error": "Method Not Allowed", "method": self.command},
            status=HTTPStatus.METHOD_NOT_ALLOWED,
        )

    def _dispatch_route(self, is_head: bool = False) -> None:
        """Route GET and HEAD requests to appropriate handlers."""
        path = self._get_normalized_path()

        if path in ("/", "/index.html"):
            self._handle_dashboard(is_head=is_head)
        elif path == "/api/status":
            self._handle_api_status(is_head=is_head)
        elif path == "/api/demo-audit":
            self._handle_api_demo_audit(is_head=is_head)
        elif path == "/api/csrf-token":
            self._handle_api_csrf_token(is_head=is_head)
        elif path == "/api/history":
            self._handle_api_history_list(is_head=is_head)
        elif path == "/api/history/compare":
            self._handle_api_history_compare(is_head=is_head)
        elif path.startswith("/api/history/compare/"):
            rest = path[len("/api/history/compare/"):].strip()
            parts = [p for p in rest.split("/") if p]
            if len(parts) == 2:
                self._handle_api_history_compare(is_head=is_head, scan_id_a=parts[0], scan_id_b=parts[1])
            else:
                self._send_json_response(
                    {"status": "BAD_REQUEST", "error": "Invalid comparison route. Expected /api/history/compare/<scan_id_a>/<scan_id_b> or query parameters"},
                    status=HTTPStatus.BAD_REQUEST,
                    is_head=is_head,
                )
        elif path.startswith("/api/history/"):
            rest = path[len("/api/history/"):].strip()
            parts = [p for p in rest.split("/") if p]
            if len(parts) == 1:
                self._handle_api_history_item(parts[0], is_head=is_head)
            elif len(parts) == 3 and parts[1] == "export":
                self._handle_api_history_export(parts[0], parts[2], is_head=is_head)
            elif len(parts) == 2 and parts[1] == "export":
                self._send_json_response(
                    {"status": "BAD_REQUEST", "error": "Missing export format. Supported: json, csv, html"},
                    status=HTTPStatus.BAD_REQUEST,
                    is_head=is_head,
                )
            else:
                self._send_json_response(
                    {"status": "NOT_FOUND", "error": "Endpoint not found", "path": path},
                    status=HTTPStatus.NOT_FOUND,
                    is_head=is_head,
                )
        elif path == "/api/run-audit":
            self._send_json_response(
                {"error": "Method Not Allowed: use POST to request audit run", "path": path},
                status=HTTPStatus.METHOD_NOT_ALLOWED,
                is_head=is_head,
            )
        else:
            self._send_json_response(
                {"error": "Endpoint not found", "path": path},
                status=HTTPStatus.NOT_FOUND,
                is_head=is_head,
            )

    def _handle_api_history_list(self, is_head: bool = False) -> None:
        """
        Handle GET /api/history.
        Supports query parameter 'limit' (bounded between 1 and MAX_LIST_LIMIT).
        """
        history_mgr = getattr(self.server, "history_manager", None)
        if history_mgr is None:
            self._send_json_response(
                {"status": "ERROR", "error": "Audit history persistence is not configured"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                is_head=is_head,
            )
            return

        query_str = urlparse(self.path).query
        qs = parse_qs(query_str)
        limit_val = DEFAULT_LIST_LIMIT
        if "limit" in qs:
            limit_raw = qs["limit"][0]
            try:
                parsed_limit = int(limit_raw)
                if parsed_limit < 1 or parsed_limit > MAX_LIST_LIMIT:
                    self._send_json_response(
                        {
                            "status": "BAD_REQUEST",
                            "error": f"Parameter 'limit' must be between 1 and {MAX_LIST_LIMIT}",
                        },
                        status=HTTPStatus.BAD_REQUEST,
                        is_head=is_head,
                    )
                    return
                limit_val = parsed_limit
            except ValueError:
                self._send_json_response(
                    {
                        "status": "BAD_REQUEST",
                        "error": "Parameter 'limit' must be a valid integer",
                    },
                    status=HTTPStatus.BAD_REQUEST,
                    is_head=is_head,
                )
                return

        try:
            records = history_mgr.list_audits(limit=limit_val)
            self._send_json_response(
                {
                    "status": "OK",
                    "count": len(records),
                    "limit": limit_val,
                    "history": records,
                },
                status=HTTPStatus.OK,
                is_head=is_head,
            )
        except Exception:
            self._send_json_response(
                {"status": "ERROR", "error": "Failed to retrieve audit history records"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                is_head=is_head,
            )

    def _handle_api_history_item(self, scan_id: str, is_head: bool = False) -> None:
        """
        Handle GET /api/history/<scan_id>.
        Returns sanitized audit record or 404 if not found.
        """
        history_mgr = getattr(self.server, "history_manager", None)
        if history_mgr is None:
            self._send_json_response(
                {"status": "ERROR", "error": "Audit history persistence is not configured"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                is_head=is_head,
            )
            return

        if not scan_id or not SCAN_ID_REGEX.match(scan_id):
            self._send_json_response(
                {
                    "status": "BAD_REQUEST",
                    "error": "Invalid or malformed scan ID format",
                },
                status=HTTPStatus.BAD_REQUEST,
                is_head=is_head,
            )
            return

        try:
            record = history_mgr.get_audit(scan_id)
        except ValueError:
            self._send_json_response(
                {
                    "status": "BAD_REQUEST",
                    "error": "Invalid or malformed scan ID format",
                },
                status=HTTPStatus.BAD_REQUEST,
                is_head=is_head,
            )
            return
        except Exception:
            self._send_json_response(
                {"status": "ERROR", "error": "Failed to read audit record from database"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                is_head=is_head,
            )
            return

        if record is None:
            self._send_json_response(
                {
                    "status": "NOT_FOUND",
                    "error": f"Audit record '{scan_id}' not found",
                    "scan_id": scan_id,
                },
                status=HTTPStatus.NOT_FOUND,
                is_head=is_head,
            )
            return

        self._send_json_response(
            {
                "status": "OK",
                "scan_id": scan_id,
                "audit": record,
            },
            status=HTTPStatus.OK,
            is_head=is_head,
        )

    def _handle_api_history_export(
        self,
        scan_id: str,
        export_format: str,
        is_head: bool = False,
    ) -> None:
        """
        Handle GET /api/history/<scan_id>/export/<json|csv|html>.
        Validates scan ID and format, fetches record from SQLite, and generates export report.
        """
        history_mgr = getattr(self.server, "history_manager", None)
        if history_mgr is None:
            self._send_json_response(
                {"status": "ERROR", "error": "Audit history persistence is not configured"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                is_head=is_head,
            )
            return

        fmt = export_format.lower().strip()
        if fmt not in ("json", "csv", "html"):
            self._send_json_response(
                {
                    "status": "BAD_REQUEST",
                    "error": f"Unsupported export format '{export_format}'. Supported formats: json, csv, html",
                },
                status=HTTPStatus.BAD_REQUEST,
                is_head=is_head,
            )
            return

        if not scan_id or not SCAN_ID_REGEX.match(scan_id):
            self._send_json_response(
                {
                    "status": "BAD_REQUEST",
                    "error": "Invalid or malformed scan ID format",
                },
                status=HTTPStatus.BAD_REQUEST,
                is_head=is_head,
            )
            return

        try:
            record = history_mgr.get_audit(scan_id)
        except ValueError:
            self._send_json_response(
                {
                    "status": "BAD_REQUEST",
                    "error": "Invalid or malformed scan ID format",
                },
                status=HTTPStatus.BAD_REQUEST,
                is_head=is_head,
            )
            return
        except Exception:
            self._send_json_response(
                {"status": "ERROR", "error": "Failed to read audit record from database"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                is_head=is_head,
            )
            return

        if record is None:
            self._send_json_response(
                {
                    "status": "NOT_FOUND",
                    "error": f"Audit record '{scan_id}' not found",
                    "scan_id": scan_id,
                },
                status=HTTPStatus.NOT_FOUND,
                is_head=is_head,
            )
            return

        try:
            if fmt == "json":
                content_str = generate_json_export(record)
                content_type = "application/json; charset=utf-8"
                filename = f"lpe_audit_{scan_id}.json"
            elif fmt == "csv":
                content_str = generate_csv_export(record)
                content_type = "text/csv; charset=utf-8"
                filename = f"lpe_audit_{scan_id}.csv"
            elif fmt == "html":
                content_str = generate_html_export(record)
                content_type = "text/html; charset=utf-8"
                filename = f"lpe_audit_{scan_id}.html"
            else:
                self._send_json_response(
                    {"status": "BAD_REQUEST", "error": f"Unsupported export format '{fmt}'"},
                    status=HTTPStatus.BAD_REQUEST,
                    is_head=is_head,
                )
                return
        except Exception:
            self._send_json_response(
                {"status": "ERROR", "error": "Failed to generate report export"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                is_head=is_head,
            )
            return

        body_bytes = content_str.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body_bytes)))
        self._send_security_headers()
        self.end_headers()

        if not is_head:
            self.wfile.write(body_bytes)

    def _handle_api_history_compare(
        self,
        is_head: bool = False,
        scan_id_a: Optional[str] = None,
        scan_id_b: Optional[str] = None,
    ) -> None:
        """
        Handle GET /api/history/compare.
        Compares two saved historical audit records without re-running scanners.
        """
        history_mgr = getattr(self.server, "history_manager", None)
        if history_mgr is None:
            self._send_json_response(
                {"status": "ERROR", "error": "Audit history persistence is not configured"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                is_head=is_head,
            )
            return

        # If not supplied via path, extract from query string
        if not scan_id_a or not scan_id_b:
            query_str = urlparse(self.path).query
            qs = parse_qs(query_str)
            older_list = qs.get("older", qs.get("scan_a", qs.get("base", [])))
            newer_list = qs.get("newer", qs.get("scan_b", qs.get("target", [])))
            scan_id_a = older_list[0] if older_list else None
            scan_id_b = newer_list[0] if newer_list else None

        if not scan_id_a or not scan_id_b:
            self._send_json_response(
                {
                    "status": "BAD_REQUEST",
                    "error": "Two scan IDs are required for historical comparison (e.g. ?older=<id1>&newer=<id2>)",
                },
                status=HTTPStatus.BAD_REQUEST,
                is_head=is_head,
            )
            return

        scan_id_a = str(scan_id_a).strip()
        scan_id_b = str(scan_id_b).strip()

        if not SCAN_ID_REGEX.match(scan_id_a) or not SCAN_ID_REGEX.match(scan_id_b):
            self._send_json_response(
                {
                    "status": "BAD_REQUEST",
                    "error": "Invalid or malformed scan ID format",
                },
                status=HTTPStatus.BAD_REQUEST,
                is_head=is_head,
            )
            return

        if scan_id_a == scan_id_b:
            self._send_json_response(
                {
                    "status": "BAD_REQUEST",
                    "error": "Cannot compare an audit record to itself; two distinct scan IDs are required.",
                },
                status=HTTPStatus.BAD_REQUEST,
                is_head=is_head,
            )
            return

        try:
            comparison = compare_history_audits(history_mgr, scan_id_a, scan_id_b)
            self._send_json_response(
                comparison,
                status=HTTPStatus.OK,
                is_head=is_head,
            )
        except AuditComparisonError as exc:
            msg = str(exc)
            if "not found" in msg.lower():
                status_code = HTTPStatus.NOT_FOUND
            elif "demo" in msg.lower():
                status_code = HTTPStatus.BAD_REQUEST
            else:
                status_code = HTTPStatus.BAD_REQUEST
            self._send_json_response(
                {"status": "ERROR", "error": msg},
                status=status_code,
                is_head=is_head,
            )
        except Exception:
            self._send_json_response(
                {"status": "ERROR", "error": "Internal error during audit comparison"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                is_head=is_head,
            )

    def _handle_dashboard(self, is_head: bool = False) -> None:
        """Serve the standalone dashboard HTML."""
        html_content = render_dashboard_html()
        body = html_content.encode("utf-8")

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()

        if not is_head:
            self.wfile.write(body)

    def _handle_api_status(self, is_head: bool = False) -> None:
        """Return server health and minimized host platform metadata."""
        try:
            sys_info = collect_system_info()
        except Exception as exc:
            sys_info = {"error": f"Failed to collect system info: {exc}"}

        # Principle of data minimization: expose only what the dashboard UI requires
        # for platform compatibility, omitting specific local user account details
        sanitized_sys_info = {
            "os_name": sys_info.get("os_name", "Unknown"),
            "release": sys_info.get("os_release", "Unknown"),
            "architecture": sys_info.get("architecture", "Unknown"),
            "platform_category": sys_info.get("platform_category", "Unknown"),
            "is_linux": sys_info.get("platform_category") == "Linux",
        }

        payload = {
            "status": "ACTIVE",
            "service": "LPE-Sentinel Web Dashboard",
            "version": str(__version__),
            "system_info": sanitized_sys_info,
            "capabilities": {
                "demo_mode": True,
                "live_audit": False,  # Intentionally disabled in Task 4
            },
        }
        self._send_json_response(payload, status=HTTPStatus.OK, is_head=is_head)

    def _handle_api_demo_audit(self, is_head: bool = False) -> None:
        """Return simulated demo audit payload with explicit watermarks."""
        payload = get_demo_audit_payload()
        self._send_json_response(payload, status=HTTPStatus.OK, is_head=is_head)

    def _handle_api_csrf_token(self, is_head: bool = False) -> None:
        """Return the unpredictable CSRF token for this server session."""
        token = getattr(self.server, "csrf_token", "")
        self._send_json_response({"csrf_token": token}, status=HTTPStatus.OK, is_head=is_head)

    def _send_security_headers(self) -> None:
        """Inject robust security headers on all responses."""
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
        if self.close_connection:
            self.send_header("Connection", "close")

    def _send_json_response(
        self,
        data: Dict[str, Any],
        status: HTTPStatus = HTTPStatus.OK,
        is_head: bool = False,
    ) -> None:
        """Format and write a JSON HTTP response with security headers."""
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()

        if not is_head:
            self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stderr request logging during testing."""
        pass


class LpeSentinelWebServer:
    """
    Manager class wrapping standard library ThreadingHTTPServer with convenient start/stop lifecycle.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        db_path: Optional[str] = None,
        history_manager: Optional[Any] = None,
    ) -> None:
        """
        Initialize the HTTP server.

        Args:
            host: Interface address to bind (defaults to '127.0.0.1').
            port: Port number (use 0 for auto-allocated ephemeral port).
            db_path: Optional path to SQLite audit history database.
            history_manager: Optional pre-configured AuditHistoryManager instance.
        """
        self.host = host
        self.requested_port = port
        self.httpd: Optional[ThreadingHTTPServer] = None
        self.csrf_token: str = secrets.token_hex(32)
        self.audit_lock: threading.Lock = threading.Lock()
        self._shutdown_lock: threading.Lock = threading.Lock()
        self._audit_state_lock: threading.Lock = threading.Lock()
        self._audit_idle_event: threading.Event = threading.Event()
        self._audit_idle_event.set()
        self._started: bool = False
        self._is_shut_down: bool = False
        if history_manager is not None:
            self.history_manager = history_manager
        else:
            self.history_manager = AuditHistoryManager(db_path=db_path)

    @property
    def server_port(self) -> int:
        """Return actual bound port number."""
        if self.httpd is not None:
            return int(self.httpd.server_address[1])
        return self.requested_port

    @property
    def is_serving(self) -> bool:
        """Return True if the HTTP server is currently listening for connections."""
        return self.httpd is not None

    def acquire_audit(self) -> bool:
        """
        Atomically acquire the audit lock and transition out of idle state.

        Returns True if acquired, False if an audit is already in progress.
        """
        with self._audit_state_lock:
            acquired = self.audit_lock.acquire(blocking=False)
            if acquired:
                self._audit_idle_event.clear()
            return acquired

    def release_audit(self) -> None:
        """
        Atomically signal audit completion and release the audit lock.
        """
        with self._audit_state_lock:
            self._audit_idle_event.set()
            if self.audit_lock.locked():
                self.audit_lock.release()

    @property
    def is_audit_active(self) -> bool:
        """Return True if a live security audit is actively executing."""
        with self._audit_state_lock:
            return self.audit_lock.locked() or not self._audit_idle_event.is_set()

    def wait_for_audit(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for any active in-flight live audit to complete.

        Atomically checks state and waits on the idle event if an audit is in progress.
        Does not steal the audit lock, busy-wait, or cause false 409 rejections.
        Returns True if no audit is running or the audit completed within timeout, False otherwise.
        """
        deadline = (time.monotonic() + timeout) if timeout is not None else None

        while True:
            with self._audit_state_lock:
                if self._audit_idle_event.is_set() and not self.audit_lock.locked():
                    return True
                event = self._audit_idle_event

            rem = None
            if deadline is not None:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    return False

            if not event.wait(timeout=rem):
                return False

    def start(self) -> None:
        """Start listening and serving HTTP requests indefinitely with threaded connection handling."""
        if self._started:
            if self.httpd is not None:
                raise RuntimeError("Server is already running")
            raise RuntimeError(
                "Restarting an LpeSentinelWebServer instance is not supported; "
                "instantiate a new server using create_web_server()."
            )
        self._started = True
        try:
            self.httpd = ThreadingHTTPServer((self.host, self.requested_port), LpeSentinelWebHandler)
            self.httpd.daemon_threads = True
            self.httpd.csrf_token = self.csrf_token
            self.httpd.audit_lock = self.audit_lock
            self.httpd._audit_state_lock = self._audit_state_lock
            self.httpd._audit_idle_event = self._audit_idle_event
            self.httpd.acquire_audit = self.acquire_audit
            self.httpd.release_audit = self.release_audit
            self.httpd.history_manager = self.history_manager
            print(f"[*] LPE-Sentinel Web Dashboard running at: http://{self.host}:{self.server_port}/")
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping LPE-Sentinel Web Server...")
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        """Gracefully stop the server and release sockets. Thread-safe and idempotent."""
        with self._shutdown_lock:
            self._is_shut_down = True
            if self.httpd is not None:
                httpd = self.httpd
                self.httpd = None
                try:
                    httpd.shutdown()
                    httpd.server_close()
                except Exception:
                    pass


def create_web_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    db_path: Optional[str] = None,
    history_manager: Optional[Any] = None,
) -> LpeSentinelWebServer:
    """Factory function for creating an LpeSentinelWebServer instance."""
    return LpeSentinelWebServer(host=host, port=port, db_path=db_path, history_manager=history_manager)
