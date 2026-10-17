"""
Standalone Web Application Entry Point for LPE Sentinel.

Distinct from the interactive CLI entry point (main.py). Starts the self-contained
HTTP web dashboard on a configurable interface and port.

Usage:
    python -m lpe_sentinel.web_app [--host HOST] [--port PORT] [--open-browser]
    python src/lpe_sentinel/web_app.py [--host HOST] [--port PORT]
"""

import argparse
import sys
import webbrowser
from pathlib import Path

# Allow direct script execution without manual PYTHONPATH modification
PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

try:
    from lpe_sentinel import __version__
    from lpe_sentinel.web.server import LpeSentinelWebServer
except ImportError:
    from __version__ import __version__
    from web.server import LpeSentinelWebServer


def parse_args(args=None) -> argparse.Namespace:
    """Parse command line arguments for the web application runner."""
    parser = argparse.ArgumentParser(
        description="LPE-Sentinel Defensive Security Auditing — Web Dashboard Server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Network interface to bind (e.g. 127.0.0.1 or 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port number to listen on",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Automatically open the dashboard URL in default web browser",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Path to SQLite audit history database (default: ~/.lpe_sentinel/audit_history.db)",
    )
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="Explicitly acknowledge and allow binding to non-loopback interfaces without TLS or auth",
    )
    return parser.parse_args(args)


def is_loopback_host(host: str) -> bool:
    """Determine whether the specified host string resolves to a local loopback interface."""
    clean = (host or "").strip().lower()
    return clean in ("127.0.0.1", "localhost", "::1")


def main() -> None:
    """Run the standalone web server."""
    options = parse_args()

    print("=" * 64)
    print(" LPE Sentinel — Web Dashboard Foundation (Task 4A) ")
    print(f" Version : {__version__}")
    print("=" * 64)
    print("[*] Mode   : Defensive Web Dashboard Interface")
    print("[*] Scope  : Read-Only & Zero External Dependencies")
    print(f"[*] Server : http://{options.host}:{options.port}/")
    print("=" * 64)

    if not is_loopback_host(options.host):
        if not options.allow_non_loopback:
            print(
                f"[!] SECURITY REFUSAL: Non-loopback host '{options.host}' requested without explicit acknowledgement.\n"
                "    LPE-Sentinel lacks authentication and TLS encryption by design.\n"
                "    To bind to non-loopback interfaces on isolated test networks, you must explicitly pass:\n"
                "    --allow-non-loopback",
                file=sys.stderr,
            )
            sys.exit(1)

        print(
            f"[!] SECURITY WARNING: Binding to non-loopback address '{options.host}'.\n"
            "    This unauthenticated dashboard is reachable across the local network.\n"
            "    Only bind to 0.0.0.0 on trusted, isolated internal test networks.",
            file=sys.stderr,
        )

    server = LpeSentinelWebServer(host=options.host, port=options.port, db_path=options.db_path)

    if options.open_browser:
        try:
            webbrowser.open(f"http://{options.host}:{options.port}/")
        except Exception:
            pass

    try:
        server.start()
    except Exception as exc:
        print(f"[!] Server error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
