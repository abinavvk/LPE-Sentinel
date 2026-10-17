"""
Vercel Python function entry point: cloud history (native route `/api/history`).

Cloud audit history requires persistent storage, which a serverless function does
not have, so this route intentionally returns a JSON 404 rather than an HTML
error page. Selecting it explicitly preserves the documented JSON 404 contract
without resorting to a catch-all rewrite that would break native route selection.

Read-only. Never touches SQLite or any other storage backend.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from lpe_sentinel.web.hosted import HostedHandlerBase
except ImportError as err:
    raise RuntimeError(
        f"LPE-Sentinel Vercel deployment error: Failed to import package components from {SRC_DIR}. "
        f"Ensure repository source tree is intact. Details: {err}"
    ) from err

HISTORY_ROUTE = "/api/history"


class handler(HostedHandlerBase):
    """Serves the intentional JSON 404 for the `/api/history` route."""

    def _route(self, is_head: bool = False) -> None:
        self.send_not_found(HISTORY_ROUTE, is_head=is_head)
