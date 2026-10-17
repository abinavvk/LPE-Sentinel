"""
Vercel Python function entry point: hosted status (native route `/api/status`).

Selected by Vercel's documented file-based function mapping. No rewrite is
involved, so the request path is this route's own path and the handler does not
depend on recovering the client's original URL.

Read-only. Exposes minimized deployment metadata only.
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


class handler(HostedHandlerBase):
    """Serves hosted deployment status JSON for the `/api/status` route."""

    def _route(self, is_head: bool = False) -> None:
        self.send_status(is_head=is_head)
