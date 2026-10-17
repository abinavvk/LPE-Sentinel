"""
Vercel Python function entry point: hosted dashboard (native route `/api`).

Selection is performed by Vercel's documented file-based function mapping, so
this handler never needs to recover the client's original URL. `/` and
`/index.html` reach the dashboard through the two narrow rewrites declared in
vercel.json, which resolve to this route.

Read-only. Serves no live audit, no shell execution, and no SQLite access.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from lpe_sentinel.web.hosted import DASHBOARD_PATHS, HostedHandlerBase
except ImportError as err:
    raise RuntimeError(
        f"LPE-Sentinel Vercel deployment error: Failed to import package components from {SRC_DIR}. "
        f"Ensure repository source tree is intact. Details: {err}"
    ) from err


class handler(HostedHandlerBase):
    """Serves the hosted dashboard for the `/api` route."""

    def _route(self, is_head: bool = False) -> None:
        path = self.normalized_path()
        if path in DASHBOARD_PATHS:
            self.send_dashboard(is_head=is_head)
        else:
            self.send_not_found(path, is_head=is_head)
