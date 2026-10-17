"""
Vercel Python function entry point for LPE-Sentinel's hosted deployment.

Verified against a live preview deployment: Vercel detects `framework: python`
and builds a single Python Lambda, so additional `api/*.py` files do not become
separately deployed routes. This module is therefore the one entry point, and it
dispatches on the original client request path, which the runtime does supply
intact (for example `/api/status`).

Routes served:
    /, /index.html, /api      -> hosted dashboard HTML
    /api/status               -> hosted deployment status JSON
    /api/demo-audit           -> simulated demo audit JSON (clearly labelled)
    /api/history              -> intentional JSON 404 (hosted history unavailable)
    anything else             -> JSON 404
    POST/PUT/PATCH/DELETE     -> 405

Read-only. Serves no live host audit, no shell execution, and no SQLite access.
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
    """Single hosted entry point; routing is defined by HostedHandlerBase.dispatch()."""

    def _route(self, is_head: bool = False) -> None:
        self.dispatch(is_head=is_head)