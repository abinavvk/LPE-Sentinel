"""
Vercel Python function entry point: simulated demo audit (route `/api/demo-audit`).

Selected by Vercel's documented file-based function mapping. No rewrite is
involved, so the handler does not depend on recovering the original URL.

Read-only. Returns synthetic, explicitly watermarked demo findings only. It
never runs a live host audit and never executes a shell command.
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
    """Serves simulated demo audit JSON for the `/api/demo-audit` route."""

    def _route(self, is_head: bool = False) -> None:
        self.send_demo_audit(is_head=is_head)
