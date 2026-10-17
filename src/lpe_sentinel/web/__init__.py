"""
Web application package for LPE Sentinel.

Provides a self-contained, standard-library HTTP dashboard for reviewing
security audit results and inspecting vulnerability metrics.
"""

from lpe_sentinel.web.server import LpeSentinelWebServer, create_web_server

__all__ = ["LpeSentinelWebServer", "create_web_server"]
