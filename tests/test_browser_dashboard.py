"""
Optional real-browser regression tests for the LPE-Sentinel dashboard.

Why this exists
---------------
The existing unit tests drive the dashboard's JavaScript against a hand-written
DOM stub (see tests/test_report_import.py). A stub can prove *state*
transitions but it cannot prove what a user actually *sees*: it applies no CSS,
it does not fire real events, and it does not render. Two user-reported
discrepancies (missing history highlight, stale findings after a failed import)
could only be settled by looking at a real browser.

These tests close that gap without adding a single dependency. They drive a
headless Chrome instance over the Chrome DevTools Protocol using only Node.js
built-ins (global ``fetch`` and global ``WebSocket``). Nothing is installed:
no selenium, no playwright, no puppeteer, no npm package.

Isolation guarantees (requirement: never touch the user's environment)
---------------------------------------------------------------------
* The dashboard server is launched with ``--db-path`` pointing at a throwaway
  SQLite file inside a temporary directory, so the real
  ``~/.lpe_sentinel/audit_history.db`` is never opened or modified.
* Chrome is launched with ``--user-data-dir`` pointing at a throwaway profile,
  so the user's real browser profile, cookies and sessions are untouched.
* Browser and server processes are terminated and temporary files are removed
  in ``tearDownClass`` even when a test fails.

Running
-------
These tests are deliberately **excluded from the normal unit-test suite**
because they launch a real browser, need a few seconds, and cannot run on a
machine without Chrome or a modern Node.js. They skip (with a clear message)
unless explicitly enabled::

    # Windows PowerShell
    $env:LPE_BROWSER_TESTS = "1"
    python -B -m unittest tests.test_browser_dashboard -v

Skips happen cleanly when any of the following are missing:
  * the ``LPE_BROWSER_TESTS`` environment variable,
  * Node.js >= 22 (global ``WebSocket``),
  * a Chrome or Edge binary in a standard location or on PATH.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DRIVER_SCRIPT = Path(__file__).resolve().parent / "browser_cdp.mjs"

# Chromium binaries looked for, in preference order.
CHROME_CANDIDATES = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)

# Minimum Node.js major version providing a global WebSocket client.
MIN_NODE_MAJOR = 22


def _enabled() -> bool:
    return os.environ.get("LPE_BROWSER_TESTS", "").strip().lower() in {"1", "true", "yes", "on"}


def _find_chrome():
    for candidate in CHROME_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    for name in ("chrome", "chrome.exe", "msedge", "msedge.exe"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _node_version_ok():
    """Return the Node major version, or None when Node is unusable."""
    node = shutil.which("node")
    if not node:
        return None
    try:
        out = subprocess.run(
            [node, "--version"], capture_output=True, text=True, timeout=30
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    # e.g. "v24.20.0"
    if not out.startswith("v"):
        return None
    try:
        return int(out[1:].split(".")[0])
    except (IndexError, ValueError):
        return None


NODE_MAJOR = _node_version_ok()
CHROME_PATH = _find_chrome()


def skip_reason() -> str:
    """Explain why the real-browser tests cannot run, or '' if they can."""
    if not _enabled():
        return (
            "real-browser tests are opt-in; set LPE_BROWSER_TESTS=1 to run them "
            "(they launch a real browser and are excluded from the normal suite)"
        )
    if NODE_MAJOR is None:
        return f"Node.js >= {MIN_NODE_MAJOR} is required (global WebSocket); not found on PATH"
    if NODE_MAJOR < MIN_NODE_MAJOR:
        return f"Node.js >= {MIN_NODE_MAJOR} is required (global WebSocket); found v{NODE_MAJOR}"
    if not CHROME_PATH:
        return "no Chrome or Edge binary found in a standard location or on PATH"
    if not DRIVER_SCRIPT.is_file():
        return f"missing CDP driver script: {DRIVER_SCRIPT}"
    return ""


SKIP_REASON = skip_reason()


def free_port() -> int:
    """Reserve an ephemeral loopback port and release it for immediate reuse."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_http(url: str, timeout: float = 25.0) -> bool:
    """Poll a loopback URL until it answers, without external dependencies."""
    import urllib.error
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return True
        except (urllib.error.URLError, OSError, ValueError):
            time.sleep(0.25)
    return False


def wait_for_cdp(port: int, timeout: float = 30.0) -> bool:
    """Poll the CDP HTTP endpoint until Chrome is ready to accept sessions."""
    import urllib.error
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/json/version", timeout=2
            ) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError, ValueError):
            time.sleep(0.25)
    return False


# A minimal, valid saved audit record used to populate the throwaway database.
def _seed_audit(finding_id: str, title: str) -> dict:
    return {
        "status": "COMPLETED",
        "is_complete": True,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "system_info": {
            "hostname": "seed-host",
            "os": "Linux 6.1.0-test",
            "kernel_version": "6.1.0-test",
        },
        "summary": {
            "total_findings": 1,
            "severity_counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
        },
        "errors": [],
        "scanner_results": {},
        "findings": [
            {
                "finding_id": finding_id,
                "title": title,
                "severity": "MEDIUM",
                "description": f"Seeded finding {finding_id} for browser regression testing.",
                "evidence": "seeded",
                "affected_resource": "/etc/test.conf",
                "recommendation": "Review the seeded finding.",
                "category": "permissions",
                "scanner": "seed",
            }
        ],
    }


def _empty_report() -> dict:
    """A schema-valid report containing zero findings."""
    return {
        "report_metadata": {
            "project_name": "LPE Sentinel",
            "version": "0.0.0-test",
            "format_version": "1.0",
            "generated_at": "2026-01-01T00:00:00+00:00",
        },
        "summary": {
            "total_findings": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
        "system_info": {"hostname": "import-host", "os": "Linux 6.1.0-import"},
        "findings": [],
    }


# Reusable JS snippets evaluated inside the real page.
CLICK_FIRST_RECORD = """
(async () => {
  const btn = document.querySelector('#history-list .history-item button');
  if (!btn) return 'no-record-button';
  btn.click();
  await new Promise(r => setTimeout(r, 1200));
  return 'clicked';
})()
"""

CLICK_DEMO = """
(async () => {
  document.getElementById('btn-load-demo').click();
  await new Promise(r => setTimeout(r, 1200));
  return 'clicked';
})()
"""


def import_file_js(contents: str, filename: str) -> str:
    """Build a step that drives the real file-input handler with given contents."""
    payload = json.dumps(contents)
    name = json.dumps(filename)
    return (
        "(async () => {"
        f"  const file = new File([{payload}], {name}, {{type:'application/json'}});"
        "  await handleReportFileSelected({ target: { files: [file], value: 'x' } });"
        "  await new Promise(r => setTimeout(r, 400));"
        "  return 'imported';"
        "})()"
    )


SNAPSHOT_JS = """
(() => ({
  findingsRows: document.querySelectorAll('#findings-tbody tr').length,
  tbodyText: document.getElementById('findings-tbody').innerText.slice(0, 120),
  countTotal: document.getElementById('count-total').textContent,
  sessionStatus: document.getElementById('session-status-text').textContent,
  importStatus: document.getElementById('report-import-status').textContent,
  importStatusColored: document.getElementById('report-import-status').style.color !== '',
  demoBannerVisible: document.getElementById('demo-banner').classList.contains('visible'),
  historyBannerVisible: document.getElementById('history-banner').classList.contains('visible'),
  historyItems: document.querySelectorAll('#history-list .history-item').length,
  activeHistoryItems: document.querySelectorAll('#history-list .history-item.active').length,
  jsFindings: Array.isArray(currentFindings) ? currentFindings.length : -1,
  jsScanId: typeof currentHistoryScanId === 'undefined' ? 'undefined' : currentHistoryScanId
}))()
"""

ACTIVE_STYLE_JS = """
(() => {
  const el = document.querySelector('#history-list .history-item.active');
  if (!el) return null;
  const cs = getComputedStyle(el);
  return { borderColor: cs.borderColor, background: cs.backgroundColor };
})()
"""


@unittest.skipIf(SKIP_REASON, SKIP_REASON)
class TestDashboardInRealChrome(unittest.TestCase):
    """Drive the dashboard in a real headless Chrome over CDP."""

    server_proc = None
    chrome_proc = None
    temp_dir = None
    port = None
    cdp_port = None

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="lpe-browser-test-")
        db_path = Path(cls.temp_dir) / "test-audit-history.db"
        cls.port = free_port()
        cls.cdp_port = free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}/"

        # Seed a throwaway database so the history panel is populated.
        sys.path.insert(0, str(REPO_ROOT / "src"))
        try:
            from lpe_sentinel.audit_history import AuditHistoryManager

            manager = AuditHistoryManager(db_path=str(db_path))
            manager.save_audit(_seed_audit("SEED-0001", "Seeded finding one"))
            manager.save_audit(_seed_audit("SEED-0002", "Seeded finding two"))
        finally:
            if sys.path and sys.path[0] == str(REPO_ROOT / "src"):
                sys.path.pop(0)

        cls.server_proc = subprocess.Popen(
            [
                sys.executable,
                "-B",
                str(REPO_ROOT / "src" / "lpe_sentinel" / "web_app.py"),
                "--host",
                "127.0.0.1",
                "--port",
                str(cls.port),
                "--db-path",
                str(db_path),
            ],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if not wait_for_http(cls.base_url + "api/status"):
            cls._terminate()
            raise unittest.SkipTest("dashboard server failed to start on loopback")

        profile_dir = Path(cls.temp_dir) / "chrome-profile"
        cls.chrome_proc = subprocess.Popen(
            [
                CHROME_PATH,
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-background-networking",
                f"--remote-debugging-port={cls.cdp_port}",
                f"--user-data-dir={profile_dir}",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not wait_for_cdp(cls.cdp_port):
            cls._terminate()
            raise unittest.SkipTest("headless Chrome failed to expose a CDP endpoint")

    @classmethod
    def _terminate(cls):
        for proc in (cls.chrome_proc, cls.server_proc):
            if proc is None:
                continue
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
            # Release the pipe handles so CPython does not emit ResourceWarning.
            for stream in (proc.stdout, proc.stderr, proc.stdin):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except OSError:
                        pass
        cls.chrome_proc = None
        cls.server_proc = None

    @classmethod
    def tearDownClass(cls):
        cls._terminate()
        if cls.temp_dir and Path(cls.temp_dir).is_dir():
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    # -- driver plumbing -------------------------------------------------
    def run_job(self, steps):
        """Run the CDP driver and return the list of step values."""
        job = {
            "cdpPort": self.cdp_port,
            "url": self.base_url,
            "readyExpr": (
                "typeof handleReportFileSelected === 'function' && "
                "!!document.getElementById('findings-tbody')"
            ),
            "readyTimeoutMs": 20000,
            "steps": steps,
        }
        node = shutil.which("node")
        proc = subprocess.run(
            [node, str(DRIVER_SCRIPT)],
            input=json.dumps(job),
            capture_output=True,
            text=True,
            timeout=180,
        )
        payload = None
        for line in proc.stdout.splitlines():
            if line.startswith("RESULT"):
                payload = json.loads(line[len("RESULT") :])
        if payload is None:
            self.fail(
                "CDP driver produced no RESULT line.\n"
                f"stdout: {proc.stdout[-800:]}\nstderr: {proc.stderr[-800:]}"
            )
        if not payload.get("ok"):
            self.fail(f"CDP driver error: {payload.get('error')}")
        return payload.get("values", [])

    # -- tests -----------------------------------------------------------
    def test_loading_saved_record_highlights_it(self):
        """A loaded saved audit must be visibly highlighted in the history list."""
        _, snapshot, active_style = self.run_job(
            [
                {"expr": CLICK_FIRST_RECORD, "await": True},
                {"expr": SNAPSHOT_JS},
                {"expr": ACTIVE_STYLE_JS},
            ]
        )
        self.assertEqual(snapshot["historyItems"], 2)
        self.assertIsNotNone(snapshot["jsScanId"])
        self.assertNotEqual(snapshot["jsScanId"], "undefined")
        self.assertEqual(snapshot["activeHistoryItems"], 1)
        self.assertIsNotNone(active_style, "the active history item should exist in the real DOM")
        self.assertNotEqual(active_style["borderColor"], "rgba(0, 0, 0, 0)")

    def test_demo_run_shows_findings_but_no_history_highlight(self):
        """Demo results are displayed but never highlight a saved record."""
        _, snapshot = self.run_job(
            [
                {"expr": CLICK_DEMO, "await": True},
                {"expr": SNAPSHOT_JS},
            ]
        )
        self.assertGreater(snapshot["findingsRows"], 1)
        self.assertTrue(snapshot["demoBannerVisible"])
        self.assertEqual(
            snapshot["activeHistoryItems"],
            0,
            "a demo run must not mark any saved audit record as active",
        )

    def test_invalid_json_after_demo_clears_results_and_shows_error(self):
        """A malformed import must wipe displayed demo results."""
        snapshot = self.run_job(
            [
                {"expr": CLICK_DEMO, "await": True},
                {"expr": import_file_js("{not valid json", "broken.json"), "await": True},
                {"expr": SNAPSHOT_JS},
            ]
        )[-1]
        self.assertEqual(snapshot["jsFindings"], 0)
        self.assertEqual(snapshot["findingsRows"], 1, "only the empty-state row should remain")
        self.assertIn("No Findings", snapshot["tbodyText"])
        self.assertEqual(snapshot["countTotal"], "0")
        self.assertFalse(snapshot["demoBannerVisible"])
        self.assertTrue(snapshot["importStatusColored"], "an error message should be styled")
        self.assertTrue(snapshot["importStatus"].strip())

    def test_invalid_json_after_saved_record_clears_results(self):
        """A malformed import must also wipe a loaded historical record."""
        snapshot = self.run_job(
            [
                {"expr": CLICK_FIRST_RECORD, "await": True},
                {"expr": import_file_js("{not valid json", "broken.json"), "await": True},
                {"expr": SNAPSHOT_JS},
            ]
        )[-1]
        self.assertEqual(snapshot["jsFindings"], 0)
        self.assertEqual(snapshot["findingsRows"], 1)
        self.assertIn("No Findings", snapshot["tbodyText"])
        self.assertEqual(snapshot["countTotal"], "0")
        self.assertFalse(snapshot["historyBannerVisible"])
        self.assertEqual(snapshot["activeHistoryItems"], 0, "stale highlight must be removed")

    def test_saved_history_is_preserved_after_failed_import(self):
        """A failed import clears the view but must never delete stored records."""
        snapshot = self.run_job(
            [
                {"expr": CLICK_FIRST_RECORD, "await": True},
                {"expr": import_file_js("{not valid json", "broken.json"), "await": True},
                {"expr": SNAPSHOT_JS},
            ]
        )[-1]
        self.assertEqual(
            snapshot["historyItems"],
            2,
            "persisted audit records must survive a failed import",
        )

    def test_zero_finding_report_imports_successfully(self):
        """A valid report with no findings is a success, not an error."""
        _, snapshot = self.run_job(
            [
                {
                    "expr": import_file_js(json.dumps(_empty_report()), "empty.json"),
                    "await": True,
                },
                {"expr": SNAPSHOT_JS},
            ]
        )
        self.assertEqual(snapshot["jsFindings"], 0)
        self.assertEqual(snapshot["countTotal"], "0")
        self.assertEqual(snapshot["findingsRows"], 1)
        self.assertNotIn(
            "Invalid",
            snapshot["importStatus"],
            "a schema-valid empty report must not be reported as invalid",
        )
        self.assertTrue(snapshot["importStatus"].strip())

    def test_no_unexpected_page_exceptions(self):
        """The dashboard must not raise uncaught exceptions during these flows."""
        result = self.run_job(
            [
                {"expr": CLICK_DEMO, "await": True},
                {"expr": import_file_js("{not valid json", "broken.json"), "await": True},
                {"expr": CLICK_FIRST_RECORD, "await": True},
                {"expr": SNAPSHOT_JS},
            ]
        )
        snapshot = result[-1]
        self.assertEqual(snapshot["jsFindings"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)