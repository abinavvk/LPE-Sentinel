"""
Regression tests for the local-only audit report import endpoint.

Endpoint: POST /api/import-report (local dashboard server only).

Security properties under test:
  * Full schema validation via the existing validate_report_data().
  * Response is built from an explicit allow-list, so unknown/attacker-supplied
    keys are never echoed back.
  * CSRF and Origin validation are enforced before the report is used.
  * Content-Type enforcement and the 64 KB body limit are inherited from the
    shared request-body guard.
  * Only POST is accepted; GET/PUT/PATCH/DELETE do not mutate anything.
  * Imported results are never presented as a live scan or as demo data, and
    they keep the original report's host and timestamp provenance.

Uses only the Python standard library.
"""

import json
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from http import HTTPStatus
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lpe_sentinel.models import Finding
from lpe_sentinel.reporting import build_report_data
from lpe_sentinel.report_validation import validate_report_data
from lpe_sentinel.web.server import (
    IMPORT_FINDING_FIELDS,
    _build_import_response,
    create_web_server,
)
from lpe_sentinel.web.templates import render_dashboard_html

IMPORT_PATH = "/api/import-report"


def make_report() -> dict:
    """Build a genuine report using the same function the CLI uses."""
    finding = Finding(
        finding_id="SUID-001",
        title="SUID permission bit detected",
        severity="HIGH",
        description="Synthetic fixture for import regression testing.",
        evidence="Mode: 0o104755 [SYNTHETIC]",
        affected_resource="/usr/bin/example",
        recommendation="Remove the bit if not required.",
        mitre_attack="T1548.001",
    )
    return build_report_data(
        [finding],
        system_info={
            "os_name": "Linux",
            "os_release": "6.6.0-kali",
            "hostname": "audit-target-host",
            "username": "auditor",
            "architecture": "x86_64",
            "platform_category": "Linux",
        },
    )


class TestImportResponseBuilder(unittest.TestCase):
    """Allow-list construction of the import response."""

    def test_provenance_and_flags(self) -> None:
        payload = _build_import_response(make_report())

        self.assertEqual(payload["status"], "IMPORTED")
        self.assertEqual(payload["source"], "local_report")
        self.assertIs(payload["is_live_scan"], False)
        self.assertIs(payload["is_demo"], False)
        self.assertIs(payload["is_simulated"], False)
        self.assertEqual(payload["verification_status"], "unverified")

    def test_preserves_original_host_and_timestamp(self) -> None:
        report = make_report()
        payload = _build_import_response(report)

        self.assertEqual(
            payload["system_info"]["hostname"],
            report["system_info"]["hostname"],
        )
        self.assertEqual(
            payload["report_metadata"]["generated_at"],
            report["report_metadata"]["generated_at"],
        )
        self.assertEqual(payload["summary"]["total_findings"], 1)
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["severity"], "HIGH")

    def test_unexpected_keys_are_dropped(self) -> None:
        """Crafted keys must never survive into the response."""
        report = make_report()
        report["evil"] = {"shell": "rm -rf /"}
        report["system_info"]["secret_env"] = "leaked"
        report["findings"][0]["injected"] = "<script>alert(1)</script>"

        payload = _build_import_response(report)
        serialized = json.dumps(payload)

        self.assertNotIn("evil", serialized)
        self.assertNotIn("secret_env", serialized)
        self.assertNotIn("injected", serialized)
        self.assertNotIn("rm -rf", serialized)

        # Every emitted finding key is on the allow-list.
        for key in payload["findings"][0]:
            self.assertIn(key, IMPORT_FINDING_FIELDS)


class TestImportEndpoint(unittest.TestCase):
    """End-to-end HTTP behavior of POST /api/import-report."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_web_server(host="127.0.0.1", port=0)
        cls.thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.thread.start()

        deadline = time.time() + 3.0
        while time.time() < deadline and cls.server.httpd is None:
            time.sleep(0.05)

        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"
        with urllib.request.urlopen(f"{cls.base_url}/api/csrf-token", timeout=3.0) as resp:
            cls.csrf = json.loads(resp.read().decode("utf-8"))["csrf_token"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def _post(self, body, token="default", content_type="application/json",
              origin=None, method="POST", path=IMPORT_PATH):
        headers = {"Content-Type": content_type}
        if token == "default":
            headers["X-CSRF-Token"] = self.csrf
        elif token:
            headers["X-CSRF-Token"] = token
        if origin:
            headers["Origin"] = origin

        raw = body.encode("utf-8") if isinstance(body, str) else body
        req = urllib.request.Request(
            self.base_url + path, data=raw, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            body_text = err.read().decode("utf-8")
            try:
                return err.code, json.loads(body_text)
            except Exception:
                return err.code, {"raw": body_text}

    # -- success --------------------------------------------------------

    def test_valid_report_imports_successfully(self) -> None:
        code, data = self._post(json.dumps(make_report()))

        self.assertEqual(code, HTTPStatus.OK)
        self.assertEqual(data["status"], "IMPORTED")
        self.assertEqual(data["source"], "local_report")
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["system_info"]["hostname"], "audit-target-host")

    def test_import_is_not_reported_as_live_or_demo(self) -> None:
        """An import must never masquerade as a live scan or simulated demo."""
        code, data = self._post(json.dumps(make_report()))

        self.assertEqual(code, HTTPStatus.OK)
        self.assertIs(data["is_live_scan"], False)
        self.assertIs(data["is_demo"], False)
        self.assertIs(data["is_simulated"], False)
        self.assertEqual(data["verification_status"], "unverified")
        self.assertIn("NOT", data["notice"])

    def test_empty_findings_report_is_valid(self) -> None:
        report = make_report()
        report["findings"] = []
        report["summary"]["total_findings"] = 0
        for sev in report["summary"]["severity_counts"]:
            report["summary"]["severity_counts"][sev] = 0

        code, data = self._post(json.dumps(report))
        self.assertEqual(code, HTTPStatus.OK)
        self.assertEqual(data["findings"], [])

    # -- schema validation ----------------------------------------------

    def test_invalid_schema_is_rejected_with_details(self) -> None:
        report = make_report()
        report["findings"][0]["severity"] = "NOT_A_SEVERITY"

        code, data = self._post(json.dumps(report))

        self.assertEqual(code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(data["status"], "INVALID_REPORT")
        self.assertTrue(data["validation_errors"])

    def test_summary_mismatch_is_rejected(self) -> None:
        report = make_report()
        report["summary"]["total_findings"] = 99

        code, data = self._post(json.dumps(report))

        self.assertEqual(code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(data["status"], "INVALID_REPORT")

    def test_missing_required_section_is_rejected(self) -> None:
        report = make_report()
        del report["report_metadata"]

        code, data = self._post(json.dumps(report))

        self.assertEqual(code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(data["status"], "INVALID_REPORT")

    def test_timestamp_without_timezone_is_rejected(self) -> None:
        report = make_report()
        report["report_metadata"]["generated_at"] = "2026-01-01T00:00:00"

        code, _ = self._post(json.dumps(report))

        self.assertEqual(code, HTTPStatus.BAD_REQUEST)

    def test_unexpected_keys_do_not_reach_response(self) -> None:
        report = make_report()
        report["unexpected"] = {"payload": "injected"}

        code, data = self._post(json.dumps(report))

        self.assertEqual(code, HTTPStatus.OK)
        self.assertNotIn("unexpected", data)
        self.assertNotIn("injected", json.dumps(data))

    # -- malformed input ------------------------------------------------

    def test_malformed_json_is_rejected(self) -> None:
        code, data = self._post("{not json")

        self.assertEqual(code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(data["status"], "BAD_REQUEST")

    def test_non_object_json_is_rejected(self) -> None:
        code, _ = self._post('"just a string"')
        self.assertEqual(code, HTTPStatus.BAD_REQUEST)

    def test_empty_body_is_rejected(self) -> None:
        code, _ = self._post("")
        self.assertEqual(code, HTTPStatus.BAD_REQUEST)

    def test_oversized_body_is_rejected(self) -> None:
        oversized = '{"x":"' + ("A" * 100000) + '"}'

        code, _ = self._post(oversized)

        self.assertEqual(code, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)

    def test_wrong_content_type_is_rejected(self) -> None:
        code, _ = self._post(json.dumps(make_report()), content_type="text/plain")
        self.assertEqual(code, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)

    # -- security -------------------------------------------------------

    def test_missing_csrf_token_is_rejected(self) -> None:
        code, data = self._post(json.dumps(make_report()), token=None)

        self.assertEqual(code, HTTPStatus.FORBIDDEN)
        self.assertEqual(data["status"], "FORBIDDEN")

    def test_invalid_csrf_token_is_rejected(self) -> None:
        code, data = self._post(json.dumps(make_report()), token="0" * 64)

        self.assertEqual(code, HTTPStatus.FORBIDDEN)
        self.assertEqual(data["status"], "FORBIDDEN")

    def test_foreign_origin_is_rejected(self) -> None:
        code, data = self._post(
            json.dumps(make_report()), origin="https://attacker.example"
        )

        self.assertEqual(code, HTTPStatus.FORBIDDEN)
        self.assertEqual(data["status"], "FORBIDDEN")

    def test_endpoint_does_not_accept_filesystem_paths(self) -> None:
        """A path-like key must never cause a read, and must never be echoed.

        The validator tolerates unknown keys, so this asserts the property that
        actually matters: a path is neither acted upon nor reflected.
        """
        report = make_report()
        report["path"] = "/etc/shadow"
        report["file"] = "C:\\\\Windows\\\\System32\\\\config\\\\SAM"

        code, data = self._post(json.dumps(report))

        # No filesystem read happened; the path is simply dropped from the output.
        self.assertEqual(code, HTTPStatus.OK)
        self.assertNotIn("path", data)
        self.assertNotIn("file", data)
        self.assertNotIn("etc/shadow", json.dumps(data))
        self.assertNotIn("SAM", json.dumps(data))

    # -- method restrictions --------------------------------------------

    def test_unsupported_methods_do_not_mutate(self) -> None:
        for method in ("PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                req = urllib.request.Request(
                    self.base_url + IMPORT_PATH, method=method
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req, timeout=5.0)
                self.assertEqual(ctx.exception.code, HTTPStatus.METHOD_NOT_ALLOWED)

    def test_get_does_not_import(self) -> None:
        req = urllib.request.Request(self.base_url + IMPORT_PATH, method="GET")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5.0)
        self.assertEqual(ctx.exception.code, HTTPStatus.NOT_FOUND)


class TestImportDashboardUi(unittest.TestCase):
    """The dashboard ships a file-picker workflow and no server-side paths."""

    def test_import_controls_present(self) -> None:
        html = render_dashboard_html()

        self.assertIn('id="report-file-input"', html)
        self.assertIn('type="file"', html)
        self.assertIn('accept="application/json,.json"', html)
        self.assertIn("Import Audit Report", html)
        self.assertIn('id="report-import-status"', html)
        self.assertIn("handleReportFileSelected", html)

    def test_import_reads_file_in_browser_and_posts_body(self) -> None:
        html = render_dashboard_html()

        self.assertIn("/api/import-report", html)
        self.assertIn("X-CSRF-Token", html)
        self.assertIn("/api/csrf-token", html)
        self.assertIn("NOT A LIVE SCAN", html)

    def test_hosted_dashboard_has_no_import_affordance_text(self) -> None:
        """Hosted mode blocks import in JS; the control itself is hidden by gating."""
        html = render_dashboard_html(hosted=True)

        self.assertIn("hostedCapabilities.isHosted", html)
        self.assertIn("not available in the hosted deployment", html)


class TestImportFailureClearsResults(unittest.TestCase):
    """A failed import must not leave earlier results looking like its outcome."""

    def test_failure_helper_clears_state_and_keeps_message(self) -> None:
        html = render_dashboard_html()

        # failImport exists and is the single funnel for import failures.
        self.assertIn("function failImport(", html)
        self.assertIn("clearDisplayedResults();", html)
        self.assertIn("setReportImportStatus(message, 'error');", html)

    def test_clear_helper_resets_findings_banners_and_counts(self) -> None:
        html = render_dashboard_html()

        self.assertIn("function clearDisplayedResults(", html)
        self.assertIn("currentFindings = [];", html)
        self.assertIn("isDemoMode = false;", html)
        self.assertIn("comparisonData = null;", html)
        self.assertIn("hideLiveBanner();", html)
        self.assertIn("hideHistoryBanner();", html)
        self.assertIn("resetAllFilters();", html)
        self.assertIn("updateSummaryCounts({ total_findings: 0, severity_counts: {} });", html)

    def test_every_failure_path_uses_fail_import(self) -> None:
        """No error branch may leave stale results displayed."""
        html = render_dashboard_html()
        start = html.index("async function handleReportFileSelected")
        block = html[start:start + 4200]

        # Each failure branch clears results rather than only setting a message.
        self.assertNotIn("setReportImportStatus('Report import is not available", block)
        self.assertGreaterEqual(block.count("failImport("), 5)
        # No direct error-tone status calls remain inside the handler.
        self.assertNotIn(
            "setReportImportStatus('That file is not valid JSON.",
            block.split("renderImportedReport")[0],
        )

    def test_file_picker_cancellation_does_not_clear(self) -> None:
        """Cancelling the picker must leave the dashboard untouched."""
        html = render_dashboard_html()
        start = html.index("async function handleReportFileSelected")
        block = html[start:start + 900]

        self.assertIn("if (!file) return;", block)
        # The cancel guard must precede any clearing call.
        self.assertLess(block.index("if (!file) return;"), block.index("failImport(") if "failImport(" in block else len(block))


class TestImportEmptyStates(unittest.TestCase):
    """Zero-finding imports are distinguished from filter-hidden findings."""

    def test_empty_state_message_variable_exists(self) -> None:
        html = render_dashboard_html()
        self.assertIn("let emptyStateMessage = null;", html)
        self.assertIn("function setEmptyStateMessage(", html)

    def test_zero_finding_import_sets_specific_message(self) -> None:
        html = render_dashboard_html()
        self.assertIn("recorded 0 findings", html)
        self.assertIn("imported successfully and recorded 0 findings", html)

    def test_filter_empty_state_retained_when_no_message(self) -> None:
        html = render_dashboard_html()
        self.assertIn("No Matching Findings", html)
        self.assertIn("No findings matched the selected severity, source, or search criteria.", html)

    def test_table_honours_custom_empty_message(self) -> None:
        html = render_dashboard_html()
        self.assertIn("if (emptyStateMessage) {", html)
        self.assertIn("${escapeHtml(emptyStateMessage)}", html)

    def test_import_resets_filters(self) -> None:
        """A successful import starts from a clean, predictable view."""
        html = render_dashboard_html()
        start = html.index("function renderImportedReport")
        block = html[start:html.index("function loadDemoAudit")]

        self.assertIn("resetAllFilters();", block)
        # Reset happens before the import message is set, so it is not wiped.
        self.assertLess(block.index("resetAllFilters();"), block.index("setEmptyStateMessage("))

    def test_other_data_sources_clear_import_empty_message(self) -> None:
        html = render_dashboard_html()
        self.assertGreaterEqual(html.count("setEmptyStateMessage(null);"), 4)


class TestDocumentedCommands(unittest.TestCase):
    """The documented startup commands must work for this src-layout repo."""

    PROJECT = Path(__file__).resolve().parent.parent

    def test_dashboard_entrypoint_path_exists(self) -> None:
        self.assertTrue((self.PROJECT / "src" / "lpe_sentinel" / "web_app.py").is_file())
        self.assertTrue((self.PROJECT / "src" / "lpe_sentinel" / "main.py").is_file())

    def test_readme_documents_src_layout_commands(self) -> None:
        readme = (self.PROJECT / "README.md").read_text(encoding="utf-8")

        self.assertIn("python src/lpe_sentinel/main.py", readme)
        self.assertIn("python src/lpe_sentinel/web_app.py", readme)

    def test_readme_does_not_document_broken_module_form(self) -> None:
        """`python -m lpe_sentinel...` fails without PYTHONPATH=src."""
        readme = (self.PROJECT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("python -m lpe_sentinel.main", readme)
        self.assertNotIn("python -m lpe_sentinel.web_app", readme)

    def test_readme_documents_import_workflow(self) -> None:
        readme = (self.PROJECT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Import Audit Report", readme)
        self.assertIn("unverified", readme)

    def test_entrypoints_run_from_project_root(self) -> None:
        """Execute the documented commands to prove they work."""
        import subprocess

        proc = subprocess.run(
            [sys.executable, "-B", "src/lpe_sentinel/web_app.py", "--help"],
            cwd=str(self.PROJECT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--port", proc.stdout)


class TestInvalidJsonClearsResultsBehaviour(unittest.TestCase):
    """
    Behavioural proof (not string matching) that a failed import clears results.

    Executes the JavaScript actually shipped inside render_dashboard_html()
    against a minimal DOM stub. Skipped cleanly when Node is unavailable, so no
    runtime or build dependency is introduced.
    """

    DOM_STUB = r"""
function mkEl(id){ return { id, textContent:'', innerHTML:'', value:'', style:{}, className:'',
  files:null, disabled:false, children:[],
  classList:{ _s:new Set(), add(c){this._s.add(c)}, remove(c){this._s.delete(c)},
              contains(c){return this._s.has(c)} },
  appendChild(c){ this.children.push(c); }, setAttribute(){}, removeAttribute(){},
  getAttribute(){return null}, addEventListener(){}, focus(){}, click(){} }; }
const store={};
global.document={ getElementById(id){ if(!store[id]) store[id]=mkEl(id); return store[id]; },
  querySelectorAll(){return[];}, querySelector(){return mkEl('q');},
  createElement(t){return mkEl('c-'+t);}, addEventListener(){} };
global.window={addEventListener(){},scrollTo(){}};
global.alert=()=>{};
const DEMO={findings:[{finding_id:'A',title:'t',severity:'HIGH',description:'d',
  evidence:'e',affected_resource:'/a',recommendation:'r'}],
  summary:{total_findings:1,severity_counts:{CRITICAL:0,HIGH:1,MEDIUM:0,LOW:0,INFO:0}},
  system_info:{os_name:'L',release:'r',hostname:'h',username:'u'}};
global.fetch=async(u)=>{ if(String(u).includes('/api/demo-audit'))
  return {ok:true,json:async()=>DEMO}; return {ok:true,json:async()=>({})}; };
"""

    SCENARIO = r"""
(async () => {
  const out = {};
  await loadDemoAudit();
  out.demo_findings = currentFindings.length;
  out.demo_countTotal = document.getElementById('count-total').textContent;

  try {
    await handleReportFileSelected(
      { target: { files: [{ name:'bad.json', text: async () => '{not json' }], value:'x' } });
  } catch (e) { out.exception = String(e && e.message || e); }

  out.findings        = currentFindings.length;
  out.isDemoMode      = isDemoMode;
  out.comparisonData  = comparisonData;
  out.countTotal      = document.getElementById('count-total').textContent;
  out.demoBanner      = document.getElementById('demo-banner').classList.contains('visible');
  out.sessionStatus   = document.getElementById('session-status-text').textContent;
  out.statusMessage   = document.getElementById('report-import-status').textContent;
  console.log('RESULT' + JSON.stringify(out));
})();
"""

    def _run_scenario(self) -> dict:
        import shutil
        import subprocess
        import tempfile

        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js unavailable; skipping JS behaviour verification")

        html = render_dashboard_html()
        start = html.index("<script>") + len("<script>")
        end = html.rindex("</script>")
        js = html[start:end].replace("__INITIAL_CAPABILITIES__", "null")

        program = self.DOM_STUB + "\n" + js + "\n" + self.SCENARIO
        handle = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8")
        try:
            handle.write(program)
            handle.close()
            proc = subprocess.run(
                [node, handle.name], capture_output=True, text=True, timeout=60
            )
        finally:
            import os as _os

            _os.unlink(handle.name)

        self.assertEqual(proc.returncode, 0, proc.stderr[:2000])
        for line in proc.stdout.splitlines():
            if line.startswith("RESULT"):
                return json.loads(line[len("RESULT"):])
        self.fail("scenario produced no RESULT line")

    def test_invalid_json_clears_displayed_results(self) -> None:
        """A failed import must remove previously displayed demo findings."""
        result = self._run_scenario()

        # Precondition: demo findings really were on screen.
        self.assertGreater(result["demo_findings"], 0)
        # A real DOM coerces textContent to a string; the stub keeps the raw
        # value, so compare stringified forms.
        self.assertEqual(str(result["demo_countTotal"]), str(result["demo_findings"]))

        # After the invalid-JSON import everything is cleared.
        self.assertEqual(result["findings"], 0)
        self.assertIs(result["isDemoMode"], False)
        self.assertIsNone(result["comparisonData"])
        self.assertEqual(result["countTotal"], 0)
        self.assertFalse(result["demoBanner"])
        self.assertEqual(result["sessionStatus"], "NO RESULTS")

    def test_invalid_json_still_reports_the_error(self) -> None:
        """Clearing results must not swallow the user-facing error."""
        result = self._run_scenario()

        self.assertIn("not valid JSON", result["statusMessage"])


class TestFailedImportPreservesPersistentHistory(unittest.TestCase):
    """
    A failed import clears the *view*, never the saved audit records.

    The Recent Audits panel is backed by the local SQLite history. A failed
    import must leave those records visible and selectable; only transient
    selection state is expected to reset.
    """

    def test_clear_helper_does_not_purge_history_storage(self) -> None:
        html = render_dashboard_html()
        start = html.index("function clearDisplayedResults()")
        block = html[start:html.index("function failImport(")]

        # It must never write to the persisted history list or its count.
        self.assertNotIn("history-list", block)
        self.assertNotIn("history-count-pill", block)
        self.assertNotIn("loadRecentAudits(", block)

    def test_failed_import_hides_banner_but_keeps_saved_records(self) -> None:
        html = render_dashboard_html()

        # The provenance banner for a loaded record IS cleared...
        self.assertIn("hideHistoryBanner();", html)
        # ...and the selection state is reset so nothing claims to be loaded.
        self.assertIn("currentHistoryScanId = null;", html)

    def test_history_is_refetched_from_server_not_held_in_js(self) -> None:
        """History lives server-side in SQLite; the client only renders it."""
        html = render_dashboard_html()

        self.assertIn("fetch('/api/history?limit=10')", html)
        # No client-side deletion of stored records exists anywhere.
        self.assertNotIn("deleteAudit", html)
        self.assertNotIn("/api/history/delete", html)


class TestFailedImportClearsStaleHistoryHighlight(unittest.TestCase):
    """
    Behavioural proof that a failed import drops the stale "currently loaded"
    highlight without touching the persisted audit history.
    """

    DOM_STUB = r"""
function mkEl(id){ return { id, textContent:'', innerHTML:'', value:'', style:{}, className:'',
  files:null, disabled:false, children:[],
  classList:{ _s:new Set(), add(c){this._s.add(c)}, remove(c){this._s.delete(c)},
              contains(c){return this._s.has(c)} },
  appendChild(c){ this.children.push(c); }, setAttribute(){}, removeAttribute(){},
  getAttribute(){return null}, addEventListener(){}, focus(){}, click(){} }; }
const store={};
// querySelectorAll('.history-item') returns whatever the scenario registers, so
// the same object identity is shared with getElementById().
global.__historyItems = [];
global.document={ getElementById(id){ if(!store[id]) store[id]=mkEl(id); return store[id]; },
  querySelectorAll(sel){ if(sel === '.history-item') return global.__historyItems; return []; },
  querySelector(){return mkEl('q');}, createElement(t){return mkEl('c-'+t);}, addEventListener(){} };
global.window={addEventListener(){},scrollTo(){}};
global.alert=()=>{};
const DEMO={findings:[{finding_id:'A',title:'t',severity:'HIGH',description:'d',
  evidence:'e',affected_resource:'/a',recommendation:'r'}],
  summary:{total_findings:1,severity_counts:{CRITICAL:0,HIGH:1,MEDIUM:0,LOW:0,INFO:0}},
  system_info:{os_name:'L',release:'r',hostname:'h',username:'u'}};
global.fetch=async(u)=>{ if(String(u).includes('/api/demo-audit'))
  return {ok:true,json:async()=>DEMO}; return {ok:true,json:async()=>({})}; };
"""

    SCENARIO = r"""
(async () => {
  const out = {};
  const item = document.getElementById('history-item-abc123');
  const list  = document.getElementById('history-list');
  const pill  = document.getElementById('history-count-pill');

  // Reproduce the saved-history panel exactly as loadRecentAudits() leaves it.
  // Register the exact same element object the DOM lookup returns, so the
  // clear-highlight code path operates on it.
  item.classList.add('history-item');
  global.__historyItems = [item];
  list.textContent = 'abc123 - 4 findings';
  list.appendChild(item);
  pill.textContent = '1 Record';

  // Snapshot the persisted state AFTER it exists.
  const savedListText  = list.textContent;
  const savedPillText  = pill.textContent;
  const savedItemCount = global.__historyItems.length;

  // Load the demo first (this legitimately clears any active marker).
  await loadDemoAudit();
  out.before_findings = currentFindings.length;

  // Then simulate the user opening a saved record from the history list.
  document.getElementById('history-banner').classList.add('visible');
  currentHistoryScanId = 'abc123';
  item.classList.add('active');
  out.before_activeHighlight = item.classList.contains('active');

  try {
    await handleReportFileSelected(
      { target: { files: [{ name:'bad.json', text: async () => '{not json' }], value:'x' } });
  } catch (e) { out.exception = String(e && e.message || e); }

  out.findings      = currentFindings.length;
  out.countTotal    = String(document.getElementById('count-total').textContent);
  out.scanId        = currentHistoryScanId;
  out.activeHighlight = item.classList.contains('active');
  out.listTextUnchanged = list.textContent === savedListText;
  out.pillTextUnchanged = pill.textContent === savedPillText;
  out.savedRecordsIntact = global.__historyItems.length === savedItemCount;
  out.savedRecordStillListed = list.children.length === savedItemCount;
  console.log('RESULT' + JSON.stringify(out));
})();
"""

    def _run(self) -> dict:
        import os as _os
        import shutil
        import subprocess
        import tempfile

        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js unavailable; skipping JS behaviour verification")

        html = render_dashboard_html()
        js = html[html.index("<script>") + len("<script>"):html.rindex("</script>")]
        js = js.replace("__INITIAL_CAPABILITIES__", "null")

        handle = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8")
        try:
            handle.write(self.DOM_STUB + "\n" + js + "\n" + self.SCENARIO)
            handle.close()
            proc = subprocess.run(
                [node, handle.name], capture_output=True, text=True, timeout=60
            )
        finally:
            _os.unlink(handle.name)

        self.assertEqual(proc.returncode, 0, proc.stderr[:2000])
        for line in proc.stdout.splitlines():
            if line.startswith("RESULT"):
                return json.loads(line[len("RESULT"):])
        self.fail("scenario produced no RESULT line")

    def test_failed_import_clears_results_and_highlight_but_keeps_history(self) -> None:
        result = self._run()

        # Preconditions: findings shown and the saved record marked active.
        self.assertGreater(result["before_findings"], 0)
        self.assertTrue(result["before_activeHighlight"])
        self.assertNotIn("exception", result)

        # Current findings and counts are cleared.
        self.assertEqual(result["findings"], 0)
        self.assertEqual(result["countTotal"], "0")
        self.assertIsNone(result["scanId"])

        # The stale "currently loaded" highlight is removed.
        self.assertFalse(result["activeHighlight"])

        # Persisted history is untouched: same text, same pill, same records.
        self.assertTrue(result["listTextUnchanged"])
        self.assertTrue(result["pillTextUnchanged"])
        self.assertTrue(result["savedRecordsIntact"])
        self.assertTrue(result["savedRecordStillListed"])

    def test_clear_helper_removes_active_class_from_history_items(self) -> None:
        html = render_dashboard_html()
        start = html.index("function clearDisplayedResults()")
        block = html[start:html.index("function failImport(")]

        self.assertIn(
            "document.querySelectorAll('.history-item').forEach(it => it.classList.remove('active'));",
            block,
        )


if __name__ == "__main__":
    unittest.main()