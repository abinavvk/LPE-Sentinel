"""
Audit Report Export Module for LPE-Sentinel.

Provides secure, deterministic, and dependency-free generation of audit reports
in JSON, CSV, and HTML formats from persisted historical audit records.
"""

import csv
import html
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

try:
    from lpe_sentinel.remediation_guidance import get_remediation_guidance
except ImportError:
    from remediation_guidance import get_remediation_guidance


def _sanitize_csv_cell(val: Any) -> str:
    """
    Sanitize a cell value for CSV export according to OWASP formula injection mitigation.

    Spreadsheet applications (Excel, LibreOffice Calc, Google Sheets) may parse formulas
    even when preceded by whitespace or control characters (spaces, tabs, carriage returns, newlines).
    If the stripped content begins with a dangerous prefix (=, +, -, @, \t, \r), prepend a single quote
    unless the value safely represents a standard negative numeric quantity.
    """
    if val is None:
        return ""
    s = str(val)
    if not s:
        return ""

    # Check if raw string or stripped version starts with formula trigger characters
    stripped = s.lstrip(" \t\r\n\x0b\x0c")
    if stripped and stripped[0] in ("=", "+", "-", "@", "\t", "\r"):
        # Safely preserve genuine negative numbers (e.g., "-1", "-42.5") where no whitespace precedes
        if stripped[0] == "-" and s == stripped:
            try:
                float(s)
                return s
            except ValueError:
                pass
        return "'" + s
    elif s[0] in ("\t", "\r"):
        return "'" + s
    return s


def generate_json_export(audit_record: Dict[str, Any]) -> str:
    """
    Generate machine-readable, schema-stable JSON export for a saved audit record.

    Adheres to data minimization principles: excludes process secrets, CSRF tokens,
    and unnecessary personal system data.
    """
    if not isinstance(audit_record, dict):
        raise TypeError(f"audit_record must be a dict, got {type(audit_record).__name__}")

    scan_id = str(audit_record.get("scan_id", "UNKNOWN"))
    timestamp = str(audit_record.get("timestamp", ""))
    status = str(audit_record.get("status", audit_record.get("audit_status", "UNKNOWN"))).upper()
    is_complete = bool(audit_record.get("is_complete", False))
    duration_ms = audit_record.get("duration_ms")
    if duration_ms is not None:
        try:
            duration_ms = round(float(duration_ms), 2)
        except (ValueError, TypeError):
            duration_ms = None

    summary = audit_record.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}

    system_info = audit_record.get("system_info", {})
    if not isinstance(system_info, dict):
        system_info = {}

    # Standardize scanner results
    scanners: List[Dict[str, Any]] = []
    scanners_raw = audit_record.get("scanner_results", audit_record.get("scanners", {}))
    if isinstance(scanners_raw, dict):
        for s_name in sorted(scanners_raw.keys()):
            s_info = scanners_raw[s_name]
            if isinstance(s_info, dict):
                scanners.append({
                    "name": str(s_name),
                    "status": str(s_info.get("status", "UNKNOWN")).upper(),
                    "findings_count": int(s_info.get("findings_count", 0)),
                    "error": str(s_info["error"]) if s_info.get("error") is not None else None,
                })
            else:
                scanners.append({
                    "name": str(s_name),
                    "status": str(s_info).upper(),
                    "findings_count": 0,
                    "error": None,
                })
    elif isinstance(scanners_raw, list):
        for s_item in scanners_raw:
            if isinstance(s_item, dict):
                scanners.append({
                    "name": str(s_item.get("name", "unknown")),
                    "status": str(s_item.get("status", "UNKNOWN")).upper(),
                    "findings_count": int(s_item.get("findings_count", 0)),
                    "error": str(s_item["error"]) if s_item.get("error") is not None else None,
                })

    # Standardize findings
    findings: List[Dict[str, Any]] = []
    raw_findings = audit_record.get("findings", [])
    if isinstance(raw_findings, (list, tuple)):
        for f in raw_findings:
            if isinstance(f, dict):
                f_id = str(f.get("finding_id", "UNKNOWN"))
                guidance = get_remediation_guidance(f)
                findings.append({
                    "finding_id": f_id,
                    "title": str(f.get("title", "")),
                    "severity": str(f.get("severity", "INFO")).upper(),
                    "affected_resource": str(f.get("affected_resource", "")),
                    "mitre_attack": str(f["mitre_attack"]) if f.get("mitre_attack") is not None else None,
                    "description": str(f.get("description", "")),
                    "evidence": str(f.get("evidence", "")),
                    "recommendation": str(f.get("recommendation", "")),
                    "remediation_guidance": guidance.to_dict(),
                })

    report = {
        "report_metadata": {
            "format_version": "1.0",
            "report_type": "LPE_SENTINEL_SECURITY_AUDIT",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "audit": {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "status": status,
            "is_complete": is_complete,
            "duration_ms": duration_ms,
            "summary": {
                "critical": int(summary.get("critical", 0)),
                "high": int(summary.get("high", 0)),
                "medium": int(summary.get("medium", 0)),
                "low": int(summary.get("low", 0)),
                "info": int(summary.get("info", 0)),
                "total": int(summary.get("total", len(findings))),
            },
            "system_info": {
                "os_name": str(system_info.get("os_name", "Unknown")),
                "release": str(system_info.get("release", "Unknown")),
                "architecture": str(system_info.get("architecture", "Unknown")),
                "platform_category": str(system_info.get("platform_category", "Unknown")),
            },
            "scanners": scanners,
            "findings_count": len(findings),
            "findings": findings,
        },
    }
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False)


def generate_csv_export(audit_record: Dict[str, Any]) -> str:
    """
    Generate CSV export for a saved audit record.

    Produces consistent columns and a complete header row even when findings list is empty.
    Applies formula injection mitigation to all output cells.
    """
    if not isinstance(audit_record, dict):
        raise TypeError(f"audit_record must be a dict, got {type(audit_record).__name__}")

    scan_id = str(audit_record.get("scan_id", "UNKNOWN"))

    headers = [
        "scan_id",
        "finding_id",
        "severity",
        "title",
        "affected_resource",
        "mitre_attack",
        "description",
        "evidence",
        "recommendation",
        "remediation_why_it_matters",
        "remediation_investigation",
        "remediation_recommendation",
        "remediation_validation",
    ]

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(headers)

    findings = audit_record.get("findings", [])
    if isinstance(findings, (list, tuple)):
        for f in findings:
            if isinstance(f, dict):
                guidance = get_remediation_guidance(f)
                row = [
                    _sanitize_csv_cell(scan_id),
                    _sanitize_csv_cell(f.get("finding_id", "UNKNOWN")),
                    _sanitize_csv_cell(str(f.get("severity", "INFO")).upper()),
                    _sanitize_csv_cell(f.get("title", "")),
                    _sanitize_csv_cell(f.get("affected_resource", "")),
                    _sanitize_csv_cell(f.get("mitre_attack") or ""),
                    _sanitize_csv_cell(f.get("description", "")),
                    _sanitize_csv_cell(f.get("evidence", "")),
                    _sanitize_csv_cell(f.get("recommendation", "")),
                    _sanitize_csv_cell(guidance.why_it_matters),
                    _sanitize_csv_cell(" | ".join(guidance.investigation_steps)),
                    _sanitize_csv_cell(" | ".join(guidance.remediation_steps)),
                    _sanitize_csv_cell(" | ".join(guidance.validation_steps)),
                ]
                writer.writerow(row)

    return output.getvalue()


def generate_html_export(audit_record: Dict[str, Any]) -> str:
    """
    Generate a professional, print-friendly, standalone HTML security report.

    Fully self-contained with no external dependencies or CDN links.
    Escapes all untrusted text to prevent HTML injection and XSS.
    """
    if not isinstance(audit_record, dict):
        raise TypeError(f"audit_record must be a dict, got {type(audit_record).__name__}")

    scan_id = html.escape(str(audit_record.get("scan_id", "UNKNOWN")), quote=True)
    timestamp = html.escape(str(audit_record.get("timestamp", "Unknown")), quote=True)
    raw_status = str(audit_record.get("status", audit_record.get("audit_status", "UNKNOWN"))).upper()
    status = html.escape(raw_status, quote=True)
    duration_val = audit_record.get("duration_ms")
    duration_str = html.escape(f"{float(duration_val):.1f} ms" if duration_val is not None else "N/A", quote=True)

    summary = audit_record.get("summary", {}) if isinstance(audit_record.get("summary"), dict) else {}
    crit_count = int(summary.get("critical", 0))
    high_count = int(summary.get("high", 0))
    med_count = int(summary.get("medium", 0))
    low_count = int(summary.get("low", 0))
    info_count = int(summary.get("info", 0))
    total_findings = int(summary.get("total", 0))

    system_info = audit_record.get("system_info", {}) if isinstance(audit_record.get("system_info"), dict) else {}
    os_name = html.escape(str(system_info.get("os_name", "Unknown")), quote=True)
    kernel_release = html.escape(str(system_info.get("release", "Unknown")), quote=True)
    arch = html.escape(str(system_info.get("architecture", "Unknown")), quote=True)
    platform_cat = html.escape(str(system_info.get("platform_category", "Unknown")), quote=True)

    # Scanners table rows
    scanner_rows: List[str] = []
    scanners_raw = audit_record.get("scanner_results", audit_record.get("scanners", {}))
    if isinstance(scanners_raw, dict):
        for s_name in sorted(scanners_raw.keys()):
            s_info = scanners_raw[s_name]
            if isinstance(s_info, dict):
                st = html.escape(str(s_info.get("status", "UNKNOWN")).upper(), quote=True)
                fc = html.escape(str(s_info.get("findings_count", 0)), quote=True)
                err = html.escape(str(s_info.get("error") or "-"), quote=True)
            else:
                st = html.escape(str(s_info).upper(), quote=True)
                fc = "0"
                err = "-"
            badge_class = "status-completed" if "COMPLETED" in st else ("status-partial" if "PARTIAL" in st else "status-failed")
            scanner_rows.append(f"""
              <tr>
                <td><strong>{html.escape(str(s_name), quote=True)}</strong></td>
                <td><span class="badge {badge_class}">{st}</span></td>
                <td>{fc}</td>
                <td>{err}</td>
              </tr>
            """)
    elif isinstance(scanners_raw, list):
        for s_item in scanners_raw:
            if isinstance(s_item, dict):
                s_name = html.escape(str(s_item.get("name", "unknown")), quote=True)
                st = html.escape(str(s_item.get("status", "UNKNOWN")).upper(), quote=True)
                fc = html.escape(str(s_item.get("findings_count", 0)), quote=True)
                err = html.escape(str(s_item.get("error") or "-"), quote=True)
                badge_class = "status-completed" if "COMPLETED" in st else ("status-partial" if "PARTIAL" in st else "status-failed")
                scanner_rows.append(f"""
                  <tr>
                    <td><strong>{s_name}</strong></td>
                    <td><span class="badge {badge_class}">{st}</span></td>
                    <td>{fc}</td>
                    <td>{err}</td>
                  </tr>
                """)

    scanner_table_html = "".join(scanner_rows) if scanner_rows else "<tr><td colspan='4'>No scanner metadata available</td></tr>"

    # Findings section
    findings = audit_record.get("findings", [])
    finding_cards: List[str] = []
    if isinstance(findings, (list, tuple)) and findings:
        for idx, f in enumerate(findings, start=1):
            if not isinstance(f, dict):
                continue
            f_id = html.escape(str(f.get("finding_id", f"FINDING-{idx}")), quote=True)
            f_sev = html.escape(str(f.get("severity", "INFO")).upper(), quote=True)
            f_title = html.escape(str(f.get("title", "Untitled Finding")), quote=True)
            f_res = html.escape(str(f.get("affected_resource", "")), quote=True)
            f_mitre = f.get("mitre_attack")
            mitre_badge = f'<span class="badge badge-mitre">MITRE {html.escape(str(f_mitre), quote=True)}</span>' if f_mitre else ""
            f_desc = html.escape(str(f.get("description", "")), quote=True)
            f_ev = html.escape(str(f.get("evidence", "")), quote=True)
            f_rec = html.escape(str(f.get("recommendation", "")), quote=True)
            sev_class = f"badge-{f_sev.lower()}"

            guidance = get_remediation_guidance(f)
            g_cat = html.escape(str(guidance.category), quote=True)
            g_why = html.escape(str(guidance.why_it_matters), quote=True)
            g_inv_lis = "".join(f"<li>{html.escape(s, quote=True)}</li>" for s in guidance.investigation_steps)
            g_rem_lis = "".join(f"<li>{html.escape(s, quote=True)}</li>" for s in guidance.remediation_steps)
            g_val_lis = "".join(f"<li>{html.escape(s, quote=True)}</li>" for s in guidance.validation_steps)

            finding_cards.append(f"""
            <article class="finding-card">
              <div class="finding-header">
                <div class="finding-title-row">
                  <span class="finding-id">{f_id}</span>
                  <span class="badge {sev_class}">{f_sev}</span>
                  {mitre_badge}
                  <h3 class="finding-title">{f_title}</h3>
                </div>
              </div>
              <div class="finding-resource">
                <strong>Target Resource:</strong> <code>{f_res}</code>
              </div>
              <div class="finding-body">
                <div class="finding-section-title">Description</div>
                <p class="finding-desc">{f_desc}</p>
                <div class="finding-section-title">Evidence</div>
                <pre class="evidence-box"><code>{f_ev}</code></pre>
                <div class="finding-section-title">Remediation Recommendation</div>
                <div class="recommendation-box">{f_rec}</div>
                <div class="finding-section-title" style="margin-top: 1rem; color: #38bdf8;">Advisory Remediation Guidance ({g_cat})</div>
                <div class="guidance-box" style="background: rgba(6, 182, 212, 0.05); border: 1px solid rgba(6, 182, 212, 0.2); border-radius: 6px; padding: 1rem; margin-top: 0.5rem;">
                  <div style="margin-bottom: 0.75rem;">
                    <strong style="color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">Why It Matters</strong>
                    <p style="margin: 0.25rem 0 0 0; font-size: 0.85rem; line-height: 1.5; color: #f1f5f9;">{g_why}</p>
                  </div>
                  <div style="margin-bottom: 0.75rem;">
                    <strong style="color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">Recommended Investigation Steps</strong>
                    <ul style="margin: 0.25rem 0 0 1.25rem; font-size: 0.85rem; line-height: 1.5; color: #cbd5e1;">{g_inv_lis}</ul>
                  </div>
                  <div style="margin-bottom: 0.75rem;">
                    <strong style="color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">Safe Remediation Actions</strong>
                    <ul style="margin: 0.25rem 0 0 1.25rem; font-size: 0.85rem; line-height: 1.5; color: #a7f3d0;">{g_rem_lis}</ul>
                  </div>
                  <div>
                    <strong style="color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">Validation Steps</strong>
                    <ul style="margin: 0.25rem 0 0 1.25rem; font-size: 0.85rem; line-height: 1.5; color: #cbd5e1;">{g_val_lis}</ul>
                  </div>
                </div>
              </div>
            </article>
            """)

    if finding_cards:
        findings_html = "\n".join(finding_cards)
    else:
        findings_html = """
        <div class="empty-findings-box">
          <div class="empty-icon">&#10003;</div>
          <h3>Clean Security Posture — No Findings Recorded</h3>
          <p>No privilege escalation indicators or misconfigurations were detected during this audit run.</p>
        </div>
        """

    status_badge_class = "status-completed" if "COMPLETED" in raw_status else ("status-partial" if "PARTIAL" in raw_status else "status-failed")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LPE-Sentinel Security Audit Report - {scan_id}</title>
  <style>
    :root {{
      --primary: #0f172a;
      --primary-light: #1e293b;
      --text: #0f172a;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --crit: #dc2626;
      --high: #ea580c;
      --med: #d97706;
      --low: #2563eb;
      --info: #059669;
    }}
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      color: var(--text);
      background-color: var(--bg);
      padding: 2rem 1.5rem;
    }}
    .container {{
      max-width: 1040px;
      margin: 0 auto;
      background: var(--card-bg);
      border-radius: 12px;
      border: 1px solid var(--border);
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
      padding: 2.5rem 3rem;
    }}
    header.report-header {{
      border-bottom: 2px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 1.5rem;
      flex-wrap: wrap;
    }}
    .brand-title {{
      font-size: 1.85rem;
      font-weight: 800;
      color: var(--primary);
      letter-spacing: -0.02em;
    }}
    .brand-subtitle {{
      color: var(--text-muted);
      font-size: 0.95rem;
      margin-top: 0.25rem;
    }}
    .header-meta {{
      text-align: right;
    }}
    .scan-id-tag {{
      display: inline-block;
      font-family: 'Consolas', 'Courier New', monospace;
      font-size: 0.85rem;
      background: #f1f5f9;
      padding: 0.25rem 0.6rem;
      border-radius: 6px;
      border: 1px solid #cbd5e1;
      font-weight: 700;
      color: var(--primary-light);
    }}
    .timestamp-text {{
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-top: 0.35rem;
    }}
    h2.section-heading {{
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--primary);
      margin: 2rem 0 1rem 0;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.5rem;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }}
    .meta-card {{
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.85rem 1rem;
    }}
    .meta-label {{
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .meta-value {{
      font-size: 0.95rem;
      font-weight: 700;
      color: var(--primary);
      margin-top: 0.2rem;
    }}
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(6, 1fr);
      gap: 0.75rem;
      margin-bottom: 2rem;
    }}
    @media (max-width: 768px) {{
      .metrics-grid {{
        grid-template-columns: repeat(3, 1fr);
      }}
    }}
    .metric-card {{
      background: #ffffff;
      border-radius: 8px;
      border: 1px solid var(--border);
      padding: 1rem;
      text-align: center;
      border-top: 4px solid var(--text-muted);
    }}
    .metric-card.total {{ border-top-color: var(--primary); }}
    .metric-card.critical {{ border-top-color: var(--crit); }}
    .metric-card.high {{ border-top-color: var(--high); }}
    .metric-card.medium {{ border-top-color: var(--med); }}
    .metric-card.low {{ border-top-color: var(--low); }}
    .metric-card.info {{ border-top-color: var(--info); }}
    .metric-count {{
      font-size: 1.75rem;
      font-weight: 800;
      color: var(--primary);
      line-height: 1.2;
    }}
    .metric-label {{
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      color: var(--text-muted);
      letter-spacing: 0.03em;
      margin-top: 0.25rem;
    }}
    table.scanner-table {{
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 1.5rem;
      font-size: 0.9rem;
    }}
    table.scanner-table th, table.scanner-table td {{
      padding: 0.75rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    table.scanner-table th {{
      background: #f1f5f9;
      font-weight: 700;
      color: var(--primary);
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.55rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }}
    .badge-critical {{ background: #fef2f2; color: #b91c1c; border: 1px solid #fca5a5; }}
    .badge-high {{ background: #fff7ed; color: #c2410c; border: 1px solid #fdba74; }}
    .badge-medium {{ background: #fefce8; color: #a16207; border: 1px solid #fde047; }}
    .badge-low {{ background: #eff6ff; color: #1d4ed8; border: 1px solid #93c5fd; }}
    .badge-info {{ background: #f0fdf4; color: #15803d; border: 1px solid #86efac; }}
    .badge-mitre {{ background: #f5f3ff; color: #6d28d9; border: 1px solid #ddd6fe; }}
    .status-completed {{ background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }}
    .status-partial {{ background: #fffbeb; color: #b45309; border: 1px solid #fde68a; }}
    .status-failed {{ background: #fef2f2; color: #b91c1c; border: 1px solid #fca5a5; }}

    .finding-card {{
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #ffffff;
      padding: 1.25rem 1.5rem;
      margin-bottom: 1.25rem;
      page-break-inside: avoid;
      break-inside: avoid;
    }}
    .finding-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 0.5rem;
    }}
    .finding-title-row {{
      display: flex;
      align-items: center;
      gap: 0.6rem;
      flex-wrap: wrap;
    }}
    .finding-id {{
      font-family: 'Consolas', 'Courier New', monospace;
      font-weight: 700;
      font-size: 0.85rem;
      color: #0369a1;
    }}
    .finding-title {{
      font-size: 1.05rem;
      font-weight: 700;
      color: var(--primary);
    }}
    .finding-resource {{
      margin: 0.4rem 0 0.8rem 0;
      font-size: 0.85rem;
      color: var(--text-muted);
    }}
    .finding-resource code {{
      font-family: 'Consolas', 'Courier New', monospace;
      background: #f1f5f9;
      color: #0f172a;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      border: 1px solid #cbd5e1;
    }}
    .finding-section-title {{
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      color: var(--text-muted);
      letter-spacing: 0.04em;
      margin-top: 0.75rem;
      margin-bottom: 0.25rem;
    }}
    .finding-desc {{
      font-size: 0.9rem;
      color: var(--text);
    }}
    pre.evidence-box {{
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.75rem 1rem;
      font-family: 'Consolas', 'Courier New', monospace;
      font-size: 0.8rem;
      color: #334155;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    .recommendation-box {{
      background: #f0fdf4;
      border-left: 3px solid var(--info);
      border-radius: 0 6px 6px 0;
      padding: 0.75rem 1rem;
      font-size: 0.85rem;
      color: #14532d;
      line-height: 1.4;
    }}
    .empty-findings-box {{
      text-align: center;
      padding: 3rem 1.5rem;
      background: #f0fdf4;
      border: 1px dashed #86efac;
      border-radius: 8px;
    }}
    .empty-icon {{
      font-size: 2.5rem;
      color: #16a34a;
      margin-bottom: 0.5rem;
    }}
    .empty-findings-box h3 {{
      color: #166534;
      font-size: 1.2rem;
      margin-bottom: 0.25rem;
    }}
    .empty-findings-box p {{
      color: #15803d;
      font-size: 0.9rem;
    }}
    footer.report-footer {{
      margin-top: 3rem;
      border-top: 1px solid var(--border);
      padding-top: 1.5rem;
      font-size: 0.8rem;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    @media print {{
      body {{
        padding: 0;
        background: #ffffff;
      }}
      .container {{
        box-shadow: none;
        border: none;
        padding: 0;
        max-width: 100%;
      }}
      .finding-card, .metric-card, table.scanner-table {{
        page-break-inside: avoid;
        break-inside: avoid;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header class="report-header">
      <div>
        <div class="brand-title">LPE-Sentinel Security Audit Report</div>
        <div class="brand-subtitle">Defensive Linux Privilege Escalation Auditor &amp; Security Baseline</div>
      </div>
      <div class="header-meta">
        <div><span class="scan-id-tag">{scan_id}</span></div>
        <div class="timestamp-text">Generated: {timestamp} (UTC)</div>
      </div>
    </header>

    <section aria-label="Audit Execution Overview">
      <div class="meta-grid">
        <div class="meta-card">
          <div class="meta-label">Overall Status</div>
          <div class="meta-value"><span class="badge {status_badge_class}">{status}</span></div>
        </div>
        <div class="meta-card">
          <div class="meta-label">Audit Duration</div>
          <div class="meta-value">{duration_str}</div>
        </div>
        <div class="meta-card">
          <div class="meta-label">Target OS</div>
          <div class="meta-value">{os_name} ({platform_cat})</div>
        </div>
        <div class="meta-card">
          <div class="meta-label">Kernel / Arch</div>
          <div class="meta-value">{kernel_release} / {arch}</div>
        </div>
      </div>
    </section>

    <h2 class="section-heading">Severity Distribution</h2>
    <section class="metrics-grid" aria-label="Severity Counts">
      <div class="metric-card total">
        <div class="metric-count">{total_findings}</div>
        <div class="metric-label">Total</div>
      </div>
      <div class="metric-card critical">
        <div class="metric-count">{crit_count}</div>
        <div class="metric-label">Critical</div>
      </div>
      <div class="metric-card high">
        <div class="metric-count">{high_count}</div>
        <div class="metric-label">High</div>
      </div>
      <div class="metric-card medium">
        <div class="metric-count">{med_count}</div>
        <div class="metric-label">Medium</div>
      </div>
      <div class="metric-card low">
        <div class="metric-count">{low_count}</div>
        <div class="metric-label">Low</div>
      </div>
      <div class="metric-card info">
        <div class="metric-count">{info_count}</div>
        <div class="metric-label">Info</div>
      </div>
    </section>

    <h2 class="section-heading">Scanner Execution Details</h2>
    <table class="scanner-table" aria-label="Scanner Results Table">
      <thead>
        <tr>
          <th>Scanner Module</th>
          <th>Execution Status</th>
          <th>Findings</th>
          <th>Notes / Errors</th>
        </tr>
      </thead>
      <tbody>
        {scanner_table_html}
      </tbody>
    </table>

    <h2 class="section-heading">Audit Findings Inventory ({len(findings)})</h2>
    <section aria-label="Findings Inventory">
      {findings_html}
    </section>

    <footer class="report-footer">
      <div>LPE-Sentinel Security Audit &bull; Confidential &bull; Read-Only Historical Snapshot</div>
      <div>Format: HTML Print-Friendly Security Report</div>
    </footer>
  </div>
</body>
</html>
"""
