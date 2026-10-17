"""
HTML and CSS templates for the LPE-Sentinel Web Dashboard.

Renders a self-contained, responsive, accessible, dark-themed cybersecurity
interface. Requires zero third-party CDNs, external styles, or scripts.
"""

def render_dashboard_html() -> str:
    """
    Return the complete HTML document for the LPE-Sentinel Web Dashboard.
    """
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LPE-Sentinel — Defensive Linux Privilege Escalation Auditor</title>
  <style>
    :root {
      --bg-base: #090d16;
      --bg-surface: #111827;
      --bg-surface-elevated: #1f293d;
      --bg-surface-hover: #26334d;
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-focus: #06b6d4;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --accent-cyan: #06b6d4;
      --accent-cyan-glow: rgba(6, 182, 212, 0.25);
      --severity-crit: #f43f5e;
      --severity-high: #f97316;
      --severity-med: #eab308;
      --severity-low: #3b82f6;
      --severity-info: #10b981;
      --font-stack: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: var(--font-stack);
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* Top Navigation Header */
    header.top-nav {
      background: rgba(17, 24, 39, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-subtle);
      position: sticky;
      top: 0;
      z-index: 100;
      padding: 0.875rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .brand-container {
      display: flex;
      align-items: center;
      gap: 0.875rem;
    }

    .brand-logo {
      width: 36px;
      height: 36px;
      border-radius: 8px;
      background: linear-gradient(135deg, #0891b2, #06b6d4);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 16px var(--accent-cyan-glow);
    }

    .brand-logo svg {
      width: 22px;
      height: 22px;
      fill: #ffffff;
    }

    .brand-text h1 {
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .brand-text .version-badge {
      font-size: 0.7rem;
      font-weight: 600;
      background: rgba(6, 182, 212, 0.15);
      color: var(--accent-cyan);
      border: 1px solid rgba(6, 182, 212, 0.3);
      padding: 0.15rem 0.5rem;
      border-radius: 9999px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .brand-text p {
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .status-pill {
      font-size: 0.75rem;
      font-weight: 600;
      padding: 0.35rem 0.85rem;
      border-radius: 9999px;
      background: var(--bg-surface-elevated);
      color: var(--text-muted);
      border: 1px solid var(--border-subtle);
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #64748b;
    }

    .status-pill.active-demo .status-dot {
      background: var(--severity-med);
      box-shadow: 0 0 8px rgba(234, 179, 8, 0.6);
    }

    .status-pill.active-demo {
      color: var(--severity-med);
      border-color: rgba(234, 179, 8, 0.4);
      background: rgba(234, 179, 8, 0.1);
    }

    .status-pill.active-live {
      color: var(--accent-cyan);
      border-color: rgba(6, 182, 212, 0.4);
      background: rgba(6, 182, 212, 0.1);
    }
    .status-pill.active-live .status-dot {
      background: var(--accent-cyan);
      box-shadow: 0 0 8px rgba(6, 182, 212, 0.6);
    }

    .status-pill.busy {
      color: #93c5fd;
      border-color: rgba(59, 130, 246, 0.4);
      background: rgba(59, 130, 246, 0.1);
    }
    .status-pill.busy .status-dot {
      background: #3b82f6;
      box-shadow: 0 0 8px rgba(59, 130, 246, 0.6);
      animation: pulse 1.5s infinite;
    }

    .status-pill.partial {
      color: var(--severity-med);
      border-color: rgba(234, 179, 8, 0.4);
      background: rgba(234, 179, 8, 0.1);
    }
    .status-pill.partial .status-dot {
      background: var(--severity-med);
      box-shadow: 0 0 8px rgba(234, 179, 8, 0.6);
    }

    .status-pill.failed, .status-pill.error {
      color: var(--severity-crit);
      border-color: rgba(244, 63, 94, 0.4);
      background: rgba(244, 63, 94, 0.1);
    }
    .status-pill.failed .status-dot, .status-pill.error .status-dot {
      background: var(--severity-crit);
      box-shadow: 0 0 8px rgba(244, 63, 94, 0.6);
    }

    .status-pill.unsupported {
      color: #cbd5e1;
      border-color: rgba(203, 213, 225, 0.3);
      background: rgba(100, 116, 139, 0.15);
    }
    .status-pill.unsupported .status-dot {
      background: #94a3b8;
    }

    .status-pill.active-history {
      color: #818cf8;
      border-color: rgba(129, 140, 248, 0.4);
      background: rgba(129, 140, 248, 0.1);
    }
    .status-pill.active-history .status-dot {
      background: #818cf8;
      box-shadow: 0 0 8px rgba(129, 140, 248, 0.6);
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
    }

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    /* Main Container */
    main.dashboard-container {
      max-width: 1380px;
      width: 100%;
      margin: 0 auto;
      padding: 1.75rem 2rem 3rem 2rem;
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 1.75rem;
    }

    /* Notice Banner for Demo Mode */
    .demo-banner {
      display: none;
      background: linear-gradient(90deg, rgba(234, 179, 8, 0.12), rgba(249, 115, 22, 0.12));
      border: 1px solid rgba(234, 179, 8, 0.4);
      border-radius: 10px;
      padding: 1rem 1.25rem;
      align-items: center;
      gap: 1rem;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    }

    .demo-banner.visible {
      display: flex;
    }

    /* Notice Banner for Live Audit */
    .live-banner {
      display: none;
      background: linear-gradient(90deg, rgba(6, 182, 212, 0.12), rgba(16, 185, 129, 0.12));
      border: 1px solid rgba(6, 182, 212, 0.4);
      border-radius: 10px;
      padding: 1rem 1.25rem;
      align-items: flex-start;
      gap: 1rem;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    }

    .live-banner.partial {
      background: linear-gradient(90deg, rgba(234, 179, 8, 0.12), rgba(249, 115, 22, 0.12));
      border-color: rgba(234, 179, 8, 0.4);
    }

    .live-banner.failed {
      background: linear-gradient(90deg, rgba(244, 63, 94, 0.12), rgba(239, 68, 68, 0.12));
      border-color: rgba(244, 63, 94, 0.4);
    }

    .live-banner.visible {
      display: flex;
    }

    .live-banner-icon svg {
      width: 28px;
      height: 28px;
      fill: var(--accent-cyan);
      flex-shrink: 0;
    }

    .live-banner.partial .live-banner-icon svg {
      fill: var(--severity-med);
    }

    .live-banner.failed .live-banner-icon svg {
      fill: var(--severity-crit);
    }

    .scanner-pills-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-top: 0.5rem;
    }

    .scanner-pill {
      font-size: 0.72rem;
      font-family: monospace;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      background: rgba(15, 23, 42, 0.7);
      border: 1px solid var(--border-subtle);
      color: var(--text-muted);
    }

    .scanner-pill.completed {
      border-color: rgba(16, 185, 129, 0.4);
      color: #a7f3d0;
    }

    .scanner-pill.partial {
      border-color: rgba(234, 179, 8, 0.4);
      color: #fef08a;
    }

    .scanner-pill.failed, .scanner-pill.skipped {
      border-color: rgba(244, 63, 94, 0.4);
      color: #fecdd3;
    }

    /* Notice Banner for Historical Audit */
    .history-banner {
      display: none;
      background: linear-gradient(90deg, rgba(99, 102, 241, 0.12), rgba(139, 92, 246, 0.12));
      border: 1px solid rgba(99, 102, 241, 0.4);
      border-radius: 10px;
      padding: 1rem 1.25rem;
      align-items: center;
      gap: 1rem;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
      flex-wrap: wrap;
    }

    .history-banner.visible {
      display: flex;
    }

    .history-banner-icon svg {
      width: 28px;
      height: 28px;
      fill: #818cf8;
      flex-shrink: 0;
    }

    .history-export-actions {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-left: auto;
      flex-wrap: wrap;
    }

    .export-title {
      font-size: 0.75rem;
      font-weight: 700;
      color: #c7d2fe;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-right: 0.25rem;
    }

    .btn-export {
      padding: 0.35rem 0.65rem;
      font-size: 0.75rem;
      font-weight: 700;
      border-radius: 6px;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      transition: all 0.15s ease;
    }

    .btn-xs {
      padding: 0.2rem 0.45rem;
      font-size: 0.7rem;
      border-radius: 4px;
      text-decoration: none;
    }

    .history-item-export-group {
      display: flex;
      align-items: center;
      gap: 0.35rem;
    }

    /* Recent Audits History Section */
    .history-section {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 1.25rem 1.5rem;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
    }

    .history-list {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      max-height: 260px;
      overflow-y: auto;
      margin-top: 0.75rem;
    }

    .history-item {
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      transition: all 0.15s ease;
      gap: 1rem;
    }

    .history-item:hover {
      border-color: rgba(129, 140, 248, 0.4);
      background: var(--bg-surface-hover);
    }

    .history-item.active {
      border-color: #818cf8;
      background: rgba(99, 102, 241, 0.15);
    }

    .history-item-left {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }

    .history-item-header {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
    }

    .history-scan-id {
      font-family: monospace;
      font-size: 0.8rem;
      color: #818cf8;
      font-weight: 700;
    }

    .history-timestamp {
      font-size: 0.75rem;
      color: var(--text-dim);
    }

    .history-item-meta {
      font-size: 0.8rem;
      color: var(--text-muted);
      display: flex;
      gap: 0.75rem;
      align-items: center;
      flex-wrap: wrap;
    }

    .history-item-actions {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .demo-banner-icon svg {
      width: 28px;
      height: 28px;
      fill: var(--severity-med);
    }

    .demo-banner-text strong {
      display: block;
      color: #fef08a;
      font-size: 0.95rem;
      font-weight: 700;
      letter-spacing: 0.01em;
    }

    .demo-banner-text p {
      color: #fde68a;
      font-size: 0.85rem;
      margin-top: 0.15rem;
    }

    /* Overview Grid */
    .overview-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 1.25rem;
    }

    @media (max-width: 960px) {
      .overview-grid {
        grid-template-columns: 1fr;
      }
    }

    .card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 1.25rem 1.5rem;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
      transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }

    .card:hover {
      border-color: rgba(255, 255, 255, 0.14);
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 0.75rem;
    }

    .card-title {
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .card-title svg {
      width: 18px;
      height: 18px;
      fill: var(--accent-cyan);
    }

    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 0.875rem;
    }

    .meta-item {
      background: var(--bg-surface-elevated);
      padding: 0.65rem 0.85rem;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.04);
    }

    .meta-label {
      font-size: 0.725rem;
      font-weight: 500;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .meta-value {
      font-size: 0.875rem;
      font-weight: 600;
      color: var(--text-main);
      margin-top: 0.2rem;
      word-break: break-all;
    }

    /* Action Controls Card */
    .controls-container {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      justify-content: center;
    }

    .btn {
      appearance: none;
      border: none;
      cursor: pointer;
      font-family: inherit;
      font-size: 0.875rem;
      font-weight: 600;
      padding: 0.7rem 1.25rem;
      border-radius: 8px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      transition: all 0.2s ease;
      text-decoration: none;
    }

    .btn svg {
      width: 16px;
      height: 16px;
      fill: currentColor;
    }

    .btn-primary {
      background: linear-gradient(135deg, #0891b2, #06b6d4);
      color: #ffffff;
      box-shadow: 0 4px 12px var(--accent-cyan-glow);
    }

    .btn-primary:hover {
      background: linear-gradient(135deg, #0e7490, #0891b2);
      transform: translateY(-1px);
    }

    .btn-secondary {
      background: var(--bg-surface-elevated);
      color: var(--text-main);
      border: 1px solid var(--border-subtle);
    }

    .btn-secondary:hover {
      background: var(--bg-surface-hover);
      border-color: rgba(255, 255, 255, 0.16);
      transform: translateY(-1px);
    }

    .btn-outline {
      background: transparent;
      color: var(--text-muted);
      border: 1px solid var(--border-subtle);
    }

    .btn-outline:hover {
      color: var(--text-main);
      border-color: rgba(255, 255, 255, 0.2);
    }

    .control-hint {
      font-size: 0.75rem;
      color: var(--text-dim);
      text-align: center;
      line-height: 1.4;
    }

    /* Severity Metrics Grid */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
    }

    .metric-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 1.15rem 1.25rem;
      position: relative;
      overflow: hidden;
      transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .metric-card:hover {
      transform: translateY(-2px);
    }

    .metric-card::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      width: 4px;
      height: 100%;
    }

    .metric-card.total::before { background: var(--accent-cyan); }
    .metric-card.critical::before { background: var(--severity-crit); }
    .metric-card.high::before { background: var(--severity-high); }
    .metric-card.medium::before { background: var(--severity-med); }
    .metric-card.low::before { background: var(--severity-low); }
    .metric-card.info::before { background: var(--severity-info); }

    .metric-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .metric-title {
      font-size: 0.775rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }

    .metric-count {
      font-size: 2rem;
      font-weight: 700;
      line-height: 1.2;
      margin-top: 0.4rem;
      color: #ffffff;
    }

    .metric-desc {
      font-size: 0.75rem;
      color: var(--text-dim);
      margin-top: 0.25rem;
    }

    /* Findings Section */
    .findings-section {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 1.5rem;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
    }

    .findings-toolbar {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      margin-bottom: 1.25rem;
    }

    .filter-group {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
    }

    .filter-btn {
      background: var(--bg-surface-elevated);
      color: var(--text-muted);
      border: 1px solid var(--border-subtle);
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }

    .filter-btn:hover {
      color: var(--text-main);
      border-color: rgba(255, 255, 255, 0.2);
    }

    .filter-btn.active {
      background: var(--accent-cyan);
      color: #000000;
      border-color: var(--accent-cyan);
    }

    .search-box {
      position: relative;
      min-width: 260px;
    }

    .search-input {
      width: 100%;
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 0.45rem 0.85rem 0.45rem 2.2rem;
      font-size: 0.85rem;
      color: var(--text-main);
      outline: none;
      transition: border-color 0.2s ease;
    }

    .search-input:focus {
      border-color: var(--accent-cyan);
    }

    .search-icon {
      position: absolute;
      left: 0.75rem;
      top: 50%;
      transform: translateY(-50%);
      width: 14px;
      height: 14px;
      fill: var(--text-dim);
    }

    /* Findings Table */
    .table-container {
      overflow-x: auto;
      border-radius: 8px;
      border: 1px solid var(--border-subtle);
    }

    table.findings-table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.875rem;
    }

    table.findings-table th {
      background: var(--bg-surface-elevated);
      color: var(--text-muted);
      font-weight: 600;
      padding: 0.85rem 1rem;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border-subtle);
    }

    table.findings-table td {
      padding: 1rem;
      border-bottom: 1px solid var(--border-subtle);
      vertical-align: middle;
      color: var(--text-main);
    }

    table.findings-table tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    .badge {
      display: inline-flex;
      align-items: center;
      padding: 0.2rem 0.6rem;
      border-radius: 9999px;
      font-size: 0.7rem;
      font-weight: 700;
      letter-spacing: 0.03em;
      text-transform: uppercase;
    }

    .badge-critical { background: rgba(244, 63, 94, 0.15); color: var(--severity-crit); border: 1px solid rgba(244, 63, 94, 0.3); }
    .badge-high { background: rgba(249, 115, 22, 0.15); color: var(--severity-high); border: 1px solid rgba(249, 115, 22, 0.3); }
    .badge-medium { background: rgba(234, 179, 8, 0.15); color: var(--severity-med); border: 1px solid rgba(234, 179, 8, 0.3); }
    .badge-low { background: rgba(59, 130, 246, 0.15); color: var(--severity-low); border: 1px solid rgba(59, 130, 246, 0.3); }
    .badge-info { background: rgba(16, 185, 129, 0.15); color: var(--severity-info); border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-demo-tag { background: rgba(234, 179, 8, 0.2); color: #fef08a; border: 1px dashed rgba(234, 179, 8, 0.5); margin-left: 0.4rem; }

    .id-tag {
      font-family: monospace;
      font-weight: 700;
      color: var(--accent-cyan);
    }

    .resource-path {
      font-family: monospace;
      font-size: 0.8rem;
      color: #93c5fd;
      background: rgba(15, 23, 42, 0.6);
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      display: inline-block;
      max-width: 280px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .details-row {
      display: none;
      background: rgba(15, 23, 42, 0.4);
    }

    .details-row.open {
      display: table-row;
    }

    .details-content {
      padding: 1.25rem 1.5rem;
      border-left: 3px solid var(--accent-cyan);
      margin: 0.5rem 0;
    }

    .details-block {
      margin-bottom: 0.75rem;
    }

    .details-block:last-child {
      margin-bottom: 0;
    }

    .details-block-title {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--text-dim);
      margin-bottom: 0.25rem;
    }

    .details-block-text {
      font-size: 0.85rem;
      color: var(--text-main);
      background: var(--bg-surface-elevated);
      padding: 0.65rem 0.85rem;
      border-radius: 6px;
      font-family: monospace;
      word-break: break-all;
    }

    .empty-state {
      padding: 3.5rem 2rem;
      text-align: center;
      color: var(--text-dim);
    }

    .empty-state svg {
      width: 48px;
      height: 48px;
      fill: var(--text-dim);
      margin-bottom: 1rem;
      opacity: 0.5;
    }

    .empty-state h3 {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
    }

    .empty-state p {
      font-size: 0.85rem;
      max-width: 460px;
      margin: 0 auto;
    }

    /* Informational Dialog / Toast */
    .modal-overlay {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(4px);
      z-index: 1000;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }

    .modal-overlay.open {
      display: flex;
    }

    .modal-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 14px;
      max-width: 520px;
      width: 100%;
      padding: 1.75rem;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
    }

    .modal-title {
      font-size: 1.15rem;
      font-weight: 700;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 0.75rem;
    }

    .modal-title svg {
      width: 22px;
      height: 22px;
      fill: var(--accent-cyan);
    }

    .modal-body {
      font-size: 0.9rem;
      color: var(--text-muted);
      line-height: 1.6;
      margin-bottom: 1.5rem;
    }

    .modal-actions {
      display: flex;
      justify-content: flex-end;
      gap: 0.75rem;
    }

    /* Footer */
    footer.dashboard-footer {
      border-top: 1px solid var(--border-subtle);
      padding: 1.25rem 2rem;
      background: var(--bg-surface);
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-dim);
    }

    /* Filter Controls & Selects */
    .filter-dropdown-group {
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }

    .filter-label {
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .custom-select {
      background: var(--bg-surface-elevated);
      color: var(--text-main);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 0.4rem 0.65rem;
      font-size: 0.8rem;
      outline: none;
      transition: border-color 0.2s ease;
      cursor: pointer;
    }

    .custom-select:focus {
      border-color: var(--accent-cyan);
    }

    /* Advisory Remediation Guidance Styles */
    .guidance-container {
      margin-top: 1rem;
      background: rgba(6, 182, 212, 0.04);
      border: 1px solid rgba(6, 182, 212, 0.2);
      border-left: 3px solid var(--accent-cyan);
      border-radius: 6px;
      padding: 1rem 1.25rem;
    }

    .guidance-header {
      font-size: 0.8rem;
      font-weight: 700;
      color: var(--accent-cyan);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 0.75rem;
    }

    .guidance-header svg {
      width: 16px;
      height: 16px;
      fill: var(--accent-cyan);
    }

    .guidance-block {
      margin-bottom: 0.65rem;
    }

    .guidance-block:last-child {
      margin-bottom: 0;
    }

    .guidance-label {
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-dim);
      text-transform: uppercase;
      margin-bottom: 0.2rem;
    }

    .guidance-text {
      font-size: 0.85rem;
      color: var(--text-main);
      line-height: 1.5;
    }

    .guidance-list {
      margin: 0.25rem 0 0 1.25rem;
      font-size: 0.85rem;
      color: var(--text-muted);
      line-height: 1.5;
    }

    .guidance-list li {
      margin-bottom: 0.2rem;
    }

    /* Comparison Section Styles */
    .comparison-section {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 1.25rem 1.75rem;
      margin-bottom: 1.75rem;
    }

    .comparison-toolbar {
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 0.85rem 1.25rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .comparison-selectors {
      display: flex;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .selector-field {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .selector-field label {
      font-size: 0.8rem;
      color: var(--text-muted);
      font-weight: 600;
    }

    .selector-arrow {
      color: var(--accent-cyan);
      font-weight: bold;
    }

    .comparison-results-panel {
      margin-top: 1.25rem;
      border-top: 1px solid var(--border-subtle);
      padding-top: 1.25rem;
    }

    .comparison-header-card {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 0.85rem 1.25rem;
      margin-bottom: 1rem;
    }

    .comparison-scans-info {
      display: flex;
      align-items: center;
      gap: 1.5rem;
      flex-wrap: wrap;
    }

    .scan-info-block {
      display: flex;
      flex-direction: column;
      gap: 0.15rem;
    }

    .scan-tag {
      font-size: 0.65rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
      width: fit-content;
    }

    .scan-info-block.older .scan-tag {
      background: rgba(148, 163, 184, 0.2);
      color: var(--text-muted);
    }

    .scan-info-block.newer .scan-tag {
      background: rgba(6, 182, 212, 0.2);
      color: var(--accent-cyan);
    }

    .scan-vs {
      font-size: 0.8rem;
      font-weight: 700;
      color: var(--text-dim);
    }

    .scan-time {
      font-size: 0.75rem;
      color: var(--text-dim);
    }

    .comparison-disclaimer-banner {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      background: rgba(234, 179, 8, 0.08);
      border: 1px solid rgba(234, 179, 8, 0.25);
      border-radius: 8px;
      padding: 0.65rem 1rem;
      margin-bottom: 1rem;
      font-size: 0.8rem;
      color: #fef08a;
    }

    .comparison-disclaimer-banner svg {
      width: 18px;
      height: 18px;
      fill: #eab308;
      flex-shrink: 0;
    }

    .comparison-metrics-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 0.875rem;
      margin-bottom: 1rem;
    }

    .comp-metric-card {
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      text-align: center;
      cursor: pointer;
      transition: all 0.15s ease;
    }

    .comp-metric-card:hover {
      border-color: rgba(255, 255, 255, 0.2);
      transform: translateY(-1px);
    }

    .comp-metric-num {
      font-size: 1.5rem;
      font-weight: 700;
      line-height: 1.2;
    }

    .comp-metric-lbl {
      font-size: 0.75rem;
      color: var(--text-muted);
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.04em;
    }

    .comp-metric-card.comp-new .comp-metric-num { color: #4ade80; }
    .comp-metric-card.comp-resolved .comp-metric-num { color: #60a5fa; }
    .comp-metric-card.comp-changed .comp-metric-num { color: #fbbf24; }
    .comp-metric-card.comp-persistent .comp-metric-num { color: #94a3b8; }

    .comparison-tabs-bar {
      display: flex;
      gap: 0.5rem;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 0.5rem;
      margin-bottom: 0.75rem;
      flex-wrap: wrap;
    }

    .comp-tab {
      background: transparent;
      border: 1px solid transparent;
      color: var(--text-muted);
      font-size: 0.8rem;
      font-weight: 600;
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
    }

    .comp-tab:hover {
      color: var(--text-main);
      background: var(--bg-surface-elevated);
    }

    .comp-tab.active {
      background: var(--bg-surface-elevated);
      color: var(--accent-cyan);
      border-color: rgba(6, 182, 212, 0.3);
    }

    .badge-diff-new {
      background: rgba(74, 222, 128, 0.15);
      color: #4ade80;
      border: 1px solid rgba(74, 222, 128, 0.3);
    }

    .badge-diff-resolved {
      background: rgba(96, 165, 250, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(96, 165, 250, 0.3);
    }

    .badge-diff-changed {
      background: rgba(251, 191, 36, 0.15);
      color: #fbbf24;
      border: 1px solid rgba(251, 191, 36, 0.3);
    }

    .badge-diff-persistent {
      background: rgba(148, 163, 184, 0.15);
      color: #94a3b8;
      border: 1px solid rgba(148, 163, 184, 0.3);
    }

    .diff-change-tag {
      display: inline-block;
      font-size: 0.75rem;
      background: rgba(251, 191, 36, 0.1);
      color: #fef08a;
      border: 1px solid rgba(251, 191, 36, 0.25);
      border-radius: 4px;
      padding: 0.15rem 0.4rem;
      margin-top: 0.25rem;
    }
  </style>
</head>
<body>

  <!-- Top Navigation Header -->
  <header class="top-nav">
    <div class="brand-container">
      <div class="brand-logo" aria-hidden="true">
        <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
      </div>
      <div class="brand-text">
        <h1>LPE-Sentinel <span class="version-badge" id="app-version">v0.1.0</span></h1>
        <p>Defensive Linux Privilege Escalation Auditing &amp; Risk Inventory</p>
      </div>
    </div>
    <div class="header-actions">
      <div class="status-pill" id="session-status">
        <span class="status-dot"></span>
        <span id="session-status-text">INITIAL READY</span>
      </div>
    </div>
  </header>

  <!-- Main Dashboard Container -->
  <main class="dashboard-container">

    <!-- Demo Mode Banner (Activated in Demo Mode) -->
    <section class="demo-banner" id="demo-banner" role="alert" aria-live="polite">
      <div class="demo-banner-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
      </div>
      <div class="demo-banner-text">
        <strong>⚠️ DEMO MODE ACTIVE — SIMULATED AUDIT DATA</strong>
        <p id="demo-disclaimer-text">These findings are synthetic test fixtures for interface demonstration. They DO NOT represent a live scan of this host system.</p>
      </div>
    </section>

    <!-- Live Audit Banner (Activated after Live Audit) -->
    <section class="live-banner" id="live-banner" role="status" aria-live="polite">
      <div class="live-banner-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
      </div>
      <div class="live-banner-text">
        <strong id="live-banner-title">LIVE SECURITY AUDIT COMPLETED</strong>
        <p id="live-banner-desc">Unified defensive audit executed across standard paths.</p>
        <div class="scanner-pills-row" id="scanner-status-pills"></div>
      </div>
    </section>

    <!-- History Audit Banner (Activated when viewing a historical audit) -->
    <section class="history-banner" id="history-banner" role="status" aria-live="polite">
      <div class="history-banner-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24"><path d="M13 3a9 9 0 0 0-9 9H1l3.89 3.89.07.14L9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42A8.954 8.954 0 0 0 13 21a9 9 0 0 0 0-18zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/></svg>
      </div>
      <div class="history-banner-text" style="flex:1;">
        <strong id="history-banner-title">📜 HISTORICAL AUDIT RECORD</strong>
        <p id="history-banner-desc">Showing persisted findings from a previous audit run. Read-only historical snapshot.</p>
        <div class="scanner-pills-row" id="history-status-pills"></div>
      </div>
      <div class="history-export-actions" id="history-export-actions">
        <span class="export-title">Export:</span>
        <a id="history-export-json" href="#" class="btn btn-outline btn-export" download>JSON</a>
        <a id="history-export-csv" href="#" class="btn btn-outline btn-export" download>CSV</a>
        <a id="history-export-html" href="#" class="btn btn-outline btn-export" download>HTML</a>
      </div>
    </section>

    <!-- Overview Grid -->
    <section class="overview-grid" aria-label="System Metadata and Controls">

      <!-- System Info Card -->
      <article class="card">
        <div class="card-header">
          <h2 class="card-title">
            <svg viewBox="0 0 24 24"><path d="M20 18c1.1 0 1.99-.9 1.99-2L22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6z"/></svg>
            System Context &amp; Environment
          </h2>
          <span class="status-pill" id="platform-pill">Platform Active</span>
        </div>
        <div class="meta-grid">
          <div class="meta-item">
            <div class="meta-label">Operating System</div>
            <div class="meta-value" id="meta-os">Loading...</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Release / Kernel</div>
            <div class="meta-value" id="meta-kernel">Loading...</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Hostname</div>
            <div class="meta-value" id="meta-host">Loading...</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Auditor User</div>
            <div class="meta-value" id="meta-user">Loading...</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Architecture</div>
            <div class="meta-value" id="meta-arch">Loading...</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Platform Category</div>
            <div class="meta-value" id="meta-platform-category">Loading...</div>
          </div>
        </div>
      </article>

      <!-- Audit Actions Card -->
      <article class="card controls-container">
        <h2 class="card-title" style="margin-bottom: 0.25rem;">
          <svg viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 14l-5-5 1.41-1.41L12 14.17l7.59-7.59L21 8l-9 9z"/></svg>
          Audit Controls
        </h2>
        <button type="button" class="btn btn-secondary" id="btn-load-demo" onclick="loadDemoAudit()">
          <svg viewBox="0 0 24 24"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>
          Load Demo Audit
        </button>
        <button type="button" class="btn btn-primary" id="btn-run-audit" onclick="runUnifiedAudit()">
          <svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
          Run Unified Audit
        </button>
        <button type="button" class="btn btn-outline" id="btn-clear" onclick="resetDashboard()">
          Clear Dashboard
        </button>
        <p class="control-hint">Executes defensive, read-only audit across standard search paths.</p>
      </article>

    </section>

    <!-- Severity Summary Cards -->
    <section class="metrics-grid" aria-label="Findings Severity Metrics">
      <div class="metric-card total">
        <div class="metric-header">
          <span class="metric-title">Total Findings</span>
        </div>
        <div class="metric-count" id="count-total">0</div>
        <div class="metric-desc">Discovered across all categories</div>
      </div>
      <div class="metric-card critical">
        <div class="metric-header">
          <span class="metric-title">Critical</span>
        </div>
        <div class="metric-count" id="count-critical">0</div>
        <div class="metric-desc">Immediate mitigation required</div>
      </div>
      <div class="metric-card high">
        <div class="metric-header">
          <span class="metric-title">High</span>
        </div>
        <div class="metric-count" id="count-high">0</div>
        <div class="metric-desc">Elevated risk indicators</div>
      </div>
      <div class="metric-card medium">
        <div class="metric-header">
          <span class="metric-title">Medium</span>
        </div>
        <div class="metric-count" id="count-medium">0</div>
        <div class="metric-desc">Configuration review target</div>
      </div>
      <div class="metric-card low">
        <div class="metric-header">
          <span class="metric-title">Low</span>
        </div>
        <div class="metric-count" id="count-low">0</div>
        <div class="metric-desc">Minor security consideration</div>
      </div>
      <div class="metric-card info">
        <div class="metric-header">
          <span class="metric-title">Info</span>
        </div>
        <div class="metric-count" id="count-info">0</div>
        <div class="metric-desc">Informational / Inventory record</div>
      </div>
    </section>

    <!-- Recent Audits History Section -->
    <section class="history-section" id="history-section" aria-label="Persistent Audit History">
      <div class="card-header" style="margin-bottom:0.75rem;">
        <h2 class="card-title">
          <svg viewBox="0 0 24 24"><path d="M13 3a9 9 0 0 0-9 9H1l3.89 3.89.07.14L9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42A8.954 8.954 0 0 0 13 21a9 9 0 0 0 0-18zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/></svg>
          Recent Audits (SQLite History)
        </h2>
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <span class="status-pill" id="history-count-pill" style="font-size:0.75rem;">0 Records</span>
          <button type="button" class="btn btn-outline" id="btn-refresh-history" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;" onclick="loadRecentAudits()">
            Refresh
          </button>
        </div>
      </div>
      <div id="history-list" class="history-list">
        <div class="empty-state" style="padding: 1.5rem 1rem;">
          <p>Loading audit history...</p>
        </div>
      </div>
    </section>

    <!-- Historical Audit Comparison Section -->
    <section class="comparison-section" id="comparison-section" aria-label="Historical Audit Comparison">
      <div class="card-header" style="margin-bottom:0.75rem;">
        <h2 class="card-title">
          <svg viewBox="0 0 24 24"><path d="M9.01 14H2v2h7.01v3L13 15.5 9.01 12v2zm5.98-1v-3H22V8h-7.01V5L11 8.5l3.99 3.5z"/></svg>
          Historical Audit Comparison
        </h2>
        <span class="status-pill" id="comparison-pill" style="font-size:0.75rem;">Read-Only Diff</span>
      </div>
      <div class="comparison-toolbar">
        <div class="comparison-selectors">
          <div class="selector-field">
            <label for="compare-select-older">Baseline (Older):</label>
            <select id="compare-select-older" class="custom-select" aria-label="Select baseline audit"></select>
          </div>
          <div class="selector-arrow" aria-hidden="true">&rarr;</div>
          <div class="selector-field">
            <label for="compare-select-newer">Target (Newer):</label>
            <select id="compare-select-newer" class="custom-select" aria-label="Select target audit"></select>
          </div>
          <button type="button" class="btn btn-primary" id="btn-run-compare" onclick="executeComparison()">
            Compare Audits
          </button>
        </div>
      </div>

      <!-- Comparison Results Box (Dynamically shown) -->
      <div id="comparison-results" class="comparison-results-panel" style="display:none;">
        <div class="comparison-header-card">
          <div class="comparison-scans-info">
            <div class="scan-info-block older">
              <span class="scan-tag">OLDER AUDIT</span>
              <strong id="compare-older-id">-</strong>
              <div class="scan-time" id="compare-older-meta">-</div>
            </div>
            <div class="scan-vs" aria-hidden="true">VS</div>
            <div class="scan-info-block newer">
              <span class="scan-tag">NEWER AUDIT</span>
              <strong id="compare-newer-id">-</strong>
              <div class="scan-time" id="compare-newer-meta">-</div>
            </div>
          </div>
          <button type="button" class="btn btn-outline" style="padding:0.35rem 0.65rem; font-size:0.75rem;" onclick="closeComparison()" title="Close comparison view">Close Diff</button>
        </div>

        <div class="comparison-disclaimer-banner" role="alert">
          <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
          <span><strong>Security Notice:</strong> A resolved finding indicates only that the finding was not present in the newer recorded audit; it does not prove the system is secure.</span>
        </div>

        <div class="comparison-metrics-row">
          <div class="comp-metric-card comp-new" onclick="filterComparisonTab('NEW')">
            <div class="comp-metric-num" id="comp-count-new">0</div>
            <div class="comp-metric-lbl">New Findings</div>
          </div>
          <div class="comp-metric-card comp-resolved" onclick="filterComparisonTab('RESOLVED')">
            <div class="comp-metric-num" id="comp-count-resolved">0</div>
            <div class="comp-metric-lbl">Resolved Findings</div>
          </div>
          <div class="comp-metric-card comp-changed" onclick="filterComparisonTab('CHANGED')">
            <div class="comp-metric-num" id="comp-count-changed">0</div>
            <div class="comp-metric-lbl">Changed Findings</div>
          </div>
          <div class="comp-metric-card comp-persistent" onclick="filterComparisonTab('PERSISTENT')">
            <div class="comp-metric-num" id="comp-count-persistent">0</div>
            <div class="comp-metric-lbl">Persistent Findings</div>
          </div>
        </div>

        <div class="comparison-tabs-bar" role="tablist">
          <button type="button" class="comp-tab active" data-tab="ALL" onclick="filterComparisonTab('ALL')">All Comparison (<span id="tab-count-all">0</span>)</button>
          <button type="button" class="comp-tab" data-tab="NEW" onclick="filterComparisonTab('NEW')">New (<span id="tab-count-new">0</span>)</button>
          <button type="button" class="comp-tab" data-tab="RESOLVED" onclick="filterComparisonTab('RESOLVED')">Resolved (<span id="tab-count-resolved">0</span>)</button>
          <button type="button" class="comp-tab" data-tab="CHANGED" onclick="filterComparisonTab('CHANGED')">Changed (<span id="tab-count-changed">0</span>)</button>
          <button type="button" class="comp-tab" data-tab="PERSISTENT" onclick="filterComparisonTab('PERSISTENT')">Persistent (<span id="tab-count-persistent">0</span>)</button>
        </div>

        <div class="table-container" style="margin-top:0.75rem;">
          <table class="findings-table" id="comparison-table">
            <thead>
              <tr>
                <th scope="col" style="width: 120px;">Finding ID</th>
                <th scope="col" style="width: 110px;">Classification</th>
                <th scope="col" style="width: 100px;">Severity</th>
                <th scope="col">Title / Differences</th>
                <th scope="col">Affected Resource</th>
                <th scope="col" style="width: 90px; text-align: center;">Action</th>
              </tr>
            </thead>
            <tbody id="comparison-tbody">
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- Findings Table Section -->
    <section class="findings-section" aria-label="Security Audit Findings Table">
      <div class="findings-toolbar">
        <div class="filter-group" role="group" aria-label="Filter findings by severity">
          <button type="button" class="filter-btn active" data-filter="ALL" onclick="setFilter('ALL')">All</button>
          <button type="button" class="filter-btn" data-filter="CRITICAL" onclick="setFilter('CRITICAL')">Critical</button>
          <button type="button" class="filter-btn" data-filter="HIGH" onclick="setFilter('HIGH')">High</button>
          <button type="button" class="filter-btn" data-filter="MEDIUM" onclick="setFilter('MEDIUM')">Medium</button>
          <button type="button" class="filter-btn" data-filter="LOW" onclick="setFilter('LOW')">Low</button>
          <button type="button" class="filter-btn" data-filter="INFO" onclick="setFilter('INFO')">Info</button>
        </div>

        <div class="filter-dropdown-group">
          <label for="filter-source" class="filter-label">Source:</label>
          <select id="filter-source" class="custom-select" onchange="setSourceFilter(this.value)" aria-label="Filter findings by scanner source">
            <option value="ALL">All Sources</option>
            <option value="suid_sgid">SUID / SGID</option>
            <option value="sensitive_permissions">Sensitive Perms</option>
            <option value="sudo_audit">Sudo Config</option>
          </select>
        </div>

        <div class="search-box">
          <svg class="search-icon" viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
          <input type="text" class="search-input" id="search-input" placeholder="Search title, description, resource, recommendation..." oninput="handleSearch(this.value)" aria-label="Search findings by keyword">
        </div>

        <div class="filter-dropdown-group">
          <label for="sort-findings" class="filter-label">Sort:</label>
          <select id="sort-findings" class="custom-select" onchange="setSortOrder(this.value)" aria-label="Sort findings">
            <option value="SEVERITY">Severity Priority</option>
            <option value="TITLE_ASC">Title (A-Z)</option>
            <option value="TITLE_DESC">Title (Z-A)</option>
            <option value="SOURCE_ASC">Scanner / Source</option>
          </select>
        </div>

        <button type="button" class="btn btn-outline" id="btn-reset-filters" onclick="resetAllFilters()" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;" title="Reset all filters and sorting">
          Reset Filters
        </button>
      </div>

      <div class="table-container">
        <table class="findings-table" id="findings-table">
          <thead>
            <tr>
              <th scope="col" style="width: 110px;">Finding ID</th>
              <th scope="col" style="width: 100px;">Severity</th>
              <th scope="col">Title</th>
              <th scope="col">Affected Resource</th>
              <th scope="col" style="width: 110px;">MITRE ATT&amp;CK</th>
              <th scope="col" style="width: 90px; text-align: center;">Action</th>
            </tr>
          </thead>
          <tbody id="findings-tbody">
            <!-- Empty initial state -->
            <tr id="empty-row">
              <td colspan="6">
                <div class="empty-state">
                  <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
                  <h3>No Audit Data Loaded</h3>
                  <p>Click <strong>Load Demo Audit</strong> to preview simulated audit results, or trigger an audit session once enabled.</p>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

  </main>

  <!-- Status / Notice Modal -->
  <div class="modal-overlay" id="audit-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-card">
      <h3 class="modal-title" id="modal-title">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
        <span id="modal-title-text">Notice</span>
      </h3>
      <div class="modal-body" id="modal-body-text">
      </div>
      <div class="modal-actions">
        <button type="button" class="btn btn-primary" onclick="closeRunAuditModal()">Understood</button>
      </div>
    </div>
  </div>

  <!-- Footer -->
  <footer class="dashboard-footer">
    <p>LPE-Sentinel Defensive Security Auditing Toolkit &bull; Strictly Read-Only &bull; Zero Third-Party Dependencies</p>
  </footer>

  <!-- Embedded Client Logic -->
  <script>
    let currentFindings = [];
    let activeFilter = 'ALL';
    let activeSourceFilter = 'ALL';
    let searchQuery = '';
    let activeSortOrder = 'SEVERITY';
    let isDemoMode = false;
    let currentHistoryScanId = null;
    let comparisonData = null;
    let activeComparisonTab = 'ALL';

    function setSessionStatus(stateClass, label) {
      const pill = document.getElementById('session-status');
      pill.className = 'status-pill' + (stateClass ? ' ' + stateClass : '');
      document.getElementById('session-status-text').textContent = label;
    }

    function showLiveBanner(title, desc, scannerResults, modeClass) {
      hideHistoryBanner();
      const banner = document.getElementById('live-banner');
      banner.className = 'live-banner visible ' + (modeClass || '');
      document.getElementById('live-banner-title').textContent = title;
      document.getElementById('live-banner-desc').textContent = desc;

      const pillsContainer = document.getElementById('scanner-status-pills');
      pillsContainer.innerHTML = '';
      if (scannerResults && typeof scannerResults === 'object') {
        Object.keys(scannerResults).forEach(key => {
          const res = scannerResults[key];
          const pill = document.createElement('span');
          const status = (res.status || 'UNKNOWN').toLowerCase();
          pill.className = 'scanner-pill ' + status;
          pill.textContent = key + ': ' + (res.status || 'UNKNOWN') + (res.findings_count !== undefined ? ' (' + res.findings_count + ')' : '');
          pillsContainer.appendChild(pill);
        });
      }
    }

    function hideLiveBanner() {
      const banner = document.getElementById('live-banner');
      if (banner) {
        banner.className = 'live-banner';
      }
    }

    function showHistoryBanner(scanId, timestamp, status, scannerResults) {
      hideLiveBanner();
      const banner = document.getElementById('history-banner');
      if (banner) banner.className = 'history-banner visible';
      document.getElementById('history-banner-title').textContent = '📜 HISTORICAL AUDIT: ' + scanId;
      document.getElementById('history-banner-desc').textContent = 'Executed at ' + timestamp + ' (Status: ' + status + '). Persisted SQLite record.';

      const jsonLink = document.getElementById('history-export-json');
      const csvLink = document.getElementById('history-export-csv');
      const htmlLink = document.getElementById('history-export-html');
      if (jsonLink) jsonLink.href = '/api/history/' + encodeURIComponent(scanId) + '/export/json';
      if (csvLink) csvLink.href = '/api/history/' + encodeURIComponent(scanId) + '/export/csv';
      if (htmlLink) htmlLink.href = '/api/history/' + encodeURIComponent(scanId) + '/export/html';

      const pillsContainer = document.getElementById('history-status-pills');
      if (pillsContainer) {
        pillsContainer.innerHTML = '';
        if (scannerResults && typeof scannerResults === 'object') {
          Object.keys(scannerResults).forEach(key => {
            const res = scannerResults[key];
            const pill = document.createElement('span');
            const st = (typeof res === 'string' ? res : (res.status || 'UNKNOWN')).toLowerCase();
            pill.className = 'scanner-pill ' + st;
            const countInfo = (res && res.findings_count !== undefined) ? ' (' + res.findings_count + ')' : '';
            pill.textContent = key + ': ' + st.toUpperCase() + countInfo;
            pillsContainer.appendChild(pill);
          });
        }
      }
    }

    function hideHistoryBanner() {
      const banner = document.getElementById('history-banner');
      if (banner) {
        banner.className = 'history-banner';
      }
      const jsonLink = document.getElementById('history-export-json');
      const csvLink = document.getElementById('history-export-csv');
      const htmlLink = document.getElementById('history-export-html');
      if (jsonLink) jsonLink.href = '#';
      if (csvLink) csvLink.href = '#';
      if (htmlLink) htmlLink.href = '#';
    }

    async function loadRecentAudits() {
      const container = document.getElementById('history-list');
      const countPill = document.getElementById('history-count-pill');
      if (!container) return;

      try {
        const res = await fetch('/api/history?limit=10');
        if (!res.ok) {
          container.innerHTML = '<div class="empty-state" style="padding: 1.5rem 1rem;"><p style="color:var(--severity-crit);">Failed to load audit history (HTTP ' + res.status + ')</p></div>';
          return;
        }
        const data = await res.json();
        const history = data.history || [];
        if (countPill) {
          countPill.textContent = history.length + ' Record' + (history.length === 1 ? '' : 's');
        }

        const selectOlder = document.getElementById('compare-select-older');
        const selectNewer = document.getElementById('compare-select-newer');
        if (selectOlder && selectNewer) {
          selectOlder.innerHTML = '';
          selectNewer.innerHTML = '';
          history.forEach(h => {
            const optA = document.createElement('option');
            optA.value = h.scan_id;
            optA.textContent = h.scan_id + ' (' + h.timestamp + ' - ' + (h.total_findings || 0) + ' findings)';
            selectOlder.appendChild(optA);

            const optB = document.createElement('option');
            optB.value = h.scan_id;
            optB.textContent = h.scan_id + ' (' + h.timestamp + ' - ' + (h.total_findings || 0) + ' findings)';
            selectNewer.appendChild(optB);
          });
          if (history.length >= 2) {
            selectOlder.selectedIndex = 1;
            selectNewer.selectedIndex = 0;
          }
        }

        if (history.length === 0) {
          container.innerHTML = `
            <div class="empty-state" style="padding: 1.5rem 1rem;">
              <p>No saved audit runs yet. Run a live audit to record history.</p>
            </div>
          `;
          return;
        }

        container.innerHTML = '';
        history.forEach(item => {
          const el = document.createElement('div');
          const isSelected = currentHistoryScanId === item.scan_id;
          el.className = 'history-item' + (isSelected ? ' active' : '');
          el.id = 'history-item-' + escapeHtml(item.scan_id);

          const status = (item.status || 'UNKNOWN').toUpperCase();
          const sevBadgeClass = status === 'COMPLETED' ? 'badge-info' : (status === 'PARTIAL' ? 'badge-medium' : 'badge-critical');
          const statusBadge = '<span class="badge ' + sevBadgeClass + '">' + escapeHtml(status) + '</span>';
          const durationText = item.duration_ms ? ' (' + item.duration_ms + ' ms)' : '';
          const sev = item.summary || {};
          const sevText = 'C:' + (sev.critical || 0) + ' H:' + (sev.high || 0) + ' M:' + (sev.medium || 0) + ' L:' + (sev.low || 0) + ' I:' + (sev.info || 0);

          el.innerHTML = `
            <div class="history-item-left">
              <div class="history-item-header">
                <span class="history-scan-id">${escapeHtml(item.scan_id)}</span>
                ${statusBadge}
                <span class="history-timestamp">${escapeHtml(item.timestamp)}${durationText}</span>
              </div>
              <div class="history-item-meta">
                <span><strong>${item.total_findings || 0}</strong> findings</span>
                <span style="color:var(--text-dim);">&bull;</span>
                <span style="font-family:monospace; font-size:0.75rem;">${sevText}</span>
              </div>
            </div>
            <div class="history-item-actions">
              <button type="button" class="btn btn-secondary" style="padding:0.35rem 0.65rem; font-size:0.75rem;" onclick="viewHistoryAudit('${escapeHtml(item.scan_id)}')">
                Load Record
              </button>
              <div class="history-item-export-group" role="group" aria-label="Export audit format">
                <a href="/api/history/${encodeURIComponent(item.scan_id)}/export/json" class="btn btn-outline btn-xs" download title="Export ${escapeHtml(item.scan_id)} as JSON">JSON</a>
                <a href="/api/history/${encodeURIComponent(item.scan_id)}/export/csv" class="btn btn-outline btn-xs" download title="Export ${escapeHtml(item.scan_id)} as CSV">CSV</a>
                <a href="/api/history/${encodeURIComponent(item.scan_id)}/export/html" class="btn btn-outline btn-xs" download title="Export ${escapeHtml(item.scan_id)} as HTML">HTML</a>
              </div>
            </div>
          `;
          container.appendChild(el);
        });
      } catch (err) {
        container.innerHTML = '<div class="empty-state" style="padding: 1.5rem 1rem;"><p style="color:var(--severity-crit);">Network error loading history: ' + escapeHtml(err.message) + '</p></div>';
      }
    }

    async function viewHistoryAudit(scanId) {
      if (isAuditRunning) return;
      try {
        const res = await fetch('/api/history/' + encodeURIComponent(scanId));
        if (!res.ok) {
          showStatusModal('Audit Record Not Found', 'Could not retrieve historical audit ' + scanId + ' (HTTP ' + res.status + ')');
          return;
        }
        const data = await res.json();
        const audit = data.audit;
        if (!audit) {
          showStatusModal('Invalid Record', 'Audit record contains no data.');
          return;
        }

        currentHistoryScanId = scanId;
        isDemoMode = false;

        // Clear demo and live banners to prevent stale state display
        const demoBanner = document.getElementById('demo-banner');
        if (demoBanner) demoBanner.classList.remove('visible');
        hideLiveBanner();

        // Show History Banner
        showHistoryBanner(audit.scan_id, audit.timestamp, audit.status, audit.scanner_results);
        setSessionStatus('active-history', 'HISTORICAL RECORD');

        // Populate findings and metrics
        currentFindings = audit.findings || [];
        if (audit.summary) {
          updateSummaryCounts(audit.summary);
        }
        if (audit.system_info) {
          updateSystemInfoDisplay(audit.system_info);
        }

        renderFindingsTable();

        // Highlight selected item in history list
        document.querySelectorAll('.history-item').forEach(it => it.classList.remove('active'));
        const activeEl = document.getElementById('history-item-' + scanId);
        if (activeEl) activeEl.classList.add('active');

      } catch (err) {
        showStatusModal('Error Loading History', 'Failed to fetch historical audit record: ' + err.message);
      }
    }

    function updateSystemInfoDisplay(sysInfo) {
      if (!sysInfo) return;
      if (sysInfo.os_name) document.getElementById('meta-os').textContent = sysInfo.os_name;
      if (sysInfo.release) document.getElementById('meta-kernel').textContent = sysInfo.release;
      if (sysInfo.hostname) document.getElementById('meta-host').textContent = sysInfo.hostname;
      if (sysInfo.username) document.getElementById('meta-user').textContent = sysInfo.username;
      if (sysInfo.architecture) document.getElementById('meta-arch').textContent = sysInfo.architecture;
      if (sysInfo.platform_category) document.getElementById('meta-platform-category').textContent = sysInfo.platform_category;
    }

    function showStatusModal(title, message) {
      document.getElementById('modal-title-text').textContent = title;
      document.getElementById('modal-body-text').textContent = message;
      document.getElementById('audit-modal').classList.add('open');
    }

    function closeRunAuditModal() {
      document.getElementById('audit-modal').classList.remove('open');
    }

    // Fetch Initial System Status on Page Load
    async function initDashboard() {
      try {
        const res = await fetch('/api/status');
        if (res.ok) {
          const data = await res.json();
          document.getElementById('app-version').textContent = 'v' + (data.version || '0.1.0');
          if (data.system_info) {
            updateSystemInfoDisplay(data.system_info);
          }
        }
      } catch (err) {
        console.warn('Status fetch error:', err);
      }
      loadRecentAudits();
    }

    // Load Demo Audit Data
    async function loadDemoAudit() {
      try {
        currentHistoryScanId = null;
        hideLiveBanner();
        hideHistoryBanner();
        document.querySelectorAll('.history-item').forEach(it => it.classList.remove('active'));

        const res = await fetch('/api/demo-audit');
        if (!res.ok) throw new Error('Failed to fetch demo data');
        const data = await res.json();

        isDemoMode = true;
        currentFindings = data.findings || [];

        // Show Demo Banner
        const banner = document.getElementById('demo-banner');
        banner.classList.add('visible');
        if (data.disclaimer) {
          document.getElementById('demo-disclaimer-text').textContent = data.disclaimer;
        }

        // Update Session Status Pill
        setSessionStatus('active-demo', 'DEMO SIMULATION');

        // Update Summary Cards
        if (data.summary) {
          updateSummaryCounts(data.summary);
        }

        // Update System Context with Simulation notice
        if (data.system_info) {
          updateSystemInfoDisplay(data.system_info);
        }

        renderFindingsTable();
      } catch (err) {
        alert('Failed to load demo audit: ' + err.message);
      }
    }

    let isAuditRunning = false;

    // Run Unified Audit against POST /api/run-audit
    async function runUnifiedAudit() {
      const btn = document.getElementById('btn-run-audit');
      if (isAuditRunning || (btn && btn.disabled)) return;
      isAuditRunning = true;
      currentHistoryScanId = null;
      document.querySelectorAll('.history-item').forEach(it => it.classList.remove('active'));

      const originalBtnHtml = btn.innerHTML;
      btn.disabled = true;
      btn.setAttribute('aria-busy', 'true');
      btn.innerHTML = `
        <svg class="spin-icon" viewBox="0 0 24 24" style="animation: spin 1s linear infinite;"><path d="M12 4V2A10 10 0 0 0 2 12h2a8 8 0 0 1 8-8z"/></svg>
        Auditing...
      `;

      // Set UI State: Starting / Loading
      setSessionStatus('busy', 'AUDIT IN PROGRESS');

      // Clear previous banners, findings, and counts so failure never displays stale data
      hideLiveBanner();
      hideHistoryBanner();
      const demoBanner = document.getElementById('demo-banner');
      if (demoBanner) demoBanner.classList.remove('visible');
      currentFindings = [];
      renderFindingsTable();
      updateSummaryCounts({ total_findings: 0, severity_counts: {} });

      try {
        // 1. Fetch CSRF Token
        let csrfToken = '';
        try {
          const csrfRes = await fetch('/api/csrf-token');
          if (csrfRes.ok) {
            const csrfData = await csrfRes.json();
            csrfToken = csrfData.csrf_token || '';
          }
        } catch (tokenErr) {
          console.warn('Failed to retrieve CSRF token:', tokenErr);
        }

        // 2. Submit POST /api/run-audit with strictly bounded parameters
        const res = await fetch('/api/run-audit', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
          },
          body: JSON.stringify({
            enabled_scanners: ['suid_sgid', 'sensitive_permissions', 'sudo_audit']
          })
        });

        // 3. Handle specific HTTP statuses
        if (res.status === 409) {
          setSessionStatus('busy', 'AUDIT BUSY');
          showStatusModal(
            'Audit Already In Progress (HTTP 409)',
            'Another security audit is currently running on the server. Concurrent audits are prohibited to prevent host resource contention. Please wait a moment and try again.'
          );
          return;
        }

        if (res.status === 403) {
          setSessionStatus('error', 'CSRF / FORBIDDEN');
          showStatusModal(
            'Request Rejected (HTTP 403 Forbidden)',
            'The audit request was rejected due to an invalid or missing CSRF token, or cross-origin request protection.'
          );
          return;
        }

        let data = {};
        try {
          data = await res.json();
        } catch (jsonErr) {
          setSessionStatus('error', 'MALFORMED RESPONSE');
          showStatusModal(
            'Invalid Server Response',
            'The server returned a response that could not be parsed as valid JSON.'
          );
          return;
        }

        if (res.status === 400 && data.status === 'UNSUPPORTED_PLATFORM') {
          setSessionStatus('unsupported', 'UNSUPPORTED PLATFORM');
          showStatusModal(
            'Unsupported Host Platform',
            data.error || 'Live security auditing is strictly supported on Linux host systems (e.g. Kali Linux).'
          );
          return;
        }

        if (!res.ok) {
          setSessionStatus('failed', 'AUDIT FAILED');
          showStatusModal(
            'Audit Request Failed (HTTP ' + res.status + ')',
            data.error || 'An error occurred during audit request execution.'
          );
          return;
        }

        // Explicitly handle FAILED audit result status from engine
        if (data.status === 'FAILED') {
          setSessionStatus('failed', 'AUDIT FAILED');
          const errorMsg = (data.errors && data.errors.length)
            ? data.errors.join('; ')
            : (data.error || 'One or more security scanners failed to complete.');
          showStatusModal(
            'Audit Execution Failed',
            errorMsg
          );
          return;
        }

        // 4. Successful Audit Execution (COMPLETED or PARTIAL)
        isDemoMode = false;
        if (demoBanner) demoBanner.classList.remove('visible');

        currentFindings = data.findings || [];
        if (data.summary) {
          updateSummaryCounts(data.summary);
        }
        if (data.system_info) {
          updateSystemInfoDisplay(data.system_info);
        }

        const isPartial = data.status === 'PARTIAL' || !data.is_complete;
        if (isPartial) {
          setSessionStatus('partial', 'PARTIAL AUDIT');
          showLiveBanner(
            'PARTIAL AUDIT COVERAGE',
            'Some scanner checks were skipped or encountered permissions limits.',
            data.scanner_results,
            'partial'
          );
        } else {
          setSessionStatus('active-live', 'AUDIT COMPLETED');
          showLiveBanner(
            'LIVE SECURITY AUDIT COMPLETED',
            'Unified audit completed successfully across all scanners.',
            data.scanner_results,
            'completed'
          );
        }

        renderFindingsTable();
        // Refresh persistent history list after live audit completion
        loadRecentAudits();
      } catch (networkErr) {
        setSessionStatus('error', 'NETWORK ERROR');
        showStatusModal(
          'Network Connection Error',
          'Failed to communicate with the LPE-Sentinel backend: ' + networkErr.message
        );
      } finally {
        isAuditRunning = false;
        btn.disabled = false;
        btn.removeAttribute('aria-busy');
        btn.innerHTML = originalBtnHtml;
      }
    }

    // Update Severity Counts
    function updateSummaryCounts(summary) {
      document.getElementById('count-total').textContent = summary.total_findings || 0;
      const counts = summary.severity_counts || {};
      document.getElementById('count-critical').textContent = counts.CRITICAL || 0;
      document.getElementById('count-high').textContent = counts.HIGH || 0;
      document.getElementById('count-medium').textContent = counts.MEDIUM || 0;
      document.getElementById('count-low').textContent = counts.LOW || 0;
      document.getElementById('count-info').textContent = counts.INFO || 0;
    }

    // Helper to determine scanner/source from finding
    function getFindingSource(f) {
      if (f.scanner) return String(f.scanner).toLowerCase();
      if (f.source) return String(f.source).toLowerCase();
      const id = String(f.finding_id || '').toUpperCase();
      if (id.startsWith('SUID-') || id.startsWith('SGID-')) return 'suid_sgid';
      if (id.startsWith('PERM-')) return 'sensitive_permissions';
      if (id.startsWith('SUDO-')) return 'sudo_audit';
      return 'other';
    }

    function getFindingSourceLabel(f) {
      const src = getFindingSource(f);
      if (src === 'suid_sgid') return 'SUID / SGID';
      if (src === 'sensitive_permissions') return 'Sensitive Perms';
      if (src === 'sudo_audit') return 'Sudo Config';
      return 'General Review';
    }

    // Client-side advisory remediation guidance generator
    function getRemediationGuidance(f) {
      if (f.remediation_guidance && typeof f.remediation_guidance === 'object') {
        return f.remediation_guidance;
      }
      const id = String(f.finding_id || '').toUpperCase().trim();
      const guidanceMap = {
        'SUID-001': {
          category: 'SUID / SGID Executables',
          why_it_matters: 'Executes with file owner privileges (typically root). Flaws or unexpected features may allow unprivileged callers to execute actions as the owner.',
          investigation_steps: ['Verify if binary is an official distribution package component.', 'Check if standard unprivileged users legitimately require execution.', 'Inspect file owner and permissions with ls -l.'],
          remediation_steps: ['Remove SUID bit if not required: chmod u-s <path>', 'Restrict execution to dedicated admin group if necessary.'],
          validation_steps: ['Confirm SUID bit is absent with ls -l <path>.', 'Verify authorized operational workflows continue functioning.']
        },
        'SUID-002': {
          category: 'SUID / SGID Executables',
          why_it_matters: 'Standard dual-use utility (shell, interpreter, editor, compiler) configured with SUID permissions allows arbitrary command or script execution with owner rights.',
          investigation_steps: ['Determine why the utility was granted SUID privileges.', 'Check system audit logs for execution by unprivileged accounts.', 'Verify package integrity.'],
          remediation_steps: ['Remove SUID bit immediately: chmod u-s <path>', 'Configure explicit, restricted entries in /etc/sudoers.d/ instead of global SUID.'],
          validation_steps: ['Confirm octal permissions do not contain 4000 bit with stat -c "%a %n" <path>.', 'Test execution from an unprivileged test account.']
        },
        'SGID-001': {
          category: 'SUID / SGID Executables',
          why_it_matters: 'Executes with group privileges. If the group has access to sensitive files or devices, flaws can lead to group privilege escalation.',
          investigation_steps: ['Identify the owning group and accessible resources.', 'Assess whether SGID is required for application functionality.'],
          remediation_steps: ['Remove SGID bit if not required: chmod g-s <path>'],
          validation_steps: ['Verify group s-bit is absent with ls -l <path>.', 'Confirm service operates normally without permission errors.']
        },
        'SGID-002': {
          category: 'SUID / SGID Executables',
          why_it_matters: 'Dual-use utility with SGID can allow reading, writing, or creating files owned by the privileged group.',
          investigation_steps: ['Inspect group ownership and access scope.'],
          remediation_steps: ['Remove SGID bit: chmod g-s <path>'],
          validation_steps: ['Verify SGID bit is absent with ls -l <path>.']
        },
        'PERM-001': {
          category: 'File & Directory Permissions',
          why_it_matters: 'World-writable file can be altered or truncated by any local user. If critical configuration or script, unauthorized changes can compromise system integrity.',
          investigation_steps: ['Check processes or daemons reading this file.', 'Inspect modification history and backup copies.'],
          remediation_steps: ['Remove world write permissions: chmod o-w <path>', 'Enforce standard ownership and permissions (chmod 644 <path>).'],
          validation_steps: ['Verify stat other bits do not include write permission.', 'Ensure services read configuration without errors.']
        },
        'PERM-002': {
          category: 'File & Directory Permissions',
          why_it_matters: 'Group-writable sensitive file allows any member of the group to modify configurations or binaries.',
          investigation_steps: ['Enumerate group accounts with getent group <groupname>.', 'Assess if group write is required.'],
          remediation_steps: ['Remove group write: chmod g-w <path>', 'Use POSIX ACLs (setfacl) if specific multi-user editing is needed.'],
          validation_steps: ['Verify ls -l group mode reflects r-- or r-x without w.']
        },
        'SUDO-001': {
          category: 'Sudo Configuration',
          why_it_matters: 'NOPASSWD tag permits elevated execution without password re-authentication.',
          investigation_steps: ['Inspect sudoers rule with visudo.', 'Determine if rule is used by non-interactive automation or interactive user.'],
          remediation_steps: ['Remove NOPASSWD tag for interactive accounts.', 'Restrict target arguments strictly if automated daemon.'],
          validation_steps: ['Validate syntax with visudo -c.', 'Confirm password prompt on sudo invocation.']
        },
        'SUDO-002': {
          category: 'Sudo Configuration',
          why_it_matters: 'Unrestricted ALL command rule grants blanket root access, violating least privilege.',
          investigation_steps: ['Review operational necessity for unrestricted root.', 'Examine commands actually executed in audit logs.'],
          remediation_steps: ['Replace ALL with explicit command paths in /etc/sudoers.d/.', 'Disallow shell-escape binaries.'],
          validation_steps: ['Verify rule with visudo -c and sudo -l -U <user>.']
        },
        'SUDO-003': {
          category: 'Sudo Configuration',
          why_it_matters: 'Wildcard patterns in sudoers can be bypassed or abused with unexpected parameters.',
          investigation_steps: ['Locate wildcard pattern in sudo configuration.', 'Analyze parameter parsing vulnerability.'],
          remediation_steps: ['Replace wildcards with explicit allowable command paths.', 'Use dedicated non-writable wrapper script if necessary.'],
          validation_steps: ['Check syntax with visudo -c and test sudo -l -U <user>.']
        }
      };

      if (guidanceMap[id]) return guidanceMap[id];
      if (id.startsWith('SUID-')) return guidanceMap['SUID-001'];
      if (id.startsWith('SGID-')) return guidanceMap['SGID-001'];
      if (id.startsWith('PERM-')) return guidanceMap['PERM-001'];
      if (id.startsWith('SUDO-')) return guidanceMap['SUDO-001'];

      return {
        category: 'General Security Review',
        why_it_matters: 'Configuration or permission attribute detected that warrants administrative baseline review.',
        investigation_steps: ['Review finding details, affected resource, and evidence.', 'Consult security benchmarks for baseline requirements.'],
        remediation_steps: ['Apply least-privilege principles and restrict access to authorized administrators.', 'Document exceptions if required.'],
        validation_steps: ['Re-audit system with LPE-Sentinel to confirm resolution.', 'Verify normal operations continue.']
      };
    }

    // Reset Dashboard to Clean Initial State
    function resetDashboard() {
      isDemoMode = false;
      currentHistoryScanId = null;
      currentFindings = [];
      closeComparison();
      resetAllFilters();

      document.getElementById('demo-banner').classList.remove('visible');
      hideLiveBanner();
      hideHistoryBanner();
      document.querySelectorAll('.history-item').forEach(it => it.classList.remove('active'));
      setSessionStatus('', 'INITIAL READY');

      updateSummaryCounts({ total_findings: 0, severity_counts: {} });
      initDashboard();
      renderFindingsTable();
    }

    // Reset All Filters & Search
    function resetAllFilters() {
      activeFilter = 'ALL';
      activeSourceFilter = 'ALL';
      searchQuery = '';
      activeSortOrder = 'SEVERITY';

      document.querySelectorAll('.filter-btn').forEach(btn => {
        if (btn.getAttribute('data-filter') === 'ALL') {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      });

      const srcSelect = document.getElementById('filter-source');
      if (srcSelect) srcSelect.value = 'ALL';

      const sortSelect = document.getElementById('sort-findings');
      if (sortSelect) sortSelect.value = 'SEVERITY';

      const searchInput = document.getElementById('search-input');
      if (searchInput) searchInput.value = '';

      renderFindingsTable();
    }

    // Severity Filter Selection
    function setFilter(filter) {
      activeFilter = filter;
      document.querySelectorAll('.filter-btn').forEach(btn => {
        if (btn.getAttribute('data-filter') === filter) {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      });
      renderFindingsTable();
    }

    // Source Filter Selection
    function setSourceFilter(src) {
      activeSourceFilter = src;
      renderFindingsTable();
    }

    // Sort Order Selection
    function setSortOrder(order) {
      activeSortOrder = order;
      renderFindingsTable();
    }

    // Search Query Handling
    function handleSearch(val) {
      searchQuery = (val || '').toLowerCase().trim();
      renderFindingsTable();
    }

    // Render Findings Rows with Filtering and Sorting
    function renderFindingsTable() {
      const tbody = document.getElementById('findings-tbody');
      tbody.innerHTML = '';

      const filtered = currentFindings.filter(f => {
        if (activeFilter !== 'ALL' && (f.severity || '').toUpperCase() !== activeFilter) {
          return false;
        }
        if (activeSourceFilter !== 'ALL') {
          const src = getFindingSource(f);
          if (src !== activeSourceFilter) {
            return false;
          }
        }
        if (searchQuery) {
          const title = String(f.title || '').toLowerCase();
          const desc = String(f.description || '').toLowerCase();
          const resource = String(f.affected_resource || '').toLowerCase();
          const rec = String(f.recommendation || '').toLowerCase();
          const fid = String(f.finding_id || '').toLowerCase();
          const combined = title + ' ' + desc + ' ' + resource + ' ' + rec + ' ' + fid;
          if (!combined.includes(searchQuery)) {
            return false;
          }
        }
        return true;
      });

      // Apply Sorting
      const severityRank = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1 };
      filtered.sort((a, b) => {
        if (activeSortOrder === 'SEVERITY') {
          const rA = severityRank[(a.severity || '').toUpperCase()] || 0;
          const rB = severityRank[(b.severity || '').toUpperCase()] || 0;
          if (rA !== rB) return rB - rA;
          return String(a.title || '').localeCompare(String(b.title || ''));
        } else if (activeSortOrder === 'TITLE_ASC') {
          return String(a.title || '').localeCompare(String(b.title || ''));
        } else if (activeSortOrder === 'TITLE_DESC') {
          return String(b.title || '').localeCompare(String(a.title || ''));
        } else if (activeSortOrder === 'SOURCE_ASC') {
          const sA = getFindingSourceLabel(a);
          const sB = getFindingSourceLabel(b);
          const cmp = sA.localeCompare(sB);
          if (cmp !== 0) return cmp;
          return String(a.title || '').localeCompare(String(b.title || ''));
        }
        return 0;
      });

      if (filtered.length === 0) {
        const emptyTr = document.createElement('tr');
        emptyTr.innerHTML = `
          <td colspan="6">
            <div class="empty-state">
              <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
              <h3>No Matching Findings</h3>
              <p>No findings matched the selected severity, source, or search criteria.</p>
              <div style="margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="resetAllFilters()">Reset Filters</button>
              </div>
            </div>
          </td>
        `;
        tbody.appendChild(emptyTr);
        return;
      }

      filtered.forEach((f, idx) => {
        const sevClass = 'badge-' + (f.severity || 'info').toLowerCase();
        const demoTag = isDemoMode ? '<span class="badge badge-demo-tag">DEMO</span>' : '';
        const mitreText = f.mitre_attack ? '<span class="id-tag">' + escapeHtml(f.mitre_attack) + '</span>' : '<span style="color:var(--text-dim);">-</span>';
        const guidance = getRemediationGuidance(f);

        // Main Row
        const tr = document.createElement('tr');
        tr.id = 'finding-row-' + idx;
        tr.innerHTML = `
          <td><span class="id-tag">${escapeHtml(f.finding_id)}</span></td>
          <td><span class="badge ${sevClass}">${escapeHtml(f.severity)}</span></td>
          <td>
            <strong>${escapeHtml(f.title)}</strong>
            ${demoTag}
          </td>
          <td><span class="resource-path" title="${escapeHtml(f.affected_resource)}">${escapeHtml(f.affected_resource)}</span></td>
          <td>${mitreText}</td>
          <td style="text-align: center;">
            <button type="button" class="btn btn-outline" style="padding: 0.25rem 0.6rem; font-size: 0.75rem;" onclick="toggleDetails(${idx})" aria-expanded="false" aria-controls="details-row-${idx}">
              Details
            </button>
          </td>
        `;

        // Expandable Details Row
        const trDetails = document.createElement('tr');
        trDetails.className = 'details-row';
        trDetails.id = 'details-row-' + idx;
        trDetails.innerHTML = `
          <td colspan="6">
            <div class="details-content">
              <div class="details-block">
                <div class="details-block-title">Description</div>
                <p style="color:var(--text-main); font-size:0.85rem; line-height:1.5;">${escapeHtml(f.description)}</p>
              </div>
              <div class="details-block">
                <div class="details-block-title">Evidence</div>
                <div class="details-block-text">${escapeHtml(f.evidence)}</div>
              </div>
              <div class="details-block">
                <div class="details-block-title">Recommendation &amp; Mitigation</div>
                <div class="details-block-text" style="color:#a7f3d0; border-left: 2px solid var(--severity-info);">${escapeHtml(f.recommendation)}</div>
              </div>

              <!-- Advisory Remediation Guidance -->
              <div class="guidance-container">
                <div class="guidance-header">
                  <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
                  Advisory Remediation Guidance &bull; ${escapeHtml(guidance.category)}
                </div>
                <div class="guidance-block">
                  <div class="guidance-label">Why This Finding Matters</div>
                  <p class="guidance-text">${escapeHtml(guidance.why_it_matters)}</p>
                </div>
                <div class="guidance-block">
                  <div class="guidance-label">Recommended Investigation Steps</div>
                  <ul class="guidance-list">
                    ${(guidance.investigation_steps || []).map(s => '<li>' + escapeHtml(s) + '</li>').join('')}
                  </ul>
                </div>
                <div class="guidance-block">
                  <div class="guidance-label">Safe Remediation Actions</div>
                  <ul class="guidance-list">
                    ${(guidance.remediation_steps || []).map(s => '<li style="color:#a7f3d0;">' + escapeHtml(s) + '</li>').join('')}
                  </ul>
                </div>
                <div class="guidance-block">
                  <div class="guidance-label">Validation Step (Confirm Resolution)</div>
                  <ul class="guidance-list">
                    ${(guidance.validation_steps || []).map(s => '<li>' + escapeHtml(s) + '</li>').join('')}
                  </ul>
                </div>
              </div>
            </div>
          </td>
        `;

        tbody.appendChild(tr);
        tbody.appendChild(trDetails);
      });
    }

    function toggleDetails(idx) {
      const row = document.getElementById('details-row-' + idx);
      if (row) {
        row.classList.toggle('open');
      }
    }

    // Comparison UI Handlers
    async function executeComparison() {
      const selectOlder = document.getElementById('compare-select-older');
      const selectNewer = document.getElementById('compare-select-newer');
      if (!selectOlder || !selectNewer) return;

      const idOlder = selectOlder.value;
      const idNewer = selectNewer.value;

      if (!idOlder || !idNewer) {
        showStatusModal('Comparison Notice', 'Please select two saved audit records to compare.');
        return;
      }
      if (idOlder === idNewer) {
        showStatusModal('Invalid Selection', 'Please select two distinct audit records to compare.');
        return;
      }

      const btn = document.getElementById('btn-run-compare');
      if (btn) btn.disabled = true;

      try {
        const res = await fetch('/api/history/compare?older=' + encodeURIComponent(idOlder) + '&newer=' + encodeURIComponent(idNewer));
        const data = await res.json();
        if (!res.ok) {
          showStatusModal('Comparison Failed', data.error || ('HTTP ' + res.status));
          return;
        }

        comparisonData = data;
        renderComparisonView(data);
      } catch (err) {
        showStatusModal('Comparison Error', 'Failed to retrieve comparison: ' + err.message);
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    function renderComparisonView(data) {
      const panel = document.getElementById('comparison-results');
      if (!panel) return;
      panel.style.display = 'block';

      // Scan headers
      const older = data.older_audit || {};
      const newer = data.newer_audit || {};
      document.getElementById('compare-older-id').textContent = older.scan_id || '-';
      document.getElementById('compare-older-meta').textContent = (older.timestamp || '') + ' (' + (older.status || '') + ' &bull; ' + (older.total_findings || 0) + ' findings)';
      document.getElementById('compare-newer-id').textContent = newer.scan_id || '-';
      document.getElementById('compare-newer-meta').textContent = (newer.timestamp || '') + ' (' + (newer.status || '') + ' &bull; ' + (newer.total_findings || 0) + ' findings)';

      // Summary counts
      const s = data.summary || {};
      const newCount = s.new_count || 0;
      const resCount = s.resolved_count || 0;
      const chgCount = s.changed_count || 0;
      const perCount = s.persistent_count || 0;
      const totalCount = newCount + resCount + chgCount + perCount;

      document.getElementById('comp-count-new').textContent = newCount;
      document.getElementById('comp-count-resolved').textContent = resCount;
      document.getElementById('comp-count-changed').textContent = chgCount;
      document.getElementById('comp-count-persistent').textContent = perCount;

      document.getElementById('tab-count-all').textContent = totalCount;
      document.getElementById('tab-count-new').textContent = newCount;
      document.getElementById('tab-count-resolved').textContent = resCount;
      document.getElementById('tab-count-changed').textContent = chgCount;
      document.getElementById('tab-count-persistent').textContent = perCount;

      activeComparisonTab = 'ALL';
      renderComparisonTable();
    }

    function filterComparisonTab(tab) {
      activeComparisonTab = tab;
      document.querySelectorAll('.comp-tab').forEach(b => {
        if (b.getAttribute('data-tab') === tab) {
          b.classList.add('active');
        } else {
          b.classList.remove('active');
        }
      });
      renderComparisonTable();
    }

    function closeComparison() {
      const panel = document.getElementById('comparison-results');
      if (panel) panel.style.display = 'none';
      comparisonData = null;
    }

    function renderComparisonTable() {
      const tbody = document.getElementById('comparison-tbody');
      if (!tbody || !comparisonData) return;
      tbody.innerHTML = '';

      let items = [];

      if (activeComparisonTab === 'ALL' || activeComparisonTab === 'NEW') {
        (comparisonData.new_findings || []).forEach(f => {
          items.push({ kind: 'NEW', finding: f, changes: null });
        });
      }
      if (activeComparisonTab === 'ALL' || activeComparisonTab === 'RESOLVED') {
        (comparisonData.resolved_findings || []).forEach(f => {
          items.push({ kind: 'RESOLVED', finding: f, changes: null });
        });
      }
      if (activeComparisonTab === 'ALL' || activeComparisonTab === 'CHANGED') {
        (comparisonData.changed_findings || []).forEach(item => {
          items.push({ kind: 'CHANGED', finding: item.newer, changes: item.changes, older: item.older });
        });
      }
      if (activeComparisonTab === 'ALL' || activeComparisonTab === 'PERSISTENT') {
        (comparisonData.persistent_findings || []).forEach(f => {
          items.push({ kind: 'PERSISTENT', finding: f, changes: null });
        });
      }

      if (items.length === 0) {
        const emptyTr = document.createElement('tr');
        emptyTr.innerHTML = `
          <td colspan="6">
            <div class="empty-state" style="padding: 2rem 1rem;">
              <p>No findings recorded under '${escapeHtml(activeComparisonTab)}' comparison classification.</p>
            </div>
          </td>
        `;
        tbody.appendChild(emptyTr);
        return;
      }

      items.forEach((it, idx) => {
        const f = it.finding;
        const kind = it.kind;
        const sevClass = 'badge-' + (f.severity || 'info').toLowerCase();
        let kindBadge = '';
        if (kind === 'NEW') kindBadge = '<span class="badge badge-diff-new">NEW</span>';
        else if (kind === 'RESOLVED') kindBadge = '<span class="badge badge-diff-resolved">RESOLVED</span>';
        else if (kind === 'CHANGED') kindBadge = '<span class="badge badge-diff-changed">CHANGED</span>';
        else kindBadge = '<span class="badge badge-diff-persistent">PERSISTENT</span>';

        let diffNote = '';
        if (kind === 'CHANGED' && it.changes) {
          const changeBits = [];
          if (it.changes.severity) {
            changeBits.push('Severity: ' + escapeHtml(it.changes.severity.older) + ' &rarr; ' + escapeHtml(it.changes.severity.newer));
          }
          if (it.changes.affected_resource) {
            changeBits.push('Resource: ' + escapeHtml(it.changes.affected_resource.older) + ' &rarr; ' + escapeHtml(it.changes.affected_resource.newer));
          }
          if (it.changes.description) {
            changeBits.push('Description updated');
          }
          if (changeBits.length) {
            diffNote = '<div class="diff-change-tag">' + changeBits.join(' | ') + '</div>';
          }
        }

        const guidance = getRemediationGuidance(f);

        const tr = document.createElement('tr');
        tr.id = 'comp-row-' + idx;
        tr.innerHTML = `
          <td><span class="id-tag">${escapeHtml(f.finding_id)}</span></td>
          <td>${kindBadge}</td>
          <td><span class="badge ${sevClass}">${escapeHtml(f.severity)}</span></td>
          <td>
            <strong>${escapeHtml(f.title)}</strong>
            ${diffNote}
          </td>
          <td><span class="resource-path" title="${escapeHtml(f.affected_resource)}">${escapeHtml(f.affected_resource)}</span></td>
          <td style="text-align: center;">
            <button type="button" class="btn btn-outline" style="padding: 0.25rem 0.6rem; font-size: 0.75rem;" onclick="toggleComparisonDetails(${idx})">
              Details
            </button>
          </td>
        `;

        const trDetails = document.createElement('tr');
        trDetails.className = 'details-row';
        trDetails.id = 'comp-details-row-' + idx;
        trDetails.innerHTML = `
          <td colspan="6">
            <div class="details-content">
              <div class="details-block">
                <div class="details-block-title">Description</div>
                <p style="color:var(--text-main); font-size:0.85rem; line-height:1.5;">${escapeHtml(f.description)}</p>
              </div>
              <div class="details-block">
                <div class="details-block-title">Evidence</div>
                <div class="details-block-text">${escapeHtml(f.evidence)}</div>
              </div>
              <div class="details-block">
                <div class="details-block-title">Recommendation &amp; Mitigation</div>
                <div class="details-block-text" style="color:#a7f3d0; border-left: 2px solid var(--severity-info);">${escapeHtml(f.recommendation)}</div>
              </div>

              <!-- Advisory Remediation Guidance -->
              <div class="guidance-container">
                <div class="guidance-header">
                  <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
                  Advisory Remediation Guidance &bull; ${escapeHtml(guidance.category)}
                </div>
                <div class="guidance-block">
                  <div class="guidance-label">Why This Finding Matters</div>
                  <p class="guidance-text">${escapeHtml(guidance.why_it_matters)}</p>
                </div>
                <div class="guidance-block">
                  <div class="guidance-label">Recommended Investigation Steps</div>
                  <ul class="guidance-list">
                    ${(guidance.investigation_steps || []).map(s => '<li>' + escapeHtml(s) + '</li>').join('')}
                  </ul>
                </div>
                <div class="guidance-block">
                  <div class="guidance-label">Safe Remediation Actions</div>
                  <ul class="guidance-list">
                    ${(guidance.remediation_steps || []).map(s => '<li style="color:#a7f3d0;">' + escapeHtml(s) + '</li>').join('')}
                  </ul>
                </div>
                <div class="guidance-block">
                  <div class="guidance-label">Validation Step (Confirm Resolution)</div>
                  <ul class="guidance-list">
                    ${(guidance.validation_steps || []).map(s => '<li>' + escapeHtml(s) + '</li>').join('')}
                  </ul>
                </div>
              </div>
            </div>
          </td>
        `;

        tbody.appendChild(tr);
        tbody.appendChild(trDetails);
      });
    }

    function toggleComparisonDetails(idx) {
      const row = document.getElementById('comp-details-row-' + idx);
      if (row) {
        row.classList.toggle('open');
      }
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    // Initialize on load
    window.addEventListener('DOMContentLoaded', initDashboard);
  </script>
</body>
</html>
"""
