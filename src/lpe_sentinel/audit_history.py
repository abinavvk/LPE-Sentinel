"""
Persistent Audit History Module for LPE Sentinel using SQLite.

Provides secure, parameterized, sanitized, and bounded storage of completed
audit results using the Python standard-library sqlite3. Zero external dependencies.
"""

import json
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

try:
    from lpe_sentinel.audit_engine import AuditResult, AuditStatus
    from lpe_sentinel.models import Finding
except ImportError:
    from audit_engine import AuditResult, AuditStatus
    from models import Finding

# Default retention limit: maximum number of audit records preserved
DEFAULT_RETENTION_LIMIT: int = 100

# Bounded limit constraints for history listing API
DEFAULT_LIST_LIMIT: int = 10
MAX_LIST_LIMIT: int = 50

# Scan ID validation pattern: 8 to 64 alphanumeric chars, hyphens, underscores
SCAN_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{8,64}$")


class AuditHistoryError(Exception):
    """Sanitized exception for audit history operations without filesystem leak."""
    pass


def sanitize_findings_data(findings: Sequence[Any]) -> List[Dict[str, Any]]:
    """
    Sanitize and extract essential Finding fields for persistent storage.

    Never stores passwords, environment variables, or arbitrary objects.
    """
    sanitized: List[Dict[str, Any]] = []
    for f in findings:
        if hasattr(f, "to_dict"):
            d = f.to_dict()
        elif isinstance(f, dict):
            d = f
        else:
            continue

        finding_dict = {
            "finding_id": str(d.get("finding_id", "UNKNOWN")),
            "title": str(d.get("title", "Untitled Finding")),
            "severity": str(d.get("severity", "INFO")).upper(),
            "description": str(d.get("description", "")),
            "evidence": str(d.get("evidence", "")),
            "affected_resource": str(d.get("affected_resource", "")),
            "recommendation": str(d.get("recommendation", "")),
            "mitre_attack": str(d["mitre_attack"]) if d.get("mitre_attack") is not None else None,
        }
        sanitized.append(finding_dict)
    return sanitized


def sanitize_system_info_data(sys_info: Any) -> Dict[str, Any]:
    """
    Sanitize system metadata for persistent storage according to data minimization principles.

    Excludes sensitive identifiers (usernames, local paths, full environment blocks).
    """
    if not isinstance(sys_info, dict):
        return {"platform_category": "Unknown", "is_linux": False}

    return {
        "os_name": str(sys_info.get("os_name", "Unknown")),
        "release": str(sys_info.get("release", sys_info.get("os_release", "Unknown"))),
        "architecture": str(sys_info.get("architecture", "Unknown")),
        "platform_category": str(sys_info.get("platform_category", "Unknown")),
        "is_linux": sys_info.get("platform_category") == "Linux" or sys_info.get("is_linux") is True,
    }


def sanitize_scanner_results_data(scanner_results: Any) -> Dict[str, Any]:
    """
    Extract sanitized scanner execution statuses without raw internal objects.
    """
    results: Dict[str, Any] = {}
    if not isinstance(scanner_results, dict):
        return results

    for name, res in scanner_results.items():
        if hasattr(res, "to_dict"):
            d = res.to_dict()
        elif isinstance(res, dict):
            d = res
        else:
            d = {"status": str(res)}

        results[str(name)] = {
            "scanner_name": str(d.get("scanner_name", name)),
            "status": str(d.get("status", "UNKNOWN")),
            "findings_count": int(d.get("findings_count", 0)),
            "error": str(d["error"]) if d.get("error") is not None else None,
            "message": str(d["message"]) if d.get("message") is not None else None,
        }
    return results


def extract_severity_summary(summary: Any) -> Dict[str, int]:
    """Extract standard severity counts from an audit summary dictionary."""
    if not isinstance(summary, dict):
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}

    sev_counts = summary.get("severity_counts", {})
    if not isinstance(sev_counts, dict):
        sev_counts = {}

    critical = int(sev_counts.get("CRITICAL", summary.get("critical", 0)))
    high = int(sev_counts.get("HIGH", summary.get("high", 0)))
    medium = int(sev_counts.get("MEDIUM", summary.get("medium", 0)))
    low = int(sev_counts.get("LOW", summary.get("low", 0)))
    info = int(sev_counts.get("INFO", summary.get("info", 0)))
    total = int(summary.get("total_findings", summary.get("total", critical + high + medium + low + info)))

    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "total": total,
    }


class AuditHistoryManager:
    """
    Manages SQLite-based audit persistence, retrieval, and retention pruning.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        max_records: int = DEFAULT_RETENTION_LIMIT,
    ) -> None:
        """
        Initialize the history manager with database location and retention policy.

        Args:
            db_path: Path to SQLite database file or ':memory:'. Defaults to
                     ~/.lpe_sentinel/audit_history.db or LPE_SENTINEL_DB_PATH.
            max_records: Maximum number of audit records retained in database.
        """
        if db_path is None:
            env_path = os.environ.get("LPE_SENTINEL_DB_PATH")
            if env_path:
                self.db_path = str(Path(env_path).resolve())
            else:
                self.db_path = str((Path.home() / ".lpe_sentinel" / "audit_history.db").resolve())
        else:
            self.db_path = str(db_path)

        self.max_records = max(1, int(max_records))
        self._lock = threading.Lock()
        self._initialized = False

    def _get_connection(self) -> sqlite3.Connection:
        """Open a standard library sqlite3 connection with row factory and timeout."""
        if self.db_path != ":memory:":
            parent_dir = os.path.dirname(self.db_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)

        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _connection(self):
        """Context manager that guarantees transaction commit/rollback and explicit connection close."""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def init_db(self) -> None:
        """
        Create schema and index if not already present. Idempotent.
        """
        with self._lock:
            try:
                with self._connection() as conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS audit_history (
                            scan_id TEXT PRIMARY KEY,
                            timestamp TEXT NOT NULL,
                            status TEXT NOT NULL,
                            is_complete INTEGER NOT NULL,
                            duration_ms REAL,
                            total_findings INTEGER NOT NULL DEFAULT 0,
                            critical_count INTEGER NOT NULL DEFAULT 0,
                            high_count INTEGER NOT NULL DEFAULT 0,
                            medium_count INTEGER NOT NULL DEFAULT 0,
                            low_count INTEGER NOT NULL DEFAULT 0,
                            info_count INTEGER NOT NULL DEFAULT 0,
                            scanners_json TEXT NOT NULL,
                            findings_json TEXT NOT NULL,
                            system_info_json TEXT NOT NULL,
                            errors_json TEXT NOT NULL,
                            created_at REAL NOT NULL
                        )
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_audit_history_created_at
                        ON audit_history(created_at DESC)
                    """)
                self._initialized = True
            except (sqlite3.Error, OSError) as exc:
                raise AuditHistoryError("Failed to initialize audit history database") from exc

    def _ensure_initialized(self) -> None:
        """Ensure database table exists before performing read/write operations."""
        if not self._initialized:
            self.init_db()

    def save_audit(
        self,
        audit: Union[AuditResult, Dict[str, Any]],
        duration_ms: Optional[float] = None,
        sanitized_sys_info: Optional[Dict[str, Any]] = None,
        scan_id: Optional[str] = None,
    ) -> str:
        """
        Persist a completed audit result and prune records beyond retention limit.

        Args:
            audit: AuditResult instance or equivalent dictionary.
            duration_ms: Execution duration in milliseconds.
            sanitized_sys_info: Optional pre-sanitized host metadata.
            scan_id: Optional custom scan ID (must match SCAN_ID_REGEX).

        Returns:
            The unique scan_id string for the saved record.

        Raises:
            AuditHistoryError: If database persistence fails.
            ValueError: If custom scan_id is invalid.
        """
        self._ensure_initialized()

        if scan_id is None:
            scan_id = f"audit-{uuid.uuid4().hex[:16]}"
        else:
            if not isinstance(scan_id, str) or not SCAN_ID_REGEX.match(scan_id):
                raise ValueError(f"Invalid scan_id format: {scan_id!r}")

        # Extract fields depending on whether audit is AuditResult or dict
        if isinstance(audit, AuditResult):
            status = str(audit.status).upper()
            is_complete = bool(audit.is_complete)
            timestamp = str(audit.timestamp)
            raw_findings = audit.findings
            raw_summary = audit.summary
            raw_sys_info = audit.system_info
            raw_scanners = audit.scanner_results
            raw_errors = audit.errors
        elif isinstance(audit, dict):
            status = str(audit.get("status", "COMPLETED")).upper()
            is_complete = bool(audit.get("is_complete", status == "COMPLETED"))
            timestamp = str(audit.get("timestamp", datetime.now(timezone.utc).isoformat()))
            raw_findings = audit.get("findings", [])
            raw_summary = audit.get("summary", {})
            raw_sys_info = audit.get("system_info", {})
            raw_scanners = audit.get("scanner_results", {})
            raw_errors = audit.get("errors", [])
        else:
            raise AuditHistoryError("Unsupported audit object type for persistence")

        summary_counts = extract_severity_summary(raw_summary)
        sanitized_findings = sanitize_findings_data(raw_findings)
        sanitized_system = sanitize_system_info_data(sanitized_sys_info or raw_sys_info)
        sanitized_scanners = sanitize_scanner_results_data(raw_scanners)
        sanitized_errors = [str(err) for err in raw_errors if isinstance(err, str)]

        # Deterministic JSON serialization
        findings_json = json.dumps(sanitized_findings, sort_keys=True)
        system_info_json = json.dumps(sanitized_system, sort_keys=True)
        scanners_json = json.dumps(sanitized_scanners, sort_keys=True)
        errors_json = json.dumps(sanitized_errors, sort_keys=True)
        now_ts = time.time()

        with self._lock:
            try:
                with self._connection() as conn:
                    # 1. Insert new record with parameterized SQL
                    conn.execute("""
                        INSERT INTO audit_history (
                            scan_id, timestamp, status, is_complete, duration_ms,
                            total_findings, critical_count, high_count, medium_count, low_count, info_count,
                            scanners_json, findings_json, system_info_json, errors_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        timestamp,
                        status,
                        1 if is_complete else 0,
                        duration_ms,
                        summary_counts["total"],
                        summary_counts["critical"],
                        summary_counts["high"],
                        summary_counts["medium"],
                        summary_counts["low"],
                        summary_counts["info"],
                        scanners_json,
                        findings_json,
                        system_info_json,
                        errors_json,
                        now_ts,
                    ))

                    # 2. Prune records exceeding retention limit
                    conn.execute("""
                        DELETE FROM audit_history
                        WHERE scan_id NOT IN (
                            SELECT scan_id FROM audit_history
                            ORDER BY created_at DESC
                            LIMIT ?
                        )
                    """, (self.max_records,))
            except (sqlite3.Error, OSError) as exc:
                raise AuditHistoryError("Failed to save audit record to database") from exc

        return scan_id

    def list_audits(self, limit: int = DEFAULT_LIST_LIMIT) -> List[Dict[str, Any]]:
        """
        Retrieve recent audit summaries ordered by most recent first.

        Args:
            limit: Maximum records to return (bounded between 1 and MAX_LIST_LIMIT).

        Returns:
            List of summary dictionaries.

        Raises:
            AuditHistoryError: If database read fails.
        """
        self._ensure_initialized()
        bounded_limit = max(1, min(int(limit), MAX_LIST_LIMIT))

        with self._lock:
            try:
                with self._connection() as conn:
                    cursor = conn.execute("""
                        SELECT scan_id, timestamp, status, is_complete, duration_ms,
                               total_findings, critical_count, high_count, medium_count,
                               low_count, info_count, scanners_json, created_at
                        FROM audit_history
                        ORDER BY created_at DESC
                        LIMIT ?
                    """, (bounded_limit,))
                    rows = cursor.fetchall()
            except (sqlite3.Error, OSError) as exc:
                raise AuditHistoryError("Failed to retrieve audit history from database") from exc

        results: List[Dict[str, Any]] = []
        for r in rows:
            try:
                scanners_data = json.loads(r["scanners_json"])
            except Exception:
                scanners_data = {}

            scanner_statuses = {}
            for s_name, s_info in scanners_data.items():
                if isinstance(s_info, dict):
                    scanner_statuses[s_name] = s_info.get("status", "UNKNOWN")
                else:
                    scanner_statuses[s_name] = str(s_info)

            results.append({
                "scan_id": r["scan_id"],
                "timestamp": r["timestamp"],
                "status": r["status"],
                "is_complete": bool(r["is_complete"]),
                "duration_ms": r["duration_ms"],
                "total_findings": r["total_findings"],
                "summary": {
                    "critical": r["critical_count"],
                    "high": r["high_count"],
                    "medium": r["medium_count"],
                    "low": r["low_count"],
                    "info": r["info_count"],
                    "total": r["total_findings"],
                },
                "scanner_statuses": scanner_statuses,
            })
        return results

    def get_audit(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a single full audit record by its scan ID.

        Args:
            scan_id: The unique scan identifier to query.

        Returns:
            Full audit record dict suitable for dashboard rendering, or None if not found.

        Raises:
            ValueError: If scan_id format is invalid.
            AuditHistoryError: If database read or JSON deserialization fails.
        """
        self._ensure_initialized()

        if not isinstance(scan_id, str) or not SCAN_ID_REGEX.match(scan_id):
            raise ValueError(f"Invalid scan ID format: {scan_id!r}")

        with self._lock:
            try:
                with self._connection() as conn:
                    cursor = conn.execute("""
                        SELECT scan_id, timestamp, status, is_complete, duration_ms,
                               total_findings, critical_count, high_count, medium_count,
                               low_count, info_count, scanners_json, findings_json,
                               system_info_json, errors_json, created_at
                        FROM audit_history
                        WHERE scan_id = ?
                    """, (scan_id,))
                    row = cursor.fetchone()
            except (sqlite3.Error, OSError) as exc:
                raise AuditHistoryError("Failed to read audit record from database") from exc

        if row is None:
            return None

        try:
            findings = json.loads(row["findings_json"])
            system_info = json.loads(row["system_info_json"])
            scanner_results = json.loads(row["scanners_json"])
            errors = json.loads(row["errors_json"])
        except Exception as exc:
            raise AuditHistoryError("Corrupt data in audit history record") from exc

        return {
            "scan_id": row["scan_id"],
            "timestamp": row["timestamp"],
            "status": row["status"],
            "is_complete": bool(row["is_complete"]),
            "duration_ms": row["duration_ms"],
            "is_historical": True,
            "is_demo": False,
            "is_simulated": False,
            "summary": {
                "critical": row["critical_count"],
                "high": row["high_count"],
                "medium": row["medium_count"],
                "low": row["low_count"],
                "info": row["info_count"],
                "total": row["total_findings"],
            },
            "system_info": system_info,
            "scanner_results": scanner_results,
            "errors": errors,
            "findings": findings,
        }

    def count_audits(self) -> int:
        """Return the total number of records currently stored."""
        self._ensure_initialized()
        with self._lock:
            try:
                with self._connection() as conn:
                    cursor = conn.execute("SELECT COUNT(*) AS total FROM audit_history")
                    row = cursor.fetchone()
                    return int(row["total"]) if row else 0
            except (sqlite3.Error, OSError) as exc:
                raise AuditHistoryError("Failed to count audit history records") from exc
