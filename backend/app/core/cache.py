import sqlite3
import json
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

class EvidenceCache:
    """
    Local SQLite cache for OSV queries and raw vulnerability records.
    Ensures zero duplicate network calls, offline repeatability, and audit provenance.
    """

    def __init__(self, db_path: str = "patchorder_cache.db"):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        return self._conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Table 1: Package queries (stores list of vuln IDs matching package+version)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS package_queries (
                    ecosystem TEXT NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    vuln_ids_json TEXT NOT NULL,
                    raw_response TEXT NOT NULL,
                    response_hash TEXT NOT NULL,
                    retrieved_at TEXT NOT NULL,
                    PRIMARY KEY (ecosystem, name, version)
                )
            """)

            # Table 2: Full vulnerability details (stores complete advisory from /v1/vulns/{id})
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_details (
                    vuln_id TEXT PRIMARY KEY,
                    raw_json TEXT NOT NULL,
                    modified_at TEXT,
                    published_at TEXT,
                    source_hash TEXT NOT NULL,
                    retrieved_at TEXT NOT NULL
                )
            """)

            # Table 3: Scan runs provenance log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    scan_id TEXT PRIMARY KEY,
                    project_name TEXT,
                    manifest_type TEXT,
                    total_components INTEGER,
                    vulnerable_components INTEGER,
                    scanned_at TEXT NOT NULL,
                    duration_ms REAL
                )
            """)

            # Table 4: Analysis store for stateful multi-route browsing
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_store (
                    analysis_id TEXT PRIMARY KEY,
                    project_name TEXT,
                    created_at TEXT NOT NULL,
                    data_json TEXT NOT NULL
                )
            """)

            # Table 5: Commit-based scan results (Qualys integration)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS commit_scan_store (
                    job_id TEXT PRIMARY KEY,
                    repository_url TEXT,
                    revision TEXT,
                    resolved_sha TEXT,
                    scan_status TEXT,
                    findings_count INTEGER DEFAULT 0,
                    scanned_at TEXT NOT NULL,
                    data_json TEXT NOT NULL
                )
            """)
            conn.commit()

    def get_package_vulns(self, ecosystem: str, name: str, version: str) -> Optional[List[str]]:
        """Retrieve cached list of vuln IDs for package coordinate."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT vuln_ids_json FROM package_queries WHERE ecosystem = ? AND name = ? AND version = ?",
                (ecosystem, name, version)
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row["vuln_ids_json"])
            return None

    def set_package_vulns(self, ecosystem: str, name: str, version: str, vuln_ids: List[str], raw_response: str) -> None:
        """Cache OSV batch query results for package coordinate."""
        now_iso = datetime.now(timezone.utc).isoformat()
        resp_hash = hashlib.sha256(raw_response.encode("utf-8")).hexdigest()
        vuln_ids_json = json.dumps(vuln_ids)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO package_queries 
                (ecosystem, name, version, vuln_ids_json, raw_response, response_hash, retrieved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ecosystem, name, version, vuln_ids_json, raw_response, resp_hash, now_iso))
            conn.commit()

    def get_vuln_detail(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full advisory record by OSV ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT raw_json FROM vulnerability_details WHERE vuln_id = ?",
                (vuln_id,)
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row["raw_json"])
            return None

    def set_vuln_detail(self, vuln_id: str, raw_data: Dict[str, Any]) -> None:
        """Cache full advisory record with raw JSON and timestamps."""
        now_iso = datetime.now(timezone.utc).isoformat()
        raw_json = json.dumps(raw_data)
        source_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
        modified_at = raw_data.get("modified")
        published_at = raw_data.get("published")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO vulnerability_details
                (vuln_id, raw_json, modified_at, published_at, source_hash, retrieved_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (vuln_id, raw_json, modified_at, published_at, source_hash, now_iso))
            conn.commit()

    def log_scan(
        self,
        scan_id: str,
        project_name: str,
        manifest_type: str,
        total_components: int,
        vulnerable_components: int,
        duration_ms: float
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_logs 
                (scan_id, project_name, manifest_type, total_components, vulnerable_components, scanned_at, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, project_name, manifest_type, total_components, vulnerable_components, now_iso, duration_ms))
            conn.commit()

    def save_analysis(self, analysis_id: str, project_name: str, data: Dict[str, Any]) -> None:
        """Store complete analysis state for multi-route access."""
        now_iso = datetime.now(timezone.utc).isoformat()
        data_json = json.dumps(data)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO analysis_store
                (analysis_id, project_name, created_at, data_json)
                VALUES (?, ?, ?, ?)
            """, (analysis_id, project_name, now_iso, data_json))
            conn.commit()

    def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored analysis by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data_json FROM analysis_store WHERE analysis_id = ?", (analysis_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["data_json"])
            return None

    def list_analyses(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent analyses metadata."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT analysis_id, project_name, created_at 
                FROM analysis_store ORDER BY created_at DESC LIMIT ?
            """, (limit,))
            return [dict(r) for r in c_rows] if (c_rows := cursor.fetchall()) else []

    def save_commit_scan(self, job_id: str, data: Dict[str, Any]) -> None:
        """Persist a CommitScanRecord for later retrieval."""
        now_iso = datetime.now(timezone.utc).isoformat()
        data_json = json.dumps(data)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO commit_scan_store
                (job_id, repository_url, revision, resolved_sha, scan_status, findings_count, scanned_at, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                job_id,
                data.get("repository_url", ""),
                data.get("revision", ""),
                data.get("resolved_sha"),
                data.get("scan_status", "unknown"),
                data.get("findings_count", 0),
                data.get("scanned_at", now_iso),
                data_json,
            ))
            conn.commit()

    def get_commit_scan(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a CommitScanRecord by job_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT data_json FROM commit_scan_store WHERE job_id = ?",
                (job_id,)
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row["data_json"])
            return None

    def list_commit_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent commit-scan records (metadata only)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT job_id, repository_url, revision, resolved_sha, scan_status, findings_count, scanned_at
                FROM commit_scan_store ORDER BY scanned_at DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows] if rows else []

