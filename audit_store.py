"""
AI-GRID Audit Store & Persistence Engine (v4.0)

Provides SQLite-backed persistence for all audit runs, structured Evidence items,
security findings, and compliance assessment states.

Ensures audits are preserved across server restarts, supporting research
reproducibility and longitudinal governance tracking.
"""

import hashlib
import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aigrid.audit_store")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "aigrid_audits.db")


class AuditStore:
    """SQLite-backed persistent store for AI-GRID audits and evidence trails."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes database tables if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audits (
                    audit_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    audit_mode TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    model_version TEXT,
                    domain TEXT,
                    aas_score REAL,
                    trust_grade TEXT NOT NULL,
                    bottleneck_dimension TEXT,
                    bottleneck_score REAL,
                    overall_confidence REAL,
                    payload_json TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    audit_id TEXT NOT NULL,
                    dimension TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tier TEXT NOT NULL,
                    value REAL,
                    description TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (audit_id) REFERENCES audits(audit_id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    audit_id TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    dimension TEXT NOT NULL,
                    finding TEXT NOT NULL,
                    action TEXT NOT NULL,
                    eu_ai_act_ref TEXT,
                    owasp_ref TEXT,
                    mitre_atlas_ref TEXT,
                    FOREIGN KEY (audit_id) REFERENCES audits(audit_id) ON DELETE CASCADE
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audits_created ON audits(created_at DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audits_mode ON audits(audit_mode)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_audit ON audit_evidence(audit_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_audit ON audit_findings(audit_id)")
            conn.commit()

    def save_audit(self, payload: Dict[str, Any]) -> str:
        """
        Persists a full audit payload and returns its unique audit_id.
        """
        audit_id = str(uuid.uuid4())
        created_at = payload.get("model_metadata", {}).get("audit_timestamp") or datetime.now().isoformat()
        audit_mode = payload.get("audit_mode", "unknown")
        meta = payload.get("model_metadata", {})
        scoring = payload.get("scoring", {})

        model_name = meta.get("model_name", "AI System Under Audit")
        model_version = meta.get("version", "1.0.0")
        domain = meta.get("domain", "General Purpose AI")
        aas_raw = scoring.get("aas_score")
        aas_score = float(aas_raw) if aas_raw is not None else None
        trust_grade = str(scoring.get("trust_grade", "INSUFFICIENT_EVIDENCE"))
        bottleneck_dimension = str(scoring.get("bottleneck_dimension", "Unknown"))
        btn_raw = scoring.get("bottleneck_score")
        bottleneck_score = float(btn_raw) if btn_raw is not None else None
        conf_raw = scoring.get("overall_confidence")
        overall_confidence = float(conf_raw) if conf_raw is not None else 0.0

        # Attach ID back to payload
        payload["audit_id"] = audit_id

        # Compute cryptographic SHA-256 integrity hash of canonical payload
        canonical_bytes = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        audit_hash = hashlib.sha256(canonical_bytes).hexdigest()
        payload["audit_hash"] = audit_hash
        payload["sha256_hash"] = audit_hash

        payload_json = json.dumps(payload, ensure_ascii=False)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audits (
                    audit_id, created_at, audit_mode, model_name, model_version,
                    domain, aas_score, trust_grade, bottleneck_dimension,
                    bottleneck_score, overall_confidence, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                audit_id, created_at, audit_mode, model_name, model_version,
                domain, aas_score, trust_grade, bottleneck_dimension,
                bottleneck_score, overall_confidence, payload_json,
            ))

            # Store findings
            findings = payload.get("remediation_plan", [])
            for f in findings:
                cursor.execute("""
                    INSERT INTO audit_findings (
                        audit_id, priority, dimension, finding, action,
                        eu_ai_act_ref, owasp_ref, mitre_atlas_ref
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    audit_id,
                    f.get("priority", "MEDIUM"),
                    f.get("dimension", "General"),
                    f.get("finding", ""),
                    f.get("action", ""),
                    f.get("eu_ai_act_ref", ""),
                    f.get("owasp_ref", ""),
                    f.get("mitre_atlas_ref", ""),
                ))

            conn.commit()

        logger.info(f"Saved audit {audit_id} ({audit_mode}) to SQLite store.")
        return audit_id

    def get_audit(self, audit_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a complete audit payload by audit_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT payload_json FROM audits WHERE audit_id = ?", (audit_id,))
            row = cursor.fetchone()
            if not row:
                return None
            try:
                return json.loads(row["payload_json"])
            except Exception as e:
                logger.error(f"Failed to deserialize audit {audit_id}: {e}")
                return None

    def get_latest_audit(self, audit_mode: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves the most recent audit, optionally filtered by mode ('mcp' or 'questionnaire')."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if audit_mode:
                cursor.execute(
                    "SELECT payload_json FROM audits WHERE audit_mode = ? ORDER BY created_at DESC LIMIT 1",
                    (audit_mode,)
                )
            else:
                cursor.execute(
                    "SELECT payload_json FROM audits ORDER BY created_at DESC LIMIT 1"
                )
            row = cursor.fetchone()
            if not row:
                return None
            try:
                return json.loads(row["payload_json"])
            except Exception as e:
                logger.error(f"Failed to deserialize latest audit: {e}")
                return None

    def list_audits(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists metadata summaries for past audits."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT audit_id, created_at, audit_mode, model_name, model_version,
                       domain, aas_score, trust_grade, bottleneck_dimension,
                       bottleneck_score, overall_confidence
                FROM audits
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def delete_audit(self, audit_id: str) -> bool:
        """Deletes an audit and associated records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM audits WHERE audit_id = ?", (audit_id,))
            conn.commit()
            return cursor.rowcount > 0

    def clear_all(self):
        """Clears all audit records (for test teardown or reset)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM audit_findings")
            cursor.execute("DELETE FROM audit_evidence")
            cursor.execute("DELETE FROM audits")
            conn.commit()
