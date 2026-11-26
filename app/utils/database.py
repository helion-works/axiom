"""Scan storage for the API: SQLite, with an in-memory fallback when SQLite cannot be opened."""

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.utils.logging import get_logger

logger = get_logger("database")

_backend: str = "memory"  # "memory" or "sqlite"
_scan_store: dict = {}  # in-memory fallback
_counter = 0
_sqlite_path: Optional[str] = None

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
"""


def _get_sqlite_path() -> str:
    from app.utils.config import settings
    db_dir = os.path.join(settings.TEMP_SCAN_DIR, "db")
    os.makedirs(db_dir, exist_ok=True)
    return os.path.join(db_dir, "mcpguard_scans.db")


def _sqlite_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_sqlite_path)
    conn.row_factory = sqlite3.Row
    return conn


async def init_db():
    global _backend, _sqlite_path
    try:
        _sqlite_path = _get_sqlite_path()
        with sqlite3.connect(_sqlite_path) as conn:
            conn.executescript(_SQLITE_SCHEMA)
        _backend = "sqlite"
        logger.info("Database backend: SQLite", extra={"target": _sqlite_path})
    except Exception as e:
        _backend = "memory"
        logger.warning(
            f"SQLite init failed, falling back to in-memory: {e}"
        )


async def save_scan(scan_data: dict) -> str:
    global _counter

    scan_id = f"mcpg_{uuid.uuid4().hex[:10]}"
    scan_data["id"] = scan_id
    scan_data["created_at"] = datetime.now(timezone.utc).isoformat()

    if _backend == "sqlite" and _sqlite_path:
        try:
            with _sqlite_conn() as conn:
                conn.execute(
                    "INSERT INTO scans (id, data, created_at) VALUES (?, ?, ?)",
                    (scan_id, json.dumps(scan_data, default=str), scan_data["created_at"]),
                )
            return scan_id
        except Exception as e:
            logger.error(f"SQLite save failed, falling back to memory: {e}")

    # In-memory fallback
    _scan_store[scan_id] = scan_data
    return scan_id


async def get_scan(scan_id: str) -> Optional[dict]:
    if _backend == "sqlite" and _sqlite_path:
        try:
            with _sqlite_conn() as conn:
                row = conn.execute(
                    "SELECT data FROM scans WHERE id = ?", (scan_id,)
                ).fetchone()
                if row:
                    return json.loads(row["data"])
                return None
        except Exception as e:
            logger.error(f"SQLite get failed: {e}")

    return _scan_store.get(scan_id)


async def list_scans(limit: int = 50) -> list:
    if _backend == "sqlite" and _sqlite_path:
        try:
            with _sqlite_conn() as conn:
                rows = conn.execute(
                    "SELECT data FROM scans ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [json.loads(r["data"]) for r in rows]
        except Exception as e:
            logger.error(f"SQLite list failed: {e}")

    results = sorted(
        _scan_store.values(),
        key=lambda x: x.get("created_at", ""),
        reverse=True,
    )
    return results[:limit]
