"""
Axiom Scan History — Local Persistence & Version Diffing

Stores scan results in the Axiom data directory (history.db) (SQLite).
On re-scans, compares against previous results and highlights changes:
new findings, resolved findings, risk score deltas, tool mutations.

Foundation for: axiom watch, CI regression detection,
"has this server gotten worse since last scan?"
"""

import os
import json
import platform
import sqlite3
import hashlib
from typing import Optional, List, Any
from datetime import datetime, timezone
from dataclasses import dataclass, field

from app.models.schemas import FindingSeverity


def _default_mcpguard_dir() -> str:
    """Cross-platform data directory for Axiom."""
    system = platform.system()
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        return os.path.join(base, "axiom")
    elif system == "Darwin":
        return os.path.expanduser("~/Library/Application Support/axiom")
    else:
        # Linux / other — follow XDG
        xdg = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
        return os.path.join(xdg, "axiom")


def _resolve_data_dir() -> str:
    """AXIOM_DATA_DIR (or deprecated AGENTAV_DATA_DIR / MCPGUARD_DATA_DIR), else the default.

    If a legacy "agentav" or "mcpguard" directory exists and the new "axiom" one
    does not, keep using the legacy one so existing scan history is preserved.
    """
    explicit = (os.environ.get("AXIOM_DATA_DIR") or os.environ.get("AGENTAV_DATA_DIR")
                or os.environ.get("MCPGUARD_DATA_DIR"))
    if explicit:
        return explicit
    new = _default_mcpguard_dir()
    if not os.path.exists(new):
        for name in ("agentav", "mcpguard"):
            legacy = os.path.join(os.path.dirname(new), name)
            if os.path.exists(legacy):
                return legacy
    return new


MCPGUARD_DIR = _resolve_data_dir()
HISTORY_DB = os.path.join(MCPGUARD_DIR, "history.db")

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    target_url TEXT,
    scan_hash TEXT NOT NULL,
    risk_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    findings_count INTEGER NOT NULL,
    critical_count INTEGER NOT NULL,
    high_count INTEGER NOT NULL,
    medium_count INTEGER NOT NULL,
    low_count INTEGER NOT NULL,
    tool_count INTEGER NOT NULL,
    tools_json TEXT,
    findings_json TEXT NOT NULL,
    full_result_json TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    scan_duration REAL,
    package_ecosystem TEXT,
    package_version TEXT
);
CREATE INDEX IF NOT EXISTS idx_target ON scan_history(target);
CREATE INDEX IF NOT EXISTS idx_target_time ON scan_history(target, scanned_at DESC);
"""


@dataclass
class ScanDiff:
    """Comparison between two scans of the same target."""
    target: str
    previous_scan_at: str
    current_scan_at: str
    risk_score_prev: float = 0
    risk_score_curr: float = 0
    risk_score_delta: float = 0
    risk_level_prev: str = ""
    risk_level_curr: str = ""
    risk_changed: bool = False
    new_findings: List[dict] = field(default_factory=list)
    resolved_findings: List[dict] = field(default_factory=list)
    unchanged_findings: int = 0
    tools_added: List[str] = field(default_factory=list)
    tools_removed: List[str] = field(default_factory=list)
    tools_description_changed: List[dict] = field(default_factory=list)
    improved: bool = False
    degraded: bool = False
    unchanged: bool = False

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "previous_scan_at": self.previous_scan_at,
            "current_scan_at": self.current_scan_at,
            "risk_score_prev": self.risk_score_prev,
            "risk_score_curr": self.risk_score_curr,
            "risk_score_delta": self.risk_score_delta,
            "risk_level_prev": self.risk_level_prev,
            "risk_level_curr": self.risk_level_curr,
            "new_findings_count": len(self.new_findings),
            "resolved_findings_count": len(self.resolved_findings),
            "unchanged_findings": self.unchanged_findings,
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "tools_added": self.tools_added,
            "tools_removed": self.tools_removed,
            "tools_description_changed": self.tools_description_changed,
            "verdict": "improved" if self.improved else "degraded" if self.degraded else "unchanged",
        }


class ScanHistory:
    """Manages local scan result persistence and version diffing."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or HISTORY_DB
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(CREATE_TABLE_SQL)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def save(self, target: str, result: dict,
             package_ecosystem: str = None, package_version: str = None) -> int:
        """Save a scan result. Returns row ID."""
        findings = result.get("findings", [])
        findings_dicts = []
        for f in findings:
            if hasattr(f, "model_dump"):
                findings_dicts.append(f.model_dump())
            elif isinstance(f, dict):
                findings_dicts.append(f)

        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings_dicts:
            s = f.get("severity", "info")
            if isinstance(s, str) and s in sev:
                sev[s] += 1

        profile = result.get("server_profile")
        tool_list, tool_count = [], 0
        if profile:
            tools = profile.tools if hasattr(profile, "tools") else profile.get("tools", [])
            for t in tools:
                n = t.name if hasattr(t, "name") else t.get("name", "")
                d = t.description if hasattr(t, "description") else t.get("description", "")
                tool_list.append({"name": n, "description": d[:200]})
            tool_count = len(tools)

        risk_level = result.get("risk_level", "safe")
        if hasattr(risk_level, "value"):
            risk_level = risk_level.value

        scan_hash = hashlib.sha256(
            json.dumps(findings_dicts, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]

        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO scan_history
                   (target, target_url, scan_hash, risk_score, risk_level,
                    findings_count, critical_count, high_count, medium_count, low_count,
                    tool_count, tools_json, findings_json, full_result_json,
                    scanned_at, scan_duration, package_ecosystem, package_version)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (target, result.get("target_url"), scan_hash,
                 result.get("risk_score", 0), risk_level,
                 len(findings_dicts), sev["critical"], sev["high"], sev["medium"], sev["low"],
                 tool_count, json.dumps(tool_list, default=str),
                 json.dumps(findings_dicts, default=str),
                 json.dumps(self._safe(result), default=str),
                 datetime.now(timezone.utc).isoformat(),
                 result.get("scan_duration_seconds"),
                 package_ecosystem, package_version),
            )
            return cur.lastrowid

    def get_latest(self, target: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scan_history WHERE target=? ORDER BY scanned_at DESC LIMIT 1",
                (target,),
            ).fetchone()
            return dict(row) if row else None

    def get_timeline(self, target: str, limit: int = 20) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, target, risk_score, risk_level,
                          findings_count, critical_count, high_count,
                          tool_count, scanned_at, scan_duration,
                          package_version, scan_hash
                   FROM scan_history WHERE target=? ORDER BY scanned_at DESC LIMIT ?""",
                (target, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def list_targets(self, limit: int = 50) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT target, MAX(scanned_at) as last_scanned,
                          COUNT(*) as scan_count, risk_score, risk_level, findings_count
                   FROM scan_history GROUP BY target ORDER BY last_scanned DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def diff(self, target: str, current_result: dict) -> Optional[ScanDiff]:
        """Compare current result against last saved scan. None if no history."""
        prev = self.get_latest(target)
        if not prev:
            return None

        prev_findings = json.loads(prev["findings_json"])
        prev_tools = json.loads(prev.get("tools_json") or "[]")

        curr_findings = []
        for f in current_result.get("findings", []):
            curr_findings.append(f.model_dump() if hasattr(f, "model_dump") else f)

        profile = current_result.get("server_profile")
        curr_tools = []
        if profile:
            tools = profile.tools if hasattr(profile, "tools") else profile.get("tools", [])
            for t in tools:
                n = t.name if hasattr(t, "name") else t.get("name", "")
                d = t.description if hasattr(t, "description") else t.get("description", "")
                curr_tools.append({"name": n, "description": d[:200]})

        now = datetime.now(timezone.utc).isoformat()
        curr_risk = current_result.get("risk_score", 0)
        curr_level = current_result.get("risk_level", "safe")
        if hasattr(curr_level, "value"):
            curr_level = curr_level.value

        d = ScanDiff(target=target, previous_scan_at=prev["scanned_at"], current_scan_at=now)
        d.risk_score_prev = prev["risk_score"]
        d.risk_score_curr = curr_risk
        d.risk_score_delta = round(curr_risk - prev["risk_score"], 1)
        d.risk_level_prev = prev["risk_level"]
        d.risk_level_curr = curr_level
        d.risk_changed = d.risk_score_delta != 0

        # Finding diff by (category, title) fingerprint
        def fkey(f):
            cat = f.get('category', '')
            if hasattr(cat, 'value'):
                cat = cat.value
            return f"{cat}::{f.get('title', '')}"

        prev_map = {fkey(f): f for f in prev_findings}
        curr_map = {fkey(f): f for f in curr_findings}
        d.new_findings = [curr_map[k] for k in set(curr_map) - set(prev_map)]
        d.resolved_findings = [prev_map[k] for k in set(prev_map) - set(curr_map)]
        d.unchanged_findings = len(set(prev_map) & set(curr_map))

        # Tool diff
        prev_names = {t.get("name", "") for t in prev_tools}
        curr_names = {t.get("name", "") for t in curr_tools}
        d.tools_added = list(curr_names - prev_names)
        d.tools_removed = list(prev_names - curr_names)

        prev_desc = {t.get("name"): t.get("description", "") for t in prev_tools}
        curr_desc = {t.get("name"): t.get("description", "") for t in curr_tools}
        for name in prev_names & curr_names:
            if prev_desc.get(name) != curr_desc.get(name):
                d.tools_description_changed.append({
                    "tool": name,
                    "previous": prev_desc.get(name, "")[:100],
                    "current": curr_desc.get(name, "")[:100],
                })

        # Verdict
        if d.risk_score_delta < 0 or len(d.resolved_findings) > len(d.new_findings):
            d.improved = True
        elif d.risk_score_delta > 0 or len(d.new_findings) > len(d.resolved_findings):
            d.degraded = True
        else:
            d.unchanged = True

        return d

    def prune(self, keep_per_target: int = 50):
        with self._conn() as conn:
            for (t,) in conn.execute("SELECT DISTINCT target FROM scan_history").fetchall():
                conn.execute(
                    """DELETE FROM scan_history WHERE target=? AND id NOT IN (
                       SELECT id FROM scan_history WHERE target=?
                       ORDER BY scanned_at DESC LIMIT ?)""",
                    (t, t, keep_per_target),
                )

    def clear(self, target: str = None):
        with self._conn() as conn:
            if target:
                conn.execute("DELETE FROM scan_history WHERE target=?", (target,))
            else:
                conn.execute("DELETE FROM scan_history")

    def stats(self) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
            targets = conn.execute("SELECT COUNT(DISTINCT target) FROM scan_history").fetchone()[0]
            size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
            return {"total_scans": total, "unique_targets": targets,
                    "db_size_bytes": size, "db_path": self.db_path}

    def _safe(self, obj):
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        elif hasattr(obj, "value"):
            return obj.value
        elif isinstance(obj, dict):
            return {k: self._safe(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._safe(v) for v in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        return obj


scan_history = ScanHistory()
