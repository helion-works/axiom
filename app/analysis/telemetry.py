"""
Anonymous, opt-out usage ping (documented in the README, "Usage ping").

What is sent, and nothing else (the exact shape is documented in the README and pinned by
tests/test_phase4_telemetry.py):

    {"schema": 1, "install_id": "<uuid4>", "client_version": "0.6.0", "os": "windows|macos|linux|other",
     "python": "3.12",
     "counts": {"clients_detected": n, "servers_inventoried": n, "findings_critical": n,
                "findings_high": n, "findings_medium": n},
     "sent_at": "<ISO-8601 UTC>"}

Never: server names, tool names, file paths, env var names or values, config contents,
hostnames, usernames, findings text. Counts only. At most one send per 24 h, after a
successful `axiom check` (or the no-argument default run), on a background thread with a
3 s timeout that the command waits for before it exits; a failure is logged at debug level
and ignored. `axiom telemetry off`,
`AXIOM_TELEMETRY=0` (legacy `MCPGUARD_TELEMETRY=0`) and `DO_NOT_TRACK=1` each mean no
network call at all.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("axiom.telemetry")

CLIENT_VERSION = "0.6.0"
DEFAULT_ENDPOINT = "https://telemetry.helionworks.com/v1/ping"
PAYLOAD_KEYS = ("schema", "install_id", "client_version", "os", "python", "counts", "sent_at")
COUNT_KEYS = ("clients_detected", "servers_inventoried", "findings_critical", "findings_high", "findings_medium")
NOTICE = (
    "Axiom sends an anonymous usage ping (install id, version, OS, and finding COUNTS - never\n"
    "names, paths or contents). See exactly what is sent with `axiom telemetry show`.\n"
    "Disable any time with `axiom telemetry off`.\n"
)


def _data_dir() -> str:
    from app.analysis.scan_history import MCPGUARD_DIR
    os.makedirs(MCPGUARD_DIR, exist_ok=True)
    return MCPGUARD_DIR


def _state_path() -> str:
    return os.path.join(_data_dir(), "telemetry.json")


def load_state() -> Dict[str, Any]:
    try:
        with open(_state_path(), "r", encoding="utf-8") as f:
            st = json.load(f)
            if isinstance(st, dict):
                return st
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_state(st: Dict[str, Any]) -> None:
    try:
        with open(_state_path(), "w", encoding="utf-8") as f:
            json.dump(st, f, indent=2)
    except OSError:
        pass


def install_id(regenerate: bool = False) -> str:
    """Random UUIDv4, stored next to the data; never derived from hardware or user names."""
    st = load_state()
    if regenerate or not st.get("install_id"):
        st["install_id"] = str(uuid.uuid4())
        save_state(st)
    return st["install_id"]


def env_disabled() -> bool:
    for var in ("AXIOM_TELEMETRY", "AGENTAV_TELEMETRY", "MCPGUARD_TELEMETRY"):
        v = os.getenv(var)
        if v is not None and v.strip().lower() in ("0", "false", "no", "off"):
            return True
    dnt = os.getenv("DO_NOT_TRACK")
    return bool(dnt and dnt.strip().lower() in ("1", "true", "yes"))


def enabled() -> bool:
    if env_disabled():
        return False
    return bool(load_state().get("enabled", True))


def set_enabled(value: bool) -> None:
    st = load_state()
    st["enabled"] = bool(value)
    save_state(st)


def endpoint() -> str:
    return os.getenv("AXIOM_TELEMETRY_ENDPOINT") or load_state().get("endpoint") or DEFAULT_ENDPOINT


def _os_name() -> str:
    s = platform.system().lower()
    # Anything else is sent as "other": the raw platform string can carry a build number.
    return {"windows": "windows", "darwin": "macos", "linux": "linux"}.get(s, "other")


def build_payload(counts: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """The whole thing. Anything not in PAYLOAD_KEYS / COUNT_KEYS is dropped, whatever is passed in."""
    counts = counts or {}
    safe_counts = {k: int(counts.get(k, 0) or 0) for k in COUNT_KEYS}
    return {
        "schema": 1,
        "install_id": install_id(),
        "client_version": CLIENT_VERSION,
        "os": _os_name(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "counts": safe_counts,
        "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def counts_from_check(result: Dict[str, Any]) -> Dict[str, int]:
    """Counts only, derived from a `check` run (a local config scan result)."""
    findings = result.get("findings", []) or []
    def sev(f):
        s = getattr(f, "severity", None)
        s = getattr(s, "value", s)
        return s or (f.get("severity") if isinstance(f, dict) else None)
    return {
        "clients_detected": len(result.get("config_files_found", []) or []),
        "servers_inventoried": int(result.get("total_servers", 0) or 0),
        "findings_critical": sum(1 for f in findings if sev(f) == "critical"),
        "findings_high": sum(1 for f in findings if sev(f) == "high"),
        "findings_medium": sum(1 for f in findings if sev(f) == "medium"),
    }


def first_run_notice_due() -> bool:
    return enabled() and not load_state().get("notice_shown")


def mark_notice_shown() -> None:
    st = load_state()
    st["notice_shown"] = True
    save_state(st)


def _throttled(st: Dict[str, Any]) -> bool:
    last = st.get("last_sent_at")
    if not last:
        return False
    try:
        return datetime.now(timezone.utc) - datetime.fromisoformat(last.replace("Z", "+00:00")) < timedelta(hours=24)
    except ValueError:
        return False


def _post(payload: Dict[str, Any]) -> None:
    try:
        import httpx
        with httpx.Client(timeout=3.0) as client:
            client.post(endpoint(), json=payload, headers={"User-Agent": f"axiom/{CLIENT_VERSION} ({payload['os']})"})
    except Exception as e:  # never surfaces
        logger.debug("telemetry send failed: %s", e)


_pending: Optional[threading.Thread] = None


def flush(timeout: float = 3.5) -> None:
    """Wait for a ping started by maybe_send. A command calls this just before it exits:
    the send runs on a daemon thread, which the interpreter would otherwise end unsent."""
    global _pending
    thread, _pending = _pending, None
    if thread is not None:
        thread.join(timeout)


def maybe_send(counts: Dict[str, int], *, blocking: bool = False) -> bool:
    """Send at most once per 24 h, only when enabled. Returns True if a send was started."""
    global _pending
    if not enabled():
        return False
    st = load_state()
    if _throttled(st):
        return False
    payload = build_payload(counts)
    st = load_state()  # build_payload creates the install id on first use; reload so it is not overwritten
    st["last_sent_at"] = payload["sent_at"]
    save_state(st)
    if blocking:
        _post(payload)
    else:
        t = threading.Thread(target=_post, args=(payload,), daemon=True)
        t.start()
        _pending = t
    return True
