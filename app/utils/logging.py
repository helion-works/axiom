"""Structured logging for Axiom with scan correlation IDs."""

import logging
import json
import uuid
import contextvars
from datetime import datetime, timezone
from typing import Optional

# Context variable to track scan correlation ID across async calls
_scan_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "scan_id", default=None
)


def get_scan_id() -> Optional[str]:
    return _scan_id_var.get()


def set_scan_id(scan_id: Optional[str] = None) -> str:
    """Set (or generate) a correlation ID for the current scan."""
    sid = scan_id or f"scan_{uuid.uuid4().hex[:12]}"
    _scan_id_var.set(sid)
    return sid


def clear_scan_id():
    _scan_id_var.set(None)


class JSONFormatter(logging.Formatter):
    """Emit structured JSON log lines with scan correlation."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        scan_id = get_scan_id()
        if scan_id:
            entry["scan_id"] = scan_id

        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = self.formatException(record.exc_info)

        # Include any extra fields passed via `extra={}`
        for key in ("target", "duration", "risk_score", "finding_count",
                     "transport", "server_name", "repo_url", "repo_size_mb"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val

        return json.dumps(entry, default=str)


def setup_logging(level: str = "INFO", json_output: bool = True):
    """Configure root logger for Axiom."""
    root = logging.getLogger("axiom")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    if root.handlers:
        return  # Already configured

    handler = logging.StreamHandler()
    if json_output:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )

    root.addHandler(handler)
    # Prevent duplicate logs from propagating to root
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the axiom namespace."""
    return logging.getLogger(f"axiom.{name}")
