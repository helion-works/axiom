"""
The severity policy (docs/SEVERITY.md) as code.

Two things live here so every detector applies them the same way:

* **host class** — a transport finding depends on where the server is. Loopback is
  INFO, a private range is LOW, a public host is HIGH, and "we cannot tell" (static
  source, no URL) is LOW.
* **risk score / level** — the level of a scan is driven by its *worst* finding, not by
  how many capability notes it has. Ten LOW notes do not make a server "medium".
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Optional, Tuple
from urllib.parse import urlparse

from app.models.schemas import Finding, FindingSeverity, RiskLevel

LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-_:\[\]]+$")


def host_class(target: Optional[str]) -> str:
    """'loopback' | 'private' | 'public' | 'unknown' for a URL, host, or host:port."""
    if not target:
        return "unknown"
    host = target.strip()
    if "://" in host:
        host = urlparse(host).hostname or ""
    else:
        host = host.split("/")[0]
        if host.startswith("["):
            host = host[1:host.find("]")] if "]" in host else host[1:]
        elif host.count(":") == 1:
            host = host.split(":")[0]
    host = host.strip().lower().rstrip(".")
    if not host or not _HOST_RE.match(host):
        return "unknown"
    if host in LOOPBACK_NAMES or host.endswith(".localhost"):
        return "loopback"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host.endswith((".local", ".internal", ".lan", ".home", ".corp", ".intranet")):
            return "private"
        return "public"
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "unknown"            # 0.0.0.0 / :: — a bind address, not a place
    if ip.is_private or ip.is_link_local:
        return "private"
    return "public"


def transport_severity(target: Optional[str]) -> Tuple[FindingSeverity, str]:
    """Severity for an unauthenticated / plain-HTTP transport finding, with the reason."""
    cls = host_class(target)
    if cls == "loopback":
        return FindingSeverity.INFO, "the server is on the loopback interface; only this machine can reach it"
    if cls == "private":
        return FindingSeverity.LOW, "the server is on a private network range; reachable on the LAN only"
    if cls == "public":
        return FindingSeverity.HIGH, "the server is reachable from the internet"
    return FindingSeverity.LOW, "the host is not known from the source; verify where this server is deployed"


# ---------------------------------------------------------------------------
# risk score: worst finding first, then breadth
# ---------------------------------------------------------------------------

_BASE = {
    FindingSeverity.CRITICAL: 75.0,
    FindingSeverity.HIGH: 50.0,
    FindingSeverity.MEDIUM: 25.0,
    FindingSeverity.LOW: 5.0,
    FindingSeverity.INFO: 0.0,
}
_ORDER = [FindingSeverity.INFO, FindingSeverity.LOW, FindingSeverity.MEDIUM, FindingSeverity.HIGH, FindingSeverity.CRITICAL]


def risk_score(findings: Iterable[Finding]) -> float:
    """0–100. The worst severity sets the band (critical ≥75, high ≥50, medium ≥25, low ≥5);
    additional findings of the top two bands add a little breadth inside the band."""
    findings = list(findings)
    if not findings:
        return 0.0
    worst = max((f.severity for f in findings), key=_ORDER.index)
    score = _BASE[worst]
    if worst in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        extra_crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        extra_high = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
        n = extra_crit + extra_high - 1
        score += min(24.0, 4.0 * max(n, 0))
    elif worst == FindingSeverity.MEDIUM:
        n = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM) - 1
        score += min(20.0, 3.0 * max(n, 0))
    elif worst == FindingSeverity.LOW:
        n = sum(1 for f in findings if f.severity == FindingSeverity.LOW) - 1
        score += min(15.0, 2.0 * max(n, 0))
    return min(round(score, 1), 100.0)


def risk_level(score: float) -> RiskLevel:
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    if score > 0:
        return RiskLevel.LOW
    return RiskLevel.SAFE
