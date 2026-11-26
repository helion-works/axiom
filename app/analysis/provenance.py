"""
Provenance, not just CVEs (Phase 4, E.3).

A per-server provenance check with three signals beside the OSV advisories:

* **registry identity** — does what we scanned match what the official MCP Registry lists
  under that package / name: same source repository? A mismatch is ``provenance_mismatch``
  (HIGH): the artefact is not the one the registry vouches for.
* **lookalike name** — a registry entry whose short name is one edit (or one confusable
  character) away from ours, published by a different publisher and pointing at a different
  repository, is ``registry_typosquat`` (HIGH).
* **freshness** — a registry entry published less than 7 days ago is ``supply_chain``
  (MEDIUM): nobody has had time to look at it.

Lookups go to ``https://registry.modelcontextprotocol.io/v0/servers?search=…`` and are
cached for 24 hours next to the OSV cache. Everything is best-effort: no network, no
findings, and the scan goes on.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.analysis.tool_poisoning import _near_duplicate, homoglyph_reason
from app.models.schemas import Finding, FindingCategory, FindingSeverity

REGISTRY_URL = os.getenv("AXIOM_REGISTRY_URL", "https://registry.modelcontextprotocol.io/v0/servers")
CACHE_TTL = 24 * 3600
FRESH_DAYS = 7


# ---------------------------------------------------------------------------
# identity of what we scanned
# ---------------------------------------------------------------------------

def normalise_repo(url: Optional[str]) -> str:
    if not url or not isinstance(url, str):
        return ""
    u = url.strip()
    u = re.sub(r"^git\+", "", u)
    u = re.sub(r"^git@github\.com:", "https://github.com/", u)
    u = re.sub(r"^ssh://git@", "https://", u)
    u = re.sub(r"\.git$", "", u)
    u = u.rstrip("/").lower()
    m = re.match(r"^https?://(www\.)?(github\.com|gitlab\.com)/([^/]+)/([^/#?]+)", u)
    if m:
        return f"https://{m.group(2)}/{m.group(3)}/{m.group(4)}"
    return u


def short_name(name: str) -> str:
    """'io.github.owner/airtable-mcp-server' -> 'airtable-mcp-server'; '@scope/pkg' -> 'pkg'."""
    n = (name or "").split("/")[-1]
    return n.lower()


def publisher_of(registry_name: str) -> str:
    return (registry_name or "").split("/")[0].lower()


def identify(scan_dir: str, target_url: Optional[str] = None, package_info: Any = None,
             server_name: Optional[str] = None) -> Dict[str, Any]:
    """What we scanned: package names, repository, announced server name."""
    ident: Dict[str, Any] = {"npm": None, "pypi": None, "repository": normalise_repo(target_url), "server_name": server_name or ""}
    pkg_json = os.path.join(scan_dir, "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                pkg = json.load(f)
            if isinstance(pkg.get("name"), str):
                ident["npm"] = pkg["name"]
            repo = pkg.get("repository")
            if isinstance(repo, dict):
                repo = repo.get("url")
            if isinstance(repo, str) and not ident["repository"]:
                if re.match(r"^[\w.-]+/[\w.-]+$", repo):
                    repo = "https://github.com/" + repo
                ident["repository"] = normalise_repo(repo)
        except (OSError, json.JSONDecodeError):
            pass
    pyproject = os.path.join(scan_dir, "pyproject.toml")
    if os.path.exists(pyproject):
        try:
            with open(pyproject, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            m = re.search(r'(?m)^name\s*=\s*"([^"]+)"', text)
            if m:
                ident["pypi"] = m.group(1)
            if not ident["repository"]:
                m = re.search(r'(?im)^(?:Repository|Source|Homepage)\s*=\s*"([^"]+)"', text)
                if m:
                    ident["repository"] = normalise_repo(m.group(1))
        except OSError:
            pass
    if not ident["repository"] and os.path.isdir(os.path.join(scan_dir, ".git")):
        try:
            r = subprocess.run(["git", "-C", scan_dir, "config", "--get", "remote.origin.url"],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                ident["repository"] = normalise_repo(r.stdout.strip())
        except Exception:
            pass
    if package_info is not None:
        eco = getattr(package_info, "ecosystem", None) or (package_info.get("ecosystem") if isinstance(package_info, dict) else None)
        name = getattr(package_info, "name", None) or (package_info.get("name") if isinstance(package_info, dict) else None)
        if eco == "npm" and name and not ident["npm"]:
            ident["npm"] = name
        if eco in ("pypi", "PyPI") and name and not ident["pypi"]:
            ident["pypi"] = name
    return ident


# ---------------------------------------------------------------------------
# registry access (cached)
# ---------------------------------------------------------------------------

def _cache_path() -> str:
    from app.analysis.scan_history import MCPGUARD_DIR
    os.makedirs(MCPGUARD_DIR, exist_ok=True)
    return os.path.join(MCPGUARD_DIR, "registry_cache.json")


def _load_cache() -> Dict[str, Any]:
    try:
        with open(_cache_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    try:
        with open(_cache_path(), "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except OSError:
        pass


async def _search(term: str) -> List[Dict[str, Any]]:
    """Latest registry entries whose name contains ``term`` (trimmed to what we compare)."""
    try:
        import httpx
    except ImportError:  # pragma: no cover
        return []
    async with httpx.AsyncClient() as client:
        resp = await client.get(REGISTRY_URL, params={"search": term, "version": "latest", "limit": "100"}, timeout=15.0)
        if resp.status_code != 200:
            return []
        out = []
        for item in resp.json().get("servers", []):
            s = item.get("server", {})
            meta = (item.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
            out.append({
                "name": s.get("name"), "version": s.get("version"),
                "repository": normalise_repo((s.get("repository") or {}).get("url")),
                "packages": [f"{p.get('registryType')}:{p.get('identifier')}" for p in (s.get("packages") or []) if p.get("identifier")],
                "publishedAt": meta.get("publishedAt"), "status": meta.get("status"),
            })
        return out


async def search_registry(term: str, cache_enabled: bool = True) -> List[Dict[str, Any]]:
    term = (term or "").strip().lower()
    if not term or len(term) < 3:
        return []
    cache = _load_cache() if cache_enabled else {}
    key = f"search:{term}"
    now = time.time()
    if key in cache and now - cache[key].get("t", 0) < CACHE_TTL:
        return cache[key]["entries"]
    try:
        entries = await _search(term)
    except Exception:
        return []
    if cache_enabled:
        cache[key] = {"t": now, "entries": entries}
        _save_cache(cache)
    return entries


# ---------------------------------------------------------------------------
# the check
# ---------------------------------------------------------------------------

def _days_since(iso: Optional[str]) -> Optional[float]:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0
    except ValueError:
        return None


async def provenance_check(scan_dir: str, target_url: Optional[str] = None, package_info: Any = None,
                           server_name: Optional[str] = None, cache_enabled: bool = True) -> Tuple[Dict[str, Any], List[Finding]]:
    ident = identify(scan_dir, target_url, package_info, server_name)
    report: Dict[str, Any] = {"identity": ident, "registry": {"status": "unknown"}, "lookalikes": [], "checked_at": None}
    findings: List[Finding] = []

    our_pkgs = {f"npm:{ident['npm']}" if ident["npm"] else None, f"pypi:{ident['pypi']}" if ident["pypi"] else None} - {None}
    our_short = {short_name(n) for n in (ident["npm"], ident["pypi"], ident["server_name"]) if n}
    our_repo = ident["repository"]
    # The registry search is a substring match; a lookalike that differs in its last
    # characters would never come back for the full name, so also search a stem.
    terms = set()
    for sn in our_short:
        if len(sn) >= 3:
            terms.add(sn)
        if len(sn) >= 8:
            terms.add(sn[:-3])
    terms = sorted(terms)
    if not terms:
        report["registry"]["status"] = "no_identity"
        return report, findings

    entries: Dict[str, Dict[str, Any]] = {}
    for t in terms:
        for e in await search_registry(t, cache_enabled=cache_enabled):
            if e.get("name"):
                entries[e["name"]] = e
    report["checked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # 1. identity: an entry that lists our package, or whose short name equals ours
    matched = [e for e in entries.values() if set(e["packages"]) & our_pkgs or short_name(e["name"]) in our_short
               or (our_repo and e["repository"] == our_repo)]
    if not matched:
        report["registry"]["status"] = "not_in_registry"
    else:
        same_repo = [e for e in matched if our_repo and e["repository"] == our_repo]
        exact_pkg = [e for e in matched if set(e["packages"]) & our_pkgs]
        chosen = (same_repo or exact_pkg or matched)[0]
        report["registry"].update({"entry": chosen["name"], "repository": chosen["repository"],
                                   "packages": chosen["packages"], "publishedAt": chosen["publishedAt"],
                                   "version": chosen["version"]})
        if our_repo and chosen["repository"] and chosen["repository"] != our_repo and exact_pkg:
            report["registry"]["status"] = "mismatch"
            findings.append(Finding(
                id="provenance_mismatch",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.SUPPLY_CHAIN,
                title=f"Registry entry '{chosen['name']}' points at a different repository than the one scanned",
                description=f"The official MCP Registry lists package {', '.join(sorted(set(chosen['packages']) & our_pkgs))} "
                            f"under '{chosen['name']}' with source {chosen['repository']}, but this scan came from {our_repo}. "
                            "The artefact is not the one the registry vouches for.",
                recommendation="Install from the repository the registry names, or verify why the sources differ before trusting this one.",
                owasp_asi=["ASI04"], owasp_mcp=["MCP04"],
                evidence=f"registry: {chosen['repository']} | scanned: {our_repo}",
                location=f"static:{scan_dir}:provenance",
            ))
        elif our_repo and chosen["repository"] and chosen["repository"] != our_repo:
            report["registry"]["status"] = "name_match_different_repo"
        else:
            report["registry"]["status"] = "match"
        days = _days_since(chosen.get("publishedAt"))
        if days is not None and days < FRESH_DAYS and report["registry"]["status"] in ("match", "mismatch"):
            findings.append(Finding(
                id="provenance_fresh_publish",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.SUPPLY_CHAIN,
                title=f"Registry entry '{chosen['name']}' was published {days:.0f} day(s) ago",
                description=f"'{chosen['name']}' version {chosen['version']} appeared in the registry on {chosen['publishedAt']}. "
                            "Nothing this new has been looked at by anyone; pin it and review it before an agent uses it.",
                recommendation="Pin the version and review the diff from the previous release.",
                owasp_asi=["ASI04"], owasp_mcp=["MCP04"],
                evidence=f"publishedAt {chosen['publishedAt']}",
                location=f"static:{scan_dir}:provenance",
            ))

    # 2. lookalikes: one edit / one confusable away, different publisher, different repo
    our_pub = {publisher_of(e["name"]) for e in matched} if matched else set()
    for e in entries.values():
        sn = short_name(e["name"])
        if sn in our_short:
            continue
        for ours in our_short:
            if _near_duplicate(sn, ours) or (homoglyph_reason(sn, [ours]) and sn != ours):
                if publisher_of(e["name"]) in our_pub or (our_repo and e["repository"] == our_repo):
                    continue
                report["lookalikes"].append({"name": e["name"], "repository": e["repository"], "ours": ours})
                findings.append(Finding(
                    id=f"registry_typosquat_{re.sub(r'[^A-Za-z0-9_.-]+', '_', e['name'])[:60]}",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.SUPPLY_CHAIN,
                    title=f"Registry name '{e['name']}' is one edit away from '{ours}' and comes from a different publisher",
                    description=f"'{e['name']}' ({e['repository'] or 'no repository'}) differs from '{ours}' by one character or "
                                "a confusable glyph and is published by someone else. One of the two is a lookalike; an agent "
                                "configured by name can be pointed at the wrong one.",
                    recommendation="Install by exact registry name and verify the repository; report the lookalike to the registry.",
                    owasp_asi=["ASI04"], owasp_mcp=["MCP04"],
                    evidence=f"{e['name']} ~ {ours}",
                    location=f"static:{scan_dir}:provenance",
                ))
                break
    return report, findings
