"""
Dependencies and advisories (docs/SEVERITY.md, "Advisories are a signal, not the headline").

* Manifests give the direct dependencies; lockfiles (package-lock.json, uv.lock,
  poetry.lock, Pipfile.lock) give exact versions and the transitive set.
* OSV (``/v1/querybatch``) is asked **with the version** whenever one is known, so only
  advisories whose affected range covers that version come back. A package whose version
  is unknown produces one INFO note, not every advisory ever filed.
* Severity comes from the advisory (``database_specific.severity`` or CVSS), capped at
  HIGH; one level lower for transitive packages.
* Results are cached for 24 hours in the data directory; ``--no-deps`` skips the lookup.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.models.schemas import DependencyInfo, Finding, FindingCategory, FindingSeverity

_EXACT_RE = re.compile(r"^\d+(\.\d+)*([a-zA-Z0-9.+-]*)$")
_RANGE_PREFIX_RE = re.compile(r"^[\^~>=<!]+")
CACHE_TTL_SECONDS = 24 * 3600


# ---------------------------------------------------------------------------
# manifests + lockfiles
# ---------------------------------------------------------------------------

def _clean_version(v: Optional[str]) -> str:
    if not v or not isinstance(v, str):
        return "unknown"
    v = v.strip()
    if v in ("", "*", "latest"):
        return "unknown"
    v = _RANGE_PREFIX_RE.sub("", v).strip()
    v = v.split(",")[0].split(" ")[0].strip()
    return v if _EXACT_RE.match(v) else "unknown"


_EXACT_SPEC_RE = re.compile(r"^=?\s*v?(\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.+-]*)?)$")


def exact_version(dep: DependencyInfo) -> Optional[str]:
    """The one version a dependency can be matched on, or None when there is not one.

    The lockfile's version when a lockfile lists the package; otherwise the manifest's
    version only when it pins exactly (``1.2.3``, ``=1.2.3``). A range such as ``^1.2.3``,
    ``~1.2`` or ``>=1.0`` without a lockfile is not a version: its lowest bound says
    nothing about what gets installed.
    """
    if dep.locked_version:
        return dep.locked_version
    if dep.declared_spec is not None:
        m = _EXACT_SPEC_RE.match(dep.declared_spec.strip())
        return m.group(1) if m else None
    return None if dep.version == "unknown" else dep.version


def _toml_packages(path: str) -> List[Tuple[str, str]]:
    """(name, version) for every [[package]] table in a uv.lock / poetry.lock."""
    out: List[Tuple[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return out
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
        version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', block)
        if name and version:
            out.append((name.group(1), version.group(1)))
    return out


def read_lockfiles(scan_dir: str) -> Dict[Tuple[str, str], str]:
    """{(ecosystem, name): exact version} from every lockfile in the scan root."""
    locked: Dict[Tuple[str, str], str] = {}
    pl = os.path.join(scan_dir, "package-lock.json")
    if os.path.exists(pl):
        try:
            with open(pl, "r", encoding="utf-8") as f:
                doc = json.load(f)
            pkgs = doc.get("packages")
            if isinstance(pkgs, dict):          # lockfile v2/v3
                for key, meta in pkgs.items():
                    if not key or not isinstance(meta, dict):
                        continue
                    name = key.split("node_modules/")[-1]
                    if meta.get("version"):
                        locked.setdefault(("npm", name), str(meta["version"]))
            deps = doc.get("dependencies")
            if isinstance(deps, dict):          # lockfile v1
                def walk(d: Dict[str, Any]) -> None:
                    for name, meta in d.items():
                        if isinstance(meta, dict):
                            if meta.get("version"):
                                locked.setdefault(("npm", name), str(meta["version"]))
                            if isinstance(meta.get("dependencies"), dict):
                                walk(meta["dependencies"])
                walk(deps)
        except (OSError, json.JSONDecodeError):
            pass
    for lock in ("uv.lock", "poetry.lock"):
        p = os.path.join(scan_dir, lock)
        if os.path.exists(p):
            for name, version in _toml_packages(p):
                locked.setdefault(("pypi", name.lower()), version)
    pf = os.path.join(scan_dir, "Pipfile.lock")
    if os.path.exists(pf):
        try:
            with open(pf, "r", encoding="utf-8") as f:
                doc = json.load(f)
            for section in ("default", "develop"):
                for name, meta in (doc.get(section) or {}).items():
                    v = meta.get("version", "") if isinstance(meta, dict) else ""
                    if isinstance(v, str) and v.startswith("=="):
                        locked.setdefault(("pypi", name.lower()), v[2:])
        except (OSError, json.JSONDecodeError):
            pass
    return locked


def extract_dependencies(scan_dir: str) -> List[DependencyInfo]:
    """Direct dependencies from manifests, pinned by lockfiles; transitive packages from lockfiles."""
    deps: List[DependencyInfo] = []
    direct: Dict[Tuple[str, str], DependencyInfo] = {}

    def add_direct(name: str, version: str, eco: str, source: str) -> None:
        key = (eco, name.lower() if eco == "pypi" else name)
        if key in direct or not name:
            return
        d = DependencyInfo(name=name, version=_clean_version(version), ecosystem=eco, direct=True, source=source,
                           declared_spec=version or "")
        direct[key] = d
        deps.append(d)

    pkg_path = os.path.join(scan_dir, "package.json")
    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, "r", encoding="utf-8") as f:
                pkg = json.load(f)
            for name, version in (pkg.get("dependencies") or {}).items():
                add_direct(name, version if isinstance(version, str) else "", "npm", "package.json")
        except (OSError, json.JSONDecodeError):
            pass

    req_path = os.path.join(scan_dir, "requirements.txt")
    if os.path.exists(req_path):
        try:
            with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if not line or line.startswith("-"):
                        continue
                    m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*(?:([=~!<>]+)\s*([^;\s]+))?", line)
                    if m:
                        name = re.sub(r"\[.*\]", "", m.group(1))
                        version = m.group(3) if m.group(2) in ("==", "===") else ""
                        add_direct(name, version or "", "pypi", "requirements.txt")
        except OSError:
            pass

    pyproject_path = os.path.join(scan_dir, "pyproject.toml")
    if os.path.exists(pyproject_path):
        try:
            with open(pyproject_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            m = re.search(r"(?ms)^dependencies\s*=\s*\[(.*?)\]", content)
            if m:
                for raw in re.findall(r'"([^"]+)"|\'([^\']+)\'', m.group(1)):
                    spec = (raw[0] or raw[1]).strip()
                    mm = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:([=~!<>]+)\s*([^;,\s]+))?", spec)
                    if mm:
                        version = mm.group(3) if mm.group(2) in ("==", "===") else ""
                        add_direct(mm.group(1), version or "", "pypi", "pyproject.toml")
            # poetry style [tool.poetry.dependencies]
            m = re.search(r"(?ms)^\[tool\.poetry\.dependencies\]\s*$(.*?)(?=^\[|\Z)", content)
            if m:
                for line in m.group(1).splitlines():
                    mm = re.match(r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*"([^"]*)"', line)
                    if mm and mm.group(1).lower() != "python":
                        add_direct(mm.group(1), mm.group(2), "pypi", "pyproject.toml")
        except OSError:
            pass

    locked = read_lockfiles(scan_dir)
    for key, version in locked.items():
        eco, name = key
        if key in direct:
            direct[key].locked_version = version
            if direct[key].version == "unknown":
                direct[key].version = version
                direct[key].source = f"{direct[key].source}+lock"
        else:
            deps.append(DependencyInfo(name=name, version=version, ecosystem=eco, direct=False, source="lockfile",
                                       locked_version=version))
    return deps


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------

def _cache_path() -> str:
    from app.analysis.scan_history import MCPGUARD_DIR
    os.makedirs(MCPGUARD_DIR, exist_ok=True)
    return os.path.join(MCPGUARD_DIR, "osv_cache.json")


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


def advisory_severity(vuln: Dict[str, Any]) -> Tuple[FindingSeverity, str]:
    """(severity, label) from an OSV record. Capped at HIGH; unknown -> MEDIUM."""
    label = ""
    ds = vuln.get("database_specific") or {}
    if isinstance(ds.get("severity"), str):
        label = ds["severity"].upper()
    if not label:
        for sev in vuln.get("severity") or []:
            score = str(sev.get("score", ""))
            m = re.search(r"/AV:", score)
            if m:
                # crude CVSS v3 band from the vector: use the base score if present in db, else MEDIUM
                label = "MODERATE"
                break
    if not label and ds.get("cvss_base_score") not in (None, ""):
        try:
            base = float(ds.get("cvss_base_score"))
            label = "CRITICAL" if base >= 9 else "HIGH" if base >= 7 else "MODERATE" if base >= 4 else "LOW"
        except (TypeError, ValueError):
            label = ""
    mapping = {"CRITICAL": FindingSeverity.HIGH, "HIGH": FindingSeverity.HIGH, "MODERATE": FindingSeverity.MEDIUM,
               "MEDIUM": FindingSeverity.MEDIUM, "LOW": FindingSeverity.LOW}
    return mapping.get(label, FindingSeverity.MEDIUM), label or "unrated"


def _lower(sev: FindingSeverity) -> FindingSeverity:
    order = [FindingSeverity.INFO, FindingSeverity.LOW, FindingSeverity.MEDIUM, FindingSeverity.HIGH, FindingSeverity.CRITICAL]
    return order[max(0, order.index(sev) - 1)]


async def osv_findings(deps: List[DependencyInfo], osv_api_url: str, cache_enabled: bool = True) -> List[Finding]:
    """Version-aware OSV lookup for every dependency; cached 24 h."""
    try:
        import httpx
    except ImportError:  # pragma: no cover
        return []
    findings: List[Finding] = []
    cache = _load_cache() if cache_enabled else {}
    now = time.time()
    queries: List[Tuple[DependencyInfo, Dict[str, Any], str]] = []
    for dep in deps:
        eco = "npm" if dep.ecosystem == "npm" else "PyPI"
        q: Dict[str, Any] = {"package": {"name": dep.name, "ecosystem": eco}}
        if dep.version != "unknown":
            q["version"] = dep.version
        key = f"{eco}:{dep.name}:{dep.version}"
        queries.append((dep, q, key))

    pending = [(dep, q, key) for dep, q, key in queries
               if not (key in cache and now - cache[key].get("t", 0) < CACHE_TTL_SECONDS)]
    try:
        async with httpx.AsyncClient() as client:
            for i in range(0, len(pending), 100):
                batch = pending[i:i + 100]
                resp = await client.post(f"{osv_api_url}/querybatch", json={"queries": [q for _, q, _ in batch]}, timeout=20.0)
                if resp.status_code != 200:
                    continue
                results = resp.json().get("results", [])
                for (dep, q, key), res in zip(batch, results):
                    cache[key] = {"t": now, "vulns": [{"id": v.get("id"), "summary": v.get("summary", ""),
                                                        "database_specific": v.get("database_specific", {}),
                                                        "severity": v.get("severity", [])}
                                                       for v in (res or {}).get("vulns", [])]}
    except Exception:
        pass
    if cache_enabled:
        _save_cache(cache)

    for dep, q, key in queries:
        entry = cache.get(key)
        if not entry:
            continue
        vulns = entry.get("vulns", [])
        if not vulns:
            continue
        dep.has_vulnerabilities = True
        if dep.version == "unknown":
            dep.vulnerability_count = len(vulns)
            findings.append(Finding(
                id=f"osv_{dep.ecosystem}_{dep.name}_unversioned",
                severity=FindingSeverity.INFO,
                category=FindingCategory.DEPENDENCY_VULN,
                title=f"{dep.name}: {len(vulns)} advisories exist for some versions (version not pinned)",
                description=f"'{dep.name}' is declared without an exact version ({dep.source}), so the "
                            f"{len(vulns)} OSV advisories for this package cannot be matched against what is "
                            "installed. Pin the version (or commit a lockfile) to turn this into a real check.",
                recommendation=f"Pin {dep.name} to an exact version and commit the lockfile.",
                owasp_asi=["ASI04"],
            ))
            continue
        for v in vulns:
            dep.vulnerability_count += 1
            dep.vulns.append(v.get("id") or "unknown")
            sev, label = advisory_severity(v)
            if not dep.direct:
                sev = _lower(sev)
            findings.append(Finding(
                id=str(v.get("id") or f"osv_{dep.name}"),
                severity=sev,
                category=FindingCategory.DEPENDENCY_VULN,
                title=f"Advisory in dependency {dep.name}@{dep.version}: {v.get('id')}",
                description=(v.get("summary") or "Known vulnerability") + f" (advisory severity: {label}; "
                            + ("direct dependency" if dep.direct else "transitive dependency") + ")",
                cve_id=v.get("id"),
                recommendation=f"Update {dep.name} to a version outside the advisory's affected range.",
                owasp_asi=["ASI04"],
            ))
    return findings
