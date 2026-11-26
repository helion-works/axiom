"""
Output formats for CI and governance (Phase 4, E.2).

* ``to_sarif``  — SARIF 2.1.0. One rule per Axiom rule id (with the OWASP ASI / MCP Top 10
  mapping in ``properties``), one result per finding with a ``physicalLocation`` (file + line
  when known, else the target) and the evidence / replay in the message and properties.
  Upload with GitHub Code Scanning: ``gh api ... /code-scanning/sarifs`` or the
  ``github/codeql-action/upload-sarif`` action (see README).
* ``to_aibom``  — a CycloneDX 1.5 JSON bill of materials in which the MCP server, every tool,
  resource and prompt is a component carrying its capability tags, fingerprint and
  provenance, and every finding is a vulnerability that ``affects`` the component it was
  found on. "What agents and tools do we run, and what can they do?"
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from app.analysis.evidence import enrich_findings
from app.models.schemas import Finding, FindingSeverity

AXIOM_VERSION = "0.6.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_LEVEL = {FindingSeverity.CRITICAL: "error", FindingSeverity.HIGH: "error", FindingSeverity.MEDIUM: "warning",
                FindingSeverity.LOW: "note", FindingSeverity.INFO: "note"}
_SARIF_RANK = {FindingSeverity.CRITICAL: 95.0, FindingSeverity.HIGH: 80.0, FindingSeverity.MEDIUM: 50.0,
               FindingSeverity.LOW: 20.0, FindingSeverity.INFO: 5.0}
_CDX_SEV = {FindingSeverity.CRITICAL: "critical", FindingSeverity.HIGH: "high", FindingSeverity.MEDIUM: "medium",
            FindingSeverity.LOW: "low", FindingSeverity.INFO: "info"}


def _findings_of(result: Any) -> List[Finding]:
    raw = result.get("findings", []) if isinstance(result, dict) else getattr(result, "findings", [])
    out: List[Finding] = []
    for f in raw:
        if isinstance(f, Finding):
            out.append(f)
        elif isinstance(f, dict):
            try:
                out.append(Finding(**{k: v for k, v in f.items() if k in Finding.model_fields}))
            except Exception:
                continue
    return out


def _target_of(result: Any) -> str:
    if isinstance(result, dict):
        return str(result.get("target_url") or result.get("target") or "target")
    return str(getattr(result, "server_name", "target"))


def _split_location(loc: str):
    """('path', line or None) from a location string; live/static pseudo-locations map to the target."""
    if not loc:
        return None, None
    if loc.startswith(("live:", "static:", "config:")):
        return loc, None
    m = re.match(r"^(.*?):(\d+)$", loc)
    if m:
        return m.group(1), int(m.group(2))
    return loc, None


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------

def to_sarif(result: Any, *, mode: str = "static") -> Dict[str, Any]:
    findings = enrich_findings(_findings_of(result), mode=mode, target=_target_of(result))
    target = _target_of(result)
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for f in findings:
        rid = f.rule_id or f.id
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.title[:200] if f.title else rid},
                "fullDescription": {"text": (f.description or f.title or rid)[:1000]},
                "help": {"text": f.recommendation or "See docs/SEVERITY.md."},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {
                    "category": f.category.value,
                    "owasp_asi": list(f.owasp_asi or []),
                    "owasp_mcp": list(f.owasp_mcp or []),
                    "tags": ["security", f.category.value] + [f"owasp-asi:{x}" for x in (f.owasp_asi or [])]
                            + [f"owasp-mcp:{x}" for x in (f.owasp_mcp or [])],
                    "precision": "high" if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) else "medium",
                    "security-severity": str(_SARIF_RANK[f.severity] / 10.0),
                },
            }
        path, line = _split_location(f.location)
        uri = (path or target).replace("\\", "/")
        region = {"startLine": line} if line else None
        phys: Dict[str, Any] = {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%" if line else None}}
        if phys["artifactLocation"]["uriBaseId"] is None:
            del phys["artifactLocation"]["uriBaseId"]
        if region:
            phys["region"] = region
        results.append({
            "ruleId": rid,
            "ruleIndex": list(rules).index(rid),
            "level": _SARIF_LEVEL[f.severity],
            "rank": _SARIF_RANK[f.severity],
            "message": {"text": f"{f.title}. Evidence: {f.evidence}"[:2000]},
            "locations": [{"physicalLocation": phys}],
            "partialFingerprints": {"axiom/findingId": f.id,
                                    "axiom/v1": hashlib.sha256(f"{rid}|{f.location}|{f.evidence}".encode("utf-8")).hexdigest()[:32]},
            "properties": {
                "severity": f.severity.value, "category": f.category.value, "finding_id": f.id,
                "evidence": f.evidence, "location": f.location, "replay": f.replay,
                "owasp_asi": list(f.owasp_asi or []), "owasp_mcp": list(f.owasp_mcp or []),
                "recommendation": f.recommendation,
            },
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Axiom",
                "fullName": "Axiom by Helion Works — security scanner for MCP servers and agent tooling",
                "version": AXIOM_VERSION,
                "semanticVersion": AXIOM_VERSION,
                "informationUri": "https://github.com/helion-works/axiom",
                "rules": list(rules.values()),
            }},
            "automationDetails": {"id": f"axiom/{mode}/{re.sub(r'[^A-Za-z0-9_.-]+', '_', target)[:80]}"},
            "invocations": [{"executionSuccessful": True, "endTimeUtc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")}],
            "results": results,
            "properties": {
                "target": target, "mode": mode,
                "risk_level": (result.get("risk_level").value if isinstance(result, dict) and hasattr(result.get("risk_level"), "value")
                               else (result.get("risk_level") if isinstance(result, dict) else getattr(getattr(result, "risk_level", None), "value", None))),
                "fingerprint": result.get("fingerprint") if isinstance(result, dict) else None,
            },
        }],
    }


# ---------------------------------------------------------------------------
# AIBOM (CycloneDX 1.5)
# ---------------------------------------------------------------------------

def _bom_ref(kind: str, name: str) -> str:
    return f"axiom:{kind}:{re.sub(r'[^A-Za-z0-9_.:/@-]+', '_', name)[:120]}"


def to_aibom(result: Any, *, mode: str = "static") -> Dict[str, Any]:
    """CycloneDX 1.5 JSON: the server and everything an agent is shown as components, findings as vulnerabilities."""
    findings = enrich_findings(_findings_of(result), mode=mode, target=_target_of(result))
    target = _target_of(result)
    smap: Optional[Dict[str, Any]] = None
    if isinstance(result, dict) and result.get("surface_map"):
        smap = result["surface_map"]
    elif not isinstance(result, dict):
        from app.analysis.surface_map import build_live_map
        try:
            smap = build_live_map(result).to_dict()
        except Exception:
            smap = None
    server_name = (smap or {}).get("server", {}).get("name") or target
    fingerprint = (smap or {}).get("fingerprint") or (result.get("fingerprint") if isinstance(result, dict) else None) or ""
    server_ref = _bom_ref("server", server_name)
    provenance = result.get("provenance") if isinstance(result, dict) else None
    pkg = result.get("package_info") if isinstance(result, dict) else None

    def props(d: Dict[str, Any]) -> List[Dict[str, str]]:
        return [{"name": k, "value": json.dumps(v) if not isinstance(v, str) else v} for k, v in d.items() if v not in (None, "", [], {})]

    components: List[Dict[str, Any]] = [{
        "type": "application",
        "bom-ref": server_ref,
        "name": server_name,
        "version": (getattr(pkg, "version", None) if pkg is not None and not isinstance(pkg, dict) else (pkg or {}).get("version")) or (smap or {}).get("server", {}).get("version") or "unknown",
        "description": "MCP server (agent tool provider)",
        "properties": props({
            "axiom:kind": "mcp-server",
            "axiom:transport": (smap or {}).get("server", {}).get("transport"),
            "axiom:auth": (smap or {}).get("server", {}).get("auth"),
            "axiom:fingerprint": fingerprint,
            "axiom:instructions_present": bool((smap or {}).get("server", {}).get("instructions")),
            "axiom:source": target,
            "axiom:languages": (smap or {}).get("source", {}).get("languages"),
            "axiom:provenance": provenance,
        }),
    }]
    if fingerprint:
        components[0]["hashes"] = [{"alg": "SHA-256", "content": fingerprint}]
    item_refs: Dict[str, str] = {}
    for t in (smap or {}).get("tools", []):
        ref = _bom_ref("tool", f"{server_name}/{t['name']}")
        item_refs[t["name"]] = ref
        components.append({
            "type": "library", "bom-ref": ref, "name": t["name"], "group": server_name,
            "description": (t.get("description") or "")[:500],
            "properties": props({
                "axiom:kind": "mcp-tool", "axiom:capabilities": t.get("capabilities"),
                "axiom:parameters": list((t.get("input_schema") or {}).get("properties", {}).keys()),
                "axiom:required": (t.get("input_schema") or {}).get("required"),
                "axiom:registration": t.get("registration"), "axiom:location": t.get("location"),
            }),
        })
    for r in (smap or {}).get("resources", []):
        ref = _bom_ref("resource", f"{server_name}/{r['uri']}")
        item_refs[r["uri"]] = ref
        components.append({"type": "data", "bom-ref": ref, "name": r["uri"], "group": server_name,
                           "description": (r.get("description") or r.get("name") or "")[:500],
                           "properties": props({"axiom:kind": "mcp-resource", "axiom:mime_type": r.get("mime_type"),
                                                "axiom:location": r.get("location")})})
    for p in (smap or {}).get("prompts", []):
        ref = _bom_ref("prompt", f"{server_name}/{p['name']}")
        item_refs[p["name"]] = ref
        components.append({"type": "data", "bom-ref": ref, "name": p["name"], "group": server_name,
                           "description": (p.get("description") or "")[:500],
                           "properties": props({"axiom:kind": "mcp-prompt",
                                                "axiom:arguments": [a.get("name") for a in p.get("arguments", [])],
                                                "axiom:location": p.get("location")})})
    deps = result.get("dependencies", []) if isinstance(result, dict) else []
    for d in deps:
        name = getattr(d, "name", None) or (d.get("name") if isinstance(d, dict) else None)
        if not name:
            continue
        version = getattr(d, "version", None) or (d.get("version") if isinstance(d, dict) else "unknown")
        eco = getattr(d, "ecosystem", None) or (d.get("ecosystem") if isinstance(d, dict) else "")
        purl_type = "npm" if eco == "npm" else "pypi"
        components.append({
            "type": "library", "bom-ref": _bom_ref("dep", f"{purl_type}/{name}@{version}"), "name": name,
            "version": version, "purl": f"pkg:{purl_type}/{name}@{version}" if version != "unknown" else f"pkg:{purl_type}/{name}",
            "scope": "required" if (getattr(d, "direct", True) if not isinstance(d, dict) else d.get("direct", True)) else "optional",
            "properties": props({"axiom:kind": "dependency", "axiom:source": getattr(d, "source", None) if not isinstance(d, dict) else d.get("source")}),
        })

    vulnerabilities: List[Dict[str, Any]] = []
    for f in findings:
        affected = server_ref
        for name, ref in item_refs.items():
            if re.search(rf"(^|[_:/'\s]){re.escape(name)}([_:/'\s]|$)", f.id) or f"'{name}'" in (f.title or ""):
                affected = ref
                break
        vulnerabilities.append({
            "bom-ref": _bom_ref("finding", f.id),
            "id": f.id,
            "source": {"name": "Axiom", "url": "https://github.com/helion-works/axiom"},
            "ratings": [{"source": {"name": "Axiom"}, "severity": _CDX_SEV[f.severity], "method": "other",
                         "justification": f.rule_id}],
            "cwes": [],
            "description": f"{f.title}. {f.description}"[:2000],
            "detail": f"evidence: {f.evidence}\nlocation: {f.location}\nreplay: {f.replay}",
            "recommendation": f.recommendation,
            "advisories": ([{"title": f.cve_id, "url": f"https://osv.dev/vulnerability/{f.cve_id}"}] if f.cve_id else []),
            "affects": [{"ref": affected}],
            "properties": props({"axiom:rule_id": f.rule_id, "axiom:category": f.category.value,
                                 "axiom:owasp_asi": f.owasp_asi, "axiom:owasp_mcp": f.owasp_mcp}),
        })

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "tools": [{"vendor": "Helion Works", "name": "Axiom", "version": AXIOM_VERSION}],
            "component": components[0],
            "properties": props({"axiom:mode": mode, "axiom:bom_kind": "AIBOM (agent inventory)"}),
        },
        "components": components[1:],
        "dependencies": [{"ref": server_ref, "dependsOn": [c["bom-ref"] for c in components[1:]]}],
        "vulnerabilities": vulnerabilities,
    }


def dumps(doc: Dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False)
