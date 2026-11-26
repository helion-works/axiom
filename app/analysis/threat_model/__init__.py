"""
Threat model generation (``axiom threatmodel``, ``POST /api/v1/threatmodel``).

Pipeline::

    scan / discovery / A2A results
        -> SystemModel (system_model.from_scan / from_discovery / from_a2a, merge)
        -> deterministic threats + attack paths (rules.evaluate / rules.attack_paths)
        -> optional AI suggestions, kept separate (ai_enrich.enrich)
        -> Markdown / JSON (render)

The result dict is deterministic for a given input: it contains no timestamp
unless ``include_timestamp=True`` (then a single top-level ``generated_at``
header field is added).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from app.analysis.threat_model import ai_enrich, render, rules, system_model
from app.analysis.threat_model.ai_enrich import NOT_RUN_NOTE, build_ai_payload, enrich
from app.analysis.threat_model.render import mermaid_diagram, render_json, render_markdown
from app.analysis.threat_model.rules import (
    AttackPath,
    Threat,
    attack_paths,
    evaluate,
    load_catalogue,
    risk_band,
)
from app.analysis.threat_model.system_model import (
    SCHEMA_VERSION,
    Component,
    DataFlow,
    SystemModel,
    from_a2a,
    from_discovery,
    from_scan,
    merge,
    to_plain,
)

__all__ = [
    "AttackPath", "Component", "DataFlow", "SystemModel", "Threat",
    "build_model", "build_threat_model", "from_a2a", "from_discovery", "from_scan", "merge",
    "evaluate", "attack_paths", "load_catalogue", "risk_band", "enrich", "build_ai_payload",
    "render_markdown", "render_json", "mermaid_diagram", "NOT_RUN_NOTE",
]


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def build_model(scans: Any = None, discovery: Any = None, a2a: Any = None) -> SystemModel:
    """Build and merge a SystemModel from any combination of sources."""
    models = [from_scan(s) for s in _as_list(scans)]
    models += [from_discovery(d) for d in _as_list(discovery)]
    models += [from_a2a(a) for a in _as_list(a2a)]
    if not models:
        raise ValueError("at least one source (scan, discovery or a2a) is required")
    return models[0] if len(models) == 1 else merge(models)


def _scope_lines(scans: Iterable[Any], discovery: Iterable[Any], a2a: Iterable[Any],
                 model: SystemModel) -> List[str]:
    lines = []
    for s in scans:
        d = to_plain(s) or {}
        prof = d.get("server_profile") or {}
        lines.append(f"Static scan of '{d.get('target') or prof.get('name') or 'unknown'}': "
                     f"{len(prof.get('tools') or [])} tools, {len(prof.get('resources') or [])} resources, "
                     f"{len(prof.get('prompts') or [])} prompts, {len(d.get('findings') or [])} findings "
                     f"(risk {d.get('risk_level') or 'n/a'}).")
    for r in discovery:
        d = to_plain(r) or {}
        servers = d.get("servers") or []
        lines.append(f"Local discovery: {len(servers)} configured MCP servers from "
                     f"{len(d.get('config_files_scanned') or [])} client config files "
                     f"(allowlist: {'yes' if d.get('allowlist') else 'none'}).")
    for c in model.components:
        if c.kind == "remote_agent":
            lines.append(f"A2A agent card '{c.name}': {len(c.attributes.get('skills') or [])} skills, "
                         f"signed: {'yes' if c.attributes.get('signed') else 'no'}, "
                         f"authentication declared: {'yes' if c.attributes.get('has_auth') else 'no'}.")
    if list(a2a) and not any(c.kind == "remote_agent" for c in model.components):
        lines.append("A2A agent card: no remote agent could be modelled.")
    return lines


def _coverage(threats: List[Threat]) -> Dict[str, Any]:
    stride = {k: 0 for k in rules.STRIDE}
    maestro = {str(k): 0 for k in rules.MAESTRO_LAYERS}
    cross = {str(k): 0 for k in rules.MAESTRO_LAYERS}
    asi, mcp = set(), set()
    for t in threats:
        stride[t.stride] = stride.get(t.stride, 0) + 1
        maestro[str(t.maestro_layer)] += 1
        for layer in t.cross_layer:
            cross[str(layer)] += 1
        asi.update(t.owasp_asi)
        mcp.update(t.owasp_mcp)
    bands = {b: sum(1 for t in threats if t.risk_band == b) for b in ("critical", "high", "medium", "low")}
    return {"stride": stride, "maestro": maestro, "maestro_cross": cross,
            "owasp_asi": sorted(asi), "owasp_mcp": sorted(mcp), "risk_bands": bands,
            "total_threats": len(threats)}


def build_threat_model(
    scans: Any = None,
    discovery: Any = None,
    a2a: Any = None,
    *,
    ai: bool = False,
    ai_client: Any = None,
    include_timestamp: bool = False,
    catalogue: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run the full pipeline and return the plain result dict (JSON-able)."""
    scans_l, disc_l, a2a_l = _as_list(scans), _as_list(discovery), _as_list(a2a)
    model = build_model(scans_l, disc_l, a2a_l)
    catalogue = catalogue or load_catalogue()
    threats = evaluate(model, catalogue)
    paths = attack_paths(threats, model)
    if ai:
        ai_result = enrich(model, client=ai_client)
    else:
        ai_result = {"ran": False, "note": NOT_RUN_NOTE, "model": None, "threats": [], "attack_paths": []}

    result: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "catalogue_version": catalogue.get("catalogue_version", ""),
        "sources": list(model.sources),
        "scope": {"lines": _scope_lines(scans_l, disc_l, a2a_l, model)},
        "system_model": model.model_dump(mode="json"),
        "threats": [t.model_dump(mode="json") for t in threats],
        "attack_paths": [p.model_dump(mode="json") for p in paths],
        "coverage": _coverage(threats),
        "ai": ai_result,
    }
    if include_timestamp:
        result["generated_at"] = datetime.now(timezone.utc).isoformat()
    return result
