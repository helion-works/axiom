"""
Markdown / JSON rendering for ``axiom threatmodel``.

Both renderers work on the plain result dict produced by
``app.analysis.threat_model.build_threat_model`` so a stored result can be
re-rendered later (REST download). Output is deterministic: no timestamps
unless the caller put ``generated_at`` in the result header, sorted keys in
JSON, ASCII-only text.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from app.analysis.threat_model.rules import MAESTRO_LAYERS, MITIGATION_OWNERS, STRIDE, STRIDE_NAMES
from app.analysis.threat_model.system_model import TRUST_ZONES

FRAMEWORKS = ("both", "stride", "maestro")

_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_]")
_KIND_SHAPES = {
    "agent_host": ('(["', '"])'),
    "credential": ('[("', '")]'),
    "data_store": ('[("', '")]'),
    "external_service": ('{{"', '"}}'),
}
_KIND_LABEL = {
    "agent_host": "agent host", "mcp_server": "MCP server", "tool": "tool", "resource": "resource",
    "prompt": "prompt", "data_store": "data store", "credential": "credential",
    "external_service": "external", "remote_agent": "remote agent",
}


def render_json(result: Dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


# ============================================================
# Mermaid
# ============================================================

def mermaid_id(raw: str, prefix: str = "n_") -> str:
    """Mermaid-safe id: only [A-Za-z0-9_], always prefixed (avoids keywords like 'end')."""
    return prefix + _SAFE_ID_RE.sub("_", str(raw))


def mermaid_label(text: Any, limit: int = 60) -> str:
    s = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text or ""))
    s = s.encode("ascii", "replace").decode("ascii")
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    s = s.replace("#", "#35;").replace("&", "#amp;").replace("<", "#lt;").replace(">", "#gt;")
    return s.replace('"', "#quot;").replace("`", "'")


def mermaid_diagram(model: Dict[str, Any]) -> str:
    """flowchart LR with one subgraph per trust boundary and data_class edge labels."""
    comps = {c["id"]: c for c in model.get("components", [])}
    lines = ["flowchart LR"]
    for b in model.get("boundaries", []):
        lines.append(f'  subgraph {mermaid_id(b["id"], "sg_")}["{mermaid_label(b["name"])}"]')
        for cid in b.get("inside", []):
            c = comps.get(cid)
            if not c:
                continue
            left, right = _KIND_SHAPES.get(c["kind"], ('["', '"]'))
            label = c["name"] if c["kind"] in ("agent_host", "external_service") else                 f'{c["name"]} ({_KIND_LABEL.get(c["kind"], c["kind"])})'
            lines.append(f"    {mermaid_id(cid)}{left}{mermaid_label(label)}{right}")
        lines.append("  end")
    for c in model.get("components", []):
        server = (c.get("attributes") or {}).get("server")
        if server and server in comps:
            lines.append(f"  {mermaid_id(server)} -.- {mermaid_id(c['id'])}")
    for f in model.get("flows", []):
        if f["src"] in comps and f["dst"] in comps:
            lines.append(f'  {mermaid_id(f["src"])} -->|"{mermaid_label(f["data_class"])}"| {mermaid_id(f["dst"])}')
    return "\n".join(lines)


# ============================================================
# Markdown helpers
# ============================================================

def _cell(v: Any) -> str:
    s = re.sub(r"\s+", " ", str(v if v is not None else "")).strip()
    s = s.encode("ascii", "replace").decode("ascii")
    return s.replace("|", "\\|") or "-"


def _ascii(v: Any) -> str:
    return str(v if v is not None else "").encode("ascii", "replace").decode("ascii")


def _component_notes(c: Dict[str, Any]) -> str:
    a = c.get("attributes") or {}
    notes: List[str] = []
    if a.get("capabilities"):
        notes.append("capabilities: " + ", ".join(a["capabilities"]))
    for k in ("transport", "install_source", "package", "version_pin", "classification", "provider"):
        if a.get(k) not in (None, "", []):
            notes.append(f"{k}: {a[k]}")
    if a.get("url"):
        notes.append(f"url: {a['url']}")
    for flag in ("unpinned", "plain_http", "broad_exposure", "hidden_instructions", "shared"):
        if a.get(flag):
            notes.append(flag)
    for k in ("authenticated", "signed", "has_auth"):
        if k in a:
            notes.append(f"{k}: {'yes' if a[k] else 'no'}")
    if c.get("kind") == "tool":
        notes.append("approval: " + str(a.get("approval", "autonomous")))
    if a.get("skills"):
        notes.append("skills: " + ", ".join(a["skills"]))
    if a.get("dangerous_skills"):
        notes.append("dangerous skills: " + ", ".join(a["dangerous_skills"]))
    if a.get("used_by"):
        notes.append("used by: " + ", ".join(a["used_by"]))
    return "; ".join(notes)


def _layer_name(n: int) -> str:
    return f"L{n} {MAESTRO_LAYERS.get(n, '?')}"


# ============================================================
# Markdown
# ============================================================

def render_markdown(result: Dict[str, Any], framework: str = "both") -> str:
    framework = (framework or "both").lower()
    if framework not in FRAMEWORKS:
        raise ValueError(f"framework must be one of {FRAMEWORKS}")
    show_stride = framework in ("both", "stride")
    show_maestro = framework in ("both", "maestro")

    model = result.get("system_model") or {}
    comps = {c["id"]: c for c in model.get("components", [])}
    threats = result.get("threats") or []
    paths = result.get("attack_paths") or []
    ai = result.get("ai") or {}
    name = lambda cid: comps[cid]["name"] if cid in comps else cid  # noqa: E731

    out: List[str] = ["# Axiom threat model", ""]
    out.append(f"Schema {result.get('schema_version', '0.5')} | rule catalogue "
               f"{result.get('catalogue_version', '?')} | sources: {', '.join(result.get('sources') or []) or 'none'}")
    if result.get("generated_at"):
        out.append(f"Generated at: {result['generated_at']}")
    out.append("")

    # ---- Scope
    out += ["## Scope", ""]
    for line in (result.get("scope") or {}).get("lines", []):
        out.append(f"- {_ascii(line)}")
    kinds: Dict[str, int] = {}
    for c in model.get("components", []):
        kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
    out.append(f"- Model: {len(model.get('components', []))} components "
               f"({', '.join(f'{v} {k}' for k, v in sorted(kinds.items())) or 'none'}), "
               f"{len(model.get('flows', []))} data flows, {len(model.get('boundaries', []))} trust boundaries.")
    out.append("- Not in scope: runtime behaviour of servers, model behaviour, and anything not visible in "
               "the sources above. Threats are generated by deterministic rules from the model.")
    out.append("")

    # ---- System description
    out += ["## System description", ""]
    if not model.get("components"):
        out += ["No components were found in the sources.", ""]
    for b in model.get("boundaries", []):
        out += [f"### {_ascii(b['name'])}", "", "| Component | Kind | Details |", "|---|---|---|"]
        for cid in b.get("inside", []):
            c = comps.get(cid)
            if c:
                out.append(f"| {_cell(c['name'])} (`{_cell(cid)}`) | {_cell(_KIND_LABEL.get(c['kind'], c['kind']))} "
                           f"| {_cell(_component_notes(c))} |")
        out.append("")
    if model.get("assets"):
        out += ["Assets:", ""]
        for a in model["assets"]:
            out.append(f"- {_ascii(a['name'])} ({a['kind']}): {_ascii(', '.join(name(c) for c in a['components']))}")
        out.append("")

    # ---- Diagram
    out += ["## Data-flow diagram", "", "```mermaid", mermaid_diagram(model), "```", ""]
    crossing = [f for f in model.get("flows", []) if f.get("crosses_boundary")]
    out.append(f"{len(crossing)} of {len(model.get('flows', []))} flows cross a trust boundary. "
               "Dotted lines link tools, resources and prompts to their server.")
    out.append("")

    # ---- Assumptions
    out += ["## Assumptions", ""]
    if not model.get("assumptions"):
        out.append("None.")
    for a in model.get("assumptions", []):
        out.append(f"- [{a['basis']}] {_ascii(a['text'])}")
    out.append("")

    # ---- Threat table
    out += ["## Threats", ""]
    if not threats:
        out += ["No threats were raised by the rule catalogue for this model.", ""]
    else:
        head = ["ID", "Threat", "Components"]
        if show_stride:
            head.append("STRIDE")
        if show_maestro:
            head.append("MAESTRO")
        head += ["OWASP", "L", "I", "Risk"]
        out.append("| " + " | ".join(head) + " |")
        out.append("|" + "---|" * len(head))
        for t in threats:
            row = [t["id"], t["title"], ", ".join(name(c) for c in t["affected_components"])]
            if show_stride:
                row.append(t["stride"])
            if show_maestro:
                cross = (" (+" + ",".join(f"L{x}" for x in t["cross_layer"]) + ")") if t["cross_layer"] else ""
                row.append(f"L{t['maestro_layer']}{cross}")
            row += [", ".join(t["owasp_asi"] + t["owasp_mcp"]), t["likelihood"], t["impact"],
                    f"{t['risk']} {t['risk_band']}"]
            out.append("| " + " | ".join(_cell(v) for v in row) + " |")
        out.append("")
        out += ["### Threat details", ""]
        for t in threats:
            out.append(f"#### {t['id']}: {_ascii(t['title'])}")
            out.append("")
            out.append(_ascii(t["description"]))
            out.append("")
            tags = []
            if show_stride:
                tags.append(f"STRIDE {t['stride']} ({STRIDE_NAMES.get(t['stride'], '?')})")
            if show_maestro:
                tags.append(f"MAESTRO {_layer_name(t['maestro_layer'])}")
            tags.append(f"risk {t['likelihood']}x{t['impact']} = {t['risk']} ({t['risk_band']})")
            out.append("- " + "; ".join(tags))
            if t["affected_flows"]:
                out.append("- Flows: " + ", ".join(f"`{f}`" for f in t["affected_flows"]))
            for e in t["evidence"]:
                sev = f" [{e['severity']}]" if e.get("severity") else ""
                out.append(f"- Evidence ({e['kind']}{sev}): {_ascii(e['text'])} (`{_ascii(e['ref'])}`)")
            out.append("")

    # ---- Attack paths
    out += ["## Top attack paths", ""]
    if not paths:
        out.append("No chains of related threats were found.")
    for i, p in enumerate(paths, 1):
        out.append(f"{i}. **{_ascii(p['title'])}** (score {p['score']}, `{p['id']}`)")
        out.append(f"   {_ascii(p['narrative'])}")
    out.append("")

    # ---- Mitigations
    out += ["## Mitigations by owner", ""]
    by_owner: Dict[str, Dict[str, List[str]]] = {o: {} for o in MITIGATION_OWNERS}
    for t in threats:
        for m in t["mitigations"]:
            by_owner.setdefault(m["owner"], {}).setdefault(m["text"], []).append(t["id"])
    any_m = False
    for owner in sorted(by_owner, key=lambda o: (MITIGATION_OWNERS.index(o) if o in MITIGATION_OWNERS else 99, o)):
        items = by_owner[owner]
        if not items:
            continue
        any_m = True
        out += [f"### {owner}", ""]
        for text in sorted(items):
            ids = sorted(set(items[text]))
            shown = ", ".join(ids[:6]) + (f" and {len(ids) - 6} more" if len(ids) > 6 else "")
            out.append(f"- {_ascii(text)} (threats: {shown})")
        out.append("")
    if not any_m:
        out += ["None.", ""]

    # ---- Coverage
    cov = result.get("coverage") or {}
    out += ["## Framework coverage", ""]
    if show_stride:
        out += ["| STRIDE | Threats |", "|---|---|"]
        for k in STRIDE:
            out.append(f"| {k} {STRIDE_NAMES[k]} | {cov.get('stride', {}).get(k, 0)} |")
        out.append("")
    if show_maestro:
        out += ["| MAESTRO layer | Primary | Cross-layer |", "|---|---|---|"]
        for n in sorted(MAESTRO_LAYERS):
            out.append(f"| {_layer_name(n)} | {cov.get('maestro', {}).get(str(n), 0)} "
                       f"| {cov.get('maestro_cross', {}).get(str(n), 0)} |")
        out.append("")
    out.append("- OWASP Agentic Top 10 (ASI) touched: " + (", ".join(cov.get("owasp_asi") or []) or "none"))
    out.append("- OWASP MCP Top 10 touched: " + (", ".join(cov.get("owasp_mcp") or []) or "none"))
    out.append("")

    # ---- AI
    if ai.get("ran"):
        out += ["## AI-suggested threats", "",
                "These suggestions come from an AI model, are not verified and do not change the "
                "deterministic threats or scores above.", ""]
        if not ai.get("threats"):
            out.append("The AI returned no additional threats.")
        for t in ai.get("threats", []):
            tags = []
            if show_stride and t.get("stride"):
                tags.append(f"STRIDE {t['stride']}")
            if show_maestro and t.get("maestro_layer"):
                tags.append(f"MAESTRO L{t['maestro_layer']}")
            if t.get("likelihood") and t.get("impact"):
                tags.append(f"L{t['likelihood']} x I{t['impact']}")
            comps_s = ", ".join(name(c) for c in t.get("affected_components", []))
            out.append(f"- **{t['id']} {_ascii(t['title'])}** ({'; '.join(tags) or 'untagged'})"
                       f"{' - ' + _ascii(comps_s) if comps_s else ''}: {_ascii(t.get('description'))}"
                       f"{' Mitigation: ' + _ascii(t['mitigation']) if t.get('mitigation') else ''}")
        for p in ai.get("attack_paths", []):
            out.append(f"- **{p['id']} {_ascii(p['title'])}**: {_ascii(p.get('narrative'))}")
        out.append("")
    out += ["## AI enrichment", "", _ascii(ai.get("note") or "AI enrichment was not run."), ""]
    return "\n".join(out)
