"""
Deterministic rule evaluation for ``axiom threatmodel``.

Loads ``data/threat_catalogue.json`` (see its ``dsl`` block for the trigger
language), evaluates every rule against a :class:`SystemModel` and returns
threat records sorted by risk, plus the top attack paths (chains of 2-3
threats that share components, ordered entry -> pivot -> impact).

The same model always produces the same threats, ids and ordering: ids are
``<rule id>-<sha256 of the sorted affected component/flow ids>[:8]`` and no
timestamps or random values are used.
"""

from __future__ import annotations

import hashlib
import json
import os
from itertools import product
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from app.analysis.threat_model.system_model import (
    CAPABILITY_TEXT,
    Component,
    EvidenceFinding,
    SystemModel,
)

CATALOGUE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "data", "threat_catalogue.json",
)

REQUIRED_RULE_KEYS = (
    "id", "title", "description", "trigger", "stride", "maestro_layer", "cross_layer",
    "owasp_asi", "owasp_mcp", "likelihood", "impact", "mitigations",
)
STRIDE = ("S", "T", "R", "I", "D", "E")
STRIDE_NAMES = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege",
}
MAESTRO_LAYERS = {
    1: "Foundation Models",
    2: "Data Operations",
    3: "Agent Frameworks",
    4: "Deployment and Infrastructure",
    5: "Evaluation and Observability",
    6: "Security and Compliance",
    7: "Agent Ecosystem",
}
MITIGATION_OWNERS = ("developer", "operator", "platform", "security_team")
TRIGGER_TYPES = (
    "component_attr", "tool_pair", "flow", "shared_credential", "remote_agent",
    "remote_agent_skill_output", "finding",
)
STAGES = ("entry", "pivot", "impact")


# ============================================================
# Records
# ============================================================

class Mitigation(BaseModel):
    owner: str
    text: str


class Evidence(BaseModel):
    kind: str  # "finding" | "inference"
    ref: str
    text: str
    severity: Optional[str] = None


class Threat(BaseModel):
    id: str
    rule_id: str
    title: str
    description: str
    affected_components: List[str] = Field(default_factory=list)
    affected_flows: List[str] = Field(default_factory=list)
    stride: str
    maestro_layer: int
    cross_layer: List[int] = Field(default_factory=list)
    owasp_asi: List[str] = Field(default_factory=list)
    owasp_mcp: List[str] = Field(default_factory=list)
    likelihood: int
    impact: int
    risk: int
    risk_band: str
    mitigations: List[Mitigation] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    stage: str = "pivot"
    source: str = "rule"


class AttackPath(BaseModel):
    id: str
    title: str
    steps: List[str]
    stages: List[str]
    shared_components: List[List[str]]
    score: int
    narrative: str


# ============================================================
# Catalogue
# ============================================================

def load_catalogue(path: Optional[str] = None) -> Dict[str, Any]:
    """Load and validate the rule catalogue (JSON). Raises ValueError on a bad rule."""
    with open(path or CATALOGUE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    seen = set()
    for rule in data.get("rules", []):
        rid = rule.get("id", "?")
        missing = [k for k in REQUIRED_RULE_KEYS if k not in rule]
        if missing:
            raise ValueError(f"Threat rule {rid} missing keys: {missing}")
        if rid in seen:
            raise ValueError(f"Duplicate threat rule id {rid}")
        seen.add(rid)
        if rule["stride"] not in STRIDE:
            raise ValueError(f"Threat rule {rid} has invalid stride {rule['stride']!r}")
        if rule["maestro_layer"] not in MAESTRO_LAYERS:
            raise ValueError(f"Threat rule {rid} has invalid maestro_layer {rule['maestro_layer']!r}")
        if any(l not in MAESTRO_LAYERS for l in rule["cross_layer"]):
            raise ValueError(f"Threat rule {rid} has invalid cross_layer {rule['cross_layer']!r}")
        for k in ("likelihood", "impact"):
            if not isinstance(rule[k], int) or not 1 <= rule[k] <= 5:
                raise ValueError(f"Threat rule {rid} has invalid {k} {rule[k]!r}")
        if rule["trigger"].get("type") not in TRIGGER_TYPES:
            raise ValueError(f"Threat rule {rid} has unknown trigger type {rule['trigger'].get('type')!r}")
        for m in rule["mitigations"]:
            if m.get("owner") not in MITIGATION_OWNERS or not m.get("text"):
                raise ValueError(f"Threat rule {rid} has an invalid mitigation {m!r}")
        if rule.get("stage", "pivot") not in STAGES:
            raise ValueError(f"Threat rule {rid} has invalid stage {rule.get('stage')!r}")
    return data


def risk_band(risk: int) -> str:
    if risk >= 20:
        return "critical"
    if risk >= 12:
        return "high"
    if risk >= 6:
        return "medium"
    return "low"


def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


# ============================================================
# Evaluation
# ============================================================

class _Ctx:
    def __init__(self, model: SystemModel):
        self.model = model
        self.comps: Dict[str, Component] = {c.id: c for c in model.components}
        self.hosts_of_server: Dict[str, Set[str]] = {}
        for f in model.flows:
            src, dst = self.comps.get(f.src), self.comps.get(f.dst)
            if src and dst and src.kind == "agent_host" and dst.kind in ("mcp_server", "remote_agent"):
                self.hosts_of_server.setdefault(dst.id, set()).add(src.id)

    def parent(self, cid: str) -> Optional[str]:
        c = self.comps.get(cid)
        return c.attributes.get("server") if c else None

    def expand(self, cids: Iterable[str]) -> Set[str]:
        out = set(cids)
        for cid in list(out):
            p = self.parent(cid)
            if p:
                out.add(p)
        return out

    def hosts_of(self, cid: str) -> Set[str]:
        c = self.comps.get(cid)
        if c is None:
            return set()
        if c.kind == "agent_host":
            return {cid}
        server = c.attributes.get("server") or cid
        return self.hosts_of_server.get(server, set())


def _truthy(v: Any) -> bool:
    if isinstance(v, (list, dict, set, tuple)):
        return len(v) > 0
    return bool(v)


def _finding_matches(f: EvidenceFinding, sel: Dict[str, Any]) -> bool:
    if not sel:
        return False
    if f.category in _as_list(sel.get("categories")):
        return True
    if any(f.id.startswith(p) for p in _as_list(sel.get("id_prefixes"))):
        return True
    if any(p in f.id for p in _as_list(sel.get("id_contains"))):
        return True
    return False


def _finding_evidence(f: EvidenceFinding) -> Evidence:
    return Evidence(kind="finding", ref=f.id, text=f.title, severity=f.severity)


def _cap_inference(c: Component, cap: str) -> Evidence:
    reason = (c.attributes.get("capability_reasons") or {}).get(cap, "inferred")
    return Evidence(kind="inference", ref=c.id,
                    text=f"Tool '{c.name}' can {CAPABILITY_TEXT.get(cap, cap)} ({reason}).")


def _attr_inference(c: Component, attrs: List[str], missing: List[str]) -> List[Evidence]:
    out = []
    for a in attrs:
        if a in CAPABILITY_TEXT and c.kind == "tool":
            out.append(_cap_inference(c, a))
        elif _truthy(c.attributes.get(a)):
            val = c.attributes.get(a)
            shown = ", ".join(map(str, val)) if isinstance(val, list) else str(val).lower()
            out.append(Evidence(kind="inference", ref=c.id, text=f"{c.kind} '{c.name}': {a} = {shown}."))
    for a in missing:
        out.append(Evidence(kind="inference", ref=c.id, text=f"{c.kind} '{c.name}': {a} not established."))
    return out


class _Candidate:
    def __init__(self, components: Iterable[str], flows: Iterable[str] = (), evidence: Iterable[Evidence] = (),
                 key_extra: str = "", detail: str = "", finding: Optional[EvidenceFinding] = None):
        self.components = sorted(set(components))
        self.flows = sorted(set(flows))
        self.evidence = list(evidence)
        self.key_extra = key_extra
        self.detail = detail
        self.finding = finding


def _match_component_attr(ctx: _Ctx, trig: Dict[str, Any]) -> List[_Candidate]:
    kinds = _as_list(trig.get("kind"))
    zones = _as_list(trig.get("trust_zone"))
    any_attrs = _as_list(trig.get("attr"))
    all_attrs = _as_list(trig.get("attr_all"))
    missing = _as_list(trig.get("and_not")) + _as_list(trig.get("attr_missing"))
    out = []
    for c in ctx.model.components:
        if kinds and c.kind not in kinds:
            continue
        if zones and c.trust_zone not in zones:
            continue
        a = c.attributes
        if any_attrs and not any(_truthy(a.get(k)) for k in any_attrs):
            continue
        if all_attrs and not all(_truthy(a.get(k)) for k in all_attrs):
            continue
        if any(_truthy(a.get(k)) for k in missing):
            continue
        hit = [k for k in any_attrs + all_attrs if _truthy(a.get(k))]
        ev = _attr_inference(c, sorted(set(hit)), sorted(set(missing)))
        if not ev and zones:
            ev = [Evidence(kind="inference", ref=c.id, text=f"{c.kind} '{c.name}' is in trust zone {c.trust_zone}.")]
        out.append(_Candidate([c.id], evidence=ev, detail=f"{c.kind} '{c.name}'"))
    return out


def _match_tool_pair(ctx: _Ctx, trig: Dict[str, Any]) -> List[_Candidate]:
    cap_a, cap_b = trig["a"], trig["b"]
    tools = [c for c in ctx.model.components if c.kind == "tool"]
    if trig.get("same_context", True):
        contexts: Dict[str, List[Component]] = {}
        for t in tools:
            for h in sorted(ctx.hosts_of(t.id)):
                contexts.setdefault(h, []).append(t)
    else:
        contexts = {"*": tools}
    out: Dict[Tuple[str, ...], _Candidate] = {}
    for host in sorted(contexts):
        members = contexts[host]
        a_tools = [t for t in members if t.attributes.get(cap_a)]
        b_tools = [t for t in members if t.attributes.get(cap_b)]
        if not a_tools or not b_tools:
            continue
        ids = tuple(sorted({t.id for t in a_tools + b_tools}))
        if ids in out:
            continue
        ev = [_cap_inference(t, cap_a) for t in sorted(a_tools, key=lambda t: t.id)]
        ev += [_cap_inference(t, cap_b) for t in sorted(b_tools, key=lambda t: t.id)]
        names_a = ", ".join(sorted(t.name for t in a_tools))
        names_b = ", ".join(sorted(t.name for t in b_tools))
        out[ids] = _Candidate(ids, evidence=ev,
                              detail=f"{CAPABILITY_TEXT[cap_a]}: {names_a}; {CAPABILITY_TEXT[cap_b]}: {names_b}")
    return [out[k] for k in sorted(out)]


def _match_flow(ctx: _Ctx, trig: Dict[str, Any]) -> List[_Candidate]:
    out = []
    for f in ctx.model.flows:
        src, dst = ctx.comps.get(f.src), ctx.comps.get(f.dst)
        if not src or not dst:
            continue
        if "crosses_boundary" in trig and f.crosses_boundary != bool(trig["crosses_boundary"]):
            continue
        if trig.get("data_class") and f.data_class not in _as_list(trig["data_class"]):
            continue
        if trig.get("src_kind") and src.kind not in _as_list(trig["src_kind"]):
            continue
        if trig.get("dst_kind") and dst.kind not in _as_list(trig["dst_kind"]):
            continue
        if trig.get("dst_trust_zone") and dst.trust_zone not in _as_list(trig["dst_trust_zone"]):
            continue
        if trig.get("dst_attr") and not _truthy(dst.attributes.get(trig["dst_attr"])):
            continue
        if trig.get("dst_attr_missing") and _truthy(dst.attributes.get(trig["dst_attr_missing"])):
            continue
        ev = [Evidence(kind="inference", ref=f.id,
                       text=f"{f.data_class} flows from {src.kind} '{src.name}' ({src.trust_zone}) to "
                            f"{dst.kind} '{dst.name}' ({dst.trust_zone}).")]
        if trig.get("dst_attr_missing"):
            ev.append(Evidence(kind="inference", ref=dst.id,
                               text=f"{dst.kind} '{dst.name}': {trig['dst_attr_missing']} not established."))
        out.append(_Candidate([src.id, dst.id], flows=[f.id], evidence=ev,
                              detail=f"{src.name} -> {dst.name} ({f.data_class})"))
    return out


def _match_shared_credential(ctx: _Ctx, trig: Dict[str, Any]) -> List[_Candidate]:
    out = []
    for c in ctx.model.components:
        if c.kind != "credential":
            continue
        flows = [f for f in ctx.model.flows if f.src == c.id and f.data_class == "secrets"
                 and ctx.comps.get(f.dst) and ctx.comps[f.dst].kind == "mcp_server"]
        servers = sorted({f.dst for f in flows})
        if len(servers) < 2:
            continue
        names = ", ".join(sorted(ctx.comps[s].name for s in servers))
        ev = [Evidence(kind="inference", ref=c.id,
                       text=f"Credential '{c.name}' is passed to {len(servers)} servers: {names}.")]
        out.append(_Candidate([c.id] + servers, flows=[f.id for f in flows], evidence=ev,
                              detail=f"credential '{c.name}' shared by {names}"))
    return out


def _match_remote_agent(ctx: _Ctx, trig: Dict[str, Any]) -> List[_Candidate]:
    attrs = _as_list(trig.get("attr"))
    missing = _as_list(trig.get("attr_missing"))
    out = []
    for c in ctx.model.components:
        if c.kind != "remote_agent":
            continue
        if attrs and not all(_truthy(c.attributes.get(a)) for a in attrs):
            continue
        if any(_truthy(c.attributes.get(a)) for a in missing):
            continue
        ev = _attr_inference(c, attrs, missing)
        reasons = c.attributes.get("dangerous_skill_reasons") or {}
        if "dangerous_skills" in attrs:
            for sk in sorted(reasons):
                ev.append(Evidence(kind="inference", ref=c.id, text=f"Skill '{sk}': {reasons[sk]}."))
        out.append(_Candidate([c.id], evidence=ev, detail=f"remote agent '{c.name}'"))
    return out


def _match_remote_agent_output(ctx: _Ctx, trig: Dict[str, Any]) -> List[_Candidate]:
    out = []
    for c in ctx.model.components:
        if c.kind != "remote_agent" or not c.attributes.get("skills"):
            continue
        flows = [f for f in ctx.model.flows if f.src == c.id and ctx.comps.get(f.dst)
                 and ctx.comps[f.dst].kind == "agent_host"]
        if not flows:
            continue
        hosts = sorted({f.dst for f in flows})
        ev = [Evidence(kind="inference", ref=f.id,
                       text=f"Output of remote agent '{c.name}' ({len(c.attributes['skills'])} skills) "
                            f"flows into agent host '{ctx.comps[f.dst].name}' as {f.data_class}.")
              for f in flows]
        out.append(_Candidate([c.id] + hosts, flows=[f.id for f in flows], evidence=ev,
                              detail=f"remote agent '{c.name}'"))
    return out


def _match_finding(ctx: _Ctx, trig: Dict[str, Any], covered: Set[str]) -> List[_Candidate]:
    sevs = _as_list(trig.get("severity"))
    has_selector = bool(trig.get("categories") or trig.get("id_prefixes") or trig.get("id_contains"))
    matched = []
    for f in ctx.model.evidence:
        if sevs and f.severity not in sevs:
            continue
        if has_selector and not _finding_matches(f, trig):
            continue
        if trig.get("uncovered_only") and f.id in covered:
            continue
        if not f.components:
            continue
        matched.append(f)
    if trig.get("per_finding"):
        return [_Candidate(f.components, evidence=[_finding_evidence(f)], key_extra=f"{f.id}|{f.source}",
                           detail=f.title, finding=f) for f in matched]
    groups: Dict[Tuple[str, ...], List[EvidenceFinding]] = {}
    for f in matched:
        groups.setdefault(tuple(f.components), []).append(f)
    out = []
    for comps in sorted(groups):
        fs = sorted(groups[comps], key=lambda f: (f.id, f.source))
        names = ", ".join(ctx.comps[c].name for c in comps if c in ctx.comps)
        out.append(_Candidate(comps, evidence=[_finding_evidence(f) for f in fs], detail=names))
    return out


_MATCHERS = {
    "component_attr": _match_component_attr,
    "tool_pair": _match_tool_pair,
    "flow": _match_flow,
    "shared_credential": _match_shared_credential,
    "remote_agent": _match_remote_agent,
    "remote_agent_skill_output": _match_remote_agent_output,
}


def _make_threat(rule: Dict[str, Any], cand: _Candidate, ctx: _Ctx, bump_on_evidence: bool) -> Threat:
    likelihood, impact = int(rule["likelihood"]), int(rule["impact"])
    stride, layer, stage = rule["stride"], int(rule["maestro_layer"]), rule.get("stage", "pivot")
    owasp_asi, owasp_mcp = list(rule["owasp_asi"]), list(rule["owasp_mcp"])
    evidence = list(cand.evidence)
    title = rule["title"]
    description = rule["description"]

    if cand.finding is not None:  # generic lift of one finding
        f = cand.finding
        scores = (rule.get("scores_by_severity") or {}).get(f.severity)
        if scores:
            likelihood, impact = int(scores[0]), int(scores[1])
        stride = (rule.get("stride_by_category") or {}).get(f.category, stride)
        layer = int((rule.get("maestro_by_category") or {}).get(f.category, layer))
        stage = (rule.get("stage_by_category") or {}).get(f.category, stage)
        owasp_asi = sorted(set(owasp_asi) | set(f.owasp_asi))
        owasp_mcp = sorted(set(owasp_mcp) | set(f.owasp_mcp))
        title = f"{rule['title']}: {f.title}"
    else:
        sel = rule.get("evidence") or {}
        if sel:
            scope = ctx.expand(cand.components)
            already = {e.ref for e in evidence if e.kind == "finding"}
            extra = [f for f in ctx.model.evidence
                     if set(f.components) & scope and _finding_matches(f, sel) and f.id not in already]
            extra = sorted({(f.id, f.title, f.severity): f for f in extra}.values(), key=lambda f: f.id)
            if extra:
                evidence.extend(_finding_evidence(f) for f in extra)
                if bump_on_evidence:
                    likelihood = min(5, likelihood + 1)

    if cand.detail:
        description = f"{description} Affected: {cand.detail}."
    key = "|".join(cand.components) + "#" + "|".join(cand.flows) + "#" + cand.key_extra
    risk = likelihood * impact
    return Threat(
        id=f"{rule['id']}-{_h(key)}",
        rule_id=rule["id"],
        title=title,
        description=description,
        affected_components=cand.components,
        affected_flows=cand.flows,
        stride=stride,
        maestro_layer=layer,
        cross_layer=sorted(set(int(x) for x in rule["cross_layer"]) - {layer}),
        owasp_asi=sorted(set(owasp_asi)),
        owasp_mcp=sorted(set(owasp_mcp)),
        likelihood=likelihood,
        impact=impact,
        risk=risk,
        risk_band=risk_band(risk),
        mitigations=[Mitigation(**m) for m in rule["mitigations"]],
        evidence=evidence,
        stage=stage,
        source="rule",
    )


def evaluate(model: SystemModel, catalogue: Optional[Dict[str, Any]] = None) -> List[Threat]:
    """Evaluate every catalogue rule against the model. Sorted by risk desc, then id."""
    catalogue = catalogue or load_catalogue()
    ctx = _Ctx(model)
    threats: Dict[str, Threat] = {}
    deferred = []
    for rule in sorted(catalogue["rules"], key=lambda r: r["id"]):
        trig = rule["trigger"]
        if trig["type"] == "finding" and trig.get("uncovered_only"):
            deferred.append(rule)
            continue
        if trig["type"] == "finding":
            cands = _match_finding(ctx, trig, set())
            bump = False
        else:
            cands = _MATCHERS[trig["type"]](ctx, trig)
            bump = True
        for cand in cands:
            t = _make_threat(rule, cand, ctx, bump)
            threats.setdefault(t.id, t)

    covered = {e.ref for t in threats.values() for e in t.evidence if e.kind == "finding"}
    for rule in deferred:
        for cand in _match_finding(ctx, rule["trigger"], covered):
            t = _make_threat(rule, cand, ctx, False)
            threats.setdefault(t.id, t)
    return sorted(threats.values(), key=lambda t: (-t.risk, t.id))


# ============================================================
# Attack paths
# ============================================================

def attack_paths(threats: List[Threat], model: SystemModel, top: int = 5, min_risk: int = 6) -> List[AttackPath]:
    """Chains of 2-3 rule threats (entry -> pivot -> impact) whose consecutive steps
    share at least one component.

    Only threats with risk >= ``min_risk`` take part. A link is *direct* when both
    threats name the same component and *weak* when it only holds through a
    tool/resource/prompt and its own server (sibling tools never link). Paths are
    ranked by number of weak links (fewer first), then total risk, then length.
    """
    ctx = _Ctx(model)
    pool = [t for t in threats if t.risk >= min_risk]
    direct = {t.id: set(t.affected_components) for t in pool}
    scope = {t.id: ctx.expand(t.affected_components) for t in pool}
    by_stage = {s: sorted([t for t in pool if t.stage == s], key=lambda t: t.id) for s in STAGES}

    def link(a: Threat, b: Threat) -> Tuple[List[str], bool]:
        strong = direct[a.id] & direct[b.id]
        if strong:
            return sorted(strong), False
        return sorted((direct[a.id] & scope[b.id]) | (direct[b.id] & scope[a.id])), True

    cands: List[Tuple[int, int, List[Threat], List[List[str]]]] = []
    for e, p, i in product(by_stage["entry"], by_stage["pivot"], by_stage["impact"]):
        (s1, w1), (s2, w2) = link(e, p), link(p, i)
        if s1 and s2:
            cands.append((int(w1) + int(w2), e.risk + p.risk + i.risk, [e, p, i], [s1, s2]))
    for first, second in (("entry", "pivot"), ("entry", "impact"), ("pivot", "impact")):
        for a, b in product(by_stage[first], by_stage[second]):
            s, w = link(a, b)
            if s:
                cands.append((int(w), a.risk + b.risk, [a, b], [s]))

    cands.sort(key=lambda c: (c[0], -c[1], -len(c[2]), [t.id for t in c[2]]))
    chosen: List[AttackPath] = []
    chosen_sets: List[Set[str]] = []
    names = lambda cids: ", ".join(ctx.comps[c].name for c in cids if c in ctx.comps)  # noqa: E731
    for _weak, score, steps, shared in cands:
        ids = [t.id for t in steps]
        if any(set(ids) <= s for s in chosen_sets):
            continue
        chosen_sets.append(set(ids))
        parts = []
        for n, t in enumerate(steps):
            via = f" via {names(shared[n - 1])}" if n else ""
            parts.append(f"({n + 1}) {t.stage}: {t.title} [{t.id}]{via}.")
        chosen.append(AttackPath(
            id="AP-" + _h("|".join(ids)),
            title=" -> ".join(t.title for t in steps),
            steps=ids,
            stages=[t.stage for t in steps],
            shared_components=shared,
            score=score,
            narrative=" ".join(parts),
        ))
        if len(chosen) >= top:
            break
    return chosen
