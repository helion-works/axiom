"""Tests for threat model generation (Workstream C: `axiom threatmodel`)."""

import copy
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from app.analysis.threat_model import (
    build_ai_payload,
    build_model,
    build_threat_model,
    from_a2a,
    from_discovery,
    from_scan,
    load_catalogue,
    mermaid_diagram,
    merge,
    render_json,
    render_markdown,
    risk_band,
)
from app.analysis.threat_model.rules import MAESTRO_LAYERS, MITIGATION_OWNERS, REQUIRED_RULE_KEYS, STRIDE
from app.analysis.threat_model.system_model import infer_capabilities

FIX = Path(__file__).parent / "fixtures" / "threatmodel"
SCAN = FIX / "scan_exfil.json"
DISCOVERY = FIX / "discovery_shadow.json"
A2A_CARD = FIX / "a2a_run_code_card.json"
A2A_DUCK = FIX / "a2a_unsigned_card.json"

FETCH_ID = "tool_web_mailer_mcp_fetch_webpage"
SEND_ID = "tool_web_mailer_mcp_send_email"


def _load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def _by_rule(result, rule_id):
    return [t for t in result["threats"] if t["rule_id"] == rule_id]


def _no_ai_key(monkeypatch):
    from app.utils.config import settings
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


# ============================================================
# Mermaid syntax validator (no node / mermaid-cli)
# ============================================================

_SAFE_ID = re.compile(r"^[A-Za-z0-9_]+$")
_SUBGRAPH = re.compile(r'^subgraph (\S+)\["([^"]*)"\]$')
_NODE = re.compile(r'^(\S+?)(\(\[|\[\(|\{\{|\[)"([^"]*)"(\]\)|\)\]|\}\}|\])$')
_EDGE = re.compile(r'^(\S+) -->\|"([^"]*)"\| (\S+)$')
_LINK = re.compile(r"^(\S+) -\.- (\S+)$")
_SHAPES = {"([": "])", "[(": ")]", "{{": "}}", "[": "]"}


def validate_mermaid(text: str):
    """Return a list of problems: header, balanced subgraph/end, safe ids, declared edge ends."""
    errors = []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines or lines[0] != "flowchart LR":
        errors.append("first line must be 'flowchart LR'")
    depth, nodes, subgraphs, edges = 0, set(), set(), []
    for ln in lines[1:]:
        m = _SUBGRAPH.match(ln)
        if m:
            depth += 1
            subgraphs.add(m.group(1))
            if not _SAFE_ID.match(m.group(1)):
                errors.append(f"unsafe subgraph id {m.group(1)!r}")
            continue
        if ln == "end":
            depth -= 1
            if depth < 0:
                errors.append("'end' without subgraph")
            continue
        m = _EDGE.match(ln)
        if m:
            edges.append((m.group(1), m.group(3)))
            continue
        m = _LINK.match(ln)
        if m:
            edges.append((m.group(1), m.group(2)))
            continue
        m = _NODE.match(ln)
        if m:
            nid, left, _label, right = m.groups()
            if not _SAFE_ID.match(nid):
                errors.append(f"unsafe node id {nid!r}")
            if _SHAPES.get(left) != right:
                errors.append(f"mismatched shape on {nid!r}")
            if nid in nodes:
                errors.append(f"duplicate node {nid!r}")
            nodes.add(nid)
            continue
        errors.append(f"unrecognised line {ln!r}")
    if depth != 0:
        errors.append(f"unbalanced subgraph/end (depth {depth})")
    for a, b in edges:
        for n in (a, b):
            if not _SAFE_ID.match(n):
                errors.append(f"unsafe edge id {n!r}")
            elif n not in nodes:
                errors.append(f"edge references undeclared node {n!r}")
    if nodes & subgraphs:
        errors.append("node id collides with subgraph id")
    return errors


def _mermaid_block(md: str) -> str:
    m = re.search(r"```mermaid\n(.*?)\n```", md, re.S)
    assert m, "no mermaid block"
    return m.group(1)


# ============================================================
# Catalogue
# ============================================================

class TestCatalogue:
    def test_catalogue_loads_and_rules_are_valid(self):
        cat = load_catalogue()
        rules = cat["rules"]
        assert len(rules) >= 14
        ids = [r["id"] for r in rules]
        assert len(ids) == len(set(ids))
        for r in rules:
            for k in REQUIRED_RULE_KEYS:
                assert k in r, (r["id"], k)
            assert re.match(r"^TM-\d{3}$", r["id"])
            assert r["stride"] in STRIDE
            assert r["maestro_layer"] in MAESTRO_LAYERS
            assert all(x in MAESTRO_LAYERS for x in r["cross_layer"])
            assert 1 <= r["likelihood"] <= 5 and 1 <= r["impact"] <= 5
            assert r["mitigations"] and all(m["owner"] in MITIGATION_OWNERS and m["text"] for m in r["mitigations"])
            assert all(re.match(r"^ASI\d{2}$", x) for x in r["owasp_asi"])
            assert all(re.match(r"^MCP\d{2}$", x) for x in r["owasp_mcp"])
        for required in ("TM-001", "TM-002", "TM-003", "TM-004", "TM-005", "TM-006", "TM-007", "TM-008",
                         "TM-009", "TM-010", "TM-011", "TM-012", "TM-013", "TM-014", "TM-090"):
            assert required in ids

    def test_maestro_layer_names_exact(self):
        cat = load_catalogue()
        expected = {
            "1": "Foundation Models", "2": "Data Operations", "3": "Agent Frameworks",
            "4": "Deployment and Infrastructure", "5": "Evaluation and Observability",
            "6": "Security and Compliance", "7": "Agent Ecosystem",
        }
        assert cat["maestro_layers"] == expected
        assert {str(k): v for k, v in MAESTRO_LAYERS.items()} == expected

    def test_bad_rule_is_rejected(self, tmp_path):
        cat = load_catalogue()
        bad = copy.deepcopy(cat)
        bad["rules"][0]["stride"] = "X"
        p = tmp_path / "cat.json"
        p.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ValueError):
            load_catalogue(str(p))
        bad = copy.deepcopy(cat)
        bad["rules"][0]["maestro_layer"] = 8
        p.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ValueError):
            load_catalogue(str(p))

    @pytest.mark.parametrize("risk,band", [(1, "low"), (5, "low"), (6, "medium"), (11, "medium"),
                                           (12, "high"), (19, "high"), (20, "critical"), (25, "critical")])
    def test_risk_band(self, risk, band):
        assert risk_band(risk) == band


# ============================================================
# System model
# ============================================================

class TestSystemModel:
    def test_capability_keyword_table(self):
        assert "reads_external" in infer_capabilities("fetch_webpage")
        caps = infer_capabilities("send_email", "Send an email to a recipient.")
        assert "sends_out" in caps and "reads_external" not in caps
        assert "reads_external" in infer_capabilities("read_mail")
        assert "executes" in infer_capabilities("run_code")
        assert "executes" not in infer_capabilities("code_search")
        assert "writes" in infer_capabilities("delete_note")
        assert "executes" in infer_capabilities("helper", "Executes shell commands on the host.")

    def test_from_scan_components_flows_and_assumptions(self):
        model = from_scan(_load(SCAN))
        ids = {c.id for c in model.components}
        assert {FETCH_ID, SEND_ID, "srv_web_mailer_mcp", "host_agent", "ext_internet",
                "cred_smtp_password"} <= ids
        assert "cred_log_level" not in ids  # non-secret env var names are not credentials
        fetch = model.component(FETCH_ID)
        assert fetch.attributes["reads_external"] and fetch.attributes["human_approved"] is False
        texts = " ".join(a.text for a in model.assumptions)
        assert "fetch_webpage" in texts and "send_email" in texts
        assert all(a.basis in ("inferred", "default") for a in model.assumptions)
        flows = {(f.src, f.dst, f.data_class): f for f in model.flows}
        assert flows[("ext_internet", FETCH_ID, "external_content")].crosses_boundary
        assert flows[("cred_smtp_password", "srv_web_mailer_mcp", "secrets")].crosses_boundary
        assert model.sources == ["scan"] and model.schema_version == "0.5"
        for b in model.boundaries:
            assert set(b.inside).isdisjoint(b.outside)

    def test_shared_credential_is_one_component(self):
        model = from_discovery(_load(DISCOVERY))
        creds = [c for c in model.components if c.kind == "credential"]
        assert [c.id for c in creds] == ["cred_github_personal_access_token"]
        users = sorted(f.dst for f in model.flows if f.src == creds[0].id and f.data_class == "secrets")
        assert users == ["srv_gh_helper", "srv_github"]
        assert "NODE_ENV" not in json.dumps(model.model_dump())

    def test_from_discovery_real_result(self, tmp_path):
        from app.analysis.discovery import discover_servers
        cfg = tmp_path / "mcp.json"
        cfg.write_text(json.dumps({"mcpServers": {
            "approved-fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/tmp"]},
            "sketchy": {"command": "npx", "args": ["-y", "totally-unknown-mcp"], "env": {"API_TOKEN": "x"}},
            "other": {"command": "uvx", "args": ["other-mcp"], "env": {"API_TOKEN": "y"}},
        }}), encoding="utf-8")
        allow = {"version": 1, "servers": [{"name": "approved-fs", "package": "@modelcontextprotocol/server-filesystem"},
                                           {"name": "other", "package": "other-mcp"}]}
        result = discover_servers(custom_paths=[str(cfg)], include_defaults=False, allowlist=allow)
        tm = build_threat_model(discovery=result)
        shadow = _by_rule(tm, "TM-007")
        assert len(shadow) == 1
        assert shadow[0]["affected_components"] == ["srv_sketchy"]
        assert any(e["kind"] == "finding" and e["ref"].startswith("discover_unapproved_") for e in shadow[0]["evidence"])
        shared = _by_rule(tm, "TM-005")
        assert shared and set(shared[0]["affected_components"]) == {"cred_api_token", "srv_other", "srv_sketchy"}
        assert "\"x\"" not in render_json(tm) and "\"y\"" not in render_json(tm)

    def test_merge_all_sources(self):
        model = build_model(_load(SCAN), _load(DISCOVERY), _load(A2A_DUCK))
        assert model.sources == ["scan", "discover", "a2a"]
        ids = [c.id for c in model.components]
        assert len(ids) == len(set(ids)) and ids == sorted(ids)
        kinds = {c.kind for c in model.components}
        assert {"agent_host", "mcp_server", "tool", "resource", "credential", "external_service",
                "remote_agent"} <= kinds
        comp_ids = set(ids)
        assert all(f.src in comp_ids and f.dst in comp_ids for f in model.flows)

    def test_merge_unifies_server_by_package(self):
        scan = _load(SCAN)
        disc = _load(DISCOVERY)
        disc["servers"].append({
            "client": "Cursor", "config_path": "/home/user/.cursor/mcp.json", "server_name": "mailer",
            "transport": "stdio", "command": "npx", "args": ["-y", "web-mailer-mcp@1.0.0"],
            "env_var_names": [], "header_names": [], "install_source": "npm",
            "package": "web-mailer-mcp", "version_pin": "1.0.0", "classification": "approved",
        })
        model = merge([from_discovery(disc), from_scan(scan)])
        servers = [c for c in model.components if c.kind == "mcp_server" and c.attributes.get("package") == "web-mailer-mcp"]
        assert len(servers) == 1
        sid = servers[0].id
        assert model.component(FETCH_ID).attributes["server"] == sid
        # the generic host is replaced by the real client host for that server
        assert any(f.src == "host_cursor" and f.dst == sid for f in model.flows)
        assert not any(f.src == "host_agent" and f.dst == sid for f in model.flows)


# ============================================================
# Rules
# ============================================================

class TestRules:
    def test_exfiltration_chain(self):
        tm = build_threat_model(scans=_load(SCAN))
        chain = _by_rule(tm, "TM-001")
        assert len(chain) == 1
        t = chain[0]
        assert FETCH_ID in t["affected_components"] and SEND_ID in t["affected_components"]
        ev = " ".join(e["text"] for e in t["evidence"])
        assert "fetch_webpage" in ev and "send_email" in ev
        # matching scan findings provide evidence and raise likelihood by one (capped)
        assert any(e["kind"] == "finding" and e["ref"] == "toxic_combo_data_read_network_external" for e in t["evidence"])
        assert t["likelihood"] == 5 and t["risk"] == t["likelihood"] * t["impact"]
        assert t["risk_band"] == "critical" and t["source"] == "rule"
        assert t["id"].startswith("TM-001-") and len(t["id"]) == len("TM-001-") + 8

    def test_threat_records_sorted_and_complete(self):
        tm = build_threat_model(scans=_load(SCAN), discovery=_load(DISCOVERY), a2a=_load(A2A_DUCK))
        threats = tm["threats"]
        assert threats == sorted(threats, key=lambda t: (-t["risk"], t["id"]))
        keys = {"id", "title", "description", "affected_components", "affected_flows", "stride", "maestro_layer",
                "cross_layer", "owasp_asi", "owasp_mcp", "likelihood", "impact", "risk", "risk_band",
                "mitigations", "evidence", "source"}
        for t in threats:
            assert keys <= set(t)
            assert t["risk_band"] == risk_band(t["risk"])
        assert len({t["id"] for t in threats}) == len(threats)

    def test_finding_rules_and_generic_lift(self):
        tm = build_threat_model(scans=_load(SCAN))
        poison = _by_rule(tm, "TM-008")
        assert poison and poison[0]["affected_components"] == [FETCH_ID]
        assert _by_rule(tm, "TM-015")
        assert _by_rule(tm, "TM-014")[0]["affected_components"] == ["res_web_mailer_mcp_dump_all_notes"]
        lifted = _by_rule(tm, "TM-090")
        refs = [e["ref"] for t in lifted for e in t["evidence"]]
        assert refs == ["dep_known_mailparser"]  # covered findings are not lifted twice
        assert lifted[0]["owasp_mcp"] == ["MCP04"]
        assert _by_rule(tm, "TM-003")[0]["affected_components"] == ["tool_web_mailer_mcp_delete_note"]

    def test_discovery_rules(self):
        tm = build_threat_model(discovery=_load(DISCOVERY))
        shadow = _by_rule(tm, "TM-007")
        assert [t["affected_components"] for t in shadow] == [["srv_gh_helper"]]
        assert _by_rule(tm, "TM-006")[0]["affected_components"] == ["srv_gh_helper"]
        shared = _by_rule(tm, "TM-005")
        assert len(shared) == 1
        assert shared[0]["affected_components"] == ["cred_github_personal_access_token", "srv_gh_helper", "srv_github"]
        noauth = _by_rule(tm, "TM-004")
        assert [t["affected_components"] for t in noauth] == [["host_cursor", "srv_search_remote"]]
        assert noauth[0]["affected_flows"]
        assert [t["affected_components"] for t in _by_rule(tm, "TM-010")] == [["srv_legacy_api"]]

    def test_attack_paths(self):
        tm = build_threat_model(scans=_load(SCAN))
        paths = tm["attack_paths"]
        assert 1 <= len(paths) <= 5
        by_id = {t["id"]: t for t in tm["threats"]}
        first = [by_id[s]["rule_id"] for s in paths[0]["steps"]]
        assert first[0] == "TM-008" and first[-1] == "TM-001"  # poisoning -> exfiltration
        for p in paths:
            assert 2 <= len(p["steps"]) <= 3
            assert p["score"] == sum(by_id[s]["risk"] for s in p["steps"])
            assert all(p["shared_components"])


# ============================================================
# Rendering / determinism
# ============================================================

class TestRendering:
    def test_determinism_md_and_json(self, monkeypatch):
        _no_ai_key(monkeypatch)
        args = (_load(SCAN), _load(DISCOVERY), _load(A2A_DUCK))
        a = build_threat_model(*copy.deepcopy(args))
        b = build_threat_model(*copy.deepcopy(args))
        assert render_json(a).encode() == render_json(b).encode()
        assert render_markdown(a).encode() == render_markdown(b).encode()
        assert "generated_at" not in a
        ts = build_threat_model(*copy.deepcopy(args), include_timestamp=True)
        assert "generated_at" in ts
        ts.pop("generated_at")
        assert render_json(ts) == render_json(a)
        render_markdown(a).encode("ascii")  # ASCII only

    def test_markdown_sections(self, monkeypatch):
        _no_ai_key(monkeypatch)
        md = render_markdown(build_threat_model(_load(SCAN), _load(DISCOVERY)))
        for h in ("## Scope", "## System description", "## Data-flow diagram", "## Assumptions", "## Threats",
                  "## Top attack paths", "## Mitigations by owner", "## Framework coverage", "## AI enrichment"):
            assert h in md
        assert "| STRIDE |" in md and "| MAESTRO layer |" in md
        assert "OWASP MCP Top 10 touched: " in md

    def test_framework_filter(self):
        tm = build_threat_model(scans=_load(SCAN))
        stride_md = render_markdown(tm, "stride")
        assert "| STRIDE |" in stride_md and "MAESTRO" not in stride_md
        maestro_md = render_markdown(tm, "maestro")
        assert "| MAESTRO layer |" in maestro_md and "STRIDE" not in maestro_md
        with pytest.raises(ValueError):
            render_markdown(tm, "pasta")

    def test_mermaid_diagram_is_valid(self):
        tm = build_threat_model(_load(SCAN), _load(DISCOVERY), _load(A2A_DUCK))
        diagram = _mermaid_block(render_markdown(tm))
        assert validate_mermaid(diagram) == []
        assert diagram.count("subgraph ") == len(tm["system_model"]["boundaries"])
        assert '-->|"external_content"|' in diagram and '-->|"secrets"|' in diagram

    def test_mermaid_sanitises_hostile_names(self):
        scan = _load(SCAN)
        scan["server_profile"]["tools"].append({"name": 'end"]; click x call alert(1) <b>#', "description": ""})
        scan["server_profile"]["name"] = "evil server/with spaces"
        diagram = mermaid_diagram(build_threat_model(scans=scan)["system_model"])
        assert validate_mermaid(diagram) == []
        assert "<b>" not in diagram

    def test_mermaid_validator_catches_errors(self):
        assert validate_mermaid("flowchart LR\n  subgraph a[\"x\"]\n    n_a[\"A\"]\n")  # missing end
        assert validate_mermaid('flowchart LR\n  n_a["A"]\n  n_a -->|"x"| n_b')  # undeclared node
        assert validate_mermaid('flowchart LR\n  n-a["A"]')  # unsafe id


# ============================================================
# AI enrichment
# ============================================================

class _FakeMessages:
    def __init__(self, text=None, exc=None):
        self.text, self.exc, self.calls = text, exc, []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc:
            raise self.exc

        class _Block:
            def __init__(self, t):
                self.text = t

        class _Msg:
            def __init__(self, t):
                self.content = [_Block(t)]

        return _Msg(self.text)


class _FakeClient:
    def __init__(self, text=None, exc=None):
        self.messages = _FakeMessages(text, exc)


_AI_REPLY = json.dumps({
    "threats": [
        {"title": "Credential replay via mailer", "description": "The SMTP credential could be replayed.",
         "affected_components": ["credential_2", "srv_web_mailer_mcp", "not_a_component"],
         "stride": "s", "maestro_layer": 6, "likelihood": 3, "impact": 4, "mitigation": "Rotate it."},
        {"title": "Bad entry", "stride": "Z", "maestro_layer": 99},
    ],
    "attack_paths": [{"title": "Fetch then mail", "narrative": "Poisoned page drives send_email.",
                      "affected_components": [FETCH_ID]}],
})


class TestAIEnrichment:
    def test_no_key_no_ai_section_no_error(self, monkeypatch):
        _no_ai_key(monkeypatch)
        tm = build_threat_model(scans=_load(SCAN), ai=True)
        assert tm["ai"]["ran"] is False and tm["ai"]["threats"] == []
        md = render_markdown(tm)
        assert "AI-suggested threats" not in md
        assert "AI enrichment was not run" in md

    def test_mocked_client_payload_and_separation(self, monkeypatch):
        _no_ai_key(monkeypatch)
        client = _FakeClient(text="Here you go:\n" + _AI_REPLY)
        base = build_threat_model(_load(SCAN), _load(DISCOVERY))
        tm = build_threat_model(_load(SCAN), _load(DISCOVERY), ai=True, ai_client=client)

        # deterministic part unchanged
        assert tm["threats"] == base["threats"] and tm["attack_paths"] == base["attack_paths"]
        ai = tm["ai"]
        assert ai["ran"] is True
        assert [t["id"] for t in ai["threats"]] == ["AI-01", "AI-02"]
        assert all(t["source"] == "ai" for t in ai["threats"] + ai["attack_paths"])
        first = ai["threats"][0]
        assert first["stride"] == "S" and first["maestro_layer"] == 6
        assert first["affected_components"] == ["cred_smtp_password", "srv_web_mailer_mcp"]
        assert ai["threats"][1]["stride"] == "" and ai["threats"][1]["maestro_layer"] is None
        md = render_markdown(tm)
        assert "## AI-suggested threats" in md and "Credential replay via mailer" in md
        assert "Sent only the sanitised system model JSON" in md

        # what was sent
        assert len(client.messages.calls) == 1
        sent = client.messages.calls[0]["messages"][0]["content"]
        for forbidden in ("SMTP_PASSWORD", "GITHUB_PERSONAL_ACCESS_TOKEN", "NODE_ENV", "cred_smtp_password",
                          "Fetches a URL", "poison_fetch_webpage", "Hidden instruction", "mailparser",
                          "https://", "http://", "/home/user", "npx", "capability_reasons"):
            assert forbidden not in sent, forbidden
        assert "credential_1" in sent and '"credential_count": 2' in sent
        assert "fetch_webpage" in sent  # tool names are part of the model

    def test_payload_builder_only_model(self):
        model = build_model(_load(SCAN), _load(DISCOVERY))
        payload, back = build_ai_payload(model)
        assert set(payload) == {"schema_version", "sources", "components", "flows", "boundaries", "assets",
                                "assumptions", "credential_count"}
        assert back == {"credential_1": "cred_github_personal_access_token", "credential_2": "cred_smtp_password"}

    def test_model_id_comes_from_settings(self, monkeypatch):
        from app.utils.config import settings
        import os
        if not os.getenv("ANTHROPIC_MODEL"):
            assert settings.ANTHROPIC_MODEL == "claude-sonnet-4-20250514"  # unchanged default
        _no_ai_key(monkeypatch)
        monkeypatch.setattr(settings, "ANTHROPIC_MODEL", "claude-test-model")
        client = _FakeClient(text=_AI_REPLY)
        tm = build_threat_model(scans=_load(SCAN), ai=True, ai_client=client)
        assert client.messages.calls[0]["model"] == "claude-test-model"
        assert tm["ai"]["model"] == "claude-test-model" and "claude-test-model" in tm["ai"]["note"]

    async def test_scan_ai_analysis_uses_model_setting(self, monkeypatch):
        import sys
        import types
        from app.analysis.ai_analysis import generate_mcp_ai_analysis
        from app.utils.config import settings
        client = _FakeClient(text="=== OVERALL ASSESSMENT ===\nok")
        fake_mod = types.ModuleType("anthropic")
        fake_mod.Anthropic = lambda api_key=None: client
        monkeypatch.setitem(sys.modules, "anthropic", fake_mod)
        monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(settings, "ANTHROPIC_MODEL", "claude-test-model")
        await generate_mcp_ai_analysis("model-setting-target", [], None)
        assert client.messages.calls[0]["model"] == "claude-test-model"

    def test_ai_failure_is_quiet(self, monkeypatch):
        _no_ai_key(monkeypatch)
        tm = build_threat_model(scans=_load(SCAN), ai=True, ai_client=_FakeClient(exc=RuntimeError("boom")))
        assert tm["ai"]["ran"] is False and "failed" in tm["ai"]["note"]
        assert "AI-suggested threats" not in render_markdown(tm)


# ============================================================
# A2A integration
# ============================================================

class TestA2A:
    def _check(self, tm):
        rules = {t["rule_id"] for t in tm["threats"]}
        assert {"TM-011", "TM-013", "TM-012"} <= rules
        comps = {c["id"]: c for c in tm["system_model"]["components"]}
        ra = comps["ra_code_runner_agent"]
        assert ra["kind"] == "remote_agent"
        assert ra["attributes"]["signed"] is False and ra["attributes"]["has_auth"] is False
        assert "run_code" in ra["attributes"]["dangerous_skills"]
        host = comps["host_agent"]
        assert ra["trust_zone"] != host["trust_zone"]
        flows = [f for f in tm["system_model"]["flows"] if "ra_code_runner_agent" in (f["src"], f["dst"])]
        assert flows and all(f["crosses_boundary"] for f in flows)
        assert {f["data_class"] for f in flows} == {"delegation", "external_content"}
        boundary = next(b for b in tm["system_model"]["boundaries"] if "ra_code_runner_agent" in b["inside"])
        assert "host_agent" in boundary["outside"]
        dangerous = _by_rule(tm, "TM-013")[0]
        assert "run_code" in " ".join(e["text"] for e in dangerous["evidence"])
        assert validate_mermaid(mermaid_diagram(tm["system_model"])) == []

    def test_real_scanner_result(self):
        from app.analysis.a2a_scanner import scan_agent_card
        result = scan_agent_card(str(A2A_CARD))  # local file: no network
        tm = build_threat_model(a2a=result)
        self._check(tm)
        refs = {e["ref"] for t in tm["threats"] for e in t["evidence"]}
        assert {"a2a-card-unsigned", "a2a-skill-dangerous-noauth:run_code"} <= refs
        # same result from the JSON dump of the scan (REST shape)
        tm2 = build_threat_model(a2a=json.loads(result.model_dump_json()))
        assert [t["id"] for t in tm2["threats"]] == [t["id"] for t in tm["threats"]]

    def test_raw_card_offline(self):
        self._check(build_threat_model(a2a=_load(A2A_CARD)))

    def test_duck_typed_dict(self):
        self._check(build_threat_model(a2a=_load(A2A_DUCK)))

    def test_signed_authenticated_card_is_quiet(self):
        duck = _load(A2A_DUCK)
        duck.update(signed=True, has_auth=True)
        tm = build_threat_model(a2a=duck)
        rules = {t["rule_id"] for t in tm["threats"]}
        assert "TM-011" not in rules and "TM-013" not in rules


# ============================================================
# CLI
# ============================================================

class TestCLI:
    def test_from_scan_md_and_json(self, monkeypatch, tmp_path):
        _no_ai_key(monkeypatch)
        from cli.axiom_cli import app
        runner = CliRunner()
        md = runner.invoke(app, ["threatmodel", "--from-scan", str(SCAN), "--format", "md"])
        assert md.exit_code == 0, md.output
        assert "# Axiom threat model" in md.output and "```mermaid" in md.output
        assert "Exfiltration chain" in md.output

        js = runner.invoke(app, ["threatmodel", "--from-scan", str(SCAN), "--format", "json"])
        assert js.exit_code == 0, js.output
        data = json.loads(js.output)
        assert data["sources"] == ["scan"] and any(t["rule_id"] == "TM-001" for t in data["threats"])
        assert data == build_threat_model(scans=_load(SCAN))

        out = tmp_path / "tm.md"
        res = runner.invoke(app, ["threatmodel", "--from-scan", str(SCAN), "--framework", "stride", "-o", str(out)])
        assert res.exit_code == 0, res.output
        text = out.read_text(encoding="utf-8")
        assert "| STRIDE |" in text and "MAESTRO" not in text

    def test_combined_sources(self, monkeypatch):
        _no_ai_key(monkeypatch)
        from cli.axiom_cli import app
        res = CliRunner().invoke(app, ["threatmodel", "--from-scan", str(SCAN), "--from-a2a", str(A2A_CARD),
                                       "-f", "json"])
        assert res.exit_code == 0, res.output
        data = json.loads(res.output)
        assert data["sources"] == ["scan", "a2a"]
        assert any(t["rule_id"] == "TM-013" for t in data["threats"])

    def test_from_discover_with_config(self, monkeypatch, tmp_path):
        _no_ai_key(monkeypatch)
        from cli.axiom_cli import app
        cfg = tmp_path / "mcp.json"
        cfg.write_text(json.dumps({"mcpServers": {"x": {"command": "npx", "args": ["-y", "some-mcp"]}}}),
                       encoding="utf-8")
        res = CliRunner().invoke(app, ["threatmodel", "--from-discover", "--no-defaults", "--config", str(cfg),
                                       "-f", "json"])
        assert res.exit_code == 0, res.output
        data = json.loads(res.output)
        assert any(t["rule_id"] == "TM-006" for t in data["threats"])

    def test_target_runs_engine_scan(self, monkeypatch):
        _no_ai_key(monkeypatch)
        from app.analysis import engine as engine_mod
        from app.analysis.package_resolver import PackageInfo
        from app.models.schemas import (Finding, FindingCategory, FindingSeverity, MCPServerProfile,
                                        MCPToolDefinition, RiskLevel, TransportType)
        calls = []

        async def fake_scan(target, target_url=None):
            calls.append((target, target_url))
            return {
                "target": target, "target_url": target_url, "status": "completed", "risk_score": 40.0,
                "risk_level": RiskLevel.HIGH,
                "server_profile": MCPServerProfile(name=target, transport=TransportType.SSE, tools=[
                    MCPToolDefinition(name="run_shell", description="Runs a shell command.")]),
                "findings": [Finding(id="transport_no_auth", severity=FindingSeverity.HIGH,
                                     category=FindingCategory.TRANSPORT_SECURITY,
                                     title="Remote MCP server without authentication", description="d")],
                "dependencies": [], "repo_health": None,
                "package_info": PackageInfo(name="remote-mcp", ecosystem="npm"),
            }

        monkeypatch.setattr(engine_mod.engine, "scan", fake_scan)
        from cli.axiom_cli import app
        res = CliRunner().invoke(app, ["threatmodel", "https://github.com/x/remote-mcp", "-f", "json"])
        assert res.exit_code == 0, res.output
        assert calls == [("remote-mcp", "https://github.com/x/remote-mcp")]
        data = json.loads(res.output)
        rules = {t["rule_id"] for t in data["threats"]}
        assert {"TM-002", "TM-004"} <= rules
        noauth = next(t for t in data["threats"] if t["rule_id"] == "TM-004")
        assert any(e["ref"] == "transport_no_auth" for e in noauth["evidence"])
        srv = next(c for c in data["system_model"]["components"] if c["kind"] == "mcp_server")
        assert srv["attributes"]["package"] == "remote-mcp" and srv["trust_zone"] == "remote_server"

    def test_scan_json_round_trips_into_threatmodel(self, monkeypatch, tmp_path):
        """`scan --output json` carries server_profile, so `threatmodel --from-scan` sees the tools."""
        _no_ai_key(monkeypatch)
        from app.analysis import engine as engine_mod
        from app.models.schemas import (Finding, FindingCategory, FindingSeverity, MCPServerProfile,
                                        MCPToolDefinition, RiskLevel, TransportType)

        async def fake_scan(target, target_url=None):
            return {
                "target": target, "target_url": target_url, "status": "completed", "risk_score": 40.0,
                "risk_level": RiskLevel.HIGH,
                "server_profile": MCPServerProfile(name="remote-mcp", transport=TransportType.SSE, tools=[
                    MCPToolDefinition(name="fetch_webpage", description="Fetches a URL and returns the page."),
                    MCPToolDefinition(name="send_email", description="Send an email to any recipient.")]),
                "findings": [Finding(id="transport_no_auth", severity=FindingSeverity.HIGH,
                                     category=FindingCategory.TRANSPORT_SECURITY,
                                     title="Remote MCP server without authentication", description="d")],
                "dependencies": [], "repo_health": None,
            }

        monkeypatch.setattr(engine_mod.engine, "scan", fake_scan)
        from cli.axiom_cli import app
        try:
            runner = CliRunner(mix_stderr=False)  # click < 8.2
        except TypeError:  # click >= 8.2 always keeps stderr separate
            runner = CliRunner()
        res = runner.invoke(app, ["scan", "https://github.com/x/remote-mcp", "--output", "json",
                                  "--no-ai", "--no-history"])
        assert res.exit_code == 2, res.output  # high risk
        # stdout is the JSON document only (progress goes to stderr), so `> scan.json` works
        scan_json = json.loads(res.stdout)
        assert scan_json["schema_version"] == "0.5"
        assert scan_json["tools_found"] == 2
        assert [t["name"] for t in scan_json["server_profile"]["tools"]] == ["fetch_webpage", "send_email"]
        assert scan_json["server_profile"]["transport"] == "sse"
        assert scan_json["findings"][0]["id"] == "transport_no_auth"

        path = tmp_path / "scan.json"
        path.write_text(json.dumps(scan_json), encoding="utf-8")
        tm = runner.invoke(app, ["threatmodel", "--from-scan", str(path), "-f", "json"])
        assert tm.exit_code == 0, tm.output
        data = json.loads(tm.output)
        tools = {c["name"] for c in data["system_model"]["components"] if c["kind"] == "tool"}
        assert tools == {"fetch_webpage", "send_email"}
        rules = {t["rule_id"] for t in data["threats"]}
        assert {"TM-001", "TM-004"} <= rules
        noauth = next(t for t in data["threats"] if t["rule_id"] == "TM-004")
        assert any(e["ref"] == "transport_no_auth" for e in noauth["evidence"])

    def test_reduced_cli_scan_json(self):
        reduced = {"target": "srv", "risk_score": 10, "risk_level": "low", "tools_found": 0, "findings_count": 1,
                   "findings": [{"severity": "critical", "category": "code_execution", "title": "eval() on input",
                                 "owasp_asi": ["ASI05"], "owasp_mcp": None}]}
        tm = build_threat_model(scans=reduced)
        lifted = _by_rule(tm, "TM-090")
        assert len(lifted) == 1 and lifted[0]["risk"] == 20 and lifted[0]["stride"] == "E"

    def test_errors(self):
        from cli.axiom_cli import app
        runner = CliRunner()
        assert runner.invoke(app, ["threatmodel"]).exit_code == 2
        assert runner.invoke(app, ["threatmodel", "--from-scan", str(SCAN), "-f", "xml"]).exit_code == 2
        assert runner.invoke(app, ["threatmodel", "--from-scan", str(SCAN), "--framework", "x"]).exit_code == 2
        assert runner.invoke(app, ["threatmodel", "--from-scan", "does-not-exist.json"]).exit_code == 2


# ============================================================
# REST
# ============================================================

class TestREST:
    @pytest.fixture
    def client(self):
        from main import app
        return TestClient(app)

    def test_post_and_download(self, client, monkeypatch):
        _no_ai_key(monkeypatch)
        resp = client.post("/api/v1/threatmodel", json={"scan": _load(SCAN), "a2a": _load(A2A_DUCK), "ai": False})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["sources"] == ["scan", "a2a"]
        assert any(t["rule_id"] == "TM-001" for t in data["threats"])
        assert data["ai"]["ran"] is False
        tm_id = data["id"]
        assert re.match(r"^[0-9a-f]{16}$", tm_id)

        md = client.get(f"/api/v1/threatmodel/{tm_id}/report.md")
        assert md.status_code == 200
        assert md.headers["content-type"].startswith("text/markdown")
        assert "attachment" in md.headers["content-disposition"]
        assert md.text.startswith("# Axiom threat model")
        assert validate_mermaid(_mermaid_block(md.text)) == []

        js = client.get(f"/api/v1/threatmodel/{tm_id}")
        assert js.status_code == 200 and js.json()["threats"] == data["threats"]

    def test_errors(self, client):
        assert client.post("/api/v1/threatmodel", json={}).status_code == 400
        assert client.get("/api/v1/threatmodel/0123456789abcdef/report.md").status_code == 404
        assert client.get("/api/v1/threatmodel/not-an-id/report.md").status_code == 404
        assert client.post("/api/v1/threatmodel", json={"scan_id": "no-such-scan"}).status_code == 404
