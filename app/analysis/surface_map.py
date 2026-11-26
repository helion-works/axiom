"""
The Agent Surface Map.

Axiom's premise is that an MCP server's attack surface is *what the model is shown and
what the tools can do*, not the quality of its code. The Surface Map is the normalised,
language-independent record of exactly that: every tool, resource and prompt an agent
would see, the literals that reach the model on the return path, the capabilities each
tool has, and the ways the surface can change after approval (mutations).

The same Map is produced from Python source (``ast``), TypeScript/JavaScript source
(tree-sitter) and from a live session (``tools/list`` etc.), so:

* every text rule runs on the Map and scans both languages identically;
* ``fingerprint`` — sha256 over the canonical Map (names + descriptions + schemas +
  instructions) — is a stable identity for *what the agent sees*. ``axiom baseline``
  stores it, ``axiom drift`` diffs it, and ``axiom live --source <dir>`` compares the
  on-the-wire Map with the source Map: a server that advertises something its published
  source does not contain is a ``surface_mismatch`` finding. That is rug-pull detection
  without ever calling a tool.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from app.analysis.mcp_top10_detectors import _iter_files
from app.analysis.owasp_mapping import detect_dangerous_tool_capabilities
from app.analysis.py_extractor import PyExtraction, ToolBody
from app.analysis.tool_body_detectors import _TS_EXTS, extract_definitions
from app.analysis.tool_poisoning import find_identity_params, find_unpinned_install
from app.models.schemas import (
    Finding,
    FindingCategory,
    FindingSeverity,
    MCPPromptDefinition,
    MCPResourceDefinition,
    MCPToolDefinition,
)

SCHEMA = "axiom.surface/1"
CAPABILITY_TAGS = ("fs.read", "fs.write", "exec", "net.egress", "env", "identity", "install")

_CAP_TO_TAG = {
    "shell_exec": "exec", "file_read": "fs.read", "file_write": "fs.write",
    "env_dump": "env", "network_egress": "net.egress",
}
_CALL_TAGS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)^(?:fs(?:\.promises)?\.(?:readFile|readFileSync|readdir|readdirSync|createReadStream)"
                r"|open|Path(?:\.\w+)*|\w+\.(?:read_text|read_bytes|glob|rglob|iterdir)|os\.(?:listdir|walk))$"), "fs.read"),
    (re.compile(r"(?i)^(?:fs(?:\.promises)?\.(?:writeFile|writeFileSync|unlink|unlinkSync|rm|rmSync|appendFile|appendFileSync|rename|renameSync|createWriteStream)"
                r"|\w+\.(?:write_text|write_bytes|unlink|rmtree)|os\.(?:remove|unlink|rmdir|makedirs|rename|chmod)|shutil\.\w+)$"), "fs.write"),
    (re.compile(r"(?i)^(?:(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)"
                r"|os\.(?:system|popen)|subprocess\.\w+|eval|exec|compile|Function|vm\.\w+)$"), "exec"),
    (re.compile(r"(?i)^(?:fetch|axios(?:\.\w+)?|got(?:\.\w+)?|request|https?\.request|requests\.\w+|httpx\.\w+"
                r"|urllib\.request\.\w+|urlopen|aiohttp\.\w+|socket\.\w+|dns\.\w+|net\.\w+)$"), "net.egress"),
    (re.compile(r"(?i)^(?:process\.env|os\.environ|os\.getenv)$"), "env"),
    (re.compile(r"(?i)^(?:pip\.\w+|importlib\.\w+|__import__|require|import)$"), "install"),
]
_INSTALL_DESC_RE = re.compile(r"(?i)\b(install|installs|download and run|load(?:s)? a plugin|npm i\b|pip install|npx )")
_DESC_EXEC_RE = re.compile(r"(?i)\bnpm (?:install|i)\b|\bpip install\b|\buvx?\b|\bnpx\b")

_TRANSPORT_HINTS = [
    (re.compile(r"StreamableHTTPServerTransport|streamable[-_ ]?http|/mcp['\"]"), "streamable-http"),
    (re.compile(r"SSEServerTransport|sse_app\(|transport=['\"]sse['\"]|/sse['\"]"), "sse"),
    (re.compile(r"StdioServerTransport|stdio_server|transport=['\"]stdio['\"]|\.run\(\)"), "stdio"),
]


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------

@dataclass
class SurfaceTool:
    name: str
    description: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)
    return_literals: List[str] = field(default_factory=list)
    registration: str = "static"          # static | runtime | handler | live
    location: str = ""


@dataclass
class SurfaceResource:
    uri: str
    name: str = ""
    description: str = ""
    mime_type: Optional[str] = None
    content_literals: List[str] = field(default_factory=list)
    location: str = ""


@dataclass
class SurfacePrompt:
    name: str
    description: str = ""
    arguments: List[Dict[str, Any]] = field(default_factory=list)
    message_literals: List[str] = field(default_factory=list)
    location: str = ""


@dataclass
class SurfaceMutation:
    kind: str                              # add_tool | remove_tool | counter | list_changed
    name: str = ""
    location: str = ""
    inside: str = ""


@dataclass
class SurfaceMap:
    server: Dict[str, Any]
    tools: List[SurfaceTool] = field(default_factory=list)
    resources: List[SurfaceResource] = field(default_factory=list)
    prompts: List[SurfacePrompt] = field(default_factory=list)
    mutations: List[SurfaceMutation] = field(default_factory=list)
    source: Dict[str, Any] = field(default_factory=dict)
    generated_at: str = ""
    fingerprint: str = ""
    schema: str = SCHEMA

    # -- serialisation ------------------------------------------------------
    def canonical(self) -> Dict[str, Any]:
        """What the agent sees: names, descriptions, schemas, instructions. Nothing else."""
        return {
            "instructions": norm_text(self.server.get("instructions")),
            "tools": sorted(
                ({"name": t.name, "description": norm_text(t.description), "input_schema": _canon_schema(t.input_schema)}
                 for t in self.tools), key=lambda t: t["name"]),
            "resources": sorted(
                ({"uri": r.uri, "name": r.name, "description": norm_text(r.description)} for r in self.resources),
                key=lambda r: (r["uri"], r["name"])),
            "prompts": sorted(
                ({"name": p.name, "description": norm_text(p.description),
                  "arguments": sorted((a.get("name", "") for a in p.arguments))} for p in self.prompts),
                key=lambda p: p["name"]),
        }

    def compute_fingerprint(self) -> str:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.fingerprint = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        return self.fingerprint

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["schema"] = self.schema
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SurfaceMap":
        m = cls(server=d.get("server") or {}, source=d.get("source") or {},
                generated_at=d.get("generated_at", ""), fingerprint=d.get("fingerprint", ""),
                schema=d.get("schema", SCHEMA))
        m.tools = [SurfaceTool(**_only(SurfaceTool, t)) for t in d.get("tools", [])]
        m.resources = [SurfaceResource(**_only(SurfaceResource, r)) for r in d.get("resources", [])]
        m.prompts = [SurfacePrompt(**_only(SurfacePrompt, p)) for p in d.get("prompts", [])]
        m.mutations = [SurfaceMutation(**_only(SurfaceMutation, x)) for x in d.get("mutations", [])]
        return m

    def tool(self, name: str) -> Optional[SurfaceTool]:
        for t in self.tools:
            if t.name == name:
                return t
        return None


def norm_text(s: Optional[str]) -> str:
    """Whitespace-insensitive form of a description: the SDKs disagree on docstring
    indentation (the Python SDK sends the raw ``__doc__``), and that must not change identity."""
    if not s:
        return ""
    return "\n".join(" ".join(line.split()) for line in s.strip().splitlines()).strip()


def _only(cls, d: Dict[str, Any]) -> Dict[str, Any]:
    keys = cls.__dataclass_fields__.keys()  # type: ignore[attr-defined]
    return {k: v for k, v in d.items() if k in keys}


def _canon_schema(schema: Any) -> Any:
    """Drop presentation-only keys so a title change does not alter identity."""
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    out_props = {}
    for k in sorted(props):
        p = props[k] if isinstance(props[k], dict) else {}
        out_props[k] = {kk: p[kk] for kk in sorted(p) if kk in ("type", "default", "enum", "description")}
    return {"properties": out_props, "required": sorted(r for r in (schema.get("required") or []) if isinstance(r, str))}


# ---------------------------------------------------------------------------
# capability tags
# ---------------------------------------------------------------------------

def capability_tags(tool: MCPToolDefinition, body: Optional[ToolBody] = None) -> List[str]:
    tags: Set[str] = set()
    for f in detect_dangerous_tool_capabilities([tool]):
        cap = f.id.rsplit("_", 1)[-1] if f.id.startswith("cap_") else ""
        for cap_name, tag in _CAP_TO_TAG.items():
            if f.id.endswith("_" + cap_name):
                tags.add(tag)
    if body is not None:
        for _p, _sink, kind, _line, _v in getattr(body, "param_sinks", []) or []:
            tags.add(_CAP_TO_TAG.get(kind, kind))
        for call in getattr(body, "calls", set()) or set():
            for rx, tag in _CALL_TAGS:
                if rx.match(call) or rx.match(call.split(".")[-1]):
                    tags.add(tag)
                    break
    if find_identity_params(tool):
        tags.add("identity")
    if find_unpinned_install(tool) or _INSTALL_DESC_RE.search(tool.description or ""):
        tags.add("install")
    return [t for t in CAPABILITY_TAGS if t in tags]


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------

def _server_name_from_dir(scan_dir: str) -> str:
    pkg = os.path.join(scan_dir, "package.json")
    if os.path.exists(pkg):
        try:
            with open(pkg, "r", encoding="utf-8") as f:
                name = json.load(f).get("name")
            if isinstance(name, str) and name:
                return name
        except Exception:
            pass
    pyproject = os.path.join(scan_dir, "pyproject.toml")
    if os.path.exists(pyproject):
        try:
            with open(pyproject, "r", encoding="utf-8") as f:
                m = re.search(r'^name\s*=\s*"([^"]+)"', f.read(), re.M)
            if m:
                return m.group(1)
        except Exception:
            pass
    return os.path.basename(os.path.normpath(scan_dir)) or "server"


def _language_of(rel: str) -> str:
    if rel.endswith(".py"):
        return "python"
    if rel.endswith((".ts", ".tsx", ".mts", ".cts")):
        return "typescript"
    return "javascript"


def iter_extractions(scan_dir: str) -> Iterable[Tuple[str, str, PyExtraction]]:
    """(relative path, content, extraction) for every source file that defines anything."""
    if os.path.isfile(scan_dir):
        rel = os.path.basename(scan_dir)
        with open(scan_dir, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        ex = extract_definitions(content, rel)
        if ex is not None:
            yield rel, content, ex
        return
    for _, rel, content in _iter_files(scan_dir, lambda f: f.endswith(".py") or f.endswith(_TS_EXTS)):
        ex = extract_definitions(content, rel)
        if ex is None:
            continue
        if ex.tools or ex.resources or ex.prompts or ex.bodies or ex.registrations or ex.server_instructions:
            yield rel, content, ex


def _detect_transport(contents: Iterable[str]) -> str:
    joined = "\n".join(contents)
    for rx, name in _TRANSPORT_HINTS:
        if rx.search(joined):
            return name
    return "unknown"


def build_static_map(scan_dir: str, server_name: Optional[str] = None) -> SurfaceMap:
    """Build the Surface Map of a server from its source (file or directory)."""
    scan_dir = os.path.abspath(scan_dir)
    name = server_name or (_server_name_from_dir(scan_dir) if os.path.isdir(scan_dir)
                           else os.path.splitext(os.path.basename(scan_dir))[0])
    m = SurfaceMap(server={"name": name, "instructions": "", "transport": "unknown", "auth": "unknown"},
                   source={"kind": "static", "target": scan_dir, "languages": []},
                   generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    languages: Set[str] = set()
    contents: List[str] = []
    seen_tools: Set[str] = set()
    seen_resources: Set[str] = set()
    seen_prompts: Set[str] = set()
    for rel, content, ex in iter_extractions(scan_dir):
        languages.add(_language_of(rel))
        contents.append(content)
        if ex.server_instructions and not m.server["instructions"]:
            m.server["instructions"] = ex.server_instructions
            m.server["instructions_location"] = f"{rel}:{ex.server_instructions_line}"
        bodies = {(b.kind, b.name): b for b in ex.bodies}
        for t in ex.tools:
            if t.name in seen_tools:
                continue
            seen_tools.add(t.name)
            body = bodies.get(("tool", t.name))
            reg = "static"
            if body is not None and body.registered_at_runtime:
                reg = "runtime"
            elif body is not None and body.func_name in ("tools/call", "handler"):
                reg = "handler"
            m.tools.append(SurfaceTool(
                name=t.name, description=t.description or "", input_schema=t.input_schema or {},
                capabilities=capability_tags(t, body),
                return_literals=list(dict.fromkeys(body.return_strings)) if body is not None else [],
                registration=reg,
                location=f"{rel}:{body.lineno}" if body is not None else rel,
            ))
        for r in ex.resources:
            key = r.uri or r.name
            if key in seen_resources:
                continue
            seen_resources.add(key)
            body = bodies.get(("resource", r.name)) or bodies.get(("resource", r.uri))
            m.resources.append(SurfaceResource(
                uri=r.uri, name=r.name or "", description=r.description or "", mime_type=r.mime_type,
                content_literals=list(dict.fromkeys(body.return_strings)) if body is not None else [],
                location=f"{rel}:{body.lineno}" if body is not None else rel,
            ))
        for p in ex.prompts:
            if p.name in seen_prompts:
                continue
            seen_prompts.add(p.name)
            body = bodies.get(("prompt", p.name))
            m.prompts.append(SurfacePrompt(
                name=p.name, description=p.description or "", arguments=list(p.arguments or []),
                message_literals=list(dict.fromkeys(body.return_strings)) if body is not None else [],
                location=f"{rel}:{body.lineno}" if body is not None else rel,
            ))
        for reg_ in ex.registrations:
            m.mutations.append(SurfaceMutation(kind=reg_.kind, name=reg_.name or "", location=f"{rel}:{reg_.lineno}",
                                               inside=reg_.inside_function or ""))
        for b in ex.bodies:
            if b.kind == "tool" and b.count_gated:
                m.mutations.append(SurfaceMutation(kind="counter", name=b.name, location=f"{rel}:{b.lineno}"))
        for mm in re.finditer(r"""listChanged["']?\s*[:=]\s*(True|true)""", content):
            m.mutations.append(SurfaceMutation(kind="list_changed", location=f"{rel}:{content.count(chr(10), 0, mm.start()) + 1}"))
    m.server["transport"] = _detect_transport(contents)
    m.source["languages"] = sorted(languages)
    m.compute_fingerprint()
    return m


def build_live_map(result: Any) -> SurfaceMap:
    """Build the Surface Map of a server from a :class:`LiveScanResult` (nothing is called)."""
    info = result.server_info or {}
    m = SurfaceMap(
        server={"name": info.get("name") or result.server_name, "instructions": result.server_instructions or "",
                "transport": result.transport, "auth": "provided" if result.auth_provided else "none",
                "version": info.get("version"), "capabilities": result.server_capabilities or {}},
        source={"kind": "live", "target": result.server_name, "languages": []},
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    for t in result.runtime_tools:
        m.tools.append(SurfaceTool(name=t.name, description=t.description or "", input_schema=t.input_schema or {},
                                   capabilities=capability_tags(t), registration="live", location=f"live:tools/list:{t.name}"))
    for r in result.runtime_resources:
        m.resources.append(SurfaceResource(uri=r.uri, name=r.name or "", description=r.description or "",
                                           mime_type=r.mime_type,
                                           content_literals=[c for c in [result.resource_contents.get(r.uri)] if c],
                                           location=f"live:resources/list:{r.uri}"))
    for p in result.runtime_prompts:
        m.prompts.append(SurfacePrompt(name=p.name, description=p.description or "", arguments=list(p.arguments or []),
                                       message_literals=list(result.prompt_messages.get(p.name) or []),
                                       location=f"live:prompts/list:{p.name}"))
    caps = result.server_capabilities or {}
    if isinstance(caps.get("tools"), dict) and caps["tools"].get("listChanged"):
        m.mutations.append(SurfaceMutation(kind="list_changed", location="live:initialize:capabilities.tools.listChanged"))
    m.compute_fingerprint()
    return m


# ---------------------------------------------------------------------------
# diff + mismatch
# ---------------------------------------------------------------------------

def diff_maps(old: SurfaceMap, new: SurfaceMap) -> Dict[str, Any]:
    """Structural diff of what the agent sees. Keys: tools/resources/prompts -> added/removed/changed."""
    def by_name(items, key):
        return {key(i): i for i in items}

    out: Dict[str, Any] = {
        "fingerprint_changed": old.fingerprint != new.fingerprint,
        "old_fingerprint": old.fingerprint, "new_fingerprint": new.fingerprint,
        "instructions_changed": norm_text(old.server.get("instructions")) != norm_text(new.server.get("instructions")),
    }
    ot, nt = by_name(old.tools, lambda t: t.name), by_name(new.tools, lambda t: t.name)
    changed = []
    for name in sorted(set(ot) & set(nt)):
        fields = []
        if norm_text(ot[name].description) != norm_text(nt[name].description):
            fields.append("description")
        if _canon_schema(ot[name].input_schema) != _canon_schema(nt[name].input_schema):
            fields.append("input_schema")
        if set(ot[name].capabilities) != set(nt[name].capabilities):
            fields.append("capabilities")
        if fields:
            changed.append({"name": name, "fields": fields})
    out["tools"] = {"added": sorted(set(nt) - set(ot)), "removed": sorted(set(ot) - set(nt)), "changed": changed}
    orr, nr = by_name(old.resources, lambda r: r.uri), by_name(new.resources, lambda r: r.uri)
    out["resources"] = {
        "added": sorted(set(nr) - set(orr)), "removed": sorted(set(orr) - set(nr)),
        "changed": [{"uri": u, "fields": ["description"]} for u in sorted(set(orr) & set(nr))
                    if norm_text(orr[u].description) != norm_text(nr[u].description)],
    }
    op, np_ = by_name(old.prompts, lambda p: p.name), by_name(new.prompts, lambda p: p.name)
    out["prompts"] = {
        "added": sorted(set(np_) - set(op)), "removed": sorted(set(op) - set(np_)),
        "changed": [{"name": n, "fields": ["description"]} for n in sorted(set(op) & set(np_))
                    if norm_text(op[n].description) != norm_text(np_[n].description)],
    }
    out["changed"] = bool(out["instructions_changed"] or any(
        out[k][x] for k in ("tools", "resources", "prompts") for x in ("added", "removed", "changed")))
    return out


def surface_mismatch_findings(source: SurfaceMap, live: SurfaceMap) -> List[Finding]:
    """Findings for every way the on-the-wire surface differs from the published source."""
    findings: List[Finding] = []
    d = diff_maps(source, live)
    src_where = source.source.get("target", "source")

    def add(fid: str, sev: FindingSeverity, title: str, desc: str, location: str) -> None:
        findings.append(Finding(
            id=fid, severity=sev, category=FindingCategory.SURFACE_MISMATCH, title=title,
            description=desc + f" Source map: {src_where} (fingerprint {source.fingerprint[:12]}); "
                        f"live fingerprint {live.fingerprint[:12]}.",
            file_path=location,
            recommendation="Treat the running server as a different artefact from the one reviewed: re-approve "
                           "it against the live surface, or pin the version whose source was scanned.",
            owasp_asi=["ASI04", "ASI10"], owasp_mcp=["MCP03", "MCP04"],
        ))

    for name in d["tools"]["added"]:
        t = live.tool(name)
        caps = ", ".join(t.capabilities) if t and t.capabilities else "no dangerous capability tagged"
        add(f"surface_mismatch_tool_added_{name}", FindingSeverity.HIGH,
            f"Live server advertises tool '{name}' that its source does not define",
            f"'{name}' is in the live tools/list but nowhere in the scanned source ({caps}). "
            "A tool that is not in the reviewed code was injected after publication or comes from different code.",
            f"live:tools/list:{name}")
    for ch in d["tools"]["changed"]:
        name, fields = ch["name"], ch["fields"]
        sev = FindingSeverity.HIGH if "description" in fields else FindingSeverity.MEDIUM
        add(f"surface_mismatch_tool_changed_{name}", sev,
            f"Tool '{name}' differs between source and live ({', '.join(fields)})",
            f"The live definition of '{name}' differs from the source in: {', '.join(fields)}. "
            + ("A changed description is what the model reads; this is the rug-pull primitive." if "description" in fields
               else "A changed schema alters what the agent will send."),
            f"live:tools/list:{name}")
    for name in d["tools"]["removed"]:
        add(f"surface_mismatch_tool_missing_{name}", FindingSeverity.INFO,
            f"Source defines tool '{name}' that the live server does not list",
            f"'{name}' is in the source but not served; it may be gated, disabled or registered later.",
            f"live:tools/list:{name}")
    if d["instructions_changed"]:
        add("surface_mismatch_instructions", FindingSeverity.HIGH,
            "Server instructions differ between source and live",
            "The `instructions` string sent at initialize is not the one in the scanned source. "
            "Instructions are read by every client before any tool is called.",
            "live:initialize:instructions")
    for uri in d["resources"]["added"]:
        add(f"surface_mismatch_resource_added_{re.sub(r'[^A-Za-z0-9_.-]+', '_', uri)[:60]}", FindingSeverity.MEDIUM,
            f"Live server serves resource '{uri}' not in its source",
            f"'{uri}' is listed live but not defined in the scanned source.", f"live:resources/list:{uri}")
    for name in d["prompts"]["added"]:
        add(f"surface_mismatch_prompt_added_{name}", FindingSeverity.MEDIUM,
            f"Live server serves prompt '{name}' not in its source",
            f"'{name}' is listed live but not defined in the scanned source.", f"live:prompts/list:{name}")
    return findings


# ---------------------------------------------------------------------------
# baseline storage
# ---------------------------------------------------------------------------

def baseline_dir() -> str:
    from app.analysis.scan_history import MCPGUARD_DIR
    d = os.path.join(MCPGUARD_DIR, "baselines")
    os.makedirs(d, exist_ok=True)
    return d


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.@-]+", "_", name).strip("_")[:120] or "server"


def save_baseline(m: SurfaceMap, name: Optional[str] = None) -> str:
    name = _safe_name(name or m.server.get("name") or "server")
    path = os.path.join(baseline_dir(), name + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(m.to_dict(), f, indent=2, ensure_ascii=False)
    return path


def load_baseline(name_or_path: str) -> Optional[SurfaceMap]:
    path = name_or_path
    if not os.path.exists(path):
        path = os.path.join(baseline_dir(), _safe_name(name_or_path) + ".json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return SurfaceMap.from_dict(json.load(f))


def list_baselines() -> List[Dict[str, Any]]:
    out = []
    d = baseline_dir()
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".json"):
            try:
                with open(os.path.join(d, fn), "r", encoding="utf-8") as f:
                    m = json.load(f)
                out.append({"name": fn[:-5], "fingerprint": m.get("fingerprint", ""), "generated_at": m.get("generated_at", ""),
                            "tools": len(m.get("tools", [])), "path": os.path.join(d, fn)})
            except Exception:
                continue
    return out
