"""
System model for ``axiom threatmodel``.

A :class:`SystemModel` is a small, deterministic description of an agentic
system: components (agent hosts, MCP servers and their tools/resources/prompts,
credentials, data stores, external services, remote agents), the data flows
between them, the trust boundaries those flows cross, the assets worth
protecting and every assumption made while building it.

Builders
--------
* :func:`from_scan` - the dict returned by ``MCPAnalysisEngine.scan()`` /
  ``POST /scan`` (ScanResponse shape) or the reduced ``axiom scan -o json``
  output.
* :func:`from_discovery` - a ``DiscoveryResult`` (or its JSON dict) from
  ``axiom discover``.
* :func:`from_a2a` - an A2A agent card scan result (``A2AScanResult``) or the
  duck-typed dict documented on :func:`from_a2a`.
* :func:`merge` - combine several models into one.

Everything is ordered and every id is derived from names, so the same input
always yields the same model. No secret values are ever read: credentials are
modelled from environment variable *names* only.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
from enum import Enum
from typing import Any, Dict, Iterable, List, Literal, Optional, Set, Tuple
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

SCHEMA_VERSION = "0.5"

ComponentKind = Literal[
    "agent_host", "mcp_server", "tool", "resource", "prompt", "data_store",
    "credential", "external_service", "remote_agent",
]
DataClass = Literal[
    "user_prompt", "tool_arguments", "tool_results", "secrets", "files",
    "external_content", "delegation",
]
SourceKind = Literal["scan", "discover", "a2a"]

TRUST_ZONES: Dict[str, str] = {
    "local_machine": "Local machine (user trust)",
    "third_party": "Third-party code on the local machine",
    "remote_server": "Remote servers and peer agents",
    "internet": "Internet (external content and recipients)",
}
ZONE_ORDER = list(TRUST_ZONES)
SOURCE_ORDER = ["scan", "discover", "a2a"]


# ============================================================
# Models
# ============================================================

class Component(BaseModel):
    id: str
    name: str
    kind: ComponentKind
    trust_zone: str = "local_machine"
    attributes: Dict[str, Any] = Field(default_factory=dict)


class DataFlow(BaseModel):
    id: str
    src: str
    dst: str
    data_class: DataClass
    crosses_boundary: bool = False


class TrustBoundary(BaseModel):
    id: str
    name: str
    inside: List[str] = Field(default_factory=list)
    outside: List[str] = Field(default_factory=list)


class Asset(BaseModel):
    id: str
    name: str
    kind: str
    components: List[str] = Field(default_factory=list)


class Assumption(BaseModel):
    id: str
    text: str
    basis: Literal["inferred", "default"] = "inferred"


class EvidenceFinding(BaseModel):
    """A finding from a source scan, attached to the components it concerns."""
    id: str
    title: str
    severity: str = "info"
    category: str = "metadata"
    owasp_asi: List[str] = Field(default_factory=list)
    owasp_mcp: List[str] = Field(default_factory=list)
    components: List[str] = Field(default_factory=list)
    source: SourceKind = "scan"


class SystemModel(BaseModel):
    components: List[Component] = Field(default_factory=list)
    flows: List[DataFlow] = Field(default_factory=list)
    boundaries: List[TrustBoundary] = Field(default_factory=list)
    assets: List[Asset] = Field(default_factory=list)
    assumptions: List[Assumption] = Field(default_factory=list)
    evidence: List[EvidenceFinding] = Field(default_factory=list)
    sources: List[SourceKind] = Field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def component(self, cid: str) -> Optional[Component]:
        for c in self.components:
            if c.id == cid:
                return c
        return None

    def by_kind(self, kind: str) -> List[Component]:
        return [c for c in self.components if c.kind == kind]


# ============================================================
# Helpers
# ============================================================

def slug(s: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s or "").lower()).strip("_") or "x"


def _short_hash(s: str, n: int = 8) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:n]


def to_plain(obj: Any) -> Any:
    """Recursively convert Pydantic models / enums into plain JSON-able values."""
    if isinstance(obj, BaseModel):
        return to_plain(obj.model_dump(mode="json"))
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return to_plain(dataclasses.asdict(obj))
    if isinstance(obj, dict):
        return {str(k): to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_plain(v) for v in obj]
    return obj


def name_tokens(name: str) -> Set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return {t.lower() for t in re.split(r"[^A-Za-z0-9]+", spaced) if t}


_LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_SECRET_WORDS = ("key", "token", "secret", "passw", "pwd", "auth", "credential",
                 "signature", "session", "cookie", "bearer", "pat")
_AUTH_HEADER_WORDS = ("authorization", "auth", "token", "api-key", "apikey", "x-api-key", "cookie", "key")


def is_secret_name(name: str) -> bool:
    low = (name or "").lower()
    if low.endswith("_pat") or low.startswith("pat_"):
        return True
    return any(w in low for w in _SECRET_WORDS if w != "pat")


def _url_parts(url: Optional[str]) -> Tuple[str, str]:
    try:
        p = urlsplit(url or "")
        return (p.scheme or "").lower(), (p.hostname or "").lower()
    except ValueError:
        return "", ""


# ============================================================
# Capability inference (small keyword table)
# ============================================================

#: For each capability: name tokens that imply it, tokens that only count when
#: none of their "guard" tokens are present, verb+object token pairs, and
#: description phrases. First match wins and becomes the recorded reason.
CAPABILITY_TABLE: Dict[str, Dict[str, Any]] = {
    "reads_external": {
        "tokens": ["fetch", "http", "https", "web", "webpage", "website", "url", "browse",
                   "browser", "scrape", "crawl", "download", "search", "ticket", "tickets",
                   "issue", "issues", "rss", "feed", "inbox"],
        "guarded": {"email": ["send", "reply", "forward", "post", "compose", "draft"],
                    "emails": ["send", "reply", "forward", "post", "compose", "draft"],
                    "mail": ["send", "reply", "forward", "post", "compose", "draft"]},
        "pairs": [(["read", "get", "open", "load", "cat"], ["file", "files", "document", "documents"])],
        "phrases": [r"\bfetch(?:es|ing)?\b", r"\bweb ?pages?\b", r"\bwebsites?\b", r"\burls?\b",
                    r"\breads? (?:e-?mails?|mail|the inbox)\b", r"\bsearch(?:es)? the (?:web|internet)\b",
                    r"\b(?:tickets?|issues?) from\b", r"\breads? (?:a |the )?files?\b"],
    },
    "sends_out": {
        "tokens": ["send", "post", "upload", "publish", "webhook", "notify", "tweet", "forward",
                   "reply", "sms", "share", "submit"],
        "guarded": {},
        "pairs": [],
        "phrases": [r"\bsends?\b", r"\bhttp post\b", r"\bpost(?:s)? (?:a |the )?(?:request|message|data)\b",
                    r"\bwebhooks?\b", r"\buploads?\b", r"\bpublish(?:es)?\b"],
    },
    "writes": {
        "tokens": ["write", "create", "delete", "update", "modify", "remove", "insert", "edit",
                   "put", "drop", "move", "rename", "append", "patch", "overwrite", "commit"],
        "guarded": {},
        "pairs": [],
        "phrases": [r"\b(?:writes?|creates?|deletes?|updates?|modif(?:y|ies)|removes?|overwrites?)\b"],
    },
    "executes": {
        "tokens": ["exec", "execute", "run", "shell", "command", "cmd", "eval", "script", "spawn",
                   "bash", "terminal", "subprocess", "powershell"],
        "guarded": {"code": ["search", "review", "read", "get", "list", "format", "lint", "explain"]},
        "pairs": [],
        "phrases": [r"\b(?:executes?|runs?) (?:a |the |arbitrary )?(?:shell |system )?(?:commands?|code|scripts?)\b",
                    r"\beval(?:uates?)? (?:python|javascript|js|code)\b"],
    },
}

CAPABILITY_TEXT = {
    "reads_external": "read external or untrusted content",
    "sends_out": "send data to external recipients",
    "writes": "create, modify or delete data",
    "executes": "execute commands or code",
}

_FILE_TOKENS = {"file", "files", "dir", "directory", "directories", "folder", "path", "fs", "filesystem"}
_BROAD_TOKENS = {"dump", "dumpall", "export", "listall", "everything"}


def infer_capabilities(name: str, description: str = "") -> Dict[str, str]:
    """Return {capability: reason} for a tool/skill name and description."""
    tokens = name_tokens(name)
    desc = (description or "").lower()
    found: Dict[str, str] = {}
    for cap, spec in CAPABILITY_TABLE.items():
        reason = None
        for tok in spec["tokens"]:
            if tok in tokens:
                reason = f"name token '{tok}'"
                break
        if reason is None:
            for tok, guards in spec["guarded"].items():
                if tok in tokens and not (tokens & set(guards)):
                    reason = f"name token '{tok}'"
                    break
        if reason is None:
            for verbs, objs in spec["pairs"]:
                v = sorted(tokens & set(verbs))
                o = sorted(tokens & set(objs))
                if v and o:
                    reason = f"name tokens '{v[0]}' + '{o[0]}'"
                    break
        if reason is None and desc:
            for pat in spec["phrases"]:
                m = re.search(pat, desc)
                if m:
                    reason = f"description phrase '{m.group(0)}'"
                    break
        if reason:
            found[cap] = reason
    return found


# ============================================================
# Model construction
# ============================================================

class _Builder:
    def __init__(self, source: str):
        self.source = source
        self.components: Dict[str, Component] = {}
        self.flows: Dict[str, DataFlow] = {}
        self.assumptions: Dict[str, Assumption] = {}
        self.evidence: List[EvidenceFinding] = []

    def add(self, cid: str, name: str, kind: str, zone: str, **attrs: Any) -> Component:
        if cid in self.components:
            comp = self.components[cid]
            _merge_attrs(comp.attributes, attrs)
            return comp
        comp = Component(id=cid, name=name, kind=kind, trust_zone=zone, attributes=dict(attrs))
        self.components[cid] = comp
        return comp

    def flow(self, src: str, dst: str, data_class: str) -> None:
        fid = f"flow_{src}__{dst}__{data_class}"
        self.flows.setdefault(fid, DataFlow(id=fid, src=src, dst=dst, data_class=data_class))

    def assume(self, text: str, basis: str = "inferred") -> None:
        aid = "A-" + _short_hash(text)
        self.assumptions.setdefault(aid, Assumption(id=aid, text=text, basis=basis))

    def build(self) -> SystemModel:
        model = SystemModel(
            components=list(self.components.values()),
            flows=list(self.flows.values()),
            assumptions=list(self.assumptions.values()),
            evidence=self.evidence,
            sources=[self.source],
        )
        return finalize(model)


def _merge_attrs(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    for k, v in src.items():
        if k not in dst or dst[k] in (None, "", [], {}):
            dst[k] = v
        elif isinstance(dst[k], list) and isinstance(v, list):
            dst[k] = sorted(set(map(str, dst[k])) | set(map(str, v)))
        elif isinstance(dst[k], bool) and isinstance(v, bool):
            dst[k] = dst[k] or v


def _add_tool_like(b: _Builder, server_id: str, server_name: str, zone: str, kind: str,
                   name: str, description: str, prefix: str) -> Component:
    cid = f"{prefix}_{server_id[4:] if server_id.startswith('srv_') else server_id}_{slug(name)}"
    caps = infer_capabilities(name, description) if kind == "tool" else {}
    attrs: Dict[str, Any] = {"server": server_id}
    if kind == "tool":
        attrs.update({
            "capabilities": sorted(caps),
            "capability_reasons": {k: caps[k] for k in sorted(caps)},
            "human_approved": False,
            "approval": "autonomous",
        })
        for cap in CAPABILITY_TABLE:
            attrs[cap] = cap in caps
        for cap in sorted(caps):
            b.assume(f"Tool '{name}' on server '{server_name}' is assumed to {CAPABILITY_TEXT[cap]} "
                     f"({caps[cap]}).")
    toks = name_tokens(name)
    if kind in ("tool", "resource") and (toks & _BROAD_TOKENS or ("all" in toks and toks & {"list", "get", "dump", "export"})):
        attrs["broad_exposure"] = True
        b.assume(f"{kind.capitalize()} '{name}' on server '{server_name}' is assumed to return bulk "
                 "data into the model context (name suggests list-all/dump/export).")
    if kind == "tool" and toks & _FILE_TOKENS:
        attrs["touches_files"] = True
    return b.add(cid, name, kind, zone, **attrs)


def _wire_tool(b: _Builder, tool: Component) -> None:
    """Connect a tool to the internet / local files according to its capabilities."""
    a = tool.attributes
    if a.get("reads_external") or a.get("sends_out"):
        b.add("ext_internet", "Internet (web, email, tickets, remote APIs)", "external_service", "internet")
        if a.get("reads_external"):
            b.flow("ext_internet", tool.id, "external_content")
        if a.get("sends_out"):
            b.flow(tool.id, "ext_internet", "tool_arguments")
    if a.get("touches_files"):
        b.add("ds_local_files", "Local files", "data_store", "local_machine")
        if a.get("writes"):
            b.flow(tool.id, "ds_local_files", "files")
        else:
            b.flow("ds_local_files", tool.id, "files")


def _norm_findings(raw: Iterable[Any]) -> List[Dict[str, Any]]:
    out = []
    for i, f in enumerate(raw or []):
        d = to_plain(f)
        if not isinstance(d, dict):
            continue
        title = str(d.get("title") or "untitled finding")
        out.append({
            "id": str(d.get("id") or f"finding_{slug(title)[:40]}_{i}"),
            "title": title,
            "description": str(d.get("description") or ""),
            "severity": str(d.get("severity") or "info").lower(),
            "category": str(d.get("category") or "metadata").lower(),
            "owasp_asi": sorted(d.get("owasp_asi") or []),
            "owasp_mcp": sorted(d.get("owasp_mcp") or []),
        })
    return out


def _mentions(finding: Dict[str, Any], name: str) -> bool:
    if not name:
        return False
    fid = finding["id"].lower()
    s = slug(name)
    if fid.endswith("_" + s) or f"_{s}_" in fid:
        return True
    text = f"{finding['title']}\n{finding['description']}"
    for q in (f"'{name}'", f'"{name}"', f"`{name}`"):
        if q in text:
            return True
    if re.search(r"[_\-]", name) or re.search(r"[a-z][A-Z]", name):
        if re.search(r"(?<![A-Za-z0-9_\-])" + re.escape(name) + r"(?![A-Za-z0-9_\-])", text):
            return True
    return False


def _attach(b: _Builder, findings: List[Dict[str, Any]], candidates: List[Component],
            fallback: List[str]) -> None:
    """Attach each finding to the candidate components it names, else to ``fallback``."""
    for f in findings:
        hits = sorted({c.id for c in candidates if _mentions(f, c.name)})
        comps = hits or sorted(fallback)
        b.evidence.append(EvidenceFinding(
            id=f["id"], title=f["title"], severity=f["severity"], category=f["category"],
            owasp_asi=f["owasp_asi"], owasp_mcp=f["owasp_mcp"], components=comps, source=b.source,
        ))


# ------------------------------------------------------------
# from_scan
# ------------------------------------------------------------

def from_scan(scan: Any) -> SystemModel:
    """Build a model from a static scan result (engine dict, ScanResponse or CLI JSON)."""
    data = to_plain(scan) or {}
    b = _Builder("scan")
    profile = data.get("server_profile") or {}
    target = str(data.get("target") or profile.get("name") or "scanned-server")
    server_name = str(profile.get("name") or target)
    sid = f"srv_{slug(server_name)}"
    findings = _norm_findings(data.get("findings"))
    fids = {f["id"] for f in findings}

    transport = str(profile.get("transport") or "unknown").lower()
    remote = transport in ("sse", "http")
    zone = "remote_server" if remote else "third_party"
    attrs: Dict[str, Any] = {
        "transport": transport,
        "scanned": True,
        "risk_level": str(data.get("risk_level") or ""),
        "risk_score": data.get("risk_score"),
    }
    pkg = profile.get("npm_package")
    pinfo = data.get("package_info")
    if isinstance(pinfo, dict) and pinfo.get("name"):
        pkg = pkg or pinfo.get("name")
    if pkg:
        attrs["package"] = str(pkg)
    if data.get("target_url") or profile.get("repo_url"):
        attrs["repo_url"] = str(data.get("target_url") or profile.get("repo_url"))
    if remote:
        attrs["remote"] = True
        attrs["authenticated"] = "transport_no_auth" not in fids
        b.assume(f"Server '{server_name}' uses {transport} transport and is assumed to run on a remote host.")
        b.assume(f"Server '{server_name}' is assumed to {'lack' if not attrs['authenticated'] else 'have'} "
                 "authentication, based on the static transport check.")
    else:
        b.assume(f"Server '{server_name}' is assumed to be third-party code launched locally over "
                 f"{'stdio' if transport == 'stdio' else 'an unknown transport'} by the agent host.",
                 basis="default")
    if "transport_plain_http" in fids:
        attrs["plain_http"] = True
    b.add(sid, server_name, "mcp_server", zone, **attrs)

    b.add("host_agent", "Agent host (MCP client)", "agent_host", "local_machine", generic=True)
    b.assume("The scanned server is assumed to be connected to one agent host (MCP client) on the "
             "local machine.", basis="default")
    b.assume("No human approval step is assumed for tool calls (tools run autonomously).", basis="default")
    b.flow("host_agent", sid, "tool_arguments")
    b.flow(sid, "host_agent", "tool_results")

    tool_comps: List[Component] = []
    for t in sorted(profile.get("tools") or [], key=lambda t: str(t.get("name"))):
        comp = _add_tool_like(b, sid, server_name, zone, "tool", str(t.get("name") or "tool"),
                              str(t.get("description") or ""), "tool")
        if t.get("has_hidden_instructions"):
            comp.attributes["hidden_instructions"] = True
        tool_comps.append(comp)
    for r in sorted(profile.get("resources") or [], key=lambda r: str(r.get("name") or r.get("uri"))):
        tool_comps.append(_add_tool_like(b, sid, server_name, zone, "resource",
                                         str(r.get("name") or r.get("uri") or "resource"),
                                         str(r.get("description") or ""), "res"))
    for p in sorted(profile.get("prompts") or [], key=lambda p: str(p.get("name"))):
        tool_comps.append(_add_tool_like(b, sid, server_name, zone, "prompt", str(p.get("name") or "prompt"),
                                         str(p.get("description") or ""), "prompt"))

    for f in findings:
        if f["category"] == "context_oversharing":
            for c in tool_comps:
                if c.kind in ("tool", "resource") and _mentions(f, c.name):
                    c.attributes["broad_exposure"] = True
    for c in tool_comps:
        if c.kind == "tool":
            _wire_tool(b, c)

    creds = sorted({e for e in (profile.get("env_vars") or []) if is_secret_name(str(e))})
    for env in creds:
        cid = f"cred_{slug(env)}"
        b.add(cid, env, "credential", "local_machine", env_var=True)
        b.flow(cid, sid, "secrets")
        b.assume(f"Environment variable '{env}' read by '{server_name}' is assumed to hold a credential "
                 "(name-based; values are never read).")

    _attach(b, findings, tool_comps, [sid])
    return b.build()


# ------------------------------------------------------------
# from_discovery
# ------------------------------------------------------------

def _server_group_key(s: Dict[str, Any]) -> str:
    return str(s.get("package") or s.get("url") or s.get("command") or "")


def from_discovery(result: Any) -> SystemModel:
    """Build a model from ``axiom discover`` output (DiscoveryResult or its dict)."""
    data = to_plain(result) or {}
    b = _Builder("discover")
    servers = [s for s in (data.get("servers") or []) if isinstance(s, dict)]
    findings = _norm_findings(data.get("findings"))

    # Same server name + same package/url/command across clients = one component.
    by_name: Dict[str, Set[str]] = {}
    for s in servers:
        by_name.setdefault(slug(s.get("server_name")), set()).add(_server_group_key(s))

    def server_id(s: Dict[str, Any]) -> str:
        base = slug(s.get("server_name"))
        if len(by_name.get(base, ())) > 1:
            return f"srv_{base}_{_short_hash(_server_group_key(s), 6)}"
        return f"srv_{base}"

    cred_users: Dict[str, Set[str]] = {}
    server_comps: List[Component] = []
    for s in sorted(servers, key=lambda s: (str(s.get("server_name")), str(s.get("client")),
                                            str(s.get("config_path")))):
        name = str(s.get("server_name") or "server")
        client = str(s.get("client") or "unknown client")
        if s.get("disabled"):
            b.assume(f"Server '{name}' in {client} is disabled and was left out of the model.")
            continue
        sid = server_id(s)
        hid = f"host_{slug(client)}"
        b.add(hid, client, "agent_host", "local_machine", client=client)

        source = str(s.get("install_source") or "unknown")
        transport = str(s.get("transport") or "stdio")
        url = s.get("url")
        scheme, host = _url_parts(url)
        attrs: Dict[str, Any] = {
            "transport": transport if transport != "remote" else str(s.get("remote_type") or "remote"),
            "install_source": source,
            "classification": str(s.get("classification") or "unchecked"),
            "clients": [client],
        }
        if s.get("package"):
            attrs["package"] = str(s["package"])
        if s.get("version_pin"):
            attrs["version_pin"] = str(s["version_pin"])
        if s.get("command"):
            attrs["command"] = str(s["command"])
        if url:
            attrs["url"] = str(url)
            attrs["scheme"] = scheme
        if s.get("config_path"):
            attrs["config_paths"] = [str(s["config_path"])]
        env_names = [str(e) for e in (s.get("env_var_names") or [])]
        attrs["env_var_count"] = len(env_names)

        if source == "remote_url":
            zone = "local_machine" if host in _LOOPBACK else "remote_server"
            auth_headers = [h for h in (s.get("header_names") or [])
                            if any(w in str(h).lower() for w in _AUTH_HEADER_WORDS)]
            auth_env = [e for e in env_names if is_secret_name(e)]
            authenticated = bool(auth_headers or auth_env or "[REDACTED]" in str(url or ""))
            attrs["remote"] = True
            attrs["authenticated"] = authenticated
            if authenticated:
                why = ("auth header " + repr(sorted(auth_headers)[0])) if auth_headers else (
                    "credential env var" if auth_env else "credential in URL")
                b.assume(f"Remote server '{name}' is assumed to authenticate the client ({why}).")
            else:
                b.assume(f"Remote server '{name}' has no visible authentication in its client config "
                         "and is assumed to be unauthenticated.")
            if scheme == "http" and host not in _LOOPBACK:
                attrs["plain_http"] = True
        elif source in ("npm", "pypi", "container"):
            zone = "third_party"
            if not s.get("version_pin"):
                attrs["unpinned"] = True
                b.assume(f"Server '{name}' is installed from {source} without a version pin and is "
                         "assumed to pick up whatever version the registry serves at launch.")
        elif source == "local_path":
            zone = "local_machine"
            b.assume(f"Server '{name}' runs from a local path and is assumed to be locally maintained code.",
                     basis="default")
        else:
            zone = "third_party"
            b.assume(f"Server '{name}' has an unknown install source and is treated as third-party code.",
                     basis="default")
        if attrs["classification"] == "unapproved":
            attrs["unapproved"] = True

        comp = b.add(sid, name, "mcp_server", zone, **attrs)
        server_comps.append(comp)
        b.flow(hid, sid, "tool_arguments")
        b.flow(sid, hid, "tool_results")
        for env in env_names:
            if is_secret_name(env):
                cred_users.setdefault(env, set()).add(sid)

    for env in sorted(cred_users):
        cid = f"cred_{slug(env)}"
        users = sorted(cred_users[env])
        b.add(cid, env, "credential", "local_machine", env_var=True, used_by=users,
              shared=len(users) > 1)
        for sid in users:
            b.flow(cid, sid, "secrets")
        if len(users) > 1:
            names = ", ".join(sorted(b.components[u].name for u in users))
            b.assume(f"Environment variable '{env}' configured for {names} is assumed to hold the "
                     "same credential (values are never read).")
        else:
            b.assume(f"Environment variable '{env}' is assumed to hold a credential (name-based; values "
                     "are never read).")

    if servers:
        b.assume("No human approval step is assumed for tool calls (tools run autonomously).", basis="default")
    hosts = sorted(c.id for c in b.components.values() if c.kind == "agent_host")
    _attach(b, findings, server_comps, hosts[:1] if hosts else [])
    return b.build()


# ------------------------------------------------------------
# from_a2a
# ------------------------------------------------------------

_DANGEROUS_CAPS = ("executes", "writes", "sends_out")


_RAW_CARD_KEYS = ("securitySchemes", "supportedInterfaces", "protocolVersion", "capabilities",
                  "defaultInputModes", "securityRequirements", "security", "signatures", "url")


def _a2a_view(result: Any) -> Dict[str, Any]:
    """Normalise A2A input into one flat shape. Three inputs are accepted:

    1. ``A2AScanResult`` (app/analysis/a2a_scanner.py) or its JSON dump - the
       real integration: card summary + scanner findings.
    2. A raw A2A agent card (dict with securitySchemes / supportedInterfaces /
       capabilities / url ...) - analysed offline with
       ``a2a_scanner.analyze_card(card, fetch=None)`` (no network).
    3. The duck-typed shape, used as-is::

        {"name": str, "provider": str, "version": str,
         "skills": [{"id", "name", "description"}],
         "signed": bool, "has_auth": bool,
         "interface_urls": [str], "findings": [Finding-like dicts]}
    """
    d = to_plain(result) or {}
    if "card" in d and ("findings" in d or "source" in d):
        return _from_a2a_scan_result(d)
    if "signed" not in d and "has_auth" not in d and any(k in d for k in _RAW_CARD_KEYS):
        return _from_raw_card(d)
    return d


def _from_raw_card(card: Dict[str, Any]) -> Dict[str, Any]:
    from app.analysis.a2a_scanner import analyze_card  # local import: optional workstream
    findings, summary, _proto = analyze_card(card, card_url=None, discovery_path="file", fetch=None)
    view = _from_a2a_scan_result({"card": to_plain(summary), "findings": to_plain(findings)})
    raw_skills = [s for s in (card.get("skills") or []) if isinstance(s, dict)]
    if raw_skills:
        view["skills"] = [{"id": str(s.get("id") or s.get("name") or i), "name": str(s.get("name") or ""),
                           "description": str(s.get("description") or "")} for i, s in enumerate(raw_skills)]
    return view


def _from_a2a_scan_result(d: Dict[str, Any]) -> Dict[str, Any]:
    card = d.get("card") or {}
    findings = [f for f in (d.get("findings") or []) if isinstance(f, dict)]
    fids = [str(f.get("id") or "") for f in findings]
    dangerous = {}
    for f in findings:
        fid = str(f.get("id") or "")
        if fid.startswith("a2a-skill-dangerous-noauth:"):
            dangerous[fid.split(":", 1)[1]] = f"scanner finding '{f.get('title')}'"
    _scheme, host = _url_parts(d.get("final_url") or d.get("source"))
    return {
        "name": card.get("name") or host or "remote-agent",
        "provider": card.get("provider_organization") or "",
        "version": card.get("version") or "",
        "skills": [{"id": s, "name": s} for s in (card.get("skill_ids") or [])],
        # A signature that failed verification gives no more assurance than none.
        "signed": bool(card.get("signed")) and card.get("signature_verified") is not False,
        "has_auth": bool(card.get("scheme_names")) and "a2a-auth-missing" not in fids,
        "interface_urls": sorted({str(u) for u in (card.get("interfaces") or []) if u}),
        "findings": findings,
        "dangerous_skills": sorted(dangerous),
        "dangerous_skill_reasons": dangerous,
    }


def from_a2a(result: Any) -> SystemModel:
    """Build a model from an A2A agent card scan (A2AScanResult or duck-typed dict)."""
    v = _a2a_view(result)
    b = _Builder("a2a")
    name = str(v.get("name") or "remote-agent")
    rid = f"ra_{slug(name)}"
    skills = []
    dangerous = []
    dangerous_reasons: Dict[str, str] = {}
    for sk in v.get("skills") or []:
        sk = to_plain(sk)
        if isinstance(sk, str):
            sk = {"id": sk, "name": sk}
        sid = str(sk.get("id") or sk.get("name") or "skill")
        sname = str(sk.get("name") or sid)
        skills.append(sid)
        caps = infer_capabilities(f"{sid} {sname}", str(sk.get("description") or ""))
        bad = sorted(c for c in caps if c in _DANGEROUS_CAPS)
        if bad:
            dangerous.append(sid)
            dangerous_reasons[sid] = "; ".join(f"{CAPABILITY_TEXT[c]} ({caps[c]})" for c in bad)
            for c in bad:
                b.assume(f"Skill '{sid}' of remote agent '{name}' is assumed to {CAPABILITY_TEXT[c]} "
                         f"({caps[c]}).")
    for sid, why in sorted((v.get("dangerous_skill_reasons") or {}).items()):
        if sid not in dangerous:
            dangerous.append(sid)
        dangerous_reasons[sid] = "; ".join(x for x in (dangerous_reasons.get(sid), str(why)) if x)
        b.assume(f"Skill '{sid}' of remote agent '{name}' is treated as high-impact ({why}).")
    urls = sorted({str(u) for u in (v.get("interface_urls") or []) if u})
    schemes = sorted({_url_parts(u)[0] for u in urls if _url_parts(u)[0]})
    plain_http = any(_url_parts(u)[0] == "http" and _url_parts(u)[1] not in _LOOPBACK for u in urls)
    attrs: Dict[str, Any] = {
        "provider": str(v.get("provider") or ""),
        "skills": sorted(skills),
        "dangerous_skills": sorted(dangerous),
        "dangerous_skill_reasons": {k: dangerous_reasons[k] for k in sorted(dangerous_reasons)},
        "signed": bool(v.get("signed")),
        "has_auth": bool(v.get("has_auth")),
        "interface_schemes": schemes,
        "remote": True,
    }
    if v.get("version"):
        attrs["version"] = str(v["version"])
    if plain_http:
        attrs["plain_http"] = True
    b.add(rid, name, "remote_agent", "remote_server", **attrs)
    b.add("host_agent", "Agent host (MCP client)", "agent_host", "local_machine", generic=True)
    b.flow("host_agent", rid, "delegation")
    b.flow(rid, "host_agent", "external_content")
    b.assume(f"Remote agent '{name}' is assumed to be reached over the network by a local agent host "
             "that delegates tasks to it and consumes its output.", basis="default")
    b.assume(f"Remote agent '{name}' card is {'signed' if attrs['signed'] else 'not signed'} and "
             f"{'declares' if attrs['has_auth'] else 'declares no'} authentication scheme.")
    _attach(b, _norm_findings(v.get("findings")), [], [rid])
    return b.build()


# ============================================================
# merge / finalize
# ============================================================

def merge(models: List[SystemModel]) -> SystemModel:
    """Merge several models. Components with the same id (or MCP servers with the
    same package) become one; flows, assumptions and evidence are unioned."""
    comps: Dict[str, Component] = {}
    remap: Dict[str, str] = {}
    pkg_owner: Dict[str, str] = {}
    flows: Dict[str, DataFlow] = {}
    assumptions: Dict[str, Assumption] = {}
    evidence: Dict[Tuple[str, str, str], EvidenceFinding] = {}
    sources: Set[str] = set()

    ordered = sorted(models, key=lambda m: min((SOURCE_ORDER.index(s) for s in m.sources), default=9))
    for m in ordered:
        sources.update(m.sources)
        for c in m.components:
            cid = c.id
            pkg = c.attributes.get("package") if c.kind == "mcp_server" else None
            if pkg and cid not in comps and pkg in pkg_owner:
                remap[cid] = pkg_owner[pkg]
                cid = pkg_owner[pkg]
            if cid in comps:
                _merge_attrs(comps[cid].attributes, dict(c.attributes))
            else:
                comps[cid] = c.model_copy(deep=True)
                if pkg:
                    pkg_owner.setdefault(pkg, cid)
        for a in m.assumptions:
            assumptions.setdefault(a.id, a)
    for m in ordered:
        for f in m.flows:
            src, dst = remap.get(f.src, f.src), remap.get(f.dst, f.dst)
            fid = f"flow_{src}__{dst}__{f.data_class}"
            flows.setdefault(fid, DataFlow(id=fid, src=src, dst=dst, data_class=f.data_class))
        for e in m.evidence:
            e2 = e.model_copy(deep=True)
            e2.components = sorted({remap.get(c, c) for c in e.components})
            evidence.setdefault((e2.id, ",".join(e2.components), e2.source), e2)
    for c in comps.values():
        if c.attributes.get("server") in remap:
            c.attributes["server"] = remap[c.attributes["server"]]

    # Drop the generic host's flows to servers that a real (client) host already uses.
    real_hosts = {cid for cid, c in comps.items() if c.kind == "agent_host" and not c.attributes.get("generic")}
    if real_hosts and "host_agent" in comps:
        served = {f.dst for f in flows.values() if f.src in real_hosts}
        for fid in [fid for fid, f in flows.items()
                    if (f.src == "host_agent" and f.dst in served) or (f.dst == "host_agent" and f.src in served)]:
            del flows[fid]
        if not any("host_agent" in (f.src, f.dst) for f in flows.values()):
            del comps["host_agent"]
            for e in evidence.values():
                if "host_agent" in e.components:
                    e.components = sorted(real_hosts)[:1] if e.components == ["host_agent"] else \
                        [c for c in e.components if c != "host_agent"]

    model = SystemModel(
        components=list(comps.values()),
        flows=list(flows.values()),
        assumptions=list(assumptions.values()),
        evidence=list(evidence.values()),
        sources=sorted(sources, key=SOURCE_ORDER.index),
    )
    return finalize(model)


def _sort_attr_values(attrs: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k in sorted(attrs):
        v = attrs[k]
        if isinstance(v, (list, set, tuple)):
            v = sorted({str(x) for x in v})
        out[k] = v
    return out


def finalize(model: SystemModel) -> SystemModel:
    """Sort everything, compute boundary crossings, trust boundaries and assets."""
    comps = sorted(model.components, key=lambda c: c.id)
    for c in comps:
        c.attributes = _sort_attr_values(c.attributes)
    zone_of = {c.id: c.trust_zone for c in comps}
    flows = []
    for f in sorted(model.flows, key=lambda f: f.id):
        if f.src not in zone_of or f.dst not in zone_of:
            continue
        f.crosses_boundary = zone_of[f.src] != zone_of[f.dst]
        flows.append(f)

    all_ids = [c.id for c in comps]
    zones = sorted({c.trust_zone for c in comps},
                   key=lambda z: (ZONE_ORDER.index(z) if z in ZONE_ORDER else 99, z))
    boundaries = []
    for z in zones:
        inside = [cid for cid in all_ids if zone_of[cid] == z]
        boundaries.append(TrustBoundary(
            id=f"tb_{slug(z)}", name=TRUST_ZONES.get(z, z), inside=inside,
            outside=[cid for cid in all_ids if zone_of[cid] != z],
        ))

    def ids(pred) -> List[str]:
        return [c.id for c in comps if pred(c)]

    assets = []
    for aid, name, kind, members in (
        ("asset_credentials", "Credentials and API tokens", "secret", ids(lambda c: c.kind == "credential")),
        ("asset_user_context", "User conversation context and prompts", "data",
         ids(lambda c: c.kind == "agent_host")),
        ("asset_local_files", "Local files", "data", ids(lambda c: c.kind == "data_store")),
        ("asset_tool_actions", "Actions taken through write/execute/send tools", "capability",
         ids(lambda c: c.kind == "tool" and any(c.attributes.get(k) for k in ("writes", "executes", "sends_out")))),
        ("asset_delegated_tasks", "Tasks and data delegated to peer agents", "data",
         ids(lambda c: c.kind == "remote_agent")),
    ):
        if members:
            assets.append(Asset(id=aid, name=name, kind=kind, components=members))

    evidence = sorted(model.evidence, key=lambda e: (e.id, e.components, e.source))
    for e in evidence:
        e.components = sorted(set(e.components))
        e.owasp_asi = sorted(set(e.owasp_asi))
        e.owasp_mcp = sorted(set(e.owasp_mcp))

    return SystemModel(
        components=comps,
        flows=flows,
        boundaries=boundaries,
        assets=assets,
        assumptions=sorted(model.assumptions, key=lambda a: (a.text, a.id)),
        evidence=evidence,
        sources=sorted(set(model.sources), key=lambda s: SOURCE_ORDER.index(s) if s in SOURCE_ORDER else 9),
        schema_version=SCHEMA_VERSION,
    )
