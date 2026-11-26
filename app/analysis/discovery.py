"""
Shadow MCP discovery (``axiom discover``).

Builds an inventory of every MCP server configured in the local MCP clients
(Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Cline, Zed, Gemini
CLI, Continue, project-level files and any extra paths), classifies each one
against an optional allowlist, and raises one finding per unapproved
("shadow") server (OWASP ASI04 / MCP09).

Privacy guarantees
------------------
* Only local client configuration files are read. Nothing is sent anywhere
  unless the caller explicitly asks for a static scan (``run_static_scans``).
* Environment variable *values* are never copied into a record — only their
  names. Header values (remote servers) are treated the same way.
* Any argument, command or URL token that looks like a credential is replaced
  with ``[REDACTED]`` before it is stored: credential-like query parameters
  (key/token/secret/password/auth...), ``user:pass@`` userinfo, bearer tokens,
  values of ``--token``/``--api-key`` style flags, and well-known token shapes
  (sk-, ghp_/gho_/github_pat_, AKIA/ASIA, xox?-, glpat-, AIza...) or long
  high-entropy strings.
* Process enumeration (``include_processes=True``) is opt-in and local only.
  Port probing is not implemented (deferred).

Allowlist format
----------------
A JSON document (see ``data/approved_servers.example.json``)::

    {
      "version": 1,
      "servers": [
        {
          "name": "github",                                  # server name in the client config
          "install_source": "npm",                           # optional, informational
          "package": "@modelcontextprotocol/server-github",  # npm/PyPI package or container image
          "version": "2025.4.8",                             # optional exact pin required
          "url": "https://mcp.example.com/sse"               # optional, remote servers
        }
      ]
    }

A discovered server matches an entry when its package or (normalised) URL is
equal to the entry's, or when its name equals the entry's name and the entry
does not name a *different* package/URL than the one configured (so a server
called "github" that runs an unrelated package is still flagged). If the
matched entry pins ``version`` and the configured pin differs or is absent,
the server is classified ``unknown-version``. Unmatched servers are
``unapproved``. Without an allowlist every server is ``unchecked``.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field, PrivateAttr

from app.analysis.local_config import (
    MCP_CLIENT_LOCATIONS,
    LocalConfigScanner,
    current_platform_key,
    detect_transport,
    expand_config_path,
    extract_server_configs,
    load_json_tolerant,
)
from app.analysis.owasp_mapping import apply_owasp_mappings
from app.models.schemas import (
    Finding,
    FindingCategory,
    FindingSeverity,
    MCPConfigEntry,
    TransportType,
)

logger = logging.getLogger("axiom.discovery")

REDACTED = "[REDACTED]"

InstallSource = Literal["local_path", "npm", "pypi", "container", "remote_url", "unknown"]
Classification = Literal["approved", "unapproved", "unknown-version", "unchecked"]


# ============================================================
# Models
# ============================================================

class AllowlistEntry(BaseModel):
    name: Optional[str] = None
    install_source: Optional[str] = None
    package: Optional[str] = None
    version: Optional[str] = None
    url: Optional[str] = None


class Allowlist(BaseModel):
    version: int = 1
    servers: List[AllowlistEntry] = Field(default_factory=list)


class DiscoveredServer(BaseModel):
    """One MCP server entry found in a client configuration file (secrets redacted)."""
    client: str
    config_path: str
    server_name: str
    scope: Literal["user", "project", "custom"] = "user"
    project: Optional[str] = None
    transport: Literal["stdio", "remote"] = "stdio"
    remote_type: Optional[str] = None  # "sse" | "http" for remote servers
    command: Optional[str] = None
    args: List[str] = Field(default_factory=list)
    url: Optional[str] = None
    env_var_names: List[str] = Field(default_factory=list)
    header_names: List[str] = Field(default_factory=list)
    install_source: InstallSource = "unknown"
    package: Optional[str] = None
    version_pin: Optional[str] = None
    classification: Classification = "unchecked"
    allowlist_match: Optional[str] = None
    disabled: bool = False

    # Not serialised: normalised URL (scheme://host/path, no userinfo/query) for matching
    _match_url: Optional[str] = PrivateAttr(default=None)
    # Not serialised: env var name -> well-known token prefix ("ghp_", "sk-", ...) when the
    # configured value starts with one. Never holds any other part of the value.
    _env_token_prefixes: Dict[str, str] = PrivateAttr(default_factory=dict)


class DiscoveredProcess(BaseModel):
    pid: int
    name: str = ""
    cmdline: str = ""  # redacted and truncated
    indicator: str = ""
    matches_server: Optional[str] = None


class StaticScanSummary(BaseModel):
    server_name: str
    target: str
    status: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    findings: int = 0
    error: Optional[str] = None


class DiscoveryResult(BaseModel):
    discovery_version: int = 1
    generated_at: str = ""
    platform: str = ""
    config_files_scanned: List[str] = Field(default_factory=list)
    config_errors: List[str] = Field(default_factory=list)
    servers: List[DiscoveredServer] = Field(default_factory=list)
    processes: List[DiscoveredProcess] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    allowlist: Optional[str] = None  # path, "inline", or None
    summary: Dict[str, int] = Field(default_factory=dict)
    static_scans: List[StaticScanSummary] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)

    @property
    def unapproved(self) -> List[DiscoveredServer]:
        return [s for s in self.servers if s.classification == "unapproved"]


# ============================================================
# Redaction
# ============================================================

_SECRET_WORDS = ("key", "token", "secret", "passw", "pwd", "auth", "credential",
                 "signature", "session", "cookie", "bearer")


def _is_secret_name(name: str) -> bool:
    low = name.lower()
    return any(w in low for w in _SECRET_WORDS)


_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s\"'<>]+")
_KNOWN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"sk-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_\-]{12,}"
    r"|sk_(?:live|test)_[A-Za-z0-9]{12,}"
    r"|rk_(?:live|test)_[A-Za-z0-9]{12,}"
    r"|gh[pousr]_[A-Za-z0-9]{12,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|xox[abposre]-[A-Za-z0-9\-]{8,}"
    r"|glpat-[A-Za-z0-9_\-]{12,}"
    r"|AIza[0-9A-Za-z_\-]{30,}"
    r"|npm_[A-Za-z0-9]{30,}"
    r")"
)
_AUTH_SCHEME_RE = re.compile(r"(?i)\b(bearer|basic|token)(\s+)([A-Za-z0-9._~+/=\-]{6,})")
_HEADER_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|x-api-key|api-key|x-auth-token)(\s*[:=]\s*)"
    r"(?!\[REDACTED\]|(?:bearer|basic|token)\b)(\S+)"
)
_ASSIGN_RE = re.compile(r"^(-{0,2}[A-Za-z_][A-Za-z0-9_.\-]*)=(.+)$")
_FLAG_RE = re.compile(r"^-{1,2}[A-Za-z][A-Za-z0-9_.\-]*$")
_LONG_BLOB_RE = re.compile(r"(?<![A-Za-z0-9_\-+=])[A-Za-z0-9_\-+=]{32,}(?![A-Za-z0-9_\-+=])")


def _entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _redact_blob(m: re.Match) -> str:
    s = m.group(0)
    has_digit = any(c.isdigit() for c in s)
    has_alpha = any(c.isalpha() for c in s)
    if has_digit and has_alpha and _entropy(s) >= 3.5:
        return REDACTED
    return s


def _redact_query(q: str) -> str:
    if not q:
        return q
    parts = []
    for part in q.split("&"):
        name, sep, _val = part.partition("=")
        if sep and _is_secret_name(name):
            parts.append(f"{name}={REDACTED}")
        else:
            parts.append(part)
    return "&".join(parts)


def redact_url(url: str) -> str:
    """Redact userinfo and credential-like query/fragment parameters in a URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return REDACTED
    netloc = parts.netloc
    if "@" in netloc:
        netloc = f"{REDACTED}@{netloc.rsplit('@', 1)[1]}"
    rebuilt = urlunsplit((parts.scheme, netloc, parts.path,
                          _redact_query(parts.query), _redact_query(parts.fragment)))
    return rebuilt


def redact_text(text: Optional[str]) -> Optional[str]:
    """Redact anything credential-like inside a free-form string."""
    if not text:
        return text
    out = _URL_RE.sub(lambda m: redact_url(m.group(0)), text)
    out = _KNOWN_TOKEN_RE.sub(REDACTED, out)
    out = _AUTH_SCHEME_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", out)
    out = _HEADER_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", out)
    out = _LONG_BLOB_RE.sub(_redact_blob, out)
    return out


def redact_args(args: List[str]) -> List[str]:
    """Redact a command-line argument list.

    Besides token-shaped values, the value following a credential-named flag
    (``--api-key VALUE``) and the value of ``--token=VALUE`` / ``API_KEY=VALUE``
    are redacted.
    """
    out: List[str] = []
    redact_next = False
    for raw in args:
        arg = str(raw)
        if redact_next:
            redact_next = False
            if not arg.startswith("-"):
                out.append(REDACTED)
                continue
        m = _ASSIGN_RE.match(arg)
        if m and _is_secret_name(m.group(1)) and "://" not in m.group(1):
            out.append(f"{m.group(1)}={REDACTED}")
            continue
        if _FLAG_RE.match(arg) and _is_secret_name(arg):
            redact_next = True
            out.append(arg)
            continue
        out.append(redact_text(arg) or "")
    return out


def _normalise_url(url: Optional[str]) -> Optional[str]:
    """scheme://host[:port]/path without userinfo, query, fragment or trailing slash."""
    if not url:
        return None
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return None
    host = (p.hostname or "").lower()
    if p.port:
        host = f"{host}:{p.port}"
    return f"{p.scheme.lower()}://{host}{p.path.rstrip('/')}"


# ============================================================
# Install-source inference
# ============================================================

_NON_PINS = {"", "latest", "next", "*", "x"}


def _cmd_base(cmd: str) -> str:
    base = re.split(r"[\\/]", (cmd or "").strip())[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".ps1"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    return base


def _is_abs_path(p: str) -> bool:
    return bool(p) and (p.startswith(("/", "~", "\\\\")) or re.match(r"^[A-Za-z]:[\\/]", p) is not None)


def _is_path_like(p: str) -> bool:
    return _is_abs_path(p) or p.startswith((".", "./", ".\\")) or bool(
        re.search(r"\.(py|js|mjs|cjs|ts|jar|sh|rb|exe|dll)$", p, re.I)
    )


def _first_positional(args: List[str], value_flags: Tuple[str, ...]) -> Tuple[Optional[str], Dict[str, str]]:
    """Return the first non-flag argument and any values of ``value_flags``."""
    flags: Dict[str, str] = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            name, eq, val = a.partition("=")
            if name in value_flags:
                if eq:
                    flags[name] = val
                elif i + 1 < len(args):
                    flags[name] = args[i + 1]
                    i += 1
            i += 1
            continue
        return a, flags
    return None, flags


def _split_npm_spec(spec: str) -> Tuple[str, Optional[str]]:
    if spec.startswith("@"):
        scope_rest = spec[1:]
        if "@" in scope_rest:
            name, ver = scope_rest.rsplit("@", 1)
            return "@" + name, ver
        return spec, None
    if "@" in spec:
        name, ver = spec.split("@", 1)
        return name, ver
    return spec, None


def _split_pypi_spec(spec: str) -> Tuple[str, Optional[str]]:
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(==|@)\s*([^\s,;]+)$", spec)
    if m:
        return m.group(1), m.group(4)
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)", spec)
    return (m.group(1) if m else spec), None


def _split_image(spec: str) -> Tuple[str, Optional[str]]:
    if "@" in spec:
        name, digest = spec.split("@", 1)
        return name, digest
    last = spec.rsplit("/", 1)
    if ":" in last[-1]:
        name, tag = spec.rsplit(":", 1)
        return name, tag
    return spec, None


def _pin(ver: Optional[str]) -> Optional[str]:
    if ver is None or ver.strip().lower() in _NON_PINS:
        return None
    return ver.strip()


_NPX_VALUE_FLAGS = ("-p", "--package", "--registry", "--cache", "-c", "--call", "--userconfig")
_UVX_VALUE_FLAGS = ("--from", "--with", "--python", "-p", "--index-url", "--extra-index-url",
                    "--index", "-i", "--with-requirements", "--directory", "--project")
_DOCKER_VALUE_FLAGS = ("-e", "--env", "--env-file", "-v", "--volume", "--name", "--network",
                       "--net", "-p", "--publish", "--mount", "-w", "--workdir", "--entrypoint",
                       "-u", "--user", "--platform", "--label", "-l", "--add-host", "--cpus",
                       "-m", "--memory", "--hostname", "-h", "--pull", "--restart", "--cap-add",
                       "--cap-drop", "--security-opt", "--device", "--tmpfs", "--ulimit")


def infer_install_source(command: Optional[str], args: List[str], url: Optional[str]
                         ) -> Tuple[str, Optional[str], Optional[str]]:
    """Return (install_source, package, version_pin) for a server definition."""
    if url and not command:
        return "remote_url", None, None
    base = _cmd_base(command or "")
    args = [str(a) for a in (args or [])]

    # npm-family launchers
    npm_args: Optional[List[str]] = None
    if base in ("npx", "bunx", "pnpx"):
        npm_args = args
    elif base in ("npm", "pnpm", "yarn", "bun") and args and args[0] in ("exec", "dlx", "x"):
        npm_args = args[1:]
    if npm_args is not None:
        pos, flags = _first_positional([a for a in npm_args if a != "--"], _NPX_VALUE_FLAGS)
        spec = flags.get("--package") or flags.get("-p") or pos
        if not spec:
            return "npm", None, None
        if _is_path_like(spec):
            return "local_path", None, None
        name, ver = _split_npm_spec(spec)
        return "npm", name, _pin(ver)

    # PyPI-family launchers
    py_args: Optional[List[str]] = None
    if base == "uvx":
        py_args = args
    elif base == "uv" and args[:2] == ["tool", "run"]:
        py_args = args[2:]
    elif base == "pipx" and args[:1] == ["run"]:
        py_args = args[1:]
    elif base in ("pip", "pip3") and args[:1] in (["install"], ["run"]):
        py_args = args[1:]
    if py_args is not None:
        pos, flags = _first_positional(py_args, _UVX_VALUE_FLAGS)
        spec = flags.get("--from") or pos
        if not spec:
            return "pypi", None, None
        if _is_path_like(spec):
            return "local_path", None, None
        if spec.startswith(("git+", "http://", "https://")):
            return "unknown", None, None
        name, ver = _split_pypi_spec(spec)
        return "pypi", name, _pin(ver)
    if base == "uv":
        # `uv run ...` / `uv --directory /path run server.py` executes local code
        if any(_is_path_like(a) for a in args):
            return "local_path", None, None
        return "unknown", None, None

    # Containers
    if base in ("docker", "podman", "nerdctl"):
        rest = args[1:] if args[:1] in (["run"],) else (args[2:] if args[:2] == ["container", "run"] else None)
        if rest is not None:
            image, _ = _first_positional(rest, _DOCKER_VALUE_FLAGS)
            if image:
                name, ver = _split_image(image)
                return "container", name, _pin(ver)
        return "container", None, None

    # Interpreters running a local script
    if re.match(r"^(node|deno|bun|python[\d.]*|py|ruby|java|php|sh|bash)$", base):
        if any(_is_path_like(a) for a in args if not a.startswith("-")):
            return "local_path", None, None
        return "unknown", None, None

    if command and _is_path_like(command):
        return "local_path", None, None
    if url:
        return "remote_url", None, None
    return "unknown", None, None


# ============================================================
# Config location
# ============================================================

def infer_client(path: str) -> str:
    """Guess the MCP client from a config file path."""
    p = path.replace("\\", "/").lower()
    name = p.rsplit("/", 1)[-1]
    if name == "claude_desktop_config.json":
        return "claude_desktop"
    if name in (".claude.json", ".mcp.json") or "/.claude/" in p:
        return "claude_code"
    if name == "cline_mcp_settings.json" or "saoudrizwan.claude-dev" in p:
        return "cline"
    if "/.cursor/" in p:
        return "cursor"
    if "windsurf" in p or "/.codeium/" in p:
        return "windsurf"
    if "/zed/" in p:
        return "zed"
    if "/.gemini/" in p:
        return "gemini_cli"
    if "/.continue/" in p:
        return "continue"
    if "/.vscode/" in p or "/code/user/" in p:
        return "vscode"
    return "custom"


def _platform_key() -> str:
    return current_platform_key()


def _candidate_configs(custom_paths: Optional[List[str]], cwd: Optional[str],
                       platform_key: str, include_defaults: bool
                       ) -> List[Tuple[str, str, str]]:
    """List existing config files as (path, client, scope)."""
    found: List[Tuple[str, str, str]] = []
    seen = set()

    def add(path: str, client: str, scope: str):
        key = os.path.normcase(os.path.abspath(path))
        if key in seen or not os.path.isfile(path):
            return
        seen.add(key)
        found.append((path, client, scope))

    if include_defaults:
        for loc in MCP_CLIENT_LOCATIONS:
            if loc.get("scope", "user") != "user":
                continue
            raw = loc.get("paths", {}).get(platform_key)
            if raw:
                add(expand_config_path(raw, platform_key), loc.get("client", loc["id"]), "user")
        base = cwd or os.getcwd()
        for loc in MCP_CLIENT_LOCATIONS:
            if loc.get("scope") != "project":
                continue
            rel = loc.get("paths", {}).get("any")
            if rel:
                path = os.path.normpath(os.path.join(base, rel))
                client = loc.get("client", "project")
                add(path, client if client != "project" else infer_client(path), "project")

    for raw in custom_paths or []:
        path = expand_config_path(raw, platform_key)
        add(path, infer_client(path), "custom")
    return found


# ============================================================
# Allowlist
# ============================================================

def load_allowlist(source: Any) -> Allowlist:
    """Load an allowlist from a path or an already-parsed dict."""
    if isinstance(source, Allowlist):
        return source
    if isinstance(source, (str, os.PathLike)):
        data = load_json_tolerant(os.fspath(source))
    else:
        data = source
    if not isinstance(data, dict) or not isinstance(data.get("servers", []), list):
        raise ValueError("Allowlist must be a JSON object with a 'servers' list")
    allow = Allowlist.model_validate(data)
    if allow.version != 1:
        raise ValueError(f"Unsupported allowlist version {allow.version} (expected 1)")
    return allow


def _match_allowlist(server: DiscoveredServer, allow: Allowlist) -> Optional[AllowlistEntry]:
    pkg = (server.package or "").lower() or None
    url_key = server._match_url
    name = server.server_name.lower()
    name_match: Optional[AllowlistEntry] = None
    for entry in allow.servers:
        e_pkg = (entry.package or "").lower() or None
        e_url = _normalise_url(entry.url)
        if (e_pkg and pkg and e_pkg == pkg) or (e_url and url_key and e_url == url_key):
            return entry
        if name_match is None and entry.name and entry.name.lower() == name:
            conflict = (e_pkg and pkg and e_pkg != pkg) or (e_url and url_key and e_url != url_key)
            if not conflict:
                name_match = entry
    return name_match


def classify(server: DiscoveredServer, allow: Optional[Allowlist]) -> None:
    if allow is None:
        server.classification = "unchecked"
        return
    entry = _match_allowlist(server, allow)
    if entry is None:
        server.classification = "unapproved"
        return
    server.allowlist_match = entry.name or entry.package or entry.url
    if entry.version and (server.version_pin or "") != entry.version:
        server.classification = "unknown-version"
    else:
        server.classification = "approved"


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_") or "x"


def unapproved_finding(server: DiscoveredServer, index: int) -> Finding:
    origin = server.install_source
    if server.package:
        origin += f" package '{server.package}'"
    elif server.url:
        origin += f" endpoint {server.url}"
    return Finding(
        id=f"discover_unapproved_{_slug(server.client)}_{_slug(server.server_name)}_{index}",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.SUPPLY_CHAIN,
        title=f"Unapproved MCP server '{server.server_name}' configured in {server.client}",
        description=(
            f"The {server.client} configuration at {server.config_path} launches MCP server "
            f"'{server.server_name}' ({origin}), which does not match any entry in the approved "
            "server allowlist. Unreviewed ('shadow') MCP servers run with the user's privileges "
            "and receive whatever credentials the client passes them, outside any review or "
            "version control."
        ),
        file_path=server.config_path,
        recommendation=(
            "Find out who added this server and whether it is still needed. If it is, review it "
            "(for example with `axiom scan <package>`), pin an exact version and add it to the "
            "allowlist; otherwise remove it from the client configuration and rotate any "
            "credentials that were exposed to it."
        ),
        owasp_asi=["ASI04"],
        owasp_mcp=["MCP09"],
    )


# ============================================================
# Process detection (opt-in, local only)
# ============================================================

_PROCESS_INDICATORS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"@modelcontextprotocol[\\/]", re.I), "@modelcontextprotocol package"),
    (re.compile(r"\b(npx|bunx|pnpx)(\.cmd)?\b.*\b(server-[\w.\-]+|[\w.\-]*mcp[\w.\-]*)", re.I), "npx MCP server"),
    (re.compile(r"\buvx(\.exe)?\b.*mcp", re.I), "uvx MCP server"),
    (re.compile(r"\s-m\s+[\w.]*mcp[\w.]*", re.I), "python -m mcp module"),
    (re.compile(r"\b(mcp[-_]server[\w.\-]*|[\w.\-]*[-_]mcp[-_]server)\b", re.I), "mcp-server executable"),
    (re.compile(r"[\\/][^\\/\s]*mcp[^\\/\s]*[\\/]", re.I), "'mcp' in module path"),
]


def _list_processes() -> Tuple[List[Tuple[int, str, str]], Optional[str]]:
    """Return ([(pid, name, cmdline)], note). Uses psutil when available."""
    try:
        import psutil  # type: ignore
    except ImportError:
        psutil = None
    if psutil is not None:
        procs = []
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmd = p.info.get("cmdline") or []
                procs.append((int(p.info["pid"]), p.info.get("name") or "", " ".join(cmd)))
            except Exception:
                continue
        return procs, None
    try:
        if sys.platform.startswith("win"):
            ps = (
                "Get-CimInstance Win32_Process | ForEach-Object { "
                "\"$($_.ProcessId)`t$($_.Name)`t$($_.CommandLine)\" }"
            )
            out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                                 capture_output=True, text=True, timeout=20)
            procs = []
            for line in out.stdout.splitlines():
                parts = line.split("\t", 2)
                if len(parts) == 3 and parts[0].strip().isdigit():
                    procs.append((int(parts[0]), parts[1], parts[2]))
            return procs, "psutil not installed; used PowerShell Get-CimInstance fallback"
        out = subprocess.run(["ps", "-eo", "pid=,comm=,args="], capture_output=True, text=True, timeout=10)
        procs = []
        for line in out.stdout.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) >= 2 and parts[0].isdigit():
                procs.append((int(parts[0]), parts[1], parts[2] if len(parts) > 2 else parts[1]))
        return procs, "psutil not installed; used `ps` fallback"
    except Exception as e:  # pragma: no cover - depends on host tooling
        return [], f"Process enumeration skipped ({type(e).__name__}); install psutil for best results"


def detect_mcp_processes(servers: List[DiscoveredServer]) -> Tuple[List[DiscoveredProcess], Optional[str]]:
    procs, note = _list_processes()
    me = os.getpid()
    results: List[DiscoveredProcess] = []
    for pid, name, cmdline in procs:
        if pid == me or not cmdline or any(n in cmdline.lower() for n in ("axiom", "agentav", "mcpguard")):
            continue
        indicator = next((label for rx, label in _PROCESS_INDICATORS if rx.search(cmdline)), None)
        if not indicator:
            continue
        low = cmdline.lower()
        match = next((s.server_name for s in servers if s.package and s.package.lower() in low), None)
        results.append(DiscoveredProcess(
            pid=pid,
            name=name,
            cmdline=(redact_text(" ".join(redact_args(cmdline.split()))) or "")[:300],
            indicator=indicator,
            matches_server=match,
        ))
    return results, note


# ============================================================
# Discovery
# ============================================================

# Same prefixes LocalConfigScanner.analyze_entry treats as hardcoded secrets
_HARDCODED_TOKEN_PREFIXES = ("sk-", "ghp_", "gho_", "glpat-", "xoxb-", "xoxp-")


def _build_server(name: str, cfg: Dict[str, Any], project: Optional[str],
                  path: str, client: str, scope: str) -> DiscoveredServer:
    transport = detect_transport(cfg)
    raw_url = cfg.get("url") if isinstance(cfg.get("url"), str) else None
    command = cfg.get("command") or ""
    args = cfg.get("args") or []
    remote = transport in (TransportType.SSE, TransportType.HTTP) and not command
    source, package, pin = infer_install_source(command, args, raw_url if remote else None)
    env = cfg.get("env") or {}
    headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
    server = DiscoveredServer(
        client=client,
        config_path=path,
        server_name=name,
        scope="project" if project else scope,  # type: ignore[arg-type]
        project=project,
        transport="remote" if remote else "stdio",
        remote_type=transport.value if remote else None,
        command=redact_text(command) or None,
        args=redact_args(args),
        url=redact_url(raw_url) if raw_url else None,
        env_var_names=sorted(str(k) for k in env.keys()),
        header_names=sorted(str(k) for k in headers.keys()),
        install_source=source,  # type: ignore[arg-type]
        package=redact_text(package) if package else None,
        version_pin=redact_text(pin) if pin else None,
        disabled=bool(cfg.get("disabled", False)),
    )
    server._match_url = _normalise_url(raw_url)
    # Remember only *which* well-known token prefix an env value starts with, so
    # `--scan` can flag hardcoded tokens without the value ever being stored.
    server._env_token_prefixes = {
        str(k): next((pre for pre in _HARDCODED_TOKEN_PREFIXES if isinstance(v, str) and v.startswith(pre)), "")
        for k, v in env.items()
    }
    return server


def discover_servers(
    custom_paths: Optional[List[str]] = None,
    allowlist_path: Optional[str] = None,
    include_processes: bool = False,
    cwd: Optional[str] = None,
    *,
    allowlist: Optional[Any] = None,
    include_defaults: bool = True,
    scan: bool = False,
    platform_key: Optional[str] = None,
) -> DiscoveryResult:
    """Inventory every MCP server configured on this machine.

    Args:
        custom_paths: extra config files to read.
        allowlist_path: path to an allowlist JSON file (see module docstring).
        include_processes: also look for running MCP server processes (local only).
        cwd: directory used for project-level configs (default: os.getcwd()).
        allowlist: inline allowlist (dict/Allowlist), used if allowlist_path is not given.
        include_defaults: read the known client locations (False = only custom_paths).
        scan: merge LocalConfigScanner.analyze_entry findings for each server.
        platform_key: override darwin/linux/windows detection.
    """
    pkey = platform_key or _platform_key()
    result = DiscoveryResult(
        generated_at=datetime.now(timezone.utc).isoformat(),
        platform=pkey,
    )

    allow: Optional[Allowlist] = None
    if allowlist_path:
        allow = load_allowlist(allowlist_path)
        result.allowlist = allowlist_path
    elif allowlist is not None:
        allow = load_allowlist(allowlist)
        result.allowlist = "inline"

    for path, client, scope in _candidate_configs(custom_paths, cwd, pkey, include_defaults):
        result.config_files_scanned.append(path)
        try:
            data = load_json_tolerant(path)
        except (ValueError, OSError, UnicodeDecodeError) as e:
            result.config_errors.append(f"{path}: {type(e).__name__}")
            continue
        for name, cfg, project in extract_server_configs(data):
            server = _build_server(name, cfg, project, path, client, scope)
            result.servers.append(server)
            # Only already-redacted fields are ever logged.
            logger.debug(
                "Discovered MCP server '%s' (client=%s, source=%s, command=%s, args=%s, url=%s, env=%s) in %s",
                server.server_name, server.client, server.install_source, server.command,
                server.args, server.url, server.env_var_names, path,
            )

    for server in result.servers:
        classify(server, allow)

    for i, server in enumerate(s for s in result.servers if s.classification == "unapproved"):
        result.findings.append(unapproved_finding(server, i))

    if scan:
        result.findings.extend(config_findings(result.servers))
        result.notes.append(
            "--scan: merged local config checks (dangerous commands, sensitive env var names, "
            "hardcoded tokens, unpinned npx/uvx, unauthenticated remotes)."
        )

    if include_processes:
        procs, note = detect_mcp_processes(result.servers)
        result.processes = procs
        if note:
            result.notes.append(note)
        result.notes.append("Port probing is not implemented; only process command lines were inspected.")

    counts = Counter(s.classification for s in result.servers)
    result.summary = {
        "total": len(result.servers),
        "config_files": len(result.config_files_scanned),
        "approved": counts.get("approved", 0),
        "unapproved": counts.get("unapproved", 0),
        "unknown_version": counts.get("unknown-version", 0),
        "unchecked": counts.get("unchecked", 0),
        "processes": len(result.processes),
        "findings": len(result.findings),
    }
    logger.info(
        "MCP discovery complete: %d servers in %d config files (%d unapproved)",
        result.summary["total"], result.summary["config_files"], result.summary["unapproved"],
    )
    return result


def _refresh_summary(result: DiscoveryResult) -> None:
    result.summary["findings"] = len(result.findings)


# ============================================================
# --scan integration
# ============================================================

def config_findings(servers: List[DiscoveredServer]) -> List[Finding]:
    """Run LocalConfigScanner.analyze_entry over each discovered server.

    The entry handed to the analyser carries redacted command/args and, for env
    values, only the well-known token prefix (e.g. "ghp_") when there is one, so
    no finding text can contain a secret.
    """
    scanner = LocalConfigScanner()
    findings: List[Finding] = []
    seen = set()
    for s in servers:
        if s.transport == "remote":
            transport = TransportType.HTTP if s.remote_type == "http" else TransportType.SSE
        else:
            transport = TransportType.STDIO
        entry = MCPConfigEntry(
            name=s.server_name,
            command=s.command or "",
            args=s.args,
            env={k: s._env_token_prefixes.get(k, "") for k in s.env_var_names},
            source_file=s.config_path,
            transport=transport,
        )
        for f in scanner.analyze_entry(entry):
            key = (f.id, f.file_path)
            if key in seen:
                continue
            seen.add(key)
            f.title = redact_text(f.title) or f.title
            f.description = redact_text(f.description) or f.description
            findings.append(f)
    # Stamp both OWASP mappings (ASI + MCP Top 10) where the check did not set them.
    return apply_owasp_mappings(findings)


def _static_target(server: DiscoveredServer) -> Optional[Tuple[str, Optional[str]]]:
    """(target, target_url) the static engine can fetch for this server, if any."""
    if server.transport != "stdio" or not server.package or REDACTED in server.package:
        return None
    pkg = server.package
    m = re.match(r"^(?:github:|https?://github\.com/)([\w.\-]+/[\w.\-]+?)(?:\.git)?/?$", pkg)
    if m:
        return m.group(1).split("/")[-1], f"https://github.com/{m.group(1)}"
    if server.install_source in ("npm", "pypi"):
        return pkg, None
    return None


async def run_static_scans(result: DiscoveryResult, scan_engine: Any = None) -> DiscoveryResult:
    """Hand each resolvable npm/PyPI/GitHub stdio server to the static engine.

    This downloads package metadata and clones source repositories (network).
    Findings are merged into ``result.findings`` with the server name in the
    title; per-server outcomes are recorded in ``result.static_scans``.
    """
    if scan_engine is None:
        from app.analysis.engine import engine as scan_engine  # heavy import, lazily
    done: Dict[Tuple[str, Optional[str]], StaticScanSummary] = {}
    for server in result.servers:
        tgt = _static_target(server)
        if tgt is None:
            continue
        if tgt in done:
            prev = done[tgt]
            result.static_scans.append(prev.model_copy(update={"server_name": server.server_name}))
            continue
        target, target_url = tgt
        try:
            scanned = await scan_engine.scan(target, target_url)
            fnds = list(scanned.get("findings", []))
            for f in fnds:
                f.title = f"[{server.server_name}] {redact_text(f.title)}"
                f.description = redact_text(f.description) or f.description
            apply_owasp_mappings(fnds)
            result.findings.extend(fnds)
            level = scanned.get("risk_level")
            summary = StaticScanSummary(
                server_name=server.server_name,
                target=target_url or target,
                status=str(scanned.get("status", "completed")),
                risk_score=scanned.get("risk_score"),
                risk_level=getattr(level, "value", level),
                findings=len(fnds),
            )
        except Exception as e:
            summary = StaticScanSummary(server_name=server.server_name, target=target_url or target,
                                        status="error", error=type(e).__name__)
        done[tgt] = summary
        result.static_scans.append(summary)
    _refresh_summary(result)
    return result


# ============================================================
# Rendering helpers (shared by CLI and API consumers)
# ============================================================

def result_to_json(result: DiscoveryResult, indent: int = 2) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=indent)


def _md_cell(v: Any) -> str:
    return str(v if v not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def result_to_markdown(result: DiscoveryResult) -> str:
    lines = ["# MCP server inventory", ""]
    s = result.summary
    lines.append(
        f"{s.get('total', 0)} servers in {s.get('config_files', 0)} config files "
        f"(approved {s.get('approved', 0)}, unapproved {s.get('unapproved', 0)}, "
        f"unknown-version {s.get('unknown_version', 0)}, unchecked {s.get('unchecked', 0)}). "
        f"Allowlist: {result.allowlist or 'none'}."
    )
    lines += ["", "| Client | Server | Transport | Source | Package / URL | Version | Env vars | Status | Config |",
              "|---|---|---|---|---|---|---|---|---|"]
    for srv in result.servers:
        target = srv.package or srv.url or " ".join([srv.command or ""] + srv.args[:3]).strip()
        lines.append("| " + " | ".join(_md_cell(v) for v in (
            srv.client, srv.server_name, srv.transport, srv.install_source, target,
            srv.version_pin, ", ".join(srv.env_var_names), srv.classification, srv.config_path,
        )) + " |")
    if result.processes:
        lines += ["", "## Running MCP processes", "", "| PID | Indicator | Configured as | Command line |",
                  "|---|---|---|---|"]
        for p in result.processes:
            lines.append(f"| {p.pid} | {_md_cell(p.indicator)} | {_md_cell(p.matches_server)} | {_md_cell(p.cmdline)} |")
    if result.findings:
        lines += ["", "## Findings", "", "| Severity | Title | OWASP |", "|---|---|---|"]
        for f in result.findings:
            refs = (getattr(f, "owasp_asi", None) or []) + (getattr(f, "owasp_mcp", None) or [])
            lines.append(f"| {f.severity.value.upper()} | {_md_cell(f.title)} | {_md_cell(', '.join(refs))} |")
    if result.notes:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in result.notes]
    return "\n".join(lines) + "\n"
