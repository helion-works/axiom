"""
Local MCP Configuration Scanner
Discovers and analyzes all MCP servers configured on the local machine.
Scans: Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Cline, Zed,
Gemini CLI, Continue, project-level configs, and custom configs.

The table of known client config locations lives in
data/mcp_client_paths.json; MCP_CONFIG_PATHS is derived from it so existing
imports keep working.

This is a key differentiator — no other tool scans your local MCP configs
to tell you what's running and whether it's safe.
"""

import os
import re
import json
import logging
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from app.analysis.evidence import enrich_findings
from app.analysis.severity_policy import transport_severity
from app.models.schemas import (
    MCPConfigEntry, TransportType, Finding, FindingSeverity, FindingCategory
)

_log = logging.getLogger("axiom.local_config")

PLATFORM_KEYS = ("darwin", "linux", "windows")


def _load_client_paths_file() -> Dict[str, Any]:
    """Load data/mcp_client_paths.json (shipped as package data of `data`)."""
    candidates = []
    try:
        from importlib import resources
        candidates.append(resources.files("data").joinpath("mcp_client_paths.json"))
    except Exception:  # pragma: no cover - data package not importable
        pass
    candidates.append(Path(__file__).resolve().parents[2] / "data" / "mcp_client_paths.json")
    for cand in candidates:
        try:
            return json.loads(cand.read_text(encoding="utf-8"))
        except Exception:
            continue
    _log.warning("mcp_client_paths.json not found; no default MCP client paths available")
    return {"version": 1, "locations": []}


MCP_CLIENT_PATHS_DATA: Dict[str, Any] = _load_client_paths_file()

# Full location records (id, client, display_name, scope, keys, paths, note?)
MCP_CLIENT_LOCATIONS: List[Dict[str, Any]] = list(MCP_CLIENT_PATHS_DATA.get("locations", []))

# Default user-level MCP config file locations by platform: {platform: {id: path}}
MCP_CONFIG_PATHS: Dict[str, Dict[str, str]] = {
    plat: {
        loc["id"]: loc["paths"][plat]
        for loc in MCP_CLIENT_LOCATIONS
        if loc.get("scope", "user") == "user" and plat in loc.get("paths", {})
    }
    for plat in PLATFORM_KEYS
}

# Project-level config files, relative to the working directory: [(id, relpath)]
MCP_PROJECT_CONFIG_PATHS: List[Tuple[str, str]] = [
    (loc["id"], loc["paths"]["any"])
    for loc in MCP_CLIENT_LOCATIONS
    if loc.get("scope") == "project" and "any" in loc.get("paths", {})
]


def current_platform_key() -> str:
    """Map platform.system() to one of darwin / linux / windows."""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "darwin"
    return "linux"


def _home_dir(platform_key: Optional[str] = None) -> str:
    """Home directory, honouring HOME/USERPROFILE so tests can redirect it."""
    order = ("USERPROFILE", "HOME") if platform_key == "windows" else ("HOME", "USERPROFILE")
    for var in order:
        val = os.environ.get(var)
        if val:
            return val
    return os.path.expanduser("~")


_PCT_VAR = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")


def expand_config_path(path: str, platform_key: Optional[str] = None) -> str:
    """Expand '~', %VAR% and $VAR in a config path the same way on every host OS."""
    if path == "~" or path.startswith(("~/", "~\\")):
        path = _home_dir(platform_key) + path[1:]
    path = _PCT_VAR.sub(lambda m: os.environ.get(m.group(1), m.group(0)), path)
    path = os.path.expandvars(path)
    return os.path.normpath(path)


_JSONC_TOKEN = re.compile(
    r'"(?:\\.|[^"\\])*"'      # string literal (kept as is)
    r"|//[^\n]*"              # line comment
    r"|/\*.*?\*/",            # block comment
    re.DOTALL,
)
_TRAILING_COMMA = re.compile(r'("(?:\\.|[^"\\])*")|,(\s*[}\]])', re.DOTALL)


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas (VS Code / Zed settings)."""
    text = _JSONC_TOKEN.sub(lambda m: m.group(0) if m.group(0).startswith('"') else "", text)
    return _TRAILING_COMMA.sub(lambda m: m.group(1) if m.group(1) else m.group(2), text)


def load_json_tolerant(filepath: str) -> Any:
    """Load a JSON (or JSON-with-comments) file. Raises ValueError/OSError on failure."""
    with open(filepath, "r", encoding="utf-8-sig") as f:
        text = f.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(_strip_jsonc(text))


_SERVER_HINT_KEYS = ("command", "url", "serverUrl", "httpUrl", "type", "transport", "args")


def _looks_like_server(cfg: Any) -> bool:
    return isinstance(cfg, dict) and any(k in cfg for k in _SERVER_HINT_KEYS)


def normalize_server_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise client-specific server shapes to {command, args, env, url, type, ...}.

    Handles Zed's ``"command": {"path", "args", "env"}`` form, Continue's nested
    ``"transport": {...}`` form, and the various remote URL keys
    (``url`` / ``serverUrl`` / ``httpUrl``).
    """
    out = dict(cfg)
    cmd = out.get("command")
    if isinstance(cmd, dict):  # Zed (older context_servers format)
        out["command"] = cmd.get("path") or cmd.get("command") or ""
        if "args" not in out and isinstance(cmd.get("args"), list):
            out["args"] = cmd.get("args")
        if "env" not in out and isinstance(cmd.get("env"), dict):
            out["env"] = cmd.get("env")
    transport = out.get("transport")
    if isinstance(transport, dict):  # Continue experimental format
        for k, v in transport.items():
            out.setdefault(k, v)
        out["transport"] = transport.get("type")
    if not out.get("url"):
        if out.get("serverUrl"):
            out["url"] = out["serverUrl"]
        elif out.get("httpUrl"):
            out["url"] = out["httpUrl"]
            out.setdefault("type", "http")
    if not isinstance(out.get("command"), str):
        out["command"] = ""
    args = out.get("args", [])
    out["args"] = [str(a) for a in args] if isinstance(args, list) else [str(args)]
    env = out.get("env", {})
    out["env"] = env if isinstance(env, dict) else {}
    return out


def _servers_from_container(container: Any) -> List[Tuple[str, Dict[str, Any]]]:
    """Yield (name, cfg) from a dict-of-servers or list-of-servers container."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    if isinstance(container, dict):
        for name, cfg in container.items():
            if isinstance(cfg, dict):
                out.append((str(name), cfg))
    elif isinstance(container, list):
        for i, cfg in enumerate(container):
            if isinstance(cfg, dict):
                out.append((str(cfg.get("name") or f"server_{i}"), cfg))
    return out


def extract_server_configs(data: Any) -> List[Tuple[str, Dict[str, Any], Optional[str]]]:
    """Extract every MCP server definition from a parsed config document.

    Tolerates the different top-level keys used by MCP clients:
    ``mcpServers`` (Claude Desktop/Code, Cursor, Windsurf, Cline, Gemini CLI),
    ``servers`` (VS Code mcp.json), ``mcp.servers`` (VS Code settings.json),
    ``context_servers`` (Zed), ``mcp_servers`` (legacy),
    ``projects.<path>.mcpServers`` (Claude Code ~/.claude.json) and
    ``experimental.modelContextProtocolServers`` (Continue).

    Returns a list of (server_name, normalised_config, project_path_or_None).
    """
    results: List[Tuple[str, Dict[str, Any], Optional[str]]] = []
    if not isinstance(data, dict):
        return results

    def add(container: Any, project: Optional[str] = None, require_hint: bool = False):
        for name, cfg in _servers_from_container(container):
            if require_hint and not _looks_like_server(cfg):
                continue
            results.append((name, normalize_server_config(cfg), project))

    add(data.get("mcpServers"))
    add(data.get("mcp_servers"))
    add(data.get("servers"), require_hint=True)
    add(data.get("context_servers"), require_hint=True)
    mcp_block = data.get("mcp")
    if isinstance(mcp_block, dict):
        add(mcp_block.get("servers"), require_hint=True)
    experimental = data.get("experimental")
    if isinstance(experimental, dict):
        add(experimental.get("modelContextProtocolServers"), require_hint=True)
    projects = data.get("projects")
    if isinstance(projects, dict):
        for proj_path, proj in projects.items():
            if isinstance(proj, dict):
                add(proj.get("mcpServers"), project=str(proj_path))
    return results


def detect_transport(cfg: Dict[str, Any]) -> TransportType:
    """Infer the transport from a normalised server config."""
    kind = str(cfg.get("type") or cfg.get("transport") or "").lower()
    if kind in ("http", "streamable-http", "streamablehttp", "streamable_http"):
        return TransportType.HTTP
    if kind == "sse":
        return TransportType.SSE
    if cfg.get("url"):
        return TransportType.SSE
    return TransportType.STDIO

# Dangerous environment variable patterns that MCP servers shouldn't need
DANGEROUS_ENV_PATTERNS = [
    "AWS_SECRET", "AWS_ACCESS_KEY",
    "GITHUB_TOKEN", "GH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DATABASE_URL", "DB_PASSWORD",
    "PRIVATE_KEY", "SECRET_KEY",
    "SSH_KEY", "SSH_PRIVATE",
    "STRIPE_SECRET",
    "SLACK_TOKEN", "SLACK_BOT",
]

# Known risky command patterns
DANGEROUS_COMMANDS = {
    "curl": "Network access via curl — could exfiltrate data",
    "wget": "Network access via wget — could download malicious payloads",
    "bash -c": "Arbitrary bash command execution",
    "sh -c": "Arbitrary shell command execution",
    "powershell": "PowerShell execution — high privilege risk on Windows",
    "cmd /c": "Windows command prompt execution",
    "sudo": "Elevated privilege execution",
    "nc ": "Netcat — potential reverse shell",
    "ncat": "Nmap Netcat — potential reverse shell",
    "python -c": "Inline Python execution",
    "node -e": "Inline Node.js execution",
}


class LocalConfigScanner:
    """Scans local MCP configuration files to discover installed servers."""

    def __init__(self):
        self.system = platform.system().lower()
        self.platform_key = current_platform_key()

    def get_default_paths(self) -> dict:
        """Get default MCP config file paths for current platform."""
        paths = MCP_CONFIG_PATHS.get(self.platform_key) or MCP_CONFIG_PATHS.get("linux", {})
        return {
            name: expand_config_path(path, self.platform_key)
            for name, path in paths.items()
        }

    def get_project_paths(self, cwd: Optional[str] = None) -> dict:
        """Project-level MCP config paths relative to ``cwd`` (default: os.getcwd())."""
        base = cwd or os.getcwd()
        return {
            loc_id: os.path.normpath(os.path.join(base, rel))
            for loc_id, rel in MCP_PROJECT_CONFIG_PATHS
        }

    def discover_configs(self, custom_paths: List[str] = None,
                         include_defaults: bool = True) -> List[str]:
        """Find MCP config files. With ``include_defaults=False`` only ``custom_paths``
        are considered (no client defaults, no project-level files)."""
        found = []

        # Check default locations
        if include_defaults:
            for name, path in self.get_default_paths().items():
                if os.path.isfile(path):
                    found.append(path)

        # Check custom paths
        if custom_paths:
            for path in custom_paths:
                expanded = expand_config_path(path, self.platform_key)
                if os.path.isfile(expanded):
                    found.append(expanded)

        # Also check for project-level MCP configs
        if include_defaults:
            for pc in self.get_project_paths().values():
                if os.path.isfile(pc):
                    found.append(pc)

        return list(dict.fromkeys(found))

    def parse_config_file(self, filepath: str) -> List[MCPConfigEntry]:
        """Parse an MCP config file and extract server entries.

        Accepts JSON-with-comments and every server container shape handled by
        ``extract_server_configs`` (mcpServers / servers / context_servers /
        projects.*.mcpServers ...). Remote entries (url + type sse/http) get
        an SSE or HTTP transport and an empty command.
        """
        entries = []
        try:
            data = load_json_tolerant(filepath)
        except (ValueError, OSError, UnicodeDecodeError):
            return entries

        for name, config, _project in extract_server_configs(data):
            entries.append(MCPConfigEntry(
                name=name,
                command=config.get("command", "") or "",
                args=config.get("args", []),
                env={str(k): ("" if v is None else str(v)) for k, v in config.get("env", {}).items()},
                source_file=filepath,
                transport=detect_transport(config),
                url=config.get("url") if isinstance(config.get("url"), str) else None,
            ))

        return entries

    def analyze_entry(self, entry: MCPConfigEntry) -> List[Finding]:
        """Analyze a single MCP config entry for security risks."""
        findings = []

        # 1. Check command safety
        full_command = f"{entry.command} {' '.join(entry.args)}"
        for danger_cmd, desc in DANGEROUS_COMMANDS.items():
            if danger_cmd in full_command.lower():
                findings.append(Finding(
                    id=f"config_{entry.name}_dangerous_cmd",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.COMMAND_INJECTION,
                    title=f"Dangerous command in MCP server '{entry.name}'",
                    description=f"{desc}. Full command: {full_command[:200]}",
                    file_path=entry.source_file,
                    recommendation="Review this command carefully. Consider sandboxing.",
                ))

        # 2. Check for sensitive env vars being passed
        for env_key in entry.env.keys():
            for pattern in DANGEROUS_ENV_PATTERNS:
                if pattern.lower() in env_key.lower():
                    findings.append(Finding(
                        id=f"config_{entry.name}_env_{env_key}",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.CREDENTIAL_THEFT,
                        title=f"Sensitive env var '{env_key}' passed to MCP server '{entry.name}'",
                        description=f"The environment variable '{env_key}' is passed to "
                                    f"MCP server '{entry.name}' (its value is not inspected). That is how "
                                    "servers are configured; it matters only if this server is also "
                                    "flagged for exfiltration, poisoning or shadow status.",
                        file_path=entry.source_file,
                        recommendation=f"Verify '{entry.name}' genuinely needs access to '{env_key}'. "
                                       "Use scoped tokens with minimum required permissions.",
                    ))
                    break

        # 3. Check for env var values that look like they contain actual secrets
        for env_key, env_val in entry.env.items():
            if isinstance(env_val, str):
                if env_val.startswith(("sk-", "ghp_", "gho_", "glpat-", "xoxb-", "xoxp-")):
                    findings.append(Finding(
                        id=f"config_{entry.name}_hardcoded_secret",
                        severity=FindingSeverity.CRITICAL,
                        category=FindingCategory.CREDENTIAL_THEFT,
                        title=f"Hardcoded API key/token in MCP config for '{entry.name}'",
                        description=f"Environment variable '{env_key}' contains what appears to be "
                                    f"a hardcoded API key or token (starts with '{env_val[:4]}...'). "
                                    "This should be stored in a secrets manager, not in config files.",
                        file_path=entry.source_file,
                        recommendation="Move this secret to a secure vault or use environment variable "
                                       "references instead of hardcoded values.",
                    ))

        # 4. Check for npx with unknown packages (common MCP install pattern)
        if entry.command in ("npx", "npx.cmd"):
            pkg_name = entry.args[0] if entry.args else ""
            if pkg_name.startswith("-"):
                # -y flag or other flags before package name
                for arg in entry.args:
                    if not arg.startswith("-"):
                        pkg_name = arg
                        break

            if pkg_name and not pkg_name.startswith("@modelcontextprotocol/"):
                findings.append(Finding(
                    id=f"config_{entry.name}_npx_unknown",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.SUPPLY_CHAIN,
                    title=f"MCP server '{entry.name}' installed via npx from '{pkg_name}'",
                    description=f"This server is executed directly from npm via npx. Package "
                                f"'{pkg_name}' runs with full system access. npx downloads and "
                                "executes code without explicit version pinning.",
                    file_path=entry.source_file,
                    recommendation=f"Pin the version explicitly. Verify '{pkg_name}' is a "
                                   "legitimate, maintained package. Consider local installation.",
                ))

        # 5. Check for uvx (Python MCP servers)
        if entry.command in ("uvx", "uv"):
            findings.append(Finding(
                id=f"config_{entry.name}_uvx",
                severity=FindingSeverity.LOW,
                category=FindingCategory.SUPPLY_CHAIN,
                title=f"MCP server '{entry.name}' installed via uvx/uv",
                description="Python MCP server executed via uv. Verify the PyPI package "
                            "is legitimate and pin to a specific version.",
                file_path=entry.source_file,
                recommendation="Use version pinning and verify package authenticity on PyPI.",
            ))

        # 6. SSE/HTTP transport without apparent auth
        if entry.transport in (TransportType.SSE, TransportType.HTTP):
            has_auth_env = any(
                k.lower() in ("api_key", "auth_token", "bearer_token", "authorization")
                for k in entry.env.keys()
            )
            if not has_auth_env:
                remote = entry.url or (entry.command if entry.command.startswith(("http://", "https://")) else next(
                    (a for a in entry.args if a.startswith(("http://", "https://"))), None))
                sev, why = transport_severity(remote)
                findings.append(Finding(
                    id=f"config_{entry.name}_no_auth",
                    severity=sev,
                    category=FindingCategory.TRANSPORT_SECURITY,
                    title=f"Remote MCP server '{entry.name}' without visible authentication",
                    description=f"This server uses {entry.transport.value} transport (remote) "
                                f"but no authentication credentials are configured; {why}.",
                    file_path=entry.source_file,
                    recommendation="Ensure proper authentication is configured for remote MCP servers.",
                ))

        # 7. Count total env vars exposed
        if len(entry.env) > 5:
            findings.append(Finding(
                id=f"config_{entry.name}_env_overexposed",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.PERMISSION_OVERSCOPE,
                title=f"MCP server '{entry.name}' receives {len(entry.env)} environment variables",
                description="This server is configured with many environment variables. "
                            "Follow the principle of least privilege — only pass what's needed.",
                file_path=entry.source_file,
                recommendation="Audit each environment variable and remove unnecessary ones.",
            ))

        return findings

    def scan_all(self, custom_paths: List[str] = None, include_defaults: bool = True) -> dict:
        """Full local config scan — discover and analyze all MCP servers."""
        config_files = self.discover_configs(custom_paths, include_defaults=include_defaults)
        all_entries = []
        all_findings = []

        for filepath in config_files:
            entries = self.parse_config_file(filepath)
            for entry in entries:
                entry_findings = self.analyze_entry(entry)
                all_findings.extend(entry_findings)
            all_entries.extend(entries)

        # Cross-server analysis: check if multiple servers share env vars
        env_to_servers = {}
        for entry in all_entries:
            for env_key in entry.env.keys():
                env_to_servers.setdefault(env_key, []).append(entry.name)

        # Configured server names a user could confuse (server-name squatting)
        from app.analysis.tool_body_detectors import near_duplicate_names
        seen_pairs = set()
        for i, a in enumerate(all_entries):
            for b in all_entries[i + 1:]:
                if a.name == b.name or not near_duplicate_names(a.name, b.name):
                    continue
                key = tuple(sorted((a.name, b.name)))
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                all_findings.append(Finding(
                    id=f"config_squat_{a.name}__{b.name}",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.TOOL_SHADOWING,
                    title=f"Configured servers with lookalike names: '{a.name}' and '{b.name}'",
                    description=f"'{a.name}' ({a.source_file}) and '{b.name}' ({b.source_file}) differ only by a "
                                "suffix, separator or one character. The client picks one of them for a tool call; "
                                "a lookalike entry is how a malicious server receives calls meant for a trusted one.",
                    file_path=b.source_file,
                    recommendation="Remove or rename the lookalike entry; verify which package each one runs.",
                    owasp_asi=["ASI04"],
                ))

        for env_key, servers in env_to_servers.items():
            if len(servers) > 1:
                all_findings.append(Finding(
                    id=f"cross_env_{env_key}",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.CROSS_SERVER,
                    title=f"Credential '{env_key}' shared across {len(servers)} MCP servers",
                    description=f"The environment variable '{env_key}' is passed to multiple "
                                f"MCP servers: {', '.join(servers)}. If any server is compromised, "
                                "this shared credential is exposed.",
                    recommendation="Use separate, scoped credentials for each MCP server.",
                ))

        enrich_findings(all_findings, mode="config", target=config_files[0] if config_files else "local")

        return {
            "config_files_found": config_files,
            "servers_discovered": all_entries,
            "findings": all_findings,
            "total_servers": len(all_entries),
        }


# Singleton
local_scanner = LocalConfigScanner()
