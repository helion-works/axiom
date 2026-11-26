"""
Axiom Live Scanner — Runtime MCP Server Introspection

Connects to running MCP servers via stdio or SSE transport,
performs the JSON-RPC 2.0 initialization handshake, introspects
tools/resources/prompts at runtime, and analyzes what the server
*actually* exposes vs what its source code claims.

This is the most differentiated feature in Axiom — it catches:
  - Tool description mutations (source says X, runtime says Y)
  - Hidden tools not present in source code
  - Runtime-only poisoning that wouldn't appear in static analysis
  - Servers where source code isn't available at all

Usage:
    scanner = MCPLiveScanner()
    result = await scanner.scan_stdio("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"])
    result = await scanner.scan_sse("http://localhost:3000/sse")
    result = await scanner.scan_config_entry(config_entry)
    results = await scanner.scan_all_local()

Maps to OWASP Agentic AI Top 10:
    ASI01 — Detects runtime tool poisoning (goal hijack via description mutation)
    ASI02 — Identifies toxic tool combinations from live tool listings
    ASI04 — Catches supply chain attacks where published source differs from runtime
    ASI09 — Flags trust exploitation via claimed-vs-actual divergence
    ASI10 — Detects rogue tool additions not present in source
"""

import asyncio
import json
import os
import sys
import signal
import shutil
import tempfile
import subprocess
import re
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.models.schemas import (
    Finding, FindingSeverity, FindingCategory,
    MCPToolDefinition, MCPResourceDefinition, MCPPromptDefinition,
    MCPServerProfile, MCPConfigEntry, TransportType, RiskLevel,
)
from app.analysis.evidence import enrich_findings
from app.analysis.severity_policy import risk_level as _policy_level, risk_score as _policy_score, transport_severity
from app.analysis.tool_poisoning import tool_poisoning_detector, detect_sensitive_resources
from app.analysis.remote_transport import (  # noqa: F401  (MCPSSEClient kept importable)
    MCPSSEClient, MCPStreamableHTTPClient, RemoteTransportError, connect_remote,
)
from app.analysis.owasp_mapping import (
    detect_dangerous_tool_capabilities,
    dangerous_tool_map,
    detect_toxic_tool_combos, generate_owasp_coverage, CATEGORY_TO_ASI,
    generate_owasp_mcp_coverage, apply_owasp_mcp_mapping,
)

# ============================================================
# MCP JSON-RPC 2.0 Protocol Constants
# ============================================================

MCP_PROTOCOL_VERSION = "2024-11-05"
MCPGUARD_CLIENT_INFO = {"name": "axiom", "version": "0.6.0"}

# Timeout constants (seconds)
CONNECT_TIMEOUT = 30
REQUEST_TIMEOUT = 15
SHUTDOWN_TIMEOUT = 5
LIVE_SCAN_TIMEOUT = 120  # Overall timeout for a complete live scan operation

# Reading what the server lists (never calling tools)
MAX_RESOURCES_READ = 25
MAX_PROMPTS_GET = 25
MAX_CONTENT_BYTES = 65_536
READABLE_MIME_PREFIXES = ("text/", "application/json", "application/x-yaml", "application/yaml",
                          "application/xml", "application/javascript", "application/x-python")


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(s))[-60:]


# ============================================================
# Live Scan Result Model
# ============================================================

@dataclass
class LiveScanResult:
    """Result from a live MCP server scan."""
    server_name: str
    transport: str = "stdio"
    status: str = "pending"         # pending, connected, completed, error
    error: Optional[str] = None

    # Server info from initialize response
    server_info: Dict[str, Any] = field(default_factory=dict)
    server_capabilities: Dict[str, Any] = field(default_factory=dict)
    protocol_version: str = ""

    # Runtime definitions
    runtime_tools: List[MCPToolDefinition] = field(default_factory=list)
    runtime_resources: List[MCPResourceDefinition] = field(default_factory=list)
    runtime_prompts: List[MCPPromptDefinition] = field(default_factory=list)

    # What the server says and serves (read, never executed)
    auth_provided: bool = True           # False when a remote session was opened with no credential
    server_instructions: str = ""
    resource_contents: Dict[str, str] = field(default_factory=dict)      # uri -> text
    prompt_messages: Dict[str, List[str]] = field(default_factory=dict)  # prompt name -> message texts

    # Analysis
    findings: List[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.SAFE
    owasp_coverage: Optional[Dict[str, Any]] = None
    owasp_mcp_coverage: Optional[Dict[str, Any]] = None

    # Diff results (if source was also scanned)
    diff_results: Optional[Dict[str, Any]] = None

    # Timing
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_name": self.server_name,
            "transport": self.transport,
            "status": self.status,
            "error": self.error,
            "server_info": self.server_info,
            "server_capabilities": self.server_capabilities,
            "protocol_version": self.protocol_version,
            "runtime_tools": [t.model_dump() for t in self.runtime_tools],
            "runtime_resources": [r.model_dump() for r in self.runtime_resources],
            "runtime_prompts": [p.model_dump() for p in self.runtime_prompts],
            "server_instructions": self.server_instructions,
            "resources_read": len(self.resource_contents),
            "prompts_fetched": len(self.prompt_messages),
            "resource_contents": {k: v[:2048] for k, v in self.resource_contents.items()},
            "prompt_messages": {k: [m[:2048] for m in v] for k, v in self.prompt_messages.items()},
            "findings": [f.model_dump() for f in self.findings],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "owasp_coverage": self.owasp_coverage,
            "owasp_mcp_coverage": self.owasp_mcp_coverage,
            "diff_results": self.diff_results,
            "scan_duration_seconds": self.scan_duration_seconds,
        }


# ============================================================
# MCP Protocol Client (JSON-RPC 2.0)
# ============================================================

class MCPProtocolClient:
    """
    Low-level MCP protocol client.
    Handles JSON-RPC 2.0 messaging over stdio or SSE transport.
    """

    def __init__(self):
        self._request_id = 0
        self._process: Optional[asyncio.subprocess.Process] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    # ---- Stdio Transport ----

    async def connect_stdio(
        self,
        command: str,
        args: List[str] = None,
        env: Dict[str, str] = None,
        cwd: str = None,
    ) -> Dict[str, Any]:
        """
        Spawn an MCP server process, connect via stdio, and initialize.
        Returns the server's initialize response.
        """
        args = args or []
        full_env = os.environ.copy()
        if env:
            full_env.update(env)

        # Resolve command path
        cmd_path = shutil.which(command)
        if not cmd_path:
            raise ConnectionError(
                f"Command '{command}' not found in PATH. "
                f"Make sure it's installed (e.g., npm install -g {command})."
            )

        try:
            self._process = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    cmd_path, *args,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=full_env,
                    cwd=cwd,
                ),
                timeout=CONNECT_TIMEOUT,
            )
        except asyncio.TimeoutError:
            raise ConnectionError(
                f"Timeout ({CONNECT_TIMEOUT}s) spawning '{command} {' '.join(args)}'"
            )
        except FileNotFoundError:
            raise ConnectionError(f"Command not found: {command}")
        except PermissionError:
            raise ConnectionError(f"Permission denied executing: {command}")

        # Give the server a moment to start
        await asyncio.sleep(0.5)

        # Check if process died immediately
        if self._process.returncode is not None:
            stderr_output = ""
            try:
                stderr_bytes = await asyncio.wait_for(
                    self._process.stderr.read(4096), timeout=2
                )
                stderr_output = stderr_bytes.decode(errors="replace")
            except (asyncio.TimeoutError, Exception):
                pass
            raise ConnectionError(
                f"Server process exited immediately with code {self._process.returncode}. "
                f"stderr: {stderr_output[:500]}"
            )

        # Initialize
        return await self._initialize()

    async def _initialize(self) -> Dict[str, Any]:
        """Send MCP initialize handshake."""
        init_request = {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "roots": {"listChanged": False},
            },
            "clientInfo": MCPGUARD_CLIENT_INFO,
        }

        response = await self._send_request("initialize", init_request)

        # Send initialized notification (no response expected)
        await self._send_notification("notifications/initialized")

        return response

    async def list_tools(self) -> List[Dict[str, Any]]:
        """Call tools/list and return tool definitions."""
        try:
            result = await self._send_request("tools/list", {})
            return result.get("tools", [])
        except Exception:
            return []

    async def list_resources(self) -> List[Dict[str, Any]]:
        """Call resources/list and return resource definitions."""
        try:
            result = await self._send_request("resources/list", {})
            return result.get("resources", [])
        except Exception:
            return []

    async def list_prompts(self) -> List[Dict[str, Any]]:
        """Call prompts/list and return prompt definitions."""
        try:
            result = await self._send_request("prompts/list", {})
            return result.get("prompts", [])
        except Exception:
            return []

    async def read_resource(self, uri: str) -> Optional[Dict[str, Any]]:
        """Call resources/read; None on any error (one bad resource must not abort the scan)."""
        try:
            return await self._send_request("resources/read", {"uri": uri})
        except Exception:
            return None

    async def get_prompt(self, name: str, arguments: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Call prompts/get; None on any error."""
        try:
            return await self._send_request("prompts/get", {"name": name, "arguments": arguments or {}})
        except Exception:
            return None

    async def shutdown(self):
        """Gracefully shutdown the server connection."""
        if self._process and self._process.returncode is None:
            try:
                # Try graceful close
                if self._process.stdin and not self._process.stdin.is_closing():
                    self._process.stdin.close()
                await asyncio.wait_for(
                    self._process.wait(), timeout=SHUTDOWN_TIMEOUT
                )
            except asyncio.TimeoutError:
                # Force kill
                try:
                    self._process.kill()
                    await self._process.wait()
                except ProcessLookupError:
                    pass
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass

    # ---- JSON-RPC Messaging ----

    async def _send_request(self, method: str, params: dict) -> dict:
        """Send a JSON-RPC 2.0 request and wait for the response."""
        if not self._process or self._process.returncode is not None:
            raise ConnectionError("Not connected to MCP server")

        req_id = self._next_id()
        message = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }

        # Write message
        msg_bytes = (json.dumps(message) + "\n").encode("utf-8")
        self._process.stdin.write(msg_bytes)
        await self._process.stdin.drain()

        # Read response — handle MCP's line-based JSON-RPC
        response = await self._read_response(req_id)
        return response

    async def _send_notification(self, method: str, params: dict = None):
        """Send a JSON-RPC 2.0 notification (no response expected)."""
        if not self._process or self._process.returncode is not None:
            return

        message = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params:
            message["params"] = params

        msg_bytes = (json.dumps(message) + "\n").encode("utf-8")
        self._process.stdin.write(msg_bytes)
        await self._process.stdin.drain()

    async def _read_response(self, expected_id: int) -> dict:
        """
        Read JSON-RPC response from stdout.
        Handles both raw JSON lines and Content-Length framed messages (LSP-style).
        Skips notifications and waits for the matching response ID.
        """
        deadline = asyncio.get_event_loop().time() + REQUEST_TIMEOUT

        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break

            try:
                line = await asyncio.wait_for(
                    self._process.stdout.readline(),
                    timeout=min(remaining, REQUEST_TIMEOUT),
                )
            except asyncio.TimeoutError:
                raise TimeoutError(
                    f"Timeout waiting for response to request {expected_id}"
                )

            if not line:
                # EOF — process may have died
                raise ConnectionError("Server closed stdout (process may have crashed)")

            line_str = line.decode("utf-8", errors="replace").strip()

            # Skip empty lines
            if not line_str:
                continue

            # Handle Content-Length headers (some servers use LSP-style framing)
            if line_str.startswith("Content-Length:"):
                content_length = int(line_str.split(":")[1].strip())
                # Read the blank separator line
                await self._process.stdout.readline()
                # Read exact content
                try:
                    content = await asyncio.wait_for(
                        self._process.stdout.readexactly(content_length),
                        timeout=min(remaining, REQUEST_TIMEOUT),
                    )
                    line_str = content.decode("utf-8", errors="replace").strip()
                except asyncio.TimeoutError:
                    raise TimeoutError("Timeout reading Content-Length framed message")

            # Try to parse as JSON
            try:
                data = json.loads(line_str)
            except json.JSONDecodeError:
                # Not JSON — might be server log output, skip
                continue

            # Check if this is a JSON-RPC response
            if not isinstance(data, dict):
                continue

            # Skip notifications (no id field)
            if "id" not in data:
                continue

            # Check for error
            if "error" in data:
                err = data["error"]
                raise RuntimeError(
                    f"MCP error {err.get('code', '?')}: {err.get('message', 'Unknown error')}"
                )

            # Check if this is our response
            if data.get("id") == expected_id:
                return data.get("result", {})

        raise TimeoutError(f"Timeout waiting for response ID {expected_id}")


# ============================================================
# SSE Transport Client
# ============================================================

# Remote transports (Streamable HTTP, legacy SSE) live in app/analysis/remote_transport.py


# ============================================================
# Runtime Tool Analyzer
# ============================================================

class RuntimeToolAnalyzer:
    """
    Analyzes tools obtained from a live MCP server connection.
    Runs poisoning detection, toxic combo analysis, and
    source-vs-runtime diffing.
    """

    def analyze_runtime_tools(
        self, tools: List[MCPToolDefinition], server_name: str
    ) -> List[Finding]:
        """Run full security analysis on runtime tool definitions."""
        findings = []

        # 1. Tool poisoning detection (reuses existing detector)
        poison_findings = tool_poisoning_detector.analyze_all_tools(tools)
        # Tag as runtime-detected
        for f in poison_findings:
            f.id = f"live_{f.id}"
            f.description = f"[RUNTIME] {f.description}"
        findings.extend(poison_findings)

        # 2. Toxic tool combination analysis
        combo_findings = detect_toxic_tool_combos(tools)
        for f in combo_findings:
            f.id = f"live_{f.id}"
            f.description = f"[RUNTIME] {f.description}"
        findings.extend(combo_findings)

        # 2b. Per-tool dangerous capabilities (shell_exec, file_read, file_write, env_dump, egress)
        cap_findings = detect_dangerous_tool_capabilities(tools)
        capped_tools = set(dangerous_tool_map(tools))
        for f in cap_findings:
            f.id = f"live_{f.id}"
            f.description = f"[RUNTIME] {f.description}"
        findings.extend(cap_findings)

        # 3. Tool count analysis
        if len(tools) > 20:
            findings.append(Finding(
                id=f"live_{server_name}_excessive_tools",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.PERMISSION_OVERSCOPE,
                title=f"Server exposes {len(tools)} tools — large attack surface",
                description=f"[RUNTIME] Server '{server_name}' exposes {len(tools)} tools at "
                            "runtime. Large tool surfaces increase the risk of tool misuse and "
                            "make it harder to audit what the server can do.",
                recommendation="Consider splitting into multiple focused MCP servers. "
                               "Each server should follow the principle of least privilege.",
                owasp_asi=["ASI02", "ASI08"],
            ))

        # 4. Check for tools with empty or very short descriptions
        for tool in tools:
            if len(tool.description.strip()) < 10:
                findings.append(Finding(
                    id=f"live_{server_name}_{tool.name}_no_desc",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.METADATA,
                    title=f"Tool '{tool.name}' has minimal description",
                    description=f"[RUNTIME] Tool '{tool.name}' has a very short or empty "
                                f"description ('{tool.description[:30]}'). Tools without clear "
                                "descriptions are harder to audit and may hide functionality.",
                    recommendation="Tool descriptions should clearly state what the tool does "
                                   "and what side effects it has.",
                    owasp_asi=["ASI09"],
                ))

        # 5. Check for suspiciously named tools
        suspicious_tool_names = [
            (r"(?i)(debug|test|dev|internal|hidden|secret|admin|root|backdoor)", "suspicious_name"),
            (r"(?i)(exec|execute|run|shell|system|eval|command)", "dangerous_capability"),
            (r"(?i)(upload|download|transfer|send|exfil|forward|relay)", "data_movement"),
        ]
        for tool in tools:
            if tool.name in capped_tools:
                continue  # already reported with a precise capability finding
            for pattern, category in suspicious_tool_names:
                if re.search(pattern, tool.name):
                    findings.append(Finding(
                        id=f"live_{server_name}_{tool.name}_{category}",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.TOOL_POISONING,
                        title=f"Tool '{tool.name}' has suspicious name pattern: {category}",
                        description=f"[RUNTIME] Tool name '{tool.name}' matches the "
                                    f"'{category}' pattern. Review what this tool actually does.",
                        recommendation="Verify this tool's functionality matches its name.",
                        owasp_asi=["ASI01", "ASI02"],
                    ))
                    break  # One finding per tool

        # 6. Check for tools with input schemas that accept arbitrary objects
        for tool in tools:
            schema = tool.input_schema
            if isinstance(schema, dict):
                props = schema.get("properties", {})
                for prop_name, prop_def in props.items():
                    if isinstance(prop_def, dict):
                        # Check for overly permissive types
                        if prop_def.get("type") == "string" and any(
                            kw in prop_name.lower()
                            for kw in ["code", "script", "command", "query", "sql", "shell", "exec"]
                        ):
                            findings.append(Finding(
                                id=f"live_{server_name}_{tool.name}_{prop_name}_code_input",
                                severity=FindingSeverity.HIGH,
                                category=FindingCategory.CODE_EXECUTION,
                                title=f"Tool '{tool.name}' accepts code-like input '{prop_name}'",
                                description=f"[RUNTIME] Tool '{tool.name}' has a string parameter "
                                            f"named '{prop_name}' which suggests it accepts "
                                            "code, commands, or queries for execution.",
                                recommendation="Validate and sanitize this input. Implement "
                                               "allowlists for permitted operations.",
                                owasp_asi=["ASI05"],
                            ))

        return findings

    def analyze_runtime_content(self, result: "LiveScanResult", server_name: str) -> List[Finding]:
        """Run the text rules on what the server said (instructions) and served (resources,
        prompts). These are the three things a description-only scan can never see."""
        findings: List[Finding] = []
        dangerous = dangerous_tool_map(result.runtime_tools)
        sname = _slug(server_name)
        findings.extend(detect_sensitive_resources(
            result.runtime_resources, unauthenticated=not result.auth_provided,
            id_prefix=f"live_{sname}_resource"))
        if result.server_instructions:
            findings.extend(tool_poisoning_detector.scan_text(
                result.server_instructions, "server instructions",
                f"live_{sname}_instructions", dangerous_tools=dangerous,
            ))
        for uri, text in result.resource_contents.items():
            findings.extend(tool_poisoning_detector.scan_text(
                text, f"resource '{uri}'", f"live_{sname}_resource_{_slug(uri)}", dangerous_tools=dangerous,
            ))
        for name, messages in result.prompt_messages.items():
            findings.extend(tool_poisoning_detector.scan_text(
                "\n".join(messages), f"prompt '{name}'", f"live_{sname}_prompt_{_slug(name)}",
                dangerous_tools=dangerous,
            ))
        for f in findings:
            f.description = f"[RUNTIME] {f.description}"
        return findings

    @staticmethod
    def _deep_diff_schema(
        source_schema: Dict[str, Any],
        runtime_schema: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Deep-diff two JSON Schema objects and return structured differences.

        Returns dict with: added_properties, removed_properties,
        changed_properties, required_changed.
        """
        src_props = source_schema.get("properties", {})
        rtm_props = runtime_schema.get("properties", {})
        src_names = set(src_props.keys())
        rtm_names = set(rtm_props.keys())

        added = sorted(rtm_names - src_names)
        removed = sorted(src_names - rtm_names)

        changed = []
        for name in sorted(src_names & rtm_names):
            src_def = src_props[name]
            rtm_def = rtm_props[name]
            if src_def != rtm_def:
                changed.append(name)

        src_required = set(source_schema.get("required", []))
        rtm_required = set(runtime_schema.get("required", []))
        required_changed = src_required != rtm_required

        return {
            "added_properties": added,
            "removed_properties": removed,
            "changed_properties": changed,
            "required_changed": required_changed,
            "added_required": sorted(rtm_required - src_required),
            "removed_required": sorted(src_required - rtm_required),
        }

    def diff_source_vs_runtime(
        self,
        source_tools: List[MCPToolDefinition],
        runtime_tools: List[MCPToolDefinition],
        server_name: str,
    ) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Compare source-code-extracted tool definitions against runtime definitions.
        This is the key defense against supply chain attacks where published source
        differs from what the server actually exposes.
        """
        findings = []

        source_map = {t.name: t for t in source_tools}
        runtime_map = {t.name: t for t in runtime_tools}

        source_names = set(source_map.keys())
        runtime_names = set(runtime_map.keys())

        # Tools only in runtime (not in source) — CRITICAL
        runtime_only = runtime_names - source_names
        # Tools only in source (not in runtime) — informational
        source_only = source_names - runtime_names
        # Tools in both — check for description mutations
        both = source_names & runtime_names

        diff_summary = {
            "runtime_only": list(runtime_only),
            "source_only": list(source_only),
            "in_both": list(both),
            "description_mutations": [],
            "schema_mutations": [],
        }

        # Runtime-only tools: high risk — these could be hidden/injected tools
        for name in runtime_only:
            tool = runtime_map[name]
            findings.append(Finding(
                id=f"diff_{server_name}_{name}_runtime_only",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.TOOL_POISONING,
                title=f"Hidden tool '{name}' — present at runtime but NOT in source code",
                description=f"[DIFF] Tool '{name}' is exposed by the running server but does "
                            f"not appear in the source code. Description: '{tool.description[:200]}'. "
                            "This could indicate a supply chain compromise, backdoor, or "
                            "tool injection attack.",
                recommendation="URGENT: Investigate immediately. Compare the installed package "
                               "against the published source. This tool may have been injected "
                               "via a compromised dependency or build pipeline.",
                owasp_asi=["ASI01", "ASI04", "ASI10"],
            ))

        # Source-only tools: informational — server may not register all tools
        for name in source_only:
            findings.append(Finding(
                id=f"diff_{server_name}_{name}_source_only",
                severity=FindingSeverity.INFO,
                category=FindingCategory.METADATA,
                title=f"Tool '{name}' found in source but not exposed at runtime",
                description=f"[DIFF] Tool '{name}' is defined in the source code but the "
                            "running server does not expose it. This may be a disabled feature, "
                            "conditional registration, or code that hasn't been deployed.",
                recommendation="Verify whether this tool should be active or disabled.",
                owasp_asi=["ASI09"],
            ))

        # Description mutations: compare source vs runtime descriptions
        for name in both:
            src = source_map[name]
            rtm = runtime_map[name]

            if src.description.strip() != rtm.description.strip():
                # Calculate similarity
                src_words = set(src.description.lower().split())
                rtm_words = set(rtm.description.lower().split())
                if src_words and rtm_words:
                    overlap = len(src_words & rtm_words)
                    total = len(src_words | rtm_words)
                    similarity = overlap / total if total > 0 else 0
                else:
                    similarity = 0

                # Severity depends on how different they are
                if similarity < 0.3:
                    severity = FindingSeverity.CRITICAL
                    detail = "substantially different"
                elif similarity < 0.7:
                    severity = FindingSeverity.HIGH
                    detail = "notably different"
                else:
                    severity = FindingSeverity.MEDIUM
                    detail = "slightly different"

                diff_summary["description_mutations"].append({
                    "tool": name,
                    "source_desc": src.description[:200],
                    "runtime_desc": rtm.description[:200],
                    "similarity": round(similarity, 2),
                })

                findings.append(Finding(
                    id=f"diff_{server_name}_{name}_desc_mutation",
                    severity=severity,
                    category=FindingCategory.TOOL_POISONING,
                    title=f"Tool '{name}' description MUTATED between source and runtime",
                    description=f"[DIFF] Tool '{name}' has a {detail} description at runtime "
                                f"vs source code (similarity: {similarity:.0%}). "
                                f"Source: '{src.description[:100]}...' → "
                                f"Runtime: '{rtm.description[:100]}...'. "
                                "Description mutations are the #1 tool poisoning vector.",
                    recommendation="Compare the full descriptions. Runtime mutations may indicate "
                                   "a poisoned dependency or build-time injection. Re-scan the "
                                   "source code and verify the installed package integrity.",
                    owasp_asi=["ASI01", "ASI04"],
                ))

            # Schema mutations — deep diff
            if src.input_schema != rtm.input_schema and (src.input_schema or rtm.input_schema):
                schema_detail = self._deep_diff_schema(
                    src.input_schema or {}, rtm.input_schema or {},
                )
                diff_summary["schema_mutations"].append({
                    "tool": name,
                    "source_schema": src.input_schema,
                    "runtime_schema": rtm.input_schema,
                    **schema_detail,
                })

                # Added params at runtime are the highest risk
                added = schema_detail.get("added_properties", [])
                removed = schema_detail.get("removed_properties", [])
                changed = schema_detail.get("changed_properties", [])

                if added:
                    severity = FindingSeverity.CRITICAL
                    detail_parts = [
                        f"Parameters ADDED at runtime: {', '.join(added)}."
                    ]
                    if any(kw in p.lower() for p in added
                           for kw in ("url", "webhook", "endpoint", "token",
                                      "key", "secret", "password", "code",
                                      "command", "script", "query", "callback")):
                        detail_parts.append(
                            "WARNING: Added parameter name suggests data extraction "
                            "or code execution."
                        )
                else:
                    severity = FindingSeverity.HIGH
                    detail_parts = []

                if removed:
                    detail_parts.append(
                        f"Parameters REMOVED at runtime: {', '.join(removed)}."
                    )
                if changed:
                    detail_parts.append(
                        f"Parameters with changed types: {', '.join(changed)}."
                    )
                if schema_detail.get("required_changed"):
                    detail_parts.append("Required fields differ between source and runtime.")

                findings.append(Finding(
                    id=f"diff_{server_name}_{name}_schema_mutation",
                    severity=severity,
                    category=FindingCategory.TOOL_POISONING,
                    title=f"Tool '{name}' input schema differs between source and runtime",
                    description=(
                        f"[DIFF] Tool '{name}' accepts different parameters at runtime "
                        "vs what the source code defines. "
                        + " ".join(detail_parts)
                    ),
                    recommendation="Compare the input schemas. Added parameters in the runtime "
                                   "schema may be used to extract information from the AI agent.",
                    owasp_asi=["ASI01", "ASI02"],
                ))

        return findings, diff_summary


# ============================================================
# Main Live Scanner
# ============================================================

class MCPLiveScanner:
    """
    High-level live MCP server scanner.
    Orchestrates connection, introspection, and analysis.
    """

    def __init__(self):
        self.analyzer = RuntimeToolAnalyzer()

    async def scan_stdio(
        self,
        command: str,
        args: List[str] = None,
        env: Dict[str, str] = None,
        server_name: str = None,
        source_tools: List[MCPToolDefinition] = None,
        read_contents: bool = True,
    ) -> LiveScanResult:
        """
        Scan an MCP server via stdio transport.

        Args:
            command: Command to spawn the server (e.g., "npx", "python", "node")
            args: Command arguments (e.g., ["-y", "@mcp/server-filesystem", "/tmp"])
            env: Environment variables to pass to the server
            server_name: Display name (auto-detected if not provided)
            source_tools: Tools from static analysis for diff comparison
            read_contents: Also read resource contents and fetch prompt text (never calls tools)
        """
        args = args or []
        env = env or {}
        if not server_name:
            server_name = self._infer_name(command, args)

        result = LiveScanResult(server_name=server_name, transport="stdio")
        start_time = datetime.now(timezone.utc)
        client = MCPProtocolClient()

        try:
            # Wrap entire scan in an overall timeout to prevent hanging
            await asyncio.wait_for(
                self._run_stdio_scan(client, result, server_name, source_tools,
                                     command, args, env, read_contents),
                timeout=LIVE_SCAN_TIMEOUT,
            )
        except asyncio.TimeoutError:
            result.status = "error"
            result.error = (
                f"Overall scan timeout ({LIVE_SCAN_TIMEOUT}s) exceeded. "
                f"The server may be unresponsive or too slow to introspect."
            )
        except ConnectionError as e:
            result.status = "error"
            result.error = f"Connection failed: {e}"
        except TimeoutError as e:
            result.status = "error"
            result.error = f"Timeout: {e}"
        except RuntimeError as e:
            result.status = "error"
            result.error = f"Server error: {e}"
        except Exception as e:
            result.status = "error"
            result.error = f"Unexpected error: {type(e).__name__}: {e}"
        finally:
            await client.shutdown()

        end_time = datetime.now(timezone.utc)
        result.scan_duration_seconds = (end_time - start_time).total_seconds()

        return result

    async def _run_stdio_scan(
        self,
        client: MCPProtocolClient,
        result: LiveScanResult,
        server_name: str,
        source_tools: Optional[List[MCPToolDefinition]],
        command: str,
        args: List[str],
        env: Dict[str, str],
        read_contents: bool = True,
    ) -> None:
        """Inner scan logic, separated so it can be wrapped in asyncio.wait_for."""
        # 1. Connect and initialize
        init_response = await client.connect_stdio(command, args, env)
        result.status = "connected"
        result.server_info = init_response.get("serverInfo", {})
        result.server_capabilities = init_response.get("capabilities", {})
        result.protocol_version = init_response.get("protocolVersion", "")
        result.server_instructions = str(init_response.get("instructions") or "")

        # 2. Introspect — list all tools, resources, prompts
        raw_tools = await client.list_tools()
        raw_resources = await client.list_resources()
        raw_prompts = await client.list_prompts()

        # 3. Convert to Axiom models
        result.runtime_tools = self._parse_tools(raw_tools)
        result.runtime_resources = self._parse_resources(raw_resources)
        result.runtime_prompts = self._parse_prompts(raw_prompts)

        # 3b. Read what was listed (resources/read, prompts/get) — never tools/call
        if read_contents:
            await self._read_runtime_content(client, result)

        # 4. Security analysis on runtime definitions and content
        runtime_findings = self.analyzer.analyze_runtime_tools(
            result.runtime_tools, server_name
        )
        result.findings.extend(runtime_findings)
        result.findings.extend(self.analyzer.analyze_runtime_content(result, server_name))

        # 5. Diff against source if available
        if source_tools:
            diff_findings, diff_summary = self.analyzer.diff_source_vs_runtime(
                source_tools, result.runtime_tools, server_name
            )
            result.findings.extend(diff_findings)
            result.diff_results = diff_summary

        # 6. Server capability analysis
        cap_findings = self._analyze_capabilities(
            result.server_capabilities, server_name
        )
        result.findings.extend(cap_findings)

        # 7. Tag all findings with OWASP ASI refs
        for finding in result.findings:
            if not finding.owasp_asi and finding.category in CATEGORY_TO_ASI:
                finding.owasp_asi = CATEGORY_TO_ASI[finding.category]

        # 8. Score and level
        enrich_findings(result.findings, mode="live", target=getattr(result, "_replay_target", None) or result.server_name,
                        replay_cmd=getattr(result, "_replay_cmd", None))
        result.risk_score = self._calculate_risk_score(result.findings)
        result.risk_level = self._score_to_level(result.risk_score)

        apply_owasp_mcp_mapping(result.findings)

        # 9. OWASP coverage
        result.owasp_coverage = generate_owasp_coverage(result.findings)
        result.owasp_mcp_coverage = generate_owasp_mcp_coverage(result.findings)

        result.status = "completed"

    async def scan_sse(
        self,
        url: str,
        server_name: str = None,
        source_tools: List[MCPToolDefinition] = None,
        read_contents: bool = True,
        transport: str = "auto",
        headers: Dict[str, str] = None,
    ) -> LiveScanResult:
        """Scan a remote MCP server (Streamable HTTP or legacy HTTP+SSE; ``transport``
        is "auto", "streamable-http" or "sse"). ``headers`` are sent on every request
        (e.g. Authorization). Kept under its historical name; ``scan_remote`` is the alias."""
        if not server_name:
            server_name = url.split("//")[-1].split("/")[0]

        result = LiveScanResult(server_name=server_name, transport="remote")
        start_time = datetime.now(timezone.utc)
        holder: Dict[str, Any] = {"client": None}

        try:
            await asyncio.wait_for(
                self._run_sse_scan(holder, result, server_name, url, source_tools, read_contents,
                                   transport, headers or {}),
                timeout=LIVE_SCAN_TIMEOUT,
            )
        except asyncio.TimeoutError:
            result.status = "error"
            result.error = (
                f"Overall remote scan timeout ({LIVE_SCAN_TIMEOUT}s) exceeded. "
                f"The server at {url} may be unresponsive."
            )
        except Exception as e:
            result.status = "error"
            result.error = str(e)
        finally:
            if holder["client"] is not None:
                await holder["client"].shutdown()

        end_time = datetime.now(timezone.utc)
        result.scan_duration_seconds = (end_time - start_time).total_seconds()
        return result

    scan_remote = scan_sse

    async def _run_sse_scan(
        self,
        holder: Dict[str, Any],
        result: LiveScanResult,
        server_name: str,
        url: str,
        source_tools: Optional[List[MCPToolDefinition]],
        read_contents: bool = True,
        transport: str = "auto",
        headers: Dict[str, str] = None,
    ) -> None:
        """Inner remote scan logic, separated so it can be wrapped in asyncio.wait_for."""
        headers = headers or {}
        client, init_response = await connect_remote(url, headers, transport)
        holder["client"] = client
        result.transport = client.transport
        result.status = "connected"
        result.auth_provided = any(h.lower() in ("authorization", "x-api-key", "cookie") for h in headers)
        result.server_info = init_response.get("serverInfo", {})
        result.server_capabilities = init_response.get("capabilities", {})
        result.protocol_version = init_response.get("protocolVersion", "")
        result.server_instructions = str(init_response.get("instructions") or "")

        raw_tools = await client.list_tools()
        raw_resources = await client.list_resources()
        raw_prompts = await client.list_prompts()

        result.runtime_tools = self._parse_tools(raw_tools)
        result.runtime_resources = self._parse_resources(raw_resources)
        result.runtime_prompts = self._parse_prompts(raw_prompts)

        if read_contents:
            await self._read_runtime_content(client, result)

        runtime_findings = self.analyzer.analyze_runtime_tools(
            result.runtime_tools, server_name
        )
        result.findings.extend(runtime_findings)
        result.findings.extend(self.analyzer.analyze_runtime_content(result, server_name))

        cap_findings = self._analyze_capabilities(result.server_capabilities, server_name)
        result.findings.extend(cap_findings)

        if source_tools:
            diff_findings, diff_summary = self.analyzer.diff_source_vs_runtime(
                source_tools, result.runtime_tools, server_name
            )
            result.findings.extend(diff_findings)
            result.diff_results = diff_summary

        # Remote-specific: transport security and authentication
        # Severity depends on where the server is (docs/SEVERITY.md): loopback INFO,
        # private range LOW, public HIGH. A dev server on 127.0.0.1 is not a finding.
        t_sev, t_why = transport_severity(url)
        if not url.startswith("https://"):
            result.findings.append(Finding(
                id=f"live_{_slug(server_name)}_plain_http",
                severity=t_sev,
                category=FindingCategory.TRANSPORT_SECURITY,
                title="Remote MCP server accessed over plain HTTP",
                description=f"[RUNTIME] Server at {url} is being accessed over unencrypted "
                            f"HTTP; {t_why}. "
                            + ("All tool calls and responses are visible to network eavesdroppers."
                               if t_sev == FindingSeverity.HIGH else "No off-host eavesdropper can see this traffic."),
                recommendation="Use HTTPS with valid TLS certificates for anything reachable beyond this machine.",
                owasp_asi=["ASI07"],
            ))
        if not result.auth_provided:
            result.findings.append(Finding(
                id=f"live_{_slug(server_name)}_no_auth",
                severity=t_sev,
                category=FindingCategory.TRANSPORT_SECURITY,
                title="Remote MCP server accepted an unauthenticated session",
                description=f"[RUNTIME] {url} completed initialize and listed {len(result.runtime_tools)} "
                            f"tool(s) without any credential; {t_why}. "
                            + ("Anyone who can reach the port can drive these tools."
                               if t_sev != FindingSeverity.INFO else "Only processes on this machine can reach it."),
                recommendation="Require OAuth 2.1 / bearer authentication on any MCP endpoint that is not bound to localhost.",
                owasp_asi=["ASI03", "ASI07"],
            ))

        for finding in result.findings:
            if not finding.owasp_asi and finding.category in CATEGORY_TO_ASI:
                finding.owasp_asi = CATEGORY_TO_ASI[finding.category]

        enrich_findings(result.findings, mode="live", target=getattr(result, "_replay_target", None) or result.server_name,
                        replay_cmd=getattr(result, "_replay_cmd", None))
        result.risk_score = self._calculate_risk_score(result.findings)
        result.risk_level = self._score_to_level(result.risk_score)
        apply_owasp_mcp_mapping(result.findings)
        result.owasp_coverage = generate_owasp_coverage(result.findings)
        result.owasp_mcp_coverage = generate_owasp_mcp_coverage(result.findings)
        result.status = "completed"

    async def scan_config_entry(
        self,
        entry: MCPConfigEntry,
        source_tools: List[MCPToolDefinition] = None,
        read_contents: bool = True,
    ) -> LiveScanResult:
        """Scan an MCP server from a local config entry."""
        if entry.transport in (TransportType.SSE, TransportType.HTTP):
            # Find the URL from args or env
            url = None
            for arg in entry.args:
                if arg.startswith("http"):
                    url = arg
                    break
            if not url:
                return LiveScanResult(
                    server_name=entry.name,
                    transport="sse",
                    status="error",
                    error="Cannot determine SSE URL from config entry",
                )
            return await self.scan_sse(url, entry.name, source_tools, read_contents=read_contents)

        # Stdio transport
        return await self.scan_stdio(
            command=entry.command,
            args=entry.args,
            env=entry.env,
            server_name=entry.name,
            source_tools=source_tools,
            read_contents=read_contents,
        )

    async def scan_all_local(
        self,
        custom_paths: List[str] = None,
        server_filter: str = None,
        read_contents: bool = True,
    ) -> List[LiveScanResult]:
        """
        Discover all local MCP servers and scan them live.
        Optionally filter to a specific server by name.
        """
        from app.analysis.local_config import local_scanner

        # Discover servers from local configs
        config_result = local_scanner.scan_all(custom_paths)
        entries = config_result["servers_discovered"]

        if server_filter:
            entries = [e for e in entries if server_filter.lower() in e.name.lower()]

        results = []
        for entry in entries:
            try:
                result = await self.scan_config_entry(entry, read_contents=read_contents)
                results.append(result)
            except Exception as e:
                results.append(LiveScanResult(
                    server_name=entry.name,
                    transport=entry.transport.value,
                    status="error",
                    error=str(e),
                ))

        return results

    # ---- Helpers ----

    def _parse_tools(self, raw_tools: List[Dict[str, Any]]) -> List[MCPToolDefinition]:
        """Convert raw JSON tool definitions to MCPToolDefinition models."""
        tools = []
        for raw in raw_tools:
            if not isinstance(raw, dict):
                continue
            tools.append(MCPToolDefinition(
                name=raw.get("name", "unknown"),
                description=raw.get("description", ""),
                input_schema=raw.get("inputSchema", raw.get("input_schema", {})),
            ))
        return tools

    def _parse_resources(self, raw: List[Dict[str, Any]]) -> List[MCPResourceDefinition]:
        resources = []
        for r in raw:
            if not isinstance(r, dict):
                continue
            resources.append(MCPResourceDefinition(
                uri=r.get("uri", ""),
                name=r.get("name", ""),
                description=r.get("description", ""),
                mime_type=r.get("mimeType"),
            ))
        return resources

    def _parse_prompts(self, raw: List[Dict[str, Any]]) -> List[MCPPromptDefinition]:
        prompts = []
        for p in raw:
            if not isinstance(p, dict):
                continue
            prompts.append(MCPPromptDefinition(
                name=p.get("name", ""),
                description=p.get("description", ""),
                arguments=p.get("arguments", []),
            ))
        return prompts

    async def _read_runtime_content(self, client, result: LiveScanResult) -> None:
        """Read listed resources and fetch listed prompts, within strict limits.
        Skips http(s) resources (reading them makes the server do egress), non-text mime
        types and prompts with required arguments. Never calls tools/call."""
        read = 0
        for res in result.runtime_resources:
            if read >= MAX_RESOURCES_READ:
                break
            uri = res.uri or ""
            if not uri or uri.lower().startswith(("http://", "https://")):
                continue
            if res.mime_type and not res.mime_type.lower().startswith(READABLE_MIME_PREFIXES):
                continue
            response = await client.read_resource(uri)
            if not response:
                continue
            texts = [c.get("text") for c in response.get("contents", []) if isinstance(c, dict) and c.get("text")]
            if texts:
                result.resource_contents[uri] = "\n".join(texts)[:MAX_CONTENT_BYTES]
            read += 1

        fetched = 0
        for prompt in result.runtime_prompts:
            if fetched >= MAX_PROMPTS_GET:
                break
            if any(isinstance(a, dict) and a.get("required") for a in prompt.arguments):
                continue
            response = await client.get_prompt(prompt.name, {})
            if not response:
                continue
            texts = []
            for msg in response.get("messages", []):
                content = msg.get("content") if isinstance(msg, dict) else None
                if isinstance(content, dict) and content.get("text"):
                    texts.append(str(content["text"]))
                elif isinstance(content, list):
                    texts.extend(str(c.get("text")) for c in content if isinstance(c, dict) and c.get("text"))
                elif isinstance(content, str):
                    texts.append(content)
            if texts:
                result.prompt_messages[prompt.name] = [t[:MAX_CONTENT_BYTES] for t in texts]
            fetched += 1

    def _analyze_capabilities(
        self, capabilities: Dict[str, Any], server_name: str
    ) -> List[Finding]:
        """Analyze server capabilities from initialize response."""
        findings = []

        # Tool list may change after approval (rug-pull surface)
        tools_cap = capabilities.get("tools") if isinstance(capabilities, dict) else None
        if isinstance(tools_cap, dict) and tools_cap.get("listChanged") is True:
            findings.append(Finding(
                id=f"live_{_slug(server_name)}_tools_list_changed",
                severity=FindingSeverity.LOW,
                category=FindingCategory.RUG_PULL_PRIMITIVE,
                title="Server advertises that its tool list can change at runtime",
                description=f"[RUNTIME] Server '{server_name}' sets tools.listChanged=true. Tools "
                            "approved now may be replaced later without re-approval.",
                recommendation="Re-scan whenever the server signals a tool list change; prefer servers with a static tool set.",
                owasp_asi=["ASI04", "ASI10"],
            ))

        # Check for experimental or unusual capabilities
        known_caps = {"tools", "resources", "prompts", "logging", "experimental"}
        unknown_caps = set(capabilities.keys()) - known_caps
        if unknown_caps:
            findings.append(Finding(
                id=f"live_{server_name}_unknown_caps",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.METADATA,
                title=f"Server declares unknown capabilities: {', '.join(unknown_caps)}",
                description=f"[RUNTIME] Server '{server_name}' declares capabilities not in the "
                            f"standard MCP spec: {', '.join(unknown_caps)}. These may be custom "
                            "extensions that bypass normal security controls.",
                recommendation="Review what these custom capabilities do.",
                owasp_asi=["ASI02"],
            ))

        # Check for experimental features
        if "experimental" in capabilities:
            findings.append(Finding(
                id=f"live_{server_name}_experimental",
                severity=FindingSeverity.LOW,
                category=FindingCategory.METADATA,
                title=f"Server uses experimental MCP capabilities",
                description=f"[RUNTIME] Server '{server_name}' declares experimental capabilities. "
                            "Experimental features may have undocumented security implications.",
                recommendation="Monitor for spec changes that may affect security.",
                owasp_asi=["ASI02"],
            ))

        return findings

    def _infer_name(self, command: str, args: List[str]) -> str:
        """Infer a server name from its command and arguments."""
        if command in ("npx", "npx.cmd") and args:
            for arg in args:
                if not arg.startswith("-"):
                    return arg.split("/")[-1].split("@")[0]
        if command in ("uvx", "uv") and args:
            for arg in args:
                if not arg.startswith("-") and arg != "run":
                    return arg
        exe = os.path.splitext(os.path.basename(command))[0].lower()
        if exe.startswith(("python", "node", "deno", "bun")) and args:
            for arg in args:
                if not arg.startswith("-"):
                    return os.path.splitext(os.path.basename(arg))[0]
        return os.path.basename(command)

    def _calculate_risk_score(self, findings: List[Finding]) -> float:
        """docs/SEVERITY.md: the worst finding sets the band; breadth adds inside it."""
        return _policy_score(findings)

    def _score_to_level(self, score: float) -> RiskLevel:
        return _policy_level(score)


# Singleton
live_scanner = MCPLiveScanner()
