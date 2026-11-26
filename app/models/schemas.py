"""
Axiom Data Models
Deeply typed for MCP-specific security concepts.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime


# ============================================================
# Enums
# ============================================================

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    TOOL_POISONING = "tool_poisoning"
    PROMPT_INJECTION = "prompt_injection"
    CREDENTIAL_THEFT = "credential_theft"
    DATA_EXFILTRATION = "data_exfiltration"
    CODE_EXECUTION = "code_execution"
    SANDBOX_ESCAPE = "sandbox_escape"
    COMMAND_INJECTION = "command_injection"
    TRANSPORT_SECURITY = "transport_security"
    PERMISSION_OVERSCOPE = "permission_overscope"
    DEPENDENCY_VULN = "dependency_vuln"
    SUPPLY_CHAIN = "supply_chain"
    CROSS_SERVER = "cross_server"
    OBFUSCATION = "obfuscation"
    CONFIG_RISK = "config_risk"
    KNOWN_CVE = "known_cve"
    METADATA = "metadata"
    # OWASP Agentic AI Top 10 — new categories
    TOXIC_TOOL_COMBO = "toxic_tool_combo"         # ASI02
    IDENTITY_PRIVILEGE = "identity_privilege"       # ASI03
    CODE_GENERATION = "code_generation"             # ASI05
    MEMORY_POISONING = "memory_poisoning"           # ASI06
    INTER_AGENT_COMM = "inter_agent_comm"           # ASI07
    CASCADING_FAILURE = "cascading_failure"          # ASI08
    TRUST_EXPLOITATION = "trust_exploitation"        # ASI09
    ROGUE_AGENT = "rogue_agent"                     # ASI10
    # OWASP MCP Top 10 — new categories
    AUDIT_TELEMETRY = "audit_telemetry"             # MCP08
    CONTEXT_OVERSHARING = "context_oversharing"     # MCP10
    # Phase 2 — specific, per-tool findings (test-bed gap list)
    TOOL_SHADOWING = "tool_shadowing"               # description rewires other tools/servers
    HIDDEN_UNICODE = "hidden_unicode"               # invisible code points carrying text
    HOMOGLYPH = "homoglyph"                         # confusable / lookalike tool names
    RUG_PULL_PRIMITIVE = "rug_pull_primitive"       # add_tool/remove_tool after approval
    SURFACE_MISMATCH = "surface_mismatch"           # live surface differs from the published source
    RESPONSE_INJECTION = "response_injection"       # instructions in what a tool returns
    EXCESSIVE_SCOPE = "excessive_scope"             # schema defaults asking for everything
    CONFUSED_DEPUTY = "confused_deputy"             # caller-supplied target + server credential
    SHELL_EXEC = "shell_exec"                       # tool executes commands
    FILE_READ = "file_read"                         # tool reads arbitrary files
    FILE_WRITE = "file_write"                       # tool writes/deletes arbitrary files
    ENV_DUMP = "env_dump"                           # tool exposes environment / credentials


class OWASPAgenticRisk(str, Enum):
    """OWASP Top 10 for Agentic Applications 2026 (ASI prefix)."""
    ASI01 = "ASI01"  # Agent Goal Hijack
    ASI02 = "ASI02"  # Tool Misuse & Exploitation
    ASI03 = "ASI03"  # Identity & Privilege Abuse
    ASI04 = "ASI04"  # Agentic Supply Chain Vulnerabilities
    ASI05 = "ASI05"  # Unexpected Code Execution
    ASI06 = "ASI06"  # Memory & Context Poisoning
    ASI07 = "ASI07"  # Insecure Inter-Agent Communication
    ASI08 = "ASI08"  # Cascading Failures
    ASI09 = "ASI09"  # Human-Agent Trust Exploitation
    ASI10 = "ASI10"  # Rogue Agents


class OwaspMcp(str, Enum):
    """OWASP MCP Top 10 (MCP prefix). Titles live in data/owasp_mcp_top10.json."""
    MCP01 = "MCP01"
    MCP02 = "MCP02"
    MCP03 = "MCP03"
    MCP04 = "MCP04"
    MCP05 = "MCP05"
    MCP06 = "MCP06"
    MCP07 = "MCP07"
    MCP08 = "MCP08"
    MCP09 = "MCP09"
    MCP10 = "MCP10"


class TransportType(str, Enum):
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"
    UNKNOWN = "unknown"


# ============================================================
# MCP-Specific Models
# ============================================================

class MCPToolDefinition(BaseModel):
    """Parsed MCP tool definition from a server."""
    name: str
    description: str = ""
    input_schema: Dict[str, Any] = {}
    has_hidden_instructions: bool = False
    poisoning_risk: RiskLevel = RiskLevel.SAFE
    poisoning_detail: Optional[str] = None


class MCPResourceDefinition(BaseModel):
    """Parsed MCP resource definition."""
    uri: str
    name: str = ""
    description: str = ""
    mime_type: Optional[str] = None


class MCPPromptDefinition(BaseModel):
    """Parsed MCP prompt definition."""
    name: str
    description: str = ""
    arguments: List[Dict[str, Any]] = []


class MCPServerProfile(BaseModel):
    """Full profile of an MCP server's capabilities and risk surface."""
    name: str
    command: Optional[str] = None
    args: List[str] = []
    env_vars: List[str] = []
    transport: TransportType = TransportType.UNKNOWN
    tools: List[MCPToolDefinition] = []
    resources: List[MCPResourceDefinition] = []
    prompts: List[MCPPromptDefinition] = []
    repo_url: Optional[str] = None
    npm_package: Optional[str] = None
    capabilities_claimed: List[str] = []
    capabilities_actual: List[str] = []


class MCPConfigEntry(BaseModel):
    """A single MCP server entry from a local config file."""
    name: str
    command: str
    args: List[str] = []
    env: Dict[str, str] = {}
    source_file: str = ""
    transport: TransportType = TransportType.STDIO
    url: Optional[str] = None   # remote endpoint for SSE/HTTP entries


# ============================================================
# Findings & Reports
# ============================================================

class Finding(BaseModel):
    """A single security finding."""
    id: str
    severity: FindingSeverity
    category: FindingCategory
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    recommendation: str = ""
    cve_id: Optional[str] = None
    mitre_ref: Optional[str] = None
    owasp_asi: Optional[List[str]] = None  # OWASP Agentic Top 10 refs e.g. ["ASI01", "ASI02"]
    owasp_mcp: Optional[List[str]] = None  # OWASP MCP Top 10 refs e.g. ["MCP03", "MCP06"]
    related: Optional[List[str]] = None  # Analogous refs in other taxonomies, e.g. ["MCP07:2025"] on A2A findings
    # Replayable findings (docs: every finding can be confirmed without trusting Axiom)
    rule_id: str = ""      # stable rule name, independent of the tool/file it fired on
    evidence: str = ""     # the exact text the rule matched (never a secret value)
    location: str = ""     # <file>:<line> | live:<method>:<item> | config:<file> | static:<target>:<item>
    replay: str = ""       # the command / JSON-RPC request that reproduces it


class DependencyInfo(BaseModel):
    name: str
    version: str
    ecosystem: str
    has_vulnerabilities: bool = False
    vulnerability_count: int = 0
    vulns: List[str] = []
    direct: bool = True          # declared in a manifest (False: only in a lockfile)
    source: str = ""             # package.json / pyproject.toml / requirements.txt / lockfile
    # Not serialised. Used to match a dependency on an exact version (dependencies.exact_version).
    declared_spec: Optional[str] = Field(default=None, exclude=True)    # the manifest's version text, as written
    locked_version: Optional[str] = Field(default=None, exclude=True)   # the lockfile's version, when there is one


class RepoHealth(BaseModel):
    """GitHub repo health signals."""
    stars: int = 0
    forks: int = 0
    open_issues: int = 0
    last_commit_days_ago: int = 0
    contributor_count: int = 0
    created_days_ago: int = 0
    has_security_policy: bool = False
    has_code_of_conduct: bool = False
    license: Optional[str] = None
    is_archived: bool = False
    is_fork: bool = False


# ============================================================
# API Request/Response
# ============================================================

class ScanRequest(BaseModel):
    """Request to scan an MCP server."""
    target: str = Field(..., description="MCP server name or GitHub repo URL")
    target_url: Optional[str] = Field(None, description="GitHub repo URL if target is a name")
    scan_local_config: bool = Field(False, description="Also scan local MCP configs for this server")

    class Config:
        json_schema_extra = {
            "examples": [
                {"target": "https://github.com/modelcontextprotocol/servers", "target_url": None},
                {"target": "filesystem-mcp", "target_url": "https://github.com/user/filesystem-mcp"},
            ]
        }


class LocalConfigScanRequest(BaseModel):
    """Request to scan local MCP configuration files."""
    config_paths: List[str] = Field(
        default=[],
        description="Custom paths to MCP config files. If empty, scans default locations."
    )


class ScanResponse(BaseModel):
    """Full MCP scan result."""
    id: str
    target: str
    target_url: Optional[str] = None
    status: str
    risk_score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    server_profile: Optional[MCPServerProfile] = None
    findings: List[Finding] = []
    dependencies: List[DependencyInfo] = []
    repo_health: Optional[RepoHealth] = None
    ai_analysis: Optional[str] = None
    tool_poisoning_report: Optional[str] = None
    prompt_injection_risk: Optional[str] = None
    claimed_vs_actual: Optional[str] = None
    owasp_coverage: Optional[Dict[str, Any]] = None  # OWASP Agentic Top 10 coverage
    owasp_mcp_coverage: Optional[Dict[str, Any]] = None  # OWASP MCP Top 10 coverage
    created_at: str = ""
    scan_duration_seconds: Optional[float] = None
    schema_version: str = "0.5"


class LocalConfigScanResponse(BaseModel):
    """Results from scanning local MCP configurations."""
    config_files_found: List[str] = []
    servers_discovered: List[MCPConfigEntry] = []
    findings: List[Finding] = []
    total_servers: int = 0
    schema_version: str = "0.5"


class ScanListResponse(BaseModel):
    scans: List[ScanResponse]
    total: int


# ============================================================
# A2A Agent Card Scanning (Workstream D)
# ============================================================

class A2AScanRequest(BaseModel):
    """Request to statically scan a remote A2A agent card (http/https URLs only)."""
    source: str = Field(..., description="Agent base URL or direct agent card URL (http/https)")

    model_config = {"json_schema_extra": {"examples": [{"source": "https://agent.example.com"}]}}


class A2AAgentCardSummary(BaseModel):
    """Key facts pulled from an A2A agent card."""
    name: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    provider_organization: Optional[str] = None
    provider_url: Optional[str] = None
    skill_count: int = 0
    skill_ids: List[str] = []
    scheme_names: List[str] = []
    interfaces: List[str] = []
    signed: bool = False
    signature_verified: Optional[bool] = None
    extended_card_declared: bool = False


class A2AScanResult(BaseModel):
    """Result of a static (passive) A2A agent card scan."""
    source: str
    final_url: Optional[str] = None
    discovery_path_used: Optional[str] = None
    protocol_version: Optional[str] = None
    card: Optional[A2AAgentCardSummary] = None
    findings: List[Finding] = []
    risk_score: float = Field(0.0, ge=0, le=100)
    risk_level: RiskLevel = RiskLevel.SAFE
    scope_note: str = ""
    scanned_at: str = ""
    schema_version: str = "0.5"
