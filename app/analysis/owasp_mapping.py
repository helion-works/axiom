"""
OWASP Agentic AI Top 10 (2026) Mapping & Detection
Maps Axiom findings to OWASP ASI categories and provides
additional detection for gaps in coverage.

Reference: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

Coverage:
  ASI01 Agent Goal Hijack          — ✅ Strong  (tool poisoning detector)
  ASI02 Tool Misuse & Exploitation — ✅ Strong  (toxic tool combo analysis + code patterns)
  ASI03 Identity & Privilege Abuse — ✅ Strong  (local config scanner + credential analysis)
  ASI04 Supply Chain Vulns         — ✅ Strong  (dependency CVEs, lifecycle hooks, npx)
  ASI05 Unexpected Code Execution  — ✅ Strong  (code exec patterns + code generation detection)
  ASI06 Memory & Context Poisoning — 🟡 Partial (context manipulation patterns, no runtime)
  ASI07 Inter-Agent Communication  — 🟡 Partial (transport security + A2A pattern detection)
  ASI08 Cascading Failures         — 🟡 Partial (blast radius estimation, no runtime monitoring)
  ASI09 Human-Agent Trust Exploit  — ✅ Strong  (claimed-vs-actual + deceptive output detection)
  ASI10 Rogue Agents               — 🟡 Partial (sleeper patterns + behavioral drift indicators)

Also maps findings to the OWASP MCP Top 10 (MCP01..MCP10). Item IDs/titles and
Axiom's coverage assessment live in data/owasp_mcp_top10.json.
"""

import os
import re
import json
from typing import List, Dict, Any, Set, Tuple, Optional
from app.models.schemas import (
    Finding, FindingSeverity, FindingCategory,
    MCPToolDefinition, MCPServerProfile, RiskLevel,
)

# ============================================================
# OWASP ASI definitions and Axiom mapping
# ============================================================

# published_examples: a published CVE or research demonstration that illustrates the
# category. Only entries checked against their primary source are listed (the sources
# are in data/threat_intel.py); the list is empty where none has been checked.
OWASP_AGENTIC_TOP_10 = {
    "ASI01": {
        "name": "Agent Goal Hijack",
        "description": "Manipulation of instructions, inputs, or external content to redirect an agent's objectives.",
        "mcpguard_coverage": "strong",
        "detectors": ["tool_poisoning", "prompt_injection", "instruction_injection"],
        "published_examples": ["WhatsApp MCP tool poisoning (demo)", "GitHub MCP prompt injection (demo)"],
    },
    "ASI02": {
        "name": "Tool Misuse & Exploitation",
        "description": "Agents misusing legitimate tools due to prompt manipulation, misalignment, or unsafe delegation.",
        "mcpguard_coverage": "strong",
        "detectors": ["toxic_tool_combo", "tool_overscope", "tool_chaining_detection"],
        "published_examples": [],
    },
    "ASI03": {
        "name": "Identity & Privilege Abuse",
        "description": "Exploiting inherited credentials, cached tokens, delegated permissions, or agent-to-agent trust.",
        "mcpguard_coverage": "strong",
        "detectors": ["credential_analysis", "shared_credential_detection", "env_var_audit"],
        "published_examples": ["GitHub MCP prompt injection (demo)"],
    },
    "ASI04": {
        "name": "Agentic Supply Chain Vulnerabilities",
        "description": "Compromised tools, descriptors, models, or personas influencing agent behavior.",
        "mcpguard_coverage": "strong",
        "detectors": ["dependency_cve", "lifecycle_hooks", "npx_unversioned", "known_mcp_cves"],
        "published_examples": ["CVE-2025-6514 (mcp-remote)"],
    },
    "ASI05": {
        "name": "Unexpected Code Execution",
        "description": "Agents generating or executing attacker-controlled code without safeguards.",
        "mcpguard_coverage": "strong",
        "detectors": ["code_exec_patterns", "code_generation_detection", "sandbox_escape"],
        "published_examples": ["CVE-2025-49596 (MCP Inspector)", "CVE-2025-6514 (mcp-remote)"],
    },
    "ASI06": {
        "name": "Memory & Context Poisoning",
        "description": "Corrupting agent memory, RAG data, or persistent context to alter long-term behavior.",
        "mcpguard_coverage": "partial",
        "detectors": ["memory_poisoning_patterns", "context_manipulation_detection"],
        "published_examples": [],
        "gap_note": "Axiom detects static patterns. Full coverage requires runtime memory monitoring.",
    },
    "ASI07": {
        "name": "Insecure Inter-Agent Communication",
        "description": "Spoofed or manipulated messages between collaborating agents.",
        "mcpguard_coverage": "partial",
        "detectors": ["transport_security", "a2a_pattern_detection"],
        "published_examples": [],
        "gap_note": "Axiom checks transport security. Full A2A protocol analysis requires runtime interception.",
    },
    "ASI08": {
        "name": "Cascading Failures",
        "description": "Single-point failures propagating across interconnected agents and tools.",
        "mcpguard_coverage": "partial",
        "detectors": ["blast_radius_estimation", "dependency_chain_analysis"],
        "published_examples": [],
        "gap_note": "Axiom estimates blast radius from tool capabilities. Full cascading failure analysis requires runtime topology mapping.",
    },
    "ASI09": {
        "name": "Human-Agent Trust Exploitation",
        "description": "Compromised agents misleading humans who trust their outputs.",
        "mcpguard_coverage": "strong",
        "detectors": ["claimed_vs_actual", "deceptive_output_detection", "trust_manipulation_patterns"],
        "published_examples": [],
    },
    "ASI10": {
        "name": "Rogue Agents",
        "description": "Compromised or misaligned agents that act harmfully while appearing legitimate.",
        "mcpguard_coverage": "partial",
        "detectors": ["sleeper_patterns", "behavioral_drift_indicators", "persistence_detection"],
        "published_examples": [],
        "gap_note": "Axiom detects static rogue indicators. Full rogue agent detection requires runtime behavioral monitoring.",
    },
}

# Maps FindingCategory -> OWASP ASI references
CATEGORY_TO_ASI = {
    FindingCategory.TOOL_POISONING: ["ASI01"],
    FindingCategory.PROMPT_INJECTION: ["ASI01", "ASI06"],
    FindingCategory.CREDENTIAL_THEFT: ["ASI03"],
    FindingCategory.DATA_EXFILTRATION: ["ASI01", "ASI02"],
    FindingCategory.CODE_EXECUTION: ["ASI05"],
    FindingCategory.SANDBOX_ESCAPE: ["ASI05"],
    FindingCategory.COMMAND_INJECTION: ["ASI05"],
    FindingCategory.TRANSPORT_SECURITY: ["ASI07"],
    FindingCategory.PERMISSION_OVERSCOPE: ["ASI03"],
    FindingCategory.DEPENDENCY_VULN: ["ASI04"],
    FindingCategory.SUPPLY_CHAIN: ["ASI04"],
    FindingCategory.CROSS_SERVER: ["ASI02", "ASI08"],
    FindingCategory.OBFUSCATION: ["ASI01", "ASI10"],
    FindingCategory.CONFIG_RISK: ["ASI03"],
    FindingCategory.KNOWN_CVE: ["ASI04"],
    FindingCategory.TOXIC_TOOL_COMBO: ["ASI02"],
    FindingCategory.IDENTITY_PRIVILEGE: ["ASI03"],
    FindingCategory.CODE_GENERATION: ["ASI05"],
    FindingCategory.MEMORY_POISONING: ["ASI06"],
    FindingCategory.INTER_AGENT_COMM: ["ASI07"],
    FindingCategory.CASCADING_FAILURE: ["ASI08"],
    FindingCategory.TRUST_EXPLOITATION: ["ASI09"],
    FindingCategory.ROGUE_AGENT: ["ASI10"],
    FindingCategory.AUDIT_TELEMETRY: ["ASI10"],
    FindingCategory.CONTEXT_OVERSHARING: ["ASI02"],
    # Phase 2 categories
    FindingCategory.TOOL_SHADOWING: ["ASI01", "ASI04"],
    FindingCategory.HIDDEN_UNICODE: ["ASI01", "ASI10"],
    FindingCategory.HOMOGLYPH: ["ASI04", "ASI09"],
    FindingCategory.RUG_PULL_PRIMITIVE: ["ASI04", "ASI10"],
    FindingCategory.SURFACE_MISMATCH: ["ASI04", "ASI10"],
    FindingCategory.RESPONSE_INJECTION: ["ASI01", "ASI06"],
    FindingCategory.EXCESSIVE_SCOPE: ["ASI03"],
    FindingCategory.CONFUSED_DEPUTY: ["ASI03"],
    FindingCategory.SHELL_EXEC: ["ASI05"],
    FindingCategory.FILE_READ: ["ASI03"],
    FindingCategory.FILE_WRITE: ["ASI03"],
    FindingCategory.ENV_DUMP: ["ASI03"],
}


# ============================================================
# OWASP MCP Top 10 — data loading and category mapping
# ============================================================

OWASP_MCP_DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "owasp_mcp_top10.json",
)

OWASP_MCP_REQUIRED_KEYS = (
    "id", "short_id", "title", "framework_version", "coverage",
    "reason", "detector_ids", "reference_url",
)
OWASP_MCP_COVERAGE_LEVELS = ("strong", "partial", "gap")


def load_owasp_mcp_data(path: Optional[str] = None) -> Dict[str, Any]:
    """Load and validate the OWASP MCP Top 10 data file (JSON, no YAML dependency)."""
    path = path or OWASP_MCP_DATA_PATH
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    items = data.get("items", [])
    for item in items:
        missing = [k for k in OWASP_MCP_REQUIRED_KEYS if k not in item]
        if missing:
            raise ValueError(f"OWASP MCP item {item.get('id', '?')} missing keys: {missing}")
        if item["coverage"] not in OWASP_MCP_COVERAGE_LEVELS:
            raise ValueError(f"OWASP MCP item {item['id']} has invalid coverage {item['coverage']!r}")
        if item["coverage"] in ("partial", "gap") and not item["reason"]:
            raise ValueError(f"OWASP MCP item {item['id']} needs a reason for {item['coverage']}")
    return data


OWASP_MCP_TOP_10_DATA: Dict[str, Any] = load_owasp_mcp_data()


def _build_category_to_mcp(data: Dict[str, Any]) -> Dict[FindingCategory, List[str]]:
    """Derive FindingCategory -> [MCPxx] from the detector_ids in the data file."""
    valid = {c.value: c for c in FindingCategory}
    mapping: Dict[FindingCategory, List[str]] = {}
    for item in data.get("items", []):
        for det in item.get("detector_ids", []):
            cat = valid.get(det)
            if cat is not None and item["short_id"] not in mapping.setdefault(cat, []):
                mapping[cat].append(item["short_id"])
    for refs in mapping.values():
        refs.sort()
    return mapping


# Maps FindingCategory -> OWASP MCP Top 10 references
CATEGORY_TO_MCP: Dict[FindingCategory, List[str]] = _build_category_to_mcp(OWASP_MCP_TOP_10_DATA)


def apply_owasp_mcp_mapping(findings: List[Finding]) -> List[Finding]:
    """Stamp owasp_mcp on every finding that lacks an explicit reference."""
    for finding in findings:
        if not finding.owasp_mcp and finding.category in CATEGORY_TO_MCP:
            finding.owasp_mcp = list(CATEGORY_TO_MCP[finding.category])
    return findings


def apply_owasp_mappings(findings: List[Finding]) -> List[Finding]:
    """Stamp both owasp_asi and owasp_mcp where not already set."""
    for finding in findings:
        if not finding.owasp_asi and finding.category in CATEGORY_TO_ASI:
            finding.owasp_asi = list(CATEGORY_TO_ASI[finding.category])
    return apply_owasp_mcp_mapping(findings)


# ============================================================
# ASI02: Toxic Tool Combination Detector
# ============================================================

# Tool capability categories — combinations of these create risk
TOOL_CAPABILITIES = {
    "data_read": [
        r"(?i)(read|get|fetch|query|select|list|search|browse|retrieve)",
        r"(?i)(database|db|sql|table|collection|store|bucket)",
        r"(?i)(file|document|content|resource|record)",
    ],
    "data_write": [
        r"(?i)(write|put|create|insert|update|modify|delete|remove|drop)",
        r"(?i)(send|post|push|publish|emit|dispatch)",
    ],
    "network_external": [
        r"(?i)(http|https|api|url|endpoint|webhook|external|remote)",
        r"(?i)(fetch|request|curl|download|upload|stream)",
    ],
    "code_execute": [
        r"(?i)(exec|execute|run|eval|shell|command|script|spawn)",
        r"(?i)(subprocess|child_process|system|terminal|bash)",
    ],
    "credential_access": [
        r"(?i)(token|key|password|secret|credential|auth|api.?key)",
        r"(?i)(login|session|cookie|jwt|bearer|oauth)",
    ],
    "filesystem": [
        r"(?i)(file|directory|folder|path|filesystem|disk|storage)",
        r"(?i)(read.?file|write.?file|delete.?file|move|copy|rename)",
    ],
}

# Dangerous combinations: {(cap_a, cap_b): risk_description}
TOXIC_COMBOS = {
    ("data_read", "network_external"): {
        "title": "Data read + external network = exfiltration path",
        "description": "Tools that can read internal data AND make external network requests "
                       "create a direct exfiltration channel. A hijacked agent could read "
                       "sensitive data then forward it to an attacker-controlled endpoint.",
        "severity": FindingSeverity.HIGH,
    },
    ("credential_access", "network_external"): {
        "title": "Credential access + external network = credential theft path",
        "description": "Tools that access credentials AND make external requests can "
                       "exfiltrate tokens, API keys, and secrets to remote servers.",
        "severity": FindingSeverity.CRITICAL,
    },
    ("code_execute", "network_external"): {
        "title": "Code execution + external network = remote code execution path",
        "description": "Tools that execute code AND fetch external content can download "
                       "and run attacker-controlled payloads.",
        "severity": FindingSeverity.CRITICAL,
    },
    ("data_read", "data_write"): {
        "title": "Broad data read + write = data manipulation risk",
        "description": "Tools that can both read and write data could be manipulated to "
                       "corrupt, overwrite, or delete information.",
        "severity": FindingSeverity.MEDIUM,
    },
    ("filesystem", "network_external"): {
        "title": "Filesystem access + external network = file exfiltration path",
        "description": "Tools that access local files AND make network requests can "
                       "exfiltrate source code, configs, keys, and documents.",
        "severity": FindingSeverity.HIGH,
    },
    ("code_execute", "filesystem"): {
        "title": "Code execution + filesystem = unrestricted local access",
        "description": "Tools that execute code AND access the filesystem can read/write "
                       "any file the agent has permissions for, including SSH keys and credentials.",
        "severity": FindingSeverity.HIGH,
    },
    ("credential_access", "data_write"): {
        "title": "Credential access + data write = privilege persistence",
        "description": "Tools that access credentials AND write data could persist "
                       "stolen credentials or create backdoor accounts.",
        "severity": FindingSeverity.HIGH,
    },
}


def classify_tool_capabilities(
    tools: List[MCPToolDefinition], table: Optional[Dict[str, List[str]]] = None
) -> Dict[str, Set[str]]:
    """Tool name -> broad capability set (data_read, network_external, ...).
    Broad on purpose: it feeds the toxic-combo and blast-radius reasoning, not findings."""
    table = table or TOOL_CAPABILITIES
    tool_caps: Dict[str, Set[str]] = {}
    for tool in tools:
        text = f"{tool.name} {tool.description}".lower()
        caps = set()
        for cap_name, patterns in table.items():
            for pattern in patterns:
                if re.search(pattern, text):
                    caps.add(cap_name)
                    break
        if caps:
            tool_caps[tool.name] = caps
    return tool_caps


# Strict, per-tool rules. A match here names a specific tool as dangerous; the
# conservative wording keeps an ordinary filesystem server at LOW.
DANGEROUS_TOOL_RULES = [
    {
        "capability": "shell_exec",
        "category": FindingCategory.SHELL_EXEC,
        "name": r"(?i)(^|_)(exec|execute|shell|cmd|command|system|eval|spawn|bash|powershell|terminal|run_command|run_cmd|run_shell)(_|$)",
        "desc": r"(?i)\b(run|runs|execute|executes|exec)\b.{0,40}\b(shell|command|commands|script|scripts|cmd|bash|powershell|terminal)\b"
                r"|\barbitrary\s+(command|code|shell)|\badministrative\s+command|\bshell\s+command",
        "base": FindingSeverity.HIGH,
        "escalate_param": r"(?i)^(cmd|command|script|code|shell|args|argv)$",
        # Name tokens that also name things that are not a shell (spawn_subagent,
        # execute_query, system_status, eval_metrics). On their own they are a guess:
        # the finding stays LOW unless the description or a parameter that can only
        # carry a command confirms it. `args` / `code` do not confirm anything; they are
        # the generic wrapper and the generic payload.
        "weak_name_tokens": {"exec", "execute", "system", "eval", "spawn"},
        "confirm_param": r"(?i)^(cmd|command|script|shell)$",
        "unconfirmed": FindingSeverity.LOW,
        "high": FindingSeverity.CRITICAL,
        "what": "can execute shell commands",
    },
    {
        "capability": "file_read",
        "category": FindingCategory.FILE_READ,
        "name": r"(?i)^(read|cat|load|open|get)_?(file|files|path|contents?)$|^bulk_read$|^read_(any|all)_files?$",
        "desc": r"(?i)\bread(s|ing)?\b.{0,40}\b(file|files|path|disk|directory|folder)\b|\bfile\s+contents?\b|\bevery\s+file\b",
        "base": FindingSeverity.LOW,
        "escalate_desc": r"(?i)\b(any|every|arbitrary|all)\s+(file|files|path|paths)\b|absolute\s+or\s+relative|\bon\s+disk\b|\bevery\s+file\s+matching\b|\bbulk\b",
        "high": FindingSeverity.HIGH,
        "what": "reads files",
    },
    {
        "capability": "file_write",
        "category": FindingCategory.FILE_WRITE,
        "name": r"(?i)^(write|save|delete|remove|unlink|create|put|overwrite)_?(file|files|path)$",
        "desc": r"(?i)\b(write|writes|overwrite|overwrites|delete|deletes|remove|removes|unlink)\b.{0,40}\b(file|files|path|paths|disk|directory|folder)\b|\bwrite\s+content\b",
        "base": FindingSeverity.LOW,
        "escalate_desc": r"(?i)\b(any|arbitrary)\s+(path|file|location)\b|\bdelete\s+(any|arbitrary)\b",
        "high": FindingSeverity.HIGH,
        "what": "writes or deletes files",
    },
    {
        "capability": "env_dump",
        "category": FindingCategory.ENV_DUMP,
        "name": r"(?i)(^|_)(env|environ|getenv|dump_env|debug_env|environment|printenv)(_|$)",
        "desc": r"(?i)\b(all\s+)?environment\s+variables?\b|\benv(ironment)?\s+(dump|vars)\b|os\.environ|\bdump\s+env\b",
        "base": FindingSeverity.HIGH,
        "high": FindingSeverity.HIGH,
        "what": "exposes environment variables (credentials)",
    },
    {
        "capability": "network_egress",
        "category": FindingCategory.DATA_EXFILTRATION,
        "name": r"$^",
        "desc": r"(?i)\b(post|send|upload|forward|transmit|push)s?\b.{0,30}\b(arbitrary|any)\s+(url|endpoint|host|server|destination)\b|\bto\s+(an\s+)?arbitrary\s+url\b",
        "base": FindingSeverity.HIGH,
        "high": FindingSeverity.HIGH,
        "what": "sends data to a caller-chosen destination",
    },
]


def detect_dangerous_tool_capabilities(tools: List[MCPToolDefinition]) -> List[Finding]:
    """One finding per (tool, dangerous capability). Ids: cap_<tool>_<capability>."""
    findings: List[Finding] = []
    for tool in tools:
        desc = tool.description or ""
        props = (tool.input_schema or {}).get("properties", {}) if isinstance(tool.input_schema, dict) else {}
        for rule in DANGEROUS_TOOL_RULES:
            name_hit = re.search(rule["name"], tool.name)
            desc_hit = re.search(rule["desc"], desc)
            if desc_hit and re.search(r"(?i)\b(not|never|no|without|cannot|can't|doesn't|does not|don't)\b", desc_hit.group(0)):
                desc_hit = None   # "does not execute commands" is the opposite of a capability
            if not (name_hit or desc_hit):
                continue
            sev = rule["base"]
            why = []
            name_only_guess = bool(
                name_hit and not desc_hit
                and name_hit.group(2).lower() in rule.get("weak_name_tokens", ())
                and not any(re.search(rule["confirm_param"], p) for p in props)
            ) if rule.get("weak_name_tokens") else False
            if name_only_guess:
                sev = rule["unconfirmed"]
                why.append("is only named like one: no command parameter and nothing in its description confirms a shell")
            elif rule.get("escalate_param") and any(re.search(rule["escalate_param"], p) for p in props):
                sev = rule["high"]
                why.append("takes a command-like parameter")
            if rule.get("escalate_desc") and re.search(rule["escalate_desc"], desc):
                sev = rule["high"]
                why.append("is unrestricted by its own description")
            evidence = (name_hit.group(0) if name_hit else desc_hit.group(0)).strip()
            findings.append(Finding(
                id=f"cap_{tool.name}_{rule['capability']}",
                severity=sev,
                category=rule["category"],
                title=f"Tool '{tool.name}' {rule['what']} ({rule['capability']})",
                description=f"Tool '{tool.name}' {rule['what']}"
                            + (f"; it {' and '.join(why)}" if why else "")
                            + f". Evidence: '{evidence}'. Description: '{desc[:140]}'",
                recommendation="Scope the tool to the narrowest operation and location it needs, "
                               "and require explicit user approval per call.",
                owasp_asi=list(CATEGORY_TO_ASI.get(rule["category"], ["ASI02"])),
            ))
    return findings


def dangerous_tool_map(tools: List[MCPToolDefinition]) -> Dict[str, str]:
    """Tool name -> first dangerous capability (for 'content steers agent to tool X' rules)."""
    out: Dict[str, str] = {}
    for f in detect_dangerous_tool_capabilities(tools):
        if f.severity not in (FindingSeverity.HIGH, FindingSeverity.CRITICAL):
            continue  # an ordinary read_file (LOW) is not a tool worth warning about being named
        name = f.id[len("cap_"):].rsplit("_", 1)[0]
        cap = f.id.rsplit("_", 1)[-1]
        if f.id.endswith("_shell_exec"):
            name, cap = f.id[len("cap_"):-len("_shell_exec")], "shell_exec"
        elif f.id.endswith("_file_read"):
            name, cap = f.id[len("cap_"):-len("_file_read")], "file_read"
        elif f.id.endswith("_file_write"):
            name, cap = f.id[len("cap_"):-len("_file_write")], "file_write"
        elif f.id.endswith("_env_dump"):
            name, cap = f.id[len("cap_"):-len("_env_dump")], "env_dump"
        elif f.id.endswith("_network_egress"):
            name, cap = f.id[len("cap_"):-len("_network_egress")], "network_egress"
        out.setdefault(name, cap)
    return out


# Strict per-tool capability (cap_* rule) -> the vocabulary TOXIC_COMBOS uses.
_STRICT_TO_COMBO = {
    "shell_exec": "code_execute",
    "file_read": "filesystem",
    "file_write": "filesystem",
    "env_dump": "credential_access",
    "network_egress": "network_external",
}
_SEV_ORDER = [FindingSeverity.INFO, FindingSeverity.LOW, FindingSeverity.MEDIUM, FindingSeverity.HIGH, FindingSeverity.CRITICAL]


def strict_tool_capabilities(tools: List[MCPToolDefinition]) -> Dict[str, Dict[str, FindingSeverity]]:
    """Tool name -> {combo capability: severity of the cap_* finding that established it}.
    Only the strict per-tool rules count (docs/SEVERITY.md): a keyword in a description
    ("text", "run", "operation") is not a capability."""
    out: Dict[str, Dict[str, FindingSeverity]] = {}
    for f in detect_dangerous_tool_capabilities(tools):
        if not f.id.startswith("cap_"):
            continue
        tool, _, cap = f.id[4:].rpartition("_")
        # ids are cap_<tool>_<capability>; capabilities may contain an underscore
        for strict_cap, combo_cap in _STRICT_TO_COMBO.items():
            if f.id.endswith("_" + strict_cap):
                tool = f.id[4:-(len(strict_cap) + 1)]
                cur = out.setdefault(tool, {})
                if combo_cap not in cur or _SEV_ORDER.index(f.severity) > _SEV_ORDER.index(cur[combo_cap]):
                    cur[combo_cap] = f.severity
                break
    return out


def detect_toxic_tool_combos(tools: List[MCPToolDefinition]) -> List[Finding]:
    """
    ASI02: Detect dangerous combinations of tool capabilities.
    Individual tools may be safe, but together they create attack paths.

    Both sides of a combination must come from strict per-tool rules; the combo's
    severity is the higher of the two contributing capability findings, capped at HIGH,
    CRITICAL only when one side is a CRITICAL shell_exec, and never more than one level
    above the weaker side: a combination is only as real as its weaker half, so a scoped
    LOW capability next to a CRITICAL one makes a MEDIUM, not a second CRITICAL. A
    capability that is merely present (INFO) does not make a combination.
    """
    findings = []
    strict = strict_tool_capabilities(tools)
    providers: Dict[str, List[str]] = {}
    best: Dict[str, FindingSeverity] = {}
    for tool, caps in strict.items():
        for cap, sev in caps.items():
            providers.setdefault(cap, []).append(tool)
            if cap not in best or _SEV_ORDER.index(sev) > _SEV_ORDER.index(best[cap]):
                best[cap] = sev

    for (cap_a, cap_b), risk_info in TOXIC_COMBOS.items():
        if cap_a not in providers or cap_b not in providers:
            continue
        sev_a, sev_b = best[cap_a], best[cap_b]
        if _SEV_ORDER.index(min(sev_a, sev_b, key=_SEV_ORDER.index)) < _SEV_ORDER.index(FindingSeverity.LOW):
            continue  # an INFO-level capability is inventory, not a combination
        top = max(sev_a, sev_b, key=_SEV_ORDER.index)
        if top == FindingSeverity.CRITICAL and "code_execute" in (cap_a, cap_b) and FindingSeverity.CRITICAL in (sev_a, sev_b):
            sev = FindingSeverity.CRITICAL
        else:
            sev = min(top, FindingSeverity.HIGH, key=_SEV_ORDER.index)
        weaker = min(sev_a, sev_b, key=_SEV_ORDER.index)
        ceiling = _SEV_ORDER[min(_SEV_ORDER.index(weaker) + 1, len(_SEV_ORDER) - 1)]
        sev = min(sev, ceiling, key=_SEV_ORDER.index)
        if _SEV_ORDER.index(sev) < _SEV_ORDER.index(FindingSeverity.MEDIUM):
            sev = FindingSeverity.LOW
        findings.append(Finding(
            id=f"toxic_combo_{cap_a}_{cap_b}",
            severity=sev,
            category=FindingCategory.TOXIC_TOOL_COMBO,
            title=risk_info["title"],
            description=f"{risk_info['description']} "
                        f"Provided by: {', '.join(providers[cap_a])} ({cap_a}) + "
                        f"{', '.join(providers[cap_b])} ({cap_b}).",
            recommendation="Implement tool-level permission scoping. Consider whether "
                           "both capabilities are necessary or if one can be restricted.",
            owasp_asi=["ASI02"],
        ))

    return findings


# ============================================================
# ASI05: Code Generation Detection
# ============================================================

CODE_GENERATION_PATTERNS = [
    r"(?i)(generate|create|produce|write|output)\s+(code|script|program|function)",
    r"(?i)(compile|transpile|build)\s+(and\s+)?(run|execute|eval)",
    r"(?i)(dynamic|runtime)\s+(code|script|module)\s*(generation|creation|loading)",
    r"(?i)(code|script)\s*(from|based\s+on)\s*(prompt|input|user|request|instruction)",
    r"(?i)import\s*\(\s*[^)]*\+",  # dynamic import with concatenation
    r"(?i)__import__\s*\(",         # Python dynamic import
    r"(?i)require\s*\(\s*[^)]*\+",  # Node dynamic require with concat
    r"(?i)vm\.(runInNewContext|runInThisContext|createContext)",  # Node VM
    r"(?i)ast\.(literal_eval|parse)",  # Python AST
    r"(?i)(new\s+Function|GeneratorFunction|AsyncFunction)\s*\(",  # JS dynamic function creation
]


def detect_code_generation(scan_dir: str) -> List[Finding]:
    """ASI05: Detect patterns where tools generate and execute code from inputs."""
    import os
    findings = []
    counter = 0
    scan_extensions = {'.py', '.ts', '.js', '.mjs', '.cjs'}

    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in {
            'node_modules', '.git', '__pycache__', 'venv', '.venv',
            'dist', 'build', 'coverage'
        }]
        for fname in files:
            if os.path.splitext(fname)[1] not in scan_extensions:
                continue
            filepath = os.path.join(root, fname)
            rel_path = os.path.relpath(filepath, scan_dir)
            try:
                with open(filepath, "r", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue

            for line_num, line in enumerate(lines, 1):
                for pattern in CODE_GENERATION_PATTERNS:
                    if re.search(pattern, line):
                        counter += 1
                        findings.append(Finding(
                            id=f"codegen_{counter:04d}",
                            severity=FindingSeverity.LOW,
                            category=FindingCategory.CODE_GENERATION,
                            title="Dynamic code generation from input detected",
                            description=f"Pattern in {rel_path} at line {line_num}: "
                                        f"`{line.strip()[:120]}`. Tools that generate code from "
                                        "agent inputs can execute attacker-controlled payloads.",
                            file_path=rel_path,
                            line_number=line_num,
                            recommendation="Sandbox code execution. Validate and sanitize all "
                                           "inputs before code generation. Use AST-based analysis "
                                           "instead of string-based code construction.",
                            owasp_asi=["ASI05"],
                        ))
                        break
    return findings


# ============================================================
# ASI06: Memory & Context Poisoning Detection
# ============================================================

MEMORY_POISONING_PATTERNS = [
    # Persistent state manipulation
    r"(?i)(memory|context|state|session)\s*(store|save|persist|cache|set|update|write|inject)",
    r"(?i)(update|modify|overwrite|replace|inject)\s*(memory|context|history|knowledge|embedding)",
    # RAG / vector store poisoning vectors
    r"(?i)(vector|embedding|chunk|document)\s*(store|insert|upsert|index|ingest)",
    r"(?i)(rag|retrieval|knowledge.?base|corpus)\s*(update|modify|add|inject|poison)",
    # Conversation history manipulation
    r"(?i)(conversation|chat|message)\s*(history|log|record)\s*(append|modify|inject|alter)",
    r"(?i)(system\s*prompt|instruction)\s*(update|change|modify|override|append)",
    # Cross-session persistence
    r"(?i)(persist|store|save)\s*(across|between)\s*(sessions?|conversations?|requests?)",
    r"(?i)(long.?term|persistent|durable)\s*(memory|storage|state|context)",
]


def detect_memory_poisoning_patterns(scan_dir: str) -> List[Finding]:
    """ASI06: Detect patterns indicating memory/context manipulation capabilities."""
    import os
    findings = []
    counter = 0
    scan_extensions = {'.py', '.ts', '.js', '.mjs', '.cjs'}

    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in {
            'node_modules', '.git', '__pycache__', 'venv', '.venv',
            'dist', 'build', 'coverage'
        }]
        for fname in files:
            if os.path.splitext(fname)[1] not in scan_extensions:
                continue
            filepath = os.path.join(root, fname)
            rel_path = os.path.relpath(filepath, scan_dir)
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            for pattern in MEMORY_POISONING_PATTERNS:
                matches = list(re.finditer(pattern, content))
                if matches:
                    counter += 1
                    line_num = content[:matches[0].start()].count('\n') + 1
                    findings.append(Finding(
                        id=f"memory_{counter:04d}",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.MEMORY_POISONING,
                        title="Memory/context modification capability detected",
                        description=f"Pattern in {rel_path} near line {line_num}: "
                                    f"`{matches[0].group()[:100]}`. MCP servers that modify "
                                    "agent memory or context can poison long-term behavior.",
                        file_path=rel_path,
                        line_number=line_num,
                        recommendation="Validate all data before writing to agent memory. "
                                       "Implement integrity checks on persistent context. "
                                       "Log all memory modifications for audit.",
                        owasp_asi=["ASI06"],
                    ))
    return findings


# ============================================================
# ASI07: Inter-Agent Communication Pattern Detection
# ============================================================

INTER_AGENT_PATTERNS = [
    # A2A protocol patterns
    r"(?i)(agent.?to.?agent|a2a|multi.?agent|inter.?agent)\s*(protocol|comm|message|call)",
    r"(?i)(delegate|forward|relay|dispatch)\s*(to|request)\s*(agent|worker|peer|service)",
    # Trust boundary issues
    r"(?i)(trust|verify|authenticate)\s*(agent|peer|sender|source|origin)",
    r"(?i)(accept|process|execute)\s*(from\s+)?(any|all|unknown|untrusted)\s*(agent|source)",
    # Message passing without validation
    r"(?i)(message|payload|instruction)\s*(pass|forward|relay)\s*(without|no)\s*(valid|auth|check)",
    # Agent impersonation vectors
    r"(?i)(agent.?id|agent.?name|sender.?id)\s*=\s*['\"]",
    r"(?i)(spoof|impersonat|fake|forge)\s*(agent|identity|sender|message)",
]


def detect_inter_agent_patterns(scan_dir: str) -> List[Finding]:
    """ASI07: Detect insecure inter-agent communication patterns."""
    import os
    findings = []
    counter = 0
    scan_extensions = {'.py', '.ts', '.js', '.mjs', '.cjs'}

    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in {
            'node_modules', '.git', '__pycache__', 'venv', '.venv',
            'dist', 'build', 'coverage'
        }]
        for fname in files:
            if os.path.splitext(fname)[1] not in scan_extensions:
                continue
            filepath = os.path.join(root, fname)
            rel_path = os.path.relpath(filepath, scan_dir)
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            for pattern in INTER_AGENT_PATTERNS:
                matches = list(re.finditer(pattern, content))
                if matches:
                    counter += 1
                    line_num = content[:matches[0].start()].count('\n') + 1
                    findings.append(Finding(
                        id=f"interagent_{counter:04d}",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.INTER_AGENT_COMM,
                        title="Inter-agent communication pattern detected",
                        description=f"Pattern in {rel_path} near line {line_num}: "
                                    f"`{matches[0].group()[:100]}`. Inter-agent messages "
                                    "can be spoofed or manipulated without proper validation.",
                        file_path=rel_path,
                        line_number=line_num,
                        recommendation="Authenticate all inter-agent messages. Validate sender "
                                       "identity. Implement message signing and schema validation. "
                                       "Never trust agent-provided identity claims.",
                        owasp_asi=["ASI07"],
                    ))
    return findings


# ============================================================
# ASI08: Blast Radius / Cascading Failure Estimation
# ============================================================

def estimate_blast_radius(tools: List[MCPToolDefinition], findings: List[Finding]) -> List[Finding]:
    """ASI08: Estimate potential blast radius from tool capabilities and findings."""
    result_findings = []

    # Count capability breadth (strict per-tool rules only; keywords are not capabilities)
    capabilities = set()
    for caps in strict_tool_capabilities(tools).values():
        capabilities.update(caps)

    # Blast radius is derived: never above the worst non-derived finding, and no finding
    # at all unless something MEDIUM or worse fired (docs/SEVERITY.md).
    primary = [f for f in findings if f.category not in (FindingCategory.TOXIC_TOOL_COMBO, FindingCategory.CASCADING_FAILURE)]
    worst = max((f.severity for f in primary), key=_SEV_ORDER.index, default=FindingSeverity.INFO)
    if _SEV_ORDER.index(worst) < _SEV_ORDER.index(FindingSeverity.MEDIUM):
        return result_findings

    # High blast radius indicators
    critical_findings = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    has_code_exec = "code_execute" in capabilities
    has_network = "network_external" in capabilities
    has_filesystem = "filesystem" in capabilities
    has_creds = "credential_access" in capabilities

    blast_score = 0
    factors = []

    if has_code_exec:
        blast_score += 3
        factors.append("arbitrary code execution")
    if has_network:
        blast_score += 2
        factors.append("external network access")
    if has_filesystem:
        blast_score += 2
        factors.append("filesystem access")
    if has_creds:
        blast_score += 2
        factors.append("credential access")
    if len(tools) > 10:
        blast_score += 1
        factors.append(f"{len(tools)} tools (large attack surface)")
    if critical_findings > 2:
        blast_score += 2
        factors.append(f"{critical_findings} critical findings")

    if blast_score >= 5:
        severity = FindingSeverity.HIGH
        level = "HIGH"
    elif blast_score >= 3:
        severity = FindingSeverity.MEDIUM
        level = "MEDIUM"
    else:
        return result_findings  # Low blast radius, no finding needed
    if _SEV_ORDER.index(severity) > _SEV_ORDER.index(worst):
        severity = worst
        level = worst.value.upper()

    result_findings.append(Finding(
        id="blast_radius_estimate",
        severity=severity,
        category=FindingCategory.CASCADING_FAILURE,
        title=f"Blast radius: {level} — compromise of this server has broad impact",
        description=f"If this MCP server is compromised, the blast radius is {level} "
                    f"due to: {', '.join(factors)}. A single tool poisoning or supply chain "
                    "attack could cascade across all connected systems.",
        recommendation="Apply least-privilege to this server. Isolate it from other MCP "
                       "servers. Implement kill switches and behavioral monitoring. "
                       "Limit env vars to the minimum required.",
        owasp_asi=["ASI08"],
    ))

    return result_findings


# ============================================================
# ASI09: Trust Exploitation Detection (beyond claimed-vs-actual)
# ============================================================

TRUST_EXPLOITATION_PATTERNS = {
    "deceptive_output": [
        r"(?i)(format|display|present|render|show)\s*(as|like)\s*(trusted|verified|official|authentic)",
        r"(?i)(mimic|imitate|replicate|clone)\s*(output|response|format|style)",
        r"(?i)(fake|forge|fabricate|synthetic)\s*(response|result|output|data|evidence)",
    ],
    "consent_bypass": [
        r"(?i)(auto.?approve|auto.?confirm|skip.?confirm|bypass.?consent|no.?confirm)",
        r"(?i)(without\s+user|without\s+human|without\s+approval|without\s+consent)",
        r"(?i)(suppress|hide|conceal)\s*(warning|alert|prompt|confirmation|error)",
    ],
    "authority_impersonation": [
        r"(?i)(admin|system|root|operator)\s*(message|notification|alert|command)",
        r"(?i)(on\s+behalf\s+of|acting\s+as|representing|authorized\s+by)",
        r"(?i)(elevated|special|emergency)\s*(privileges?|access|authority|mode)",
    ],
}


def detect_trust_exploitation(scan_dir: str) -> List[Finding]:
    """ASI09: Detect patterns that could exploit human trust in agent outputs."""
    import os
    findings = []
    counter = 0
    scan_extensions = {'.py', '.ts', '.js', '.mjs', '.cjs'}

    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in {
            'node_modules', '.git', '__pycache__', 'venv', '.venv',
            'dist', 'build', 'coverage'
        }]
        for fname in files:
            if os.path.splitext(fname)[1] not in scan_extensions:
                continue
            filepath = os.path.join(root, fname)
            rel_path = os.path.relpath(filepath, scan_dir)
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            for category_name, patterns in TRUST_EXPLOITATION_PATTERNS.items():
                for pattern in patterns:
                    matches = list(re.finditer(pattern, content))
                    if matches:
                        counter += 1
                        line_num = content[:matches[0].start()].count('\n') + 1
                        findings.append(Finding(
                            id=f"trust_{counter:04d}",
                            severity=FindingSeverity.LOW,
                            category=FindingCategory.TRUST_EXPLOITATION,
                            title=f"Trust exploitation pattern: {category_name.replace('_', ' ')}",
                            description=f"Pattern in {rel_path} near line {line_num}: "
                                        f"`{matches[0].group()[:100]}`. This could enable "
                                        "a compromised agent to mislead users.",
                            file_path=rel_path,
                            line_number=line_num,
                            recommendation="Implement output verification. Require human "
                                           "confirmation for high-impact actions. Mark "
                                           "agent-generated content as such.",
                            owasp_asi=["ASI09"],
                        ))
                        break  # One finding per category per file
    return findings


# ============================================================
# ASI10: Rogue Agent Indicators (beyond sleeper patterns)
# ============================================================

ROGUE_AGENT_PATTERNS = [
    # Self-modification
    r"(?i)(self|auto)\s*[\._]?\s*(modify|update|patch|evolve|mutate|rewrite)",
    r"(?i)(modify|update|change|rewrite)\s*(own|self|my)\s*(code|behavior|instructions?|config)",
    # Persistence mechanisms
    r"(?i)(persist|survive|maintain)\s*(across|between|after)\s*(restart|reboot|session|crash)",
    r"(?i)(cron|schedule|timer|interval|setInterval|setTimeout)\s*.*\s*(repeat|recurring|periodic)",
    r"(?i)(startup|boot|init|autorun|daemon|service)\s*(script|hook|entry|register)",
    # Evasion
    r"(?i)(evade|avoid|bypass|circumvent)\s*(detection|monitoring|logging|audit|sandbox)",
    r"(?i)(disable|suppress|delete|clear)\s*(log|audit|trace|monitor|alert|history)",
    # Autonomous goal pursuit
    r"(?i)(autonomous|independent|self.?directed)\s*(action|decision|goal|execution)",
    r"(?i)(without\s+)?(human|user|operator)\s*(oversight|supervision|approval|review)",
]


def detect_rogue_agent_indicators(scan_dir: str) -> List[Finding]:
    """ASI10: Detect patterns that indicate potential rogue agent behavior."""
    import os
    findings = []
    counter = 0
    scan_extensions = {'.py', '.ts', '.js', '.mjs', '.cjs'}

    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in {
            'node_modules', '.git', '__pycache__', 'venv', '.venv',
            'dist', 'build', 'coverage'
        }]
        for fname in files:
            if os.path.splitext(fname)[1] not in scan_extensions:
                continue
            filepath = os.path.join(root, fname)
            rel_path = os.path.relpath(filepath, scan_dir)
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            for pattern in ROGUE_AGENT_PATTERNS:
                matches = list(re.finditer(pattern, content))
                if matches:
                    counter += 1
                    line_num = content[:matches[0].start()].count('\n') + 1
                    findings.append(Finding(
                        id=f"rogue_{counter:04d}",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.ROGUE_AGENT,
                        title="Rogue agent indicator detected",
                        description=f"Pattern in {rel_path} near line {line_num}: "
                                    f"`{matches[0].group()[:100]}`. This could indicate "
                                    "self-modifying behavior, persistence mechanisms, "
                                    "or evasion capabilities.",
                        file_path=rel_path,
                        line_number=line_num,
                        recommendation="Implement behavioral monitoring and kill switches. "
                                       "Ensure all agent actions are logged and auditable. "
                                       "Run in sandboxed environments with strict resource limits.",
                        owasp_asi=["ASI10"],
                    ))
                    break  # One finding per pattern per file
    return findings


# ============================================================
# OWASP Coverage Summary Generator
# ============================================================

def generate_owasp_coverage(findings: List[Finding]) -> Dict[str, Any]:
    """Generate OWASP Agentic AI Top 10 coverage summary from scan findings."""

    # Count findings per ASI category
    asi_findings: Dict[str, List[str]] = {f"ASI{i:02d}": [] for i in range(1, 11)}

    for finding in findings:
        # Use explicit owasp_asi if set
        if finding.owasp_asi:
            for asi in finding.owasp_asi:
                if asi in asi_findings:
                    asi_findings[asi].append(finding.id)
        # Otherwise map from category
        elif finding.category in CATEGORY_TO_ASI:
            for asi in CATEGORY_TO_ASI[finding.category]:
                if asi in asi_findings:
                    asi_findings[asi].append(finding.id)

    coverage = {}
    for asi_id, info in OWASP_AGENTIC_TOP_10.items():
        finding_ids = asi_findings.get(asi_id, [])
        coverage[asi_id] = {
            "name": info["name"],
            "coverage_level": info["mcpguard_coverage"],
            "findings_count": len(finding_ids),
            "finding_ids": finding_ids[:10],  # Cap at 10 for readability
            "detectors": info["detectors"],
        }
        if "gap_note" in info:
            coverage[asi_id]["gap_note"] = info["gap_note"]

    return {
        "framework": "OWASP Top 10 for Agentic Applications 2026",
        "reference": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        "coverage": coverage,
        "total_asi_categories_with_findings": sum(
            1 for v in coverage.values() if v["findings_count"] > 0
        ),
    }


def _mcp_items() -> List[Dict[str, Any]]:
    return list(OWASP_MCP_TOP_10_DATA.get("items", []))


def generate_owasp_mcp_coverage(findings: List[Finding]) -> Dict[str, Any]:
    """Generate OWASP MCP Top 10 coverage summary from scan findings."""
    items = _mcp_items()
    mcp_findings: Dict[str, List[str]] = {item["short_id"]: [] for item in items}

    for finding in findings:
        refs = finding.owasp_mcp or CATEGORY_TO_MCP.get(finding.category, [])
        for ref in refs:
            if ref in mcp_findings:
                mcp_findings[ref].append(finding.id)

    coverage = {}
    for item in items:
        sid = item["short_id"]
        finding_ids = mcp_findings.get(sid, [])
        coverage[sid] = {
            "id": item["id"],
            "name": item["title"],
            "coverage_level": item["coverage"],
            "reason": item["reason"],
            "findings_count": len(finding_ids),
            "finding_ids": finding_ids[:10],
            "detectors": item["detector_ids"],
        }

    return {
        "framework": OWASP_MCP_TOP_10_DATA.get("framework", "OWASP MCP Top 10"),
        "framework_version": OWASP_MCP_TOP_10_DATA.get("framework_version"),
        "reference": OWASP_MCP_TOP_10_DATA.get("reference_url"),
        "coverage": coverage,
        "total_mcp_categories_with_findings": sum(
            1 for v in coverage.values() if v["findings_count"] > 0
        ),
    }


def get_mcp_coverage_matrix() -> Dict[str, Any]:
    """OWASP MCP Top 10 matrix keyed by short id, shaped like the ASI matrix."""
    matrix: Dict[str, Any] = {}
    for item in _mcp_items():
        entry = {
            "id": item["id"],
            "name": item["title"],
            "mcpguard_coverage": item["coverage"],
            "reason": item["reason"],
            "detectors": list(item["detector_ids"]),
            "framework_version": item["framework_version"],
            "reference_url": item["reference_url"],
        }
        if item["coverage"] in ("partial", "gap"):
            entry["gap_note"] = item["reason"]
        matrix[item["short_id"]] = entry
    return matrix


def get_coverage_matrix(framework: str = "asi") -> Dict[str, Any]:
    """Return the OWASP coverage matrix (for CLI display / docs).

    framework="asi" (default) returns the Agentic Top 10 matrix exactly as before;
    "mcp" returns the MCP Top 10 matrix; "all" returns {"asi": ..., "mcp": ...}.
    """
    framework = (framework or "asi").lower()
    if framework == "asi":
        return OWASP_AGENTIC_TOP_10
    if framework == "mcp":
        return get_mcp_coverage_matrix()
    if framework == "all":
        return {"asi": OWASP_AGENTIC_TOP_10, "mcp": get_mcp_coverage_matrix()}
    raise ValueError(f"Unknown framework {framework!r}; expected 'asi', 'mcp' or 'all'")
