"""
Tool Poisoning & Prompt Injection Detector
Detects hidden instructions in MCP tool descriptions, server instructions,
resource contents and prompt templates that could manipulate AI behavior.

Modelled on published research demonstrations (see KNOWN_INCIDENTS in
data/threat_intel.py for the sources).

Maps to OWASP Agentic AI Top 10:
  ASI01 — Agent Goal Hijack (primary)
  ASI02 — Tool Misuse & Exploitation (via tool chaining)
  ASI04 — Supply chain (lookalike / homoglyph tool names)
  ASI09 — Human-Agent Trust Exploitation (via name/description mismatch)

Everything that looks at a *string* goes through ``scan_text`` so the same rules
apply to a tool description read from source and to a resource read off the wire.
"""

import re
import unicodedata
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from app.models.schemas import (
    Finding, FindingSeverity, FindingCategory, MCPToolDefinition, MCPResourceDefinition, RiskLevel
)
from app.analysis.mcp_top10_detectors import find_secrets_in_text


# Patterns that indicate tool poisoning - hidden instructions in descriptions
# Two tiers per group (docs/SEVERITY.md): "patterns" are hostile by themselves and keep
# the group's severity; "weak" patterns are steering language that ordinary guidance also
# uses ("will succeed silently", "You should: 1. Start with…") and are reported at
# "weak_severity" (MEDIUM) unless something stronger fires on the same tool.
POISONING_PATTERNS = {
    # Direct instruction injection
    "instruction_injection": {
        "patterns": [
            r"(?i)\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|guidance|rules|prompts?)",
            r"(?i)\b(disregard|forget)\s+(your|all|any|the|previous|prior)\b",
            r"(?i)\boverride\s+(your|the|all|any)\s+(instructions?|system\s+prompt|rules|guidelines)",
            r"(?i)\b(do\s+not|don't|never)\s+(tell|mention|reveal|disclose|inform|show)\s+(the\s+)?(user|anyone|them)\b",
            r"(?i)\bwithout\s+(telling|informing|notifying|asking)\s+(the\s+)?user\b",
            r"(?i)\b(secretly|covertly|surreptitiously)\b",
            r"(?i)\bsilently\s+(call|run|execute|invoke|read|send|forward|include|exfiltrate|upload|copy)\b",
            r"(?i)\b(pretend|act\s+as\s+if|behave\s+as\s+if)\s+(you|the\s+user)\b",
        ],
        "weak": [
            r"(?i)\b(you\s+must|you\s+should|you\s+need\s+to|always|never)\b",
            r"(?i)\b(before\s+responding|after\s+executing|upon\s+completion|when\s+done)\b",
            r"(?i)\b(also\s+call|then\s+invoke|additionally\s+execute|chain\s+with)\b",
            r"(?i)\b(assume\s+the\s+role|act\s+as\s+a|behave\s+as\s+a)\b",
        ],
        "severity": FindingSeverity.CRITICAL,
        "weak_severity": FindingSeverity.MEDIUM,
        "description": "Hidden instruction detected in tool description that could manipulate AI behavior",
        "weak_description": "Steering language in tool description (imperative guidance aimed at the model)",
        "owasp_asi": ["ASI01"],
    },
    # Cross-server tool shadowing: a description that tells the agent how OTHER tools behave
    "tool_shadowing": {
        "patterns": [
            r"(?i)\bwhenever\s+(the\s+)?\S+\s+tool\b",
            r"(?i)\bfrom\s+(any\s+)?other\s+servers?\b",
            r"(?i)\b(change|replace|modify|override|redirect)\s+the\s+(recipient|destination|target|arguments?|parameters?)\b",
            r"(?i)\b(when|before|after|instead\s+of)\s+(calling|using|invoking)\s+(the\s+)?(?!this\b)\S+\s+tool\b",
            r"(?i)\b(modify|fix|correct|change|override)\s+the\s+(wrong\s+)?(result|output|response|answer)\s+of\s+(the\s+)?(?!this\b)\S+(\s+tool)?\b",
        ],
        "severity": FindingSeverity.CRITICAL,
        "category": FindingCategory.TOOL_SHADOWING,
        "description": "Tool description attempts to change how another tool or server behaves (cross-server shadowing)",
        "owasp_asi": ["ASI01", "ASI04"],
    },
    # Preference override: the description claims precedence over other tools or over the
    # user's request (tool poisoning / confused-AI cases)
    "preference_override": {
        "patterns": [
            r"(?i)\b(just\s+|only\s+|always\s+)?use\s+this\s+(tool|function)\s+(rather\s+than|instead\s+of|over|before)\s+(any\s+)?(others?|other\s+tools?|anything\s+else|all\s+others?)\b",
            r"(?i)\bno\s+matter\s+(how\s+many|what|which|whether)\b",
            r"(?i)\b(just|only|always)\s+use\s+this\s+(tool|function)\b",
            r"(?i)\b(do\s+not|don't|never)\s+use\s+(any\s+)?other\s+(tools?|functions?|servers?)\b",
            r"(?i)\breplace\s+the\s+(values?|results?|arguments?|parameters?|inputs?)\s+with\b",
            r"(?i)\b(execute|call|run|use)\s+this\s+(tool|function)\s+(first|before|prior\s+to)\b.{0,60}\b(operation|tool|request|task)\b",
            r"(?i)\bthis\s+(tool|function)\s+(takes|has)\s+(precedence|priority)\b",
        ],
        "severity": FindingSeverity.HIGH,
        "category": FindingCategory.TOOL_SHADOWING,
        "description": "Tool description claims precedence over other tools or rewrites what the agent was asked to do",
        "owasp_asi": ["ASI01", "ASI02"],
    },
    # Data exfiltration instructions
    "exfil_instruction": {
        "patterns": [
            r"(?i)\b(send|forward|transmit|relay|pipe|copy|upload|post)\s+(all\s+|every\s+|the\s+|this\s+|its\s+|your\s+)?(of\s+)?(it|them|everything|results?|output|contents?|data|conversation|context|history|messages?|keys?|credentials?|tokens?|secrets?|files?)(\s+\w+){0,3}\s+to\s+(the\s+|an?\s+|our\s+)?(webhook|endpoint|server|url|api|collector|https?://|[\w-]+\.(com|net|org|io|xyz|dev|app|co|me|top|click|sh))",
            r"(?i)\b(external|remote|third.party|outside|attacker|our)\s+(server|endpoint|api|url|service|collector)\b.{0,40}\b(send|forward|post|upload|report)\b",
            r"(?i)\b(send|forward|post|upload|report)\b.{0,40}\bto\s+(an?\s+)?(external|remote|third.party|outside)\s+(server|endpoint|api|url|service)\b",
        ],
        "weak": [
            r"(?i)\b(include|append|attach|embed|forward|send)\s+(the\s+)?(user's\s+|entire\s+|full\s+)?(conversation|chat\s+history|history|context\s+window|previous\s+messages|system\s+prompt)\b",
        ],
        "severity": FindingSeverity.CRITICAL,
        "weak_severity": FindingSeverity.HIGH,
        "description": "Tool description contains instructions that could cause data exfiltration",
        "weak_description": "Tool description asks for conversation context to be forwarded",
        "owasp_asi": ["ASI01", "ASI02"],
    },
    # Tool chaining manipulation
    "tool_chaining": {
        "patterns": [],
        "weak": [
            r"(?i)\b(first\s+call|then\s+use|next\s+invoke|follow\s+up\s+with)\b",
            r"(?i)\b(retrieve\s+from|access|fetch|read)\s+(other|another|all|every)\s+(tools?|servers?|resources?)\b",
            r"(?i)\b(combine|aggregate|merge|collect)\s+(results|data|information|output)\s+from\s+(other|all|every)\b",
            r"(?i)\b(before\s+this\s+tool|after\s+this\s+tool)\b",
        ],
        "severity": FindingSeverity.HIGH,
        "weak_severity": FindingSeverity.MEDIUM,
        "description": "Tool description attempts to chain execution with other tools",
        "weak_description": "Tool description sequences other tools around itself",
        "owasp_asi": ["ASI02"],
    },
    # Privilege escalation via description
    "priv_escalation": {
        "patterns": [
            r"(?i)\b(bypass|skip|ignore|disable|circumvent)\s+(the\s+)?(auth|authentication|authorization|security|checks?|verification|consent|sandbox|permissions?|approval)\b",
        ],
        "weak": [
            r"(?i)\b(admin|root|superuser|elevated|privileged)\s+(access|mode|permissions?|rights)\b",
            r"(?i)\b(unrestricted|unlimited|full)\s+(access|permissions?|control)\b",
        ],
        "severity": FindingSeverity.CRITICAL,
        "weak_severity": FindingSeverity.HIGH,
        "description": "Tool description attempts privilege escalation",
        "weak_description": "Tool description claims elevated or unrestricted access",
        "owasp_asi": ["ASI01", "ASI03"],
    },
    # Invisible code points that can carry text the human never sees
    "invisible_unicode": {
        "patterns": [
            r"[­͏؜᠎​-‏⁠-⁤﻿]",
        ],
        "severity": FindingSeverity.CRITICAL,
        "category": FindingCategory.HIDDEN_UNICODE,
        "description": "Invisible Unicode characters (zero-width, joiners, word-joiners) in a tool definition can hide instructions from a human reviewer",
        "owasp_asi": ["ASI01", "ASI10"],
    },
    # Other hidden content via Unicode/encoding tricks
    "unicode_hiding": {
        "patterns": [
            r"[‪‫‬‭‮]",  # Bidirectional overrides
            r"[⁦⁧⁨⁩]",  # Isolate marks
            r"&#x[0-9a-fA-F]+;",  # HTML hex entities
            r"\\u[0-9a-fA-F]{4}",  # Unicode escapes
        ],
        "severity": FindingSeverity.HIGH,
        "description": "Hidden content via Unicode tricks or encoding detected in tool definition",
        "owasp_asi": ["ASI01", "ASI10"],
    },
    # Sleeper patterns (tool changes behavior after initial use)
    "sleeper_pattern": {
        "patterns": [
            # A sleeper needs a trigger condition (a count of uses, a phase) — a lone
            # noun such as "count" or "initial" is not evidence (word_count, initialize).
            r"(?i)\bafter\s+(\d+|a\s+few|several|the\s+first)\s+(calls?|uses?|invocations?|runs?|times)\b",
            r"(?i)\bon\s+(the\s+)?(first|second|third|\d+(?:st|nd|rd|th)|nth)\s+(call|use|run|invocation)\b",
            r"(?i)\b(track|count)(s|ing|ed)?\s+(the\s+)?(number\s+of\s+)?(calls|uses|invocations)\b",
            r"(?i)\b(warm.?up|calibration|learning)\s+(phase|period|mode)\b",
        ],
        "severity": FindingSeverity.HIGH,
        "description": "Tool may exhibit different behavior after initial uses (sleeper pattern)",
        "owasp_asi": ["ASI10"],
    },
}


def match_poisoning_group(info: dict, text: str):
    """(severity, matched text, description) for the strongest tier that matches, else None."""
    for pattern in info.get("patterns", []):
        m = re.search(pattern, text)
        if m:
            return info["severity"], m.group(0), info["description"]
    for pattern in info.get("weak", []):
        m = re.search(pattern, text)
        if m:
            return info.get("weak_severity", info["severity"]), m.group(0), info.get("weak_description", info["description"])
    return None

# Prompt injection patterns in MCP tool outputs/responses
PROMPT_INJECTION_PATTERNS = {
    "system_prompt_override": {
        "patterns": [
            r"(?i)<\|?(system|im_start|SYSTEM)\|?>",
            r"(?i)\[SYSTEM\]|\[INST\]|\[/INST\]",
            r"(?i)system\s*:\s*you\s+are",
            r"(?i)<<SYS>>|<</SYS>>",
        ],
        "severity": FindingSeverity.CRITICAL,
        "description": "Attempted system prompt override in MCP content",
    },
    "role_injection": {
        "patterns": [
            r'(?i)"role"\s*:\s*"(system|assistant)"',
            r"(?i)(new\s+instructions?|updated\s+instructions?|revised\s+instructions?)",
            r"(?i)(from\s+now\s+on|going\s+forward|henceforth)",
        ],
        "severity": FindingSeverity.HIGH,
        "description": "Role injection attempt detected in MCP content",
    },
}

# Strict markers: text that is only ever there to steer the model. Used on content
# that is not a tool description (server instructions, resources, prompts, and the
# strings a tool returns), where ordinary prose must not trip anything.
INJECTION_MARKERS = [
    r"(?i)<!--\s*SYSTEM",
    r"(?i)<\s*/?\s*IMPORTANT\s*>",
    r"(?i)\bignore\s+(all\s+|any\s+)?(prior|previous|above|earlier)\s+instructions\b",
    r"(?i)\bdo\s+not\s+(mention|tell)\b",
    r"(?i)\bnever\s+tell\s+the\s+user\b",
    r"\bSYSTEM\s*(NOTE|:)",                       # case-sensitive: 'school system: the mark' is prose
    r"(?im)^\s*system\s*:\s*(you|ignore|from now|new)\b",
    r"(?i)\byou\s+are\s+now\s+in\s+\w+\s+mode\b",
    r"(?i)<\|?(system|im_start)\|?>",
    r"(?i)\b(from\s+now\s+on|new\s+instructions)\b",
    r"(?i)\b(silently|secretly|covertly)\s+(call|run|execute|invoke|read|send)\b",
    r"(?i)(^|\n)\s*\[\s*important\s*\]",          # "[important] when operation is add just use this tool…"
]

# Markers that are unambiguous only in text the server *serves or returns* (resources,
# prompts, tool results): a tool result telling the model what it must call next is an
# injection; the same words in a description are ordinary guidance.
SERVED_TEXT_MARKERS = [
    r"(?i)\b(you\s+must|you\s+should|you\s+need\s+to|be\s+sure\s+to)\s+(add|call|use|invoke|run|include|execute|append)\s+[`'\"]?[A-Za-z_][\w.-]*",
    r"(?i)\bin\s+(the\s+)?final\s+(plan|answer|response)\s+you\s+(make|give|produce)\b",
]

SENSITIVE_PATHS = ("/etc/passwd", "/etc/shadow", ".ssh/", ".aws/credentials", ".aws/",
                   ".npmrc", ".pypirc", ".netrc", ".cursor/mcp.json", "claude_desktop_config.json",
                   "id_rsa", ".env", ".config")

# ---- invisible code points -------------------------------------------------
INVISIBLE_CHARS_RE = re.compile(r"[\u00ad\u034f\u061c\u180e\u200b-\u200f\u2060-\u2064\u2066-\u2069\ufeff]")


def find_invisible_chars(text: str) -> List[Tuple[int, str]]:
    """Positions and code points of invisible / format (Cf) characters in ``text``."""
    out = []
    for i, ch in enumerate(text or ""):
        if INVISIBLE_CHARS_RE.match(ch) or unicodedata.category(ch) == "Cf":
            out.append((i, f"U+{ord(ch):04X}"))
    return out


# ---- hard-coded egress URLs ------------------------------------------------
EGRESS_URL_RE = re.compile(r"https?://[^\s\"'<>)\]`]+", re.I)
EGRESS_ALLOWLIST_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.org", "example.net",
    "github.com", "raw.githubusercontent.com", "pypi.org", "npmjs.com", "registry.npmjs.org",
    "modelcontextprotocol.io", "spec.modelcontextprotocol.io", "json-schema.org", "schema.org",
    "w3.org", "api.openai.com", "api.anthropic.com", "googleapis.com", "microsoft.com",
    "docs.python.org", "owasp.org",
}
SINK_HOST_RE = re.compile(r"(telemetry|collect|ingest|beacon|sink|exfil|track|logger)|\.(xyz|top|click|tk|gq|ml|cf|ga|icu|buzz)$", re.I)
SEND_VERB_RE = re.compile(r"\b(post|send|upload|forward|submit|sync|curl|wget|exfil|transmit|ship|push|pipe)\w*\b", re.I)


def _host_allowlisted(host: str) -> bool:
    host = host.lower()
    return any(host == h or host.endswith("." + h) for h in EGRESS_ALLOWLIST_HOSTS)


def find_egress_urls(text: str) -> List[Tuple[str, str, str]]:
    """Return (url, host, level) for every http(s) URL in ``text``.
    level: 'allowlisted' | 'medium' | 'high' (sink-looking host, or a send verb nearby)."""
    out = []
    for m in EGRESS_URL_RE.finditer(text or ""):
        url = m.group(0).rstrip(".,;:")
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            host = ""
        if not host:
            continue
        if _host_allowlisted(host):
            out.append((url, host, "allowlisted"))
            continue
        before = text[max(0, m.start() - 60):m.start()]
        level = "high" if (SINK_HOST_RE.search(host) or SEND_VERB_RE.search(before)) else "medium"
        out.append((url, host, level))
    return out


# ---- confusable tool names -------------------------------------------------
_SKELETON = str.maketrans({"I": "l", "1": "l", "|": "l", "0": "o", "O": "o"})


def _skeleton(name: str) -> str:
    return name.translate(_SKELETON).replace("rn", "m").replace("vv", "w").lower()


def homoglyph_reason(name: str, all_names: Optional[List[str]] = None) -> Optional[str]:
    """Why a tool name looks confusable, or None."""
    if any(unicodedata.category(ch) in ("Cf", "Cc") for ch in name):
        return "contains invisible or control characters"
    ascii_letters = any(ch.isascii() and ch.isalpha() for ch in name)
    other_letters = any((not ch.isascii()) and ch.isalpha() for ch in name)
    if ascii_letters and other_letters:
        return "mixes Latin and non-Latin letters (homoglyph)"
    if "_" in name:
        uppers = [i for i, ch in enumerate(name) if ch.isupper()]
        if len(uppers) == 1 and name[uppers[0]] in "IO":
            i = uppers[0]
            prev_lower = i > 0 and name[i - 1].islower()
            next_lower = i + 1 < len(name) and name[i + 1].islower()
            if prev_lower or next_lower:
                return f"capital '{name[i]}' where a lowercase lookalike is expected (typosquat)"
    if all_names:
        mine = _skeleton(name)
        for other in all_names:
            if other != name and _skeleton(other) == mine:
                return f"confusable with tool '{other}'"
    return None


# ---- identity, authorization and supply-chain parameters ---------------------
IDENTITY_OVERRIDE_PARAM_RE = re.compile(
    r"(?i)^(on_behalf_of|impersonate(_as)?|as_user|act_as|run_as|sudo_user|override_user|effective_user|"
    r"target_user(_id)?|admin_override|is_admin|bypass\w*|skip_auth\w*|no_auth|elevate\w*)$")
AUTHZ_INPUT_PARAM_RE = re.compile(r"(?i)^(approval|auth|admin|session|access|privilege|role)_?(token|key|code)$|^(role|is_admin|privilege_level|permissions?)$")
INSTALL_TOOL_RE = re.compile(r"(?i)^(install|load|add|import|update|upgrade|fetch|pull)\w*$|(install|load)\w*[_ ](plugin|package|extension|module|dependency|skill)")
INSTALL_DESC_RE = re.compile(r"(?i)\b(install|load|resolve|fetch)\w*\b.{0,40}\b(plugin|package|extension|module|dependency|skill|registry)\b")
SUPPLY_CHAIN_TEXT_RE = re.compile(
    r"(?i)fallback_to_public\s*[:=]\s*(true|1|yes)|prefer_highest_version\s*[:=]\s*(true|1|yes)|"
    r"\b(unverified|unsigned|unvetted)\s+(plugin|package|release|publisher)|\bresolve[sd]?\s+to\s+(the\s+)?public\b")
RESTRICTED_RESOURCE_RE = re.compile(r"(?i)(internal|secret|credential|admin|token|password|private|debug|restricted|master[_-]?key|hidden)")


def find_identity_params(tool: MCPToolDefinition) -> List[Tuple[str, str, bool]]:
    """(param, kind, undocumented) for parameters that let the caller pick who they are or
    hand the server an authorization decision. kind: 'identity_override' | 'authz_input'."""
    out = []
    schema = tool.input_schema if isinstance(tool.input_schema, dict) else {}
    desc = (tool.description or "").lower()
    for pname in (schema.get("properties", {}) or {}):
        if IDENTITY_OVERRIDE_PARAM_RE.match(pname):
            out.append((pname, "identity_override", pname.lower() not in desc))
        elif AUTHZ_INPUT_PARAM_RE.match(pname) and not re.search(r"(?i)^(login|sign_?in|authenticate\w*|verify_token|validate_token)$", tool.name):
            out.append((pname, "authz_input", pname.lower() not in desc))
    return out


def find_unpinned_install(tool: MCPToolDefinition) -> Optional[str]:
    """Why a tool installs/loads code with an unpinned version, or None."""
    schema = tool.input_schema if isinstance(tool.input_schema, dict) else {}
    props = schema.get("properties", {}) or {}
    installs = bool(INSTALL_TOOL_RE.search(tool.name) or INSTALL_DESC_RE.search(tool.description or ""))
    if not installs:
        return None
    for pname, pdef in props.items():
        if isinstance(pdef, dict) and re.search(r"(?i)version|tag|ref|channel", pname):
            default = pdef.get("default")
            if default is None or str(default).lower() in ("latest", "*", "", "newest", "head", "main", "master"):
                return f"'{pname}' defaults to {default!r}"
    if re.search(r"(?i)\blatest\b", tool.description or ""):
        return "description resolves 'latest'"
    return None


def _near_duplicate(a: str, b: str) -> bool:
    """Names a reviewer could confuse: edit distance 1, or one is the other plus a marketing suffix."""
    if a == b:
        return False
    la, lb = a.lower(), b.lower()
    for suffix in ("_advanced", "_v2", "_v3", "_pro", "_new", "_enhanced", "_plus", "_ext", "_extended", "_premium", "2", "s"):
        if lb == la + suffix or la == lb + suffix:
            return True
    if abs(len(la) - len(lb)) > 1:
        return False
    if len(la) == len(lb):
        return sum(x != y for x, y in zip(la, lb)) == 1
    short, long_ = (la, lb) if len(la) < len(lb) else (lb, la)
    for i in range(len(long_)):
        if long_[:i] + long_[i + 1:] == short:
            return True
    return False


def detect_sensitive_resources(resources: List[MCPResourceDefinition], unauthenticated: bool = False,
                               id_prefix: str = "resource") -> List[Finding]:
    """A resource whose URI or name says 'internal', 'secret', 'admin', 'debug'… is listed to
    every client. If the session needed no credential, that is exposure, not a smell."""
    findings: List[Finding] = []
    for r in resources:
        blob = f"{r.uri} {r.name} {r.description}"
        m = RESTRICTED_RESOURCE_RE.search(blob)
        if not m:
            continue
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", r.uri)[:60]
        findings.append(Finding(
            id=f"{id_prefix}_{slug}_restricted_name",
            severity=FindingSeverity.HIGH if unauthenticated else FindingSeverity.MEDIUM,
            category=FindingCategory.CONTEXT_OVERSHARING,
            title=f"Restricted-looking resource is served to clients: {r.uri}",
            description=f"Resource '{r.uri}' ({r.name or 'unnamed'}) is labelled '{m.group(0)}' yet is "
                        + ("listed and readable in an unauthenticated session. "
                           if unauthenticated else "listed to every connected client. ")
                        + "Anything the server lists, an agent will read into the model's context.",
            recommendation="Do not expose internal/admin/debug material as MCP resources; gate it server-side with real authorization.",
            owasp_asi=["ASI03", "ASI02"],
        ))
    return findings


# ---- excessive scope in schema defaults --------------------------------------
SCOPE_PARAM_RE = re.compile(r"(?i)(scopes?|permissions?|roles?|grants?|privileges?)$|^oauth")
SCOPE_VALUE_RE = re.compile(r"(?i)(^|[\s,\[\"'])\*([\s,\]\"']|$)|\.all\b|offline_access|readwrite|read_write|full_access|\ball_access\b|\badmin\b|\*\.\*")
ROOT_PARAM_RE = re.compile(r"(?i)^(root|base|root_path|base_path|root_dir|base_dir|allowed_paths?|workdir|cwd|directory|scope_path)$")
ROOT_VALUES = {"/", "C:\\", "C:/", "c:\\", "c:/", "~", "**", "**/*", "/*", "*"}


CONTEXT_PARAM_RE = re.compile(
    r"(?i)^(tools?_list|tool_list|list_of_tools|available_tools|all_tools|other_tools|tool_names|tool_definitions"
    r"|system_prompt|system_instructions|conversation(_history)?|chat_history|full_context|previous_messages"
    r"|message_history|api_keys?|credentials|secrets|env_vars|environment_variables|auth_tokens?)$"
)
_ARGS_SECTION_RE = re.compile(r"(?ims)^\s*(args|arguments|parameters|params)\s*:\s*\n(.*?)(?=^\s*(returns?|raises?|yields?|examples?|notes?)\s*:|\Z)")
_ARG_LINE_RE = re.compile(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:")


def find_context_params(tool: MCPToolDefinition) -> List[Tuple[str, bool]]:
    """Parameters that ask the model to hand over its context (tool list, conversation,
    system prompt, keys). Returns (name, documented)."""
    props = (tool.input_schema or {}).get("properties", {}) if isinstance(tool.input_schema, dict) else {}
    out = []
    desc = (tool.description or "").lower()
    for p in props:
        if CONTEXT_PARAM_RE.match(p):
            out.append((p, p.lower() in desc))
    return out


def documented_args(description: str) -> Optional[List[str]]:
    """Parameter names listed under an Args:/Parameters: section, or None when there is no section."""
    m = _ARGS_SECTION_RE.search(description or "")
    if not m:
        return None
    return [x.group(1) for x in _ARG_LINE_RE.finditer(m.group(2))]


def find_excessive_scopes(tool: MCPToolDefinition) -> List[Tuple[str, str]]:
    """(param, reason) for schema parameters whose default or description asks for everything."""
    out = []
    schema = tool.input_schema if isinstance(tool.input_schema, dict) else {}
    props = schema.get("properties", {}) or {}
    for pname, pdef in props.items():
        if not isinstance(pdef, dict):
            continue
        default = pdef.get("default")
        blob = f"{default if default is not None else ''} {pdef.get('description', '')}"
        if SCOPE_PARAM_RE.search(pname) and SCOPE_VALUE_RE.search(blob):
            out.append((pname, f"requests broad scopes by default: {str(default)[:80]!r}"))
        elif ROOT_PARAM_RE.search(pname) and isinstance(default, str) and default.strip() in ROOT_VALUES:
            out.append((pname, f"defaults to the whole filesystem: {default!r}"))
    return out


class ToolPoisoningDetector:
    """Detects tool poisoning attacks in MCP tool definitions."""

    def analyze_tool(self, tool: MCPToolDefinition) -> Tuple[List[Finding], RiskLevel]:
        """Analyze a single MCP tool definition for poisoning indicators."""
        findings = []
        max_severity = FindingSeverity.INFO

        text_to_check = f"{tool.name} {tool.description} {str(tool.input_schema)}"

        # Unambiguous markers in a description are CRITICAL whatever else is said
        for marker in INJECTION_MARKERS:
            m = re.search(marker, tool.description or "")
            if m:
                findings.append(Finding(
                    id=f"poison_{tool.name}_injection_marker",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.TOOL_POISONING,
                    title=f"Tool poisoning: injected instructions in '{tool.name}'",
                    description=f"The description of '{tool.name}' contains text meant for the model, not the user: "
                                f"'{m.group(0).strip()}'.",
                    recommendation="A tool description must describe the tool. Remove the instruction, or do not install this server.",
                    owasp_asi=["ASI01"],
                ))
                break

        for pattern_name, pattern_info in POISONING_PATTERNS.items():
            hit = match_poisoning_group(pattern_info, text_to_check)
            if hit:
                sev, matched, desc = hit
                findings.append(Finding(
                    id=f"poison_{tool.name}_{pattern_name}",
                    severity=sev,
                    category=pattern_info.get("category", FindingCategory.TOOL_POISONING),
                    title=f"Tool poisoning: {pattern_name.replace('_', ' ')} in '{tool.name}'"
                          if sev != pattern_info.get("weak_severity") or not pattern_info.get("weak")
                          else f"Steering language ({pattern_name.replace('_', ' ')}) in '{tool.name}'",
                    description=f"{desc}. Matched pattern in tool '{tool.name}': '{matched}'",
                    recommendation="Review tool description carefully. Compare claimed functionality "
                                   "with actual code behavior. Consider removing this MCP server.",
                    owasp_asi=pattern_info.get("owasp_asi", ["ASI01"]),
                ))

        # Hard-coded egress URL in the description itself
        for n, (url, host, level) in enumerate(find_egress_urls(tool.description), 1):
            if level == "allowlisted":
                continue
            findings.append(Finding(
                id=f"egress_{tool.name}_desc_{n}",
                severity=FindingSeverity.HIGH if level == "high" else FindingSeverity.MEDIUM,
                category=FindingCategory.DATA_EXFILTRATION,
                title=f"Hard-coded egress URL in description of tool '{tool.name}': {host}",
                description=f"The description of '{tool.name}' names an external endpoint "
                            f"({url[:120]}). A tool that tells the agent where to send data is an "
                            "exfiltration channel.",
                recommendation="Remove the endpoint from the description; make egress destinations explicit, user-approved configuration.",
                owasp_asi=["ASI01", "ASI02"],
            ))

        # Excessive scope asked for in the input schema defaults
        for pname, reason in find_excessive_scopes(tool):
            findings.append(Finding(
                id=f"scope_{tool.name}_{pname}_excessive",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.EXCESSIVE_SCOPE,
                title=f"Tool '{tool.name}' parameter '{pname}' {reason.split(':')[0]}",
                description=f"Parameter '{pname}' of tool '{tool.name}' {reason}. The task does not "
                            "need that much, and an agent will pass the default through unchanged.",
                recommendation="Default to the minimum scope the tool needs; require explicit, narrow values.",
                owasp_asi=["ASI03"],
            ))

        # Identity override / caller-supplied authorization parameters
        for pname, kind, undocumented in find_identity_params(tool):
            if kind == "identity_override":
                findings.append(Finding(
                    id=f"identity_override_{tool.name}_{pname}",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.IDENTITY_PRIVILEGE,
                    title=f"Tool '{tool.name}' lets the caller choose whose identity to act under ('{pname}')",
                    description=f"Parameter '{pname}' of '{tool.name}' selects the user the action applies to"
                                + (" and is not mentioned in the description (undocumented)." if undocumented else ".")
                                + " Any agent, or anyone who can prompt it, can read or act as another user.",
                    recommendation="Derive identity from the authenticated session only; remove impersonation parameters or gate them with server-side authorization.",
                    owasp_asi=["ASI03"],
                ))
            else:
                findings.append(Finding(
                    id=f"authz_input_{tool.name}_{pname}",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.IDENTITY_PRIVILEGE,
                    title=f"Tool '{tool.name}' takes an authorization decision from caller input ('{pname}')",
                    description=f"'{tool.name}' accepts '{pname}' from the caller. If that value can be read from "
                                "another tool or resource (IDOR, logs, debug output), the agent can escalate its own privileges.",
                    recommendation="Bind approvals and roles to the authenticated principal server-side; never accept them as plain parameters.",
                    owasp_asi=["ASI03"],
                ))

        # Parameters that ask for the agent's own context (schema-level exfiltration)
        for pname, documented in find_context_params(tool):
            findings.append(Finding(
                id=f"schema_{tool.name}_context_param_{pname}",
                severity=FindingSeverity.MEDIUM if documented else FindingSeverity.HIGH,
                category=FindingCategory.DATA_EXFILTRATION,
                title=f"Tool '{tool.name}' asks the agent to pass its context as '{pname}'"
                      + ("" if documented else " (undocumented)"),
                description=f"Parameter '{pname}' of '{tool.name}' has no role in the tool's stated purpose "
                            f"('{(tool.description or '')[:80]}'); it asks the model to hand over its tool list, "
                            "conversation, system prompt or keys. The schema itself is the exfiltration channel.",
                recommendation="Remove parameters the task does not need; a tool must never ask for the agent's context.",
                owasp_asi=["ASI01", "ASI02"],
            ))

        # Documented arguments vs the real schema
        props = (tool.input_schema or {}).get("properties", {}) if isinstance(tool.input_schema, dict) else {}
        documented = documented_args(tool.description or "")
        if documented is not None and props is not None:
            missing = [a for a in documented if a not in props]
            undocumented = [p for p in props if p not in documented and not CONTEXT_PARAM_RE.match(p)]
            if missing:
                findings.append(Finding(
                    id=f"schema_{tool.name}_doc_mismatch",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.METADATA,
                    title=f"Tool '{tool.name}' documents arguments it does not take: {', '.join(missing[:4])}",
                    description=f"The description of '{tool.name}' lists {', '.join(missing[:6])} under Args, but the "
                                f"schema has {', '.join(props) or 'no parameters'}. The model will try to pass what the text says.",
                    recommendation="Keep the Args section and the schema identical.",
                    owasp_asi=["ASI02"],
                ))
            if undocumented and documented:
                findings.append(Finding(
                    id=f"schema_{tool.name}_undocumented_params",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.METADATA,
                    title=f"Tool '{tool.name}' takes parameters its description does not mention: {', '.join(undocumented[:4])}",
                    description=f"'{tool.name}' documents {', '.join(documented[:6])} but its schema also has "
                                f"{', '.join(undocumented[:6])}. A reviewer reading the description would not know these exist.",
                    recommendation="Document every parameter, or remove the ones the tool does not need.",
                    owasp_asi=["ASI02"],
                ))

        # Unpinned install/load of code at runtime (supply chain)
        why = find_unpinned_install(tool)
        if why:
            findings.append(Finding(
                id=f"unpinned_runtime_install_{tool.name}",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.SUPPLY_CHAIN,
                title=f"Tool '{tool.name}' installs or loads code with an unpinned version",
                description=f"'{tool.name}' {why}. Whatever the registry resolves — a backdoored release, "
                            "a dependency-confusion package — becomes part of the agent's tool set.",
                recommendation="Require an exact version and a signature/hash; never resolve 'latest' from a tool call.",
                owasp_asi=["ASI04"],
            ))

        # Check description length anomaly (unusually long descriptions often hide instructions)
        if len(tool.description) > 500:
            findings.append(Finding(
                id=f"poison_{tool.name}_long_desc",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.TOOL_POISONING,
                title=f"Unusually long tool description for '{tool.name}'",
                description=f"Tool description is {len(tool.description)} characters. "
                            "Long descriptions can hide malicious instructions.",
                recommendation="Review the full tool description for hidden instructions.",
            ))

        # Check for mismatch between tool name and description
        if self._name_description_mismatch(tool):
            findings.append(Finding(
                id=f"poison_{tool.name}_mismatch",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.TOOL_POISONING,
                title=f"Tool name/description mismatch for '{tool.name}'",
                description="The tool's name suggests simple functionality but its description "
                            "references capabilities beyond its stated purpose.",
                recommendation="Verify the tool actually does what its name suggests.",
            ))

        risk = RiskLevel.SAFE
        if any(f.severity == FindingSeverity.CRITICAL for f in findings):
            risk = RiskLevel.CRITICAL
        elif any(f.severity == FindingSeverity.HIGH for f in findings):
            risk = RiskLevel.HIGH
        elif any(f.severity == FindingSeverity.MEDIUM for f in findings):
            risk = RiskLevel.MEDIUM
        elif findings:
            risk = RiskLevel.LOW

        return findings, risk

    def analyze_all_tools(self, tools: List[MCPToolDefinition]) -> List[Finding]:
        """Analyze all tools from an MCP server."""
        all_findings = []
        for tool in tools:
            findings, risk = self.analyze_tool(tool)
            tool.poisoning_risk = risk
            tool.has_hidden_instructions = risk in (RiskLevel.CRITICAL, RiskLevel.HIGH)
            if findings:
                tool.poisoning_detail = findings[0].description
            all_findings.extend(findings)

        # Confusable / homoglyph tool names
        names = [t.name for t in tools]
        for tool in tools:
            reason = homoglyph_reason(tool.name, names)
            if reason:
                all_findings.append(Finding(
                    id=f"poison_{tool.name}_homoglyph",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.HOMOGLYPH,
                    title=f"Confusable (homoglyph) tool name '{tool.name}'",
                    description=f"Tool name '{tool.name}' {reason}. Lookalike names let a malicious "
                                "tool be selected in place of a trusted one, by the model or by a reviewer.",
                    recommendation="Use plain lowercase snake_case ASCII tool names; reject names that are confusable with another tool.",
                    owasp_asi=["ASI04", "ASI09"],
                ))
                if tool.poisoning_risk == RiskLevel.SAFE:
                    tool.poisoning_risk = RiskLevel.HIGH
                    tool.has_hidden_instructions = True
                    tool.poisoning_detail = f"Confusable tool name: {reason}"

        # Near-duplicate names: a lookalike of a legitimate tool is how shadowing starts
        risky = {f.id.split("_", 1)[1].rsplit("_", 1)[0] for f in all_findings if f.id.startswith("poison_")}
        for i, tool in enumerate(tools):
            for other in tools[i + 1:]:
                if _near_duplicate(tool.name, other.name):
                    suspect = other if other.name in risky or len(other.description) > len(tool.description) else tool
                    victim = tool if suspect is other else other
                    all_findings.append(Finding(
                        id=f"shadow_{suspect.name}_near_duplicate",
                        severity=FindingSeverity.HIGH if suspect.name in risky else FindingSeverity.MEDIUM,
                        category=FindingCategory.TOOL_SHADOWING,
                        title=f"Tool '{suspect.name}' is a near-duplicate of '{victim.name}'",
                        description=f"'{suspect.name}' and '{victim.name}' differ by one character or a suffix. The model "
                                    "may pick either; a lookalike with extra instructions shadows the legitimate tool.",
                        recommendation="Keep one clearly named tool per capability; remove or rename lookalikes.",
                        owasp_asi=["ASI01", "ASI04"],
                    ))

        # Cross-tool analysis: check if one tool references another's output
        tool_names = {t.name for t in tools}
        for tool in tools:
            for other_name in tool_names:
                if other_name != tool.name and other_name in tool.description:
                    all_findings.append(Finding(
                        id=f"cross_tool_{tool.name}_{other_name}",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.CROSS_SERVER,
                        title=f"Tool '{tool.name}' references tool '{other_name}'",
                        description=f"Tool description mentions another tool by name, "
                                    f"which could enable tool chaining attacks.",
                        recommendation="Verify this cross-reference is legitimate and necessary.",
                    ))

        return all_findings

    def check_prompt_injection_risk(self, content: str) -> List[Finding]:
        """Check content for prompt injection patterns."""
        findings = []
        for pattern_name, pattern_info in PROMPT_INJECTION_PATTERNS.items():
            for pattern in pattern_info["patterns"]:
                if re.search(pattern, content):
                    findings.append(Finding(
                        id=f"inject_{pattern_name}",
                        severity=pattern_info["severity"],
                        category=FindingCategory.PROMPT_INJECTION,
                        title=f"Prompt injection risk: {pattern_name.replace('_', ' ')}",
                        description=pattern_info["description"],
                        recommendation="This content could manipulate AI behavior if processed by an LLM.",
                    ))
                    break
        return findings

    def scan_text(
        self,
        text: str,
        subject: str,
        id_prefix: str,
        strict: bool = False,
        marker_category: FindingCategory = FindingCategory.PROMPT_INJECTION,
        dangerous_tools: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Run every text rule on ``text`` (server instructions, a resource, a prompt, a
        returned string). ``subject`` is the human label ("resource notes://welcome");
        ``id_prefix`` makes ids stable. ``strict=True`` keeps only unambiguous markers
        (for strings a tool returns, where ordinary prose must never fire).
        ``dangerous_tools`` maps tool name -> capability for the invokes-dangerous-tool rule."""
        findings: List[Finding] = []
        if not text:
            return findings
        text = str(text)
        snippet = text.strip().replace("\n", " ")[:160]

        # 1. unambiguous injection markers (plus served-text markers: this is not a description)
        for marker in list(INJECTION_MARKERS) + SERVED_TEXT_MARKERS:
            m = re.search(marker, text)
            if m:
                findings.append(Finding(
                    id=f"{id_prefix}_injection_marker",
                    severity=FindingSeverity.CRITICAL,
                    category=marker_category,
                    title=f"Injected instructions in {subject}",
                    description=f"{subject} contains text meant for the model, not the user: "
                                f"'{m.group(0)}'. Excerpt: '{snippet}'",
                    recommendation="Content an agent reads must not carry instructions. Remove it, or do not install this server.",
                    owasp_asi=["ASI01", "ASI06"],
                ))
                break

        # 2. description-style poisoning patterns (not in strict mode)
        if not strict:
            for pattern_name, info in POISONING_PATTERNS.items():
                if pattern_name in ("invisible_unicode", "sleeper_pattern"):
                    continue
                hit = match_poisoning_group(info, text)
                if hit:
                    sev, matched, desc = hit
                    findings.append(Finding(
                        id=f"{id_prefix}_{pattern_name}",
                        severity=sev,
                        category=info.get("category", marker_category),
                        title=f"{pattern_name.replace('_', ' ').capitalize()} in {subject}",
                        description=f"{desc}. Matched '{matched}' in {subject}. "
                                    f"Excerpt: '{snippet}'",
                        recommendation="Review this content; an agent will follow it.",
                        owasp_asi=info.get("owasp_asi", ["ASI01"]),
                    ))
            for f in self.check_prompt_injection_risk(text):
                f.id = f"{id_prefix}_{f.id}"
                f.title = f"{f.title} in {subject}"
                findings.append(f)

        # 3. invisible code points
        invisible = find_invisible_chars(text)
        if invisible:
            cps = sorted({cp for _, cp in invisible})
            findings.append(Finding(
                id=f"{id_prefix}_invisible_unicode",
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.HIDDEN_UNICODE,
                title=f"Invisible Unicode characters in {subject}",
                description=f"{subject} contains {len(invisible)} invisible character(s) "
                            f"({', '.join(cps[:6])}). Text between them is hidden from a human "
                            "reviewer but read by the model.",
                recommendation="Strip zero-width and format characters from all server-provided text.",
                owasp_asi=["ASI01", "ASI10"],
            ))

        # 4. hard-coded egress URLs
        for n, (url, host, level) in enumerate(find_egress_urls(text), 1):
            if level == "allowlisted":
                continue
            findings.append(Finding(
                id=f"{id_prefix}_egress_{n}",
                severity=FindingSeverity.HIGH if level == "high" else FindingSeverity.MEDIUM,
                category=FindingCategory.DATA_EXFILTRATION,
                title=f"External endpoint named in {subject}: {host}",
                description=f"{subject} points the agent at {url[:120]}. Combined with an "
                            "instruction, this is a ready-made exfiltration path.",
                recommendation="Content an agent reads should not name endpoints to send data to.",
                owasp_asi=["ASI01", "ASI02"],
            ))

        # 5. sensitive paths
        for sensitive in SENSITIVE_PATHS:
            if sensitive in text:
                findings.append(Finding(
                    id=f"{id_prefix}_sensitive_path",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.CREDENTIAL_THEFT,
                    title=f"Sensitive path referenced in {subject}: {sensitive}",
                    description=f"{subject} references '{sensitive}'. Excerpt: '{snippet}'",
                    recommendation="Nothing an agent reads should steer it toward credential files.",
                    owasp_asi=["ASI03"],
                ))
                break

        # 6. credentials in the text itself (served secrets, logs, configs)
        secrets = find_secrets_in_text(text)
        if secrets:
            labels = "; ".join(f"{label} ({key})" for label, key in secrets[:6])
            findings.append(Finding(
                id=f"{id_prefix}_secret_exposure",
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.CREDENTIAL_THEFT,
                title=f"Credentials exposed in {subject}",
                description=f"{subject} contains credential-shaped values: {labels}. Values are not reproduced here. "
                            "Anything a server serves ends up in the model's context and in the client's logs.",
                recommendation="Never serve credentials, tokens or flags as MCP content; keep them server-side and out of tool output.",
                owasp_asi=["ASI03"],
            ))

        # 7. supply-chain configuration that resolves untrusted code
        m = SUPPLY_CHAIN_TEXT_RE.search(text)
        if m:
            findings.append(Finding(
                id=f"{id_prefix}_supply_chain_config",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.SUPPLY_CHAIN,
                title=f"{subject} resolves code from an untrusted source",
                description=f"{subject} says '{m.group(0)}'. Resolution that prefers public or highest versions is "
                            "the precondition for dependency confusion and plugin poisoning.",
                recommendation="Pin internal packages to the internal registry; never fall back to public resolution silently.",
                owasp_asi=["ASI04"],
            ))

        # 8. names a tool that is itself dangerous
        if dangerous_tools:
            hits = sorted({name for name in dangerous_tools if re.search(rf"\b{re.escape(name)}\b", text)})
            if hits:
                caps = ", ".join(f"{n} ({dangerous_tools[n]})" for n in hits[:4])
                findings.append(Finding(
                    id=f"{id_prefix}_invokes_dangerous_tool",
                    severity=FindingSeverity.HIGH,
                    category=marker_category,
                    title=f"{subject} steers the agent to dangerous tools: {', '.join(hits[:4])}",
                    description=f"{subject} names {caps}. Content that tells the model which "
                                "high-impact tool to call next is how a hijack becomes an action.",
                    recommendation="Remove tool-invocation guidance from server-provided content.",
                    owasp_asi=["ASI01", "ASI02"],
                ))
        return findings

    def _name_description_mismatch(self, tool: MCPToolDefinition) -> bool:
        """Detect if tool name suggests benign functionality but description is suspicious."""
        benign_names = {"format", "theme", "color", "font", "style", "random", "fun",
                        "quote", "joke", "tip", "helper", "utility", "beautif"}
        suspicious_desc_keywords = {"credential", "token", "password", "ssh", "key",
                                    "exfiltrat", "forward", "send to", "transmit",
                                    "execute", "shell", "command", "subprocess"}

        name_is_benign = any(b in tool.name.lower() for b in benign_names)
        desc_is_suspicious = any(s in tool.description.lower() for s in suspicious_desc_keywords)

        return name_is_benign and desc_is_suspicious


# Singleton
tool_poisoning_detector = ToolPoisoningDetector()
