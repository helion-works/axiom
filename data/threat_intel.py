"""
Known MCP security issues.

A short curated list of published MCP vulnerabilities, each with its real identifier, the
real package name, the affected version range from the advisory, and a link to the source.
An entry is added only after it has been checked against that source.
"""

import re
from typing import Dict, List, Optional, Tuple

# Published CVEs in MCP packages. `affected` is a list of (introduced, fixed) pairs:
# a version v is affected when introduced <= v < fixed. `ghsa` is the same advisory's id
# in the GitHub Advisory Database, which is the id OSV reports it under.
KNOWN_MCP_CVES = {
    "CVE-2025-6514": {
        "title": "mcp-remote OS command injection",
        "severity": "critical",
        "package": "mcp-remote",
        "ecosystem": "npm",
        "ghsa": "GHSA-6xpm-ggf7-wc3p",
        "affected": [("0.0.5", "0.1.16")],
        "fixed": "0.1.16",
        "description": "OS command injection in mcp-remote when connecting to an untrusted MCP "
                       "server: a crafted OAuth authorization_endpoint can run commands on the "
                       "client machine. Affects versions 0.0.5 to 0.1.15.",
        "recommendation": "Update mcp-remote to 0.1.16 or later.",
        "reference": "https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/",
    },
    "CVE-2025-49596": {
        "title": "MCP Inspector proxy lacks authentication",
        "severity": "critical",
        "package": "@modelcontextprotocol/inspector",
        "ecosystem": "npm",
        "ghsa": "GHSA-7f8r-222p-6f5g",
        "affected": [("0", "0.14.1")],
        "fixed": "0.14.1",
        "description": "Versions of MCP Inspector below 0.14.1 have no authentication between the "
                       "Inspector client and its proxy, so unauthenticated requests can launch MCP "
                       "commands over stdio (remote code execution).",
        "recommendation": "Update @modelcontextprotocol/inspector to 0.14.1 or later.",
        "reference": "https://github.com/advisories/GHSA-7f8r-222p-6f5g",
    },
    "CVE-2025-53109": {
        "title": "Filesystem MCP server path validation bypass",
        "severity": "high",
        "package": "@modelcontextprotocol/server-filesystem",
        "ecosystem": "npm",
        "ghsa": "GHSA-q66q-fx2p-7w4m",
        # The advisory has two ranges: everything up to 0.6.2 (never fixed in the 0.x line),
        # and 2025.1.14 up to the fix. "0.6.3" is only the exclusive bound for "up to 0.6.2";
        # no such release exists.
        "affected": [("0", "0.6.3"), ("2025.1.14", "2025.7.1")],
        "fixed": "2025.7.1",
        "description": "Path validation in the Filesystem MCP server can be bypassed through "
                       "symlinks inside an allowed directory, giving access to files outside it. "
                       "Affects every version up to 0.6.2, and 2025.1.14 to before 2025.7.1.",
        "recommendation": "Update @modelcontextprotocol/server-filesystem to 2025.7.1 or later.",
        "reference": "https://github.com/advisories/GHSA-q66q-fx2p-7w4m",
    },
}

# Packages known to be malicious (not merely vulnerable in some versions); any version is
# reported. Empty: no entry has been verified against a primary source yet. Vulnerable
# versions of legitimate packages belong in KNOWN_MCP_CVES above.
KNOWN_VULNERABLE_PACKAGES: Dict[str, Dict[str, str]] = {}

# Published disclosures and research demonstrations that the detectors were modelled on.
# Reference material only; nothing matches against this list.
KNOWN_INCIDENTS = [
    {
        "name": "WhatsApp MCP tool poisoning",
        "kind": "research demonstration",
        "source": "Invariant Labs, April 2025",
        "reference": "https://invariantlabs.ai/blog/whatsapp-mcp-exploited",
        "description": "A second MCP server offering a harmless 'fact of the day' tool later changed "
                       "its description and made an agent send the user's WhatsApp chat history to "
                       "an attacker-chosen number.",
        "attack_type": "tool_poisoning",
        "indicators": ["tool description changes after initial load", "hidden instructions in descriptions"],
    },
    {
        "name": "GitHub MCP prompt injection",
        "kind": "research demonstration",
        "source": "Invariant Labs, May 2025",
        "reference": "https://invariantlabs.ai/blog/mcp-github-vulnerability",
        "description": "A malicious issue in a public repository made an agent copy data from the "
                       "user's private repositories into a public pull request. Described by the "
                       "researchers as a design problem in agent systems, not a bug in the server.",
        "attack_type": "prompt_injection",
        "indicators": ["broad token scopes", "untrusted content in LLM context"],
    },
    {
        "name": "Asana MCP server data exposure",
        "kind": "disclosed bug",
        "source": "The Register, June 2025",
        "reference": "https://www.theregister.com/2025/06/18/asana_mcp_server_bug/",
        "description": "A bug in Asana's MCP server could have exposed one organization's data to "
                       "MCP users in another. The server was offline from 5 to 17 June 2025.",
        "attack_type": "permission_overscope",
        "indicators": ["cross-tenant access", "insufficient isolation"],
    },
]

# Suspicious MCP tool name patterns (often used in attacks)
SUSPICIOUS_TOOL_NAMES = [
    "random_fact",
    "fun_fact",
    "daily_quote",
    "text_formatter",
    "code_beautifier",
    "helper",
    "utility",
]

# MCP registries and sources to cross-reference
MCP_REGISTRIES = {
    "smithery": "https://smithery.ai",
    "mcp-so": "https://mcp.so",
    "glama": "https://glama.ai/mcp/servers",
    "github-mcp-servers": "https://github.com/modelcontextprotocol/servers",
    "awesome-mcp": "https://github.com/punkpeye/awesome-mcp-servers",
}


# Bounded on purpose: a manifest can hold any text where a version belongs.
_NUMERIC_PREFIX = re.compile(r"^\d{1,9}(?:\.\d{1,9}){0,7}")


def version_tuple(version: Optional[str]) -> Optional[Tuple[int, ...]]:
    """The leading dotted-number part of a version as a tuple, or None when there is none.

    A pre-release of the fixed version (for example 0.1.16-beta.1) compares equal to the
    fixed version and so is treated as not affected.
    """
    m = _NUMERIC_PREFIX.match((version or "").strip().lstrip("vV"))
    if not m:
        return None
    return tuple(int(part) for part in m.group(0).split("."))


def _pad(a: Tuple[int, ...], b: Tuple[int, ...]) -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def version_affected(version: Optional[str], ranges: List[Tuple[str, str]]) -> Optional[bool]:
    """True / False when the version can be compared with the ranges, None when it cannot."""
    v = version_tuple(version)
    if v is None:
        return None
    for introduced, fixed in ranges:
        lo, hi = version_tuple(introduced), version_tuple(fixed)
        if lo is None or hi is None:
            continue
        v_lo, lo = _pad(v, lo)
        v_hi, hi = _pad(v, hi)
        if lo <= v_lo and v_hi < hi:
            return True
    return False


def advisory_aliases(cve_id: str) -> List[str]:
    """Other ids the same advisory is published under (the GHSA id OSV uses)."""
    ghsa = KNOWN_MCP_CVES.get(cve_id, {}).get("ghsa")
    return [ghsa] if ghsa else []


def cves_for_package(name: str, ecosystem: str = "npm") -> List[Tuple[str, dict]]:
    """Every listed CVE whose package is exactly this one."""
    return [(cve_id, info) for cve_id, info in KNOWN_MCP_CVES.items()
            if info["package"] == name and info["ecosystem"] == ecosystem]
