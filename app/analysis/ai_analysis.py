"""
AI-Powered MCP Security Analysis
Uses Claude to generate:
  1. Claimed vs. Actual behavior comparison
  2. Tool poisoning risk assessment
  3. Prompt injection vulnerability analysis
  4. Overall security recommendation

Includes an in-memory content-hash cache so identical tool definitions +
findings don't re-call the API.
"""

import hashlib
import time
from typing import Optional, List, Dict
from app.models.schemas import Finding, MCPServerProfile
from app.utils.config import settings
from app.utils.logging import get_logger

logger = get_logger("ai_analysis")

# ---- Cache ----

_EMPTY_RESULT: Dict[str, Optional[str]] = {
    "ai_analysis": None,
    "tool_poisoning_report": None,
    "prompt_injection_risk": None,
    "claimed_vs_actual": None,
}

# Cache keyed on content hash → (result_dict, timestamp)
_analysis_cache: Dict[str, tuple] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour
CACHE_MAX_SIZE = 200


def _build_cache_key(
    target: str,
    findings: List[Finding],
    server_profile: Optional[MCPServerProfile],
) -> str:
    """Build a deterministic hash of the inputs that affect AI analysis output."""
    parts = [target]
    for f in sorted(findings[:30], key=lambda f: f.id):
        parts.append(f"{f.severity.value}|{f.category.value}|{f.title}")
    if server_profile and server_profile.tools:
        for t in sorted(server_profile.tools, key=lambda t: t.name):
            parts.append(f"{t.name}|{t.description[:300]}")
    raw = "\n".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def _get_cached(key: str) -> Optional[dict]:
    entry = _analysis_cache.get(key)
    if entry is None:
        return None
    result, ts = entry
    if time.monotonic() - ts > CACHE_TTL_SECONDS:
        del _analysis_cache[key]
        return None
    return result


def _put_cache(key: str, result: dict):
    # Evict oldest entries if cache is full
    if len(_analysis_cache) >= CACHE_MAX_SIZE:
        oldest_key = min(_analysis_cache, key=lambda k: _analysis_cache[k][1])
        del _analysis_cache[oldest_key]
    _analysis_cache[key] = (result, time.monotonic())


# ---- Main ----

async def generate_mcp_ai_analysis(
    target: str,
    findings: List[Finding],
    server_profile: Optional[MCPServerProfile],
) -> dict:
    """
    Generate comprehensive AI analysis of an MCP server.
    Returns dict with separate analysis sections.
    Results are cached by content hash to avoid redundant API calls.
    """
    if not settings.ANTHROPIC_API_KEY:
        logger.warning("AI analysis skipped — ANTHROPIC_API_KEY not set")
        return {
            **_EMPTY_RESULT,
            "ai_analysis": "AI analysis unavailable — set ANTHROPIC_API_KEY in .env",
        }

    # Check cache
    cache_key = _build_cache_key(target, findings, server_profile)
    cached = _get_cached(cache_key)
    if cached is not None:
        logger.info("AI analysis cache hit", extra={"target": target})
        return cached

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

        # Build context
        findings_text = "\n".join(
            f"- [{f.severity.value.upper()}][{f.category.value}] {f.title}: {f.description}"
            for f in findings[:30]
        ) or "No findings."

        tools_text = ""
        if server_profile and server_profile.tools:
            tools_text = "\n".join(
                f"- Tool: {t.name}\n  Description: {t.description[:300]}\n  Poisoning Risk: {t.poisoning_risk.value}"
                for t in server_profile.tools
            )

        transport = server_profile.transport.value if server_profile else "unknown"
        tool_count = len(server_profile.tools) if server_profile else 0
        resource_count = len(server_profile.resources) if server_profile else 0

        prompt = f"""You are an expert MCP (Model Context Protocol) security analyst. Analyze this MCP server scan.

## Target: {target}
## Transport: {transport}
## Tools Defined: {tool_count}
## Resources: {resource_count}

## Tool Definitions:
{tools_text or "No tool definitions extracted."}

## Security Findings:
{findings_text}

Provide your analysis in EXACTLY this format with these 4 sections:

=== OVERALL ASSESSMENT ===
(2-3 sentences: What does this MCP server do? Is it safe to install? Give a clear recommendation: SAFE / USE WITH CAUTION / DO NOT INSTALL)

=== CLAIMED VS ACTUAL ===
(Compare what the tool descriptions claim to do versus what the code analysis reveals. Flag any mismatches where the code does more than the tool descriptions suggest.)

=== TOOL POISONING RISK ===
(Assess whether any tool descriptions contain hidden instructions, manipulation attempts, or suspicious patterns that could influence AI behavior. Rate: NONE / LOW / MEDIUM / HIGH / CRITICAL)

=== PROMPT INJECTION RISK ===
(Assess whether this MCP server could be used as a vector for prompt injection attacks. Consider: Does it return user-controlled content to the AI? Could tool responses contain hidden instructions? Rate: NONE / LOW / MEDIUM / HIGH / CRITICAL)

Be specific and actionable. Reference actual findings where relevant. No markdown formatting."""

        logger.info("Calling Claude API for analysis", extra={"target": target})

        message = client.messages.create(
            model=settings.ANTHROPIC_MODEL,
            max_tokens=1200,
            messages=[{"role": "user", "content": prompt}],
        )

        full_response = message.content[0].text

        # Parse sections
        sections = {
            "ai_analysis": _extract_section(full_response, "OVERALL ASSESSMENT"),
            "claimed_vs_actual": _extract_section(full_response, "CLAIMED VS ACTUAL"),
            "tool_poisoning_report": _extract_section(full_response, "TOOL POISONING RISK"),
            "prompt_injection_risk": _extract_section(full_response, "PROMPT INJECTION RISK"),
        }

        # Fallback to full response if parsing fails
        if not sections["ai_analysis"]:
            sections["ai_analysis"] = full_response

        # Cache result
        _put_cache(cache_key, sections)
        logger.info("AI analysis completed and cached", extra={"target": target})

        return sections

    except ImportError:
        return {**_EMPTY_RESULT, "ai_analysis": "Install anthropic package: pip install anthropic"}
    except Exception as e:
        logger.error("AI analysis failed", exc_info=True, extra={"target": target})
        return {**_EMPTY_RESULT, "ai_analysis": f"AI analysis failed: {str(e)}"}


def _extract_section(text: str, section_name: str) -> Optional[str]:
    """Extract a named section from the AI response."""
    import re
    pattern = rf"===\s*{re.escape(section_name)}\s*===\s*\n(.*?)(?====|$)"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None
