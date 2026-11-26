"""
A2A Agent Card Scanner (static / passive).

Fetches an A2A agent card (or reads one from disk) and checks the security
posture it advertises: transport, authentication schemes, card signing, skill
text, extended-card exposure, protocol version and provenance.

Passive by design. Network activity is limited to:
  * the agent card itself (for a base URL: /.well-known/agent-card.json, falling
    back to the legacy /.well-known/agent.json if the first is missing);
  * at most ONE JWKS document, when a card signature names its key via `jku`
    (or the card publishes a jwksUri-style field);
  * at most ONE unauthenticated GET of the extended agent card, only when the
    card declares one.
No task, message or other A2A RPC endpoint is ever called. All requests go
through app.utils.safe_fetch (SSRF-guarded).

Pinned to A2A specification 1.0.0; 0.2/0.3 cards are accepted as legacy.
"""

from __future__ import annotations

import base64
import functools
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from app.analysis.owasp_mapping import apply_owasp_mappings
from app.analysis.tool_poisoning import ToolPoisoningDetector
from app.models.schemas import (
    A2AAgentCardSummary,
    A2AScanResult,
    Finding,
    FindingCategory,
    FindingSeverity,
    MCPToolDefinition,
    RiskLevel,
)
from app.utils.safe_fetch import SafeFetchError, UnsafeURLError, safe_get

__all__ = [
    "A2AScanError",
    "scan_agent_card",
    "analyze_card",
    "validate_card_schema",
    "canonicalize_card",
    "SCOPE_NOTE",
    "WELL_KNOWN_PATH",
    "LEGACY_WELL_KNOWN_PATH",
]

WELL_KNOWN_PATH = "/.well-known/agent-card.json"
LEGACY_WELL_KNOWN_PATH = "/.well-known/agent.json"
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "data" / "a2a_agent_card_schema.json"
MAX_CARD_BYTES = 1_000_000

SCOPE_NOTE = (
    "Static agent card analysis only. Axiom read the published A2A agent card and, where "
    "relevant, at most one signing-key (JWKS) document and one unauthenticated request for a "
    "declared extended card. It sent no tasks or messages to the agent, so runtime behaviour "
    "(prompt injection in live A2A messages, data leaking between agents, abuse of granted "
    "authority) was not observed. Live A2A message inspection remains a gap."
)

INSTALL_HINT = "install axiom-scan[a2a]"

FetchFn = Callable[[str], Tuple[int, Dict[str, str], bytes, str]]

_SEV_ORDER = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}

# Skill text suggesting a capability that should never be reachable anonymously.
DANGEROUS_CAPABILITIES: Dict[str, List[str]] = {
    "code execution": [
        r"\b(execut\w*|run\w*|eval\w*)\s+(arbitrary\s+|user\s+|untrusted\s+)?(code|scripts?|python|javascript|programs?)\b",
        r"\bcode[\s_-]?(interpreter|execution|runner|sandbox)\b",
    ],
    "shell access": [
        r"\b(shell|bash|zsh|powershell|terminal|command[\s-]line)\b",
        r"\b(run|execut\w*)\s+(system\s+|shell\s+|os\s+)?commands?\b",
    ],
    "filesystem access": [
        r"\bfile[\s_-]?system\b",
        r"\b(read\w*|writ\w*|delet\w*|modif\w*|access\w*|upload\w*|download\w*)\s+(local\s+|arbitrary\s+|any\s+)?files?\b",
    ],
    "payments / money transfer": [
        r"\bpayments?\b",
        r"\b(transfer|send|move)\w*\s+(funds|money)\b",
        r"\b(wire|money|bank)\s+transfers?\b",
        r"\b(refunds?|checkout|purchas\w*)\b",
        r"\bcharg\w*\s+(a\s+)?(cards?|customers?)\b",
    ],
    "credentials / secrets": [
        r"\b(credentials?|passwords?|secrets?|api[\s_-]?keys?|private\s+keys?|access\s+tokens?)\b",
    ],
    "sending email": [
        r"\bsend\w*\s+(an\s+|the\s+)?e-?mails?\b",
        r"\be-?mail\s+(sending|sender|delivery)\b",
        r"\bsend_?e?mail\b",
    ],
}


class A2AScanError(Exception):
    """The agent card could not be obtained or parsed."""


# ============================================================
# Small helpers
# ============================================================

def _host(url: Optional[str]) -> Optional[str]:
    if not url or not isinstance(url, str):
        return None
    try:
        h = urlsplit(url).hostname
    except ValueError:
        return None
    return h.lower().rstrip(".") if h else None


def _scheme(url: Optional[str]) -> str:
    try:
        return (urlsplit(url).scheme or "").lower() if isinstance(url, str) else ""
    except ValueError:
        return ""


def _hosts_related(a: str, b: str) -> bool:
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _b64url_decode(data: str) -> bytes:
    data = data.strip()
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _major_version(v: Any) -> Optional[int]:
    if not isinstance(v, str):
        return None
    m = re.match(r"\s*v?(\d+)", v)
    return int(m.group(1)) if m else None


def _is_http_source(source: str) -> bool:
    return source.lower().startswith(("http://", "https://"))


def canonicalize_card(card: Dict[str, Any]) -> bytes:
    """Canonical signing payload: the card without `signatures`, serialised per RFC 8785 (JCS).

    Keys are sorted, no insignificant whitespace, UTF-8. This matches JCS for the
    strings/integers/booleans agent cards contain; unusual float formatting is the only
    known divergence from a full JCS implementation.
    """
    payload = {k: v for k, v in card.items() if k != "signatures"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _finding(
    fid: str,
    severity: FindingSeverity,
    category: FindingCategory,
    title: str,
    description: str,
    recommendation: str,
    asi: Optional[List[str]] = None,
    related: Optional[List[str]] = None,
) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        category=category,
        title=title,
        description=description,
        recommendation=recommendation,
        owasp_asi=asi,
        related=related,
    )


# ============================================================
# Card structure helpers (1.0 and legacy shapes)
# ============================================================

def _interfaces(card: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every endpoint the card advertises: [{url, binding, version, legacy}]."""
    out: List[Dict[str, Any]] = []
    for iface in card.get("supportedInterfaces") or []:
        if isinstance(iface, dict) and isinstance(iface.get("url"), str):
            out.append({
                "url": iface["url"],
                "binding": str(iface.get("protocolBinding") or ""),
                "version": iface.get("protocolVersion"),
                "legacy": False,
            })
    if isinstance(card.get("url"), str):
        out.append({
            "url": card["url"],
            "binding": str(card.get("preferredTransport") or "JSONRPC"),
            "version": card.get("protocolVersion"),
            "legacy": True,
        })
    for iface in card.get("additionalInterfaces") or []:
        if isinstance(iface, dict) and isinstance(iface.get("url"), str):
            out.append({
                "url": iface["url"],
                "binding": str(iface.get("transport") or ""),
                "version": card.get("protocolVersion"),
                "legacy": True,
            })
    return out


def _requirement_nonempty(req: Any) -> bool:
    if not isinstance(req, dict) or not req:
        return False
    if "schemes" in req:  # 1.0: {"schemes": {"name": {"list": [...]}}}
        return isinstance(req["schemes"], dict) and bool(req["schemes"])
    return True  # legacy OpenAPI style: {"name": [scopes]}


def _has_requirements(reqs: Any) -> bool:
    return isinstance(reqs, list) and any(_requirement_nonempty(r) for r in reqs)


def _card_requirements(card: Dict[str, Any]) -> Any:
    if "securityRequirements" in card:
        return card.get("securityRequirements")
    return card.get("security")


def _legacy_auth_schemes(card: Dict[str, Any]) -> List[str]:
    auth = card.get("authentication")
    if isinstance(auth, dict) and isinstance(auth.get("schemes"), list):
        return [str(s) for s in auth["schemes"] if str(s).lower() not in ("", "none", "anonymous", "public")]
    return []


def _normalize_scheme(scheme: Any) -> Tuple[str, Dict[str, Any]]:
    """Return (kind, body) for both the 1.0 oneof shape and the legacy OpenAPI shape."""
    if not isinstance(scheme, dict):
        return "unknown", {}
    wrappers = {
        "apiKeySecurityScheme": "apiKey",
        "httpAuthSecurityScheme": "http",
        "oauth2SecurityScheme": "oauth2",
        "openIdConnectSecurityScheme": "openIdConnect",
        "mtlsSecurityScheme": "mutualTLS",
    }
    for key, kind in wrappers.items():
        if isinstance(scheme.get(key), dict):
            return kind, scheme[key]
    legacy = {"apikey": "apiKey", "http": "http", "oauth2": "oauth2",
              "openidconnect": "openIdConnect", "mutualtls": "mutualTLS"}
    kind = legacy.get(str(scheme.get("type", "")).lower(), "unknown")
    return kind, scheme


def _skill_text(skill: Dict[str, Any]) -> Tuple[str, str, str]:
    """(name, description, examples) as strings."""
    name = str(skill.get("name") or skill.get("id") or "unnamed-skill")
    desc = str(skill.get("description") or "")
    examples = skill.get("examples") or []
    ex_text = "\n".join(str(e) for e in examples) if isinstance(examples, list) else str(examples)
    return name, desc, ex_text


# ============================================================
# Schema validation
# ============================================================

@functools.lru_cache(maxsize=1)
def _load_schema() -> Dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _structural_check(card: Any) -> List[str]:
    """Fallback when `jsonschema` is not installed: check the same required fields and types."""
    errors: List[str] = []
    if not isinstance(card, dict):
        return ["(root): agent card is not a JSON object"]
    expected = {
        "name": str, "description": str, "version": str, "capabilities": dict,
        "defaultInputModes": list, "defaultOutputModes": list, "skills": list,
    }
    for field, typ in expected.items():
        if field not in card:
            errors.append(f"(root): '{field}' is a required property")
        elif not isinstance(card[field], typ):
            errors.append(f"{field}: expected {typ.__name__}")
    if "supportedInterfaces" not in card and "url" not in card:
        errors.append("(root): needs 'supportedInterfaces' (A2A 1.0) or 'url' (legacy)")
    ifaces = card.get("supportedInterfaces")
    if ifaces is not None:
        if not isinstance(ifaces, list) or not ifaces:
            errors.append("supportedInterfaces: expected a non-empty array")
        else:
            for i, it in enumerate(ifaces):
                for req in ("url", "protocolBinding"):
                    if not isinstance(it, dict) or not isinstance(it.get(req), str):
                        errors.append(f"supportedInterfaces/{i}: '{req}' is a required string")
    for i, skill in enumerate(card.get("skills") or [] if isinstance(card.get("skills"), list) else []):
        if not isinstance(skill, dict):
            errors.append(f"skills/{i}: expected object")
            continue
        for req in ("id", "name", "description"):
            if not isinstance(skill.get(req), str):
                errors.append(f"skills/{i}: '{req}' is a required string")
        if not isinstance(skill.get("tags"), list):
            errors.append(f"skills/{i}: 'tags' is a required array")
    sigs = card.get("signatures")
    if sigs is not None:
        if not isinstance(sigs, list):
            errors.append("signatures: expected array")
        else:
            for i, s in enumerate(sigs):
                for req in ("protected", "signature"):
                    if not isinstance(s, dict) or not isinstance(s.get(req), str):
                        errors.append(f"signatures/{i}: '{req}' is a required string")
    prov = card.get("provider")
    if prov is not None and not isinstance(prov, dict):
        errors.append("provider: expected object")
    if "securitySchemes" in card and not isinstance(card["securitySchemes"], dict):
        errors.append("securitySchemes: expected object")
    return errors


def validate_card_schema(card: Any, use_jsonschema: bool = True) -> List[str]:
    """Validate against the pinned minimal schema; returns human-readable error strings."""
    if use_jsonschema:
        try:
            import jsonschema  # type: ignore
        except ImportError:
            jsonschema = None  # type: ignore
        if jsonschema is not None:
            schema = _load_schema()
            validator = jsonschema.validators.validator_for(schema)(schema)
            out = []
            for err in sorted(validator.iter_errors(card), key=lambda e: [str(p) for p in e.path]):
                path = "/".join(str(p) for p in err.path) or "(root)"
                out.append(f"{path}: {err.message}")
            return out
    return _structural_check(card)


# ============================================================
# Signature verification
# ============================================================

def _verify_signatures(
    card: Dict[str, Any],
    fetch: Optional[FetchFn],
    sigs: List[Any],
) -> Tuple[Optional[bool], List[str], Optional[str]]:
    """Return (verified, problems, jwks_url_used).

    verified is None when the crypto libraries are not installed.
    """
    try:
        from jwt.algorithms import get_default_algorithms  # type: ignore
    except ImportError:
        return None, [f"PyJWT is not installed ({INSTALL_HINT})"], None
    algs = get_default_algorithms()
    if "RS256" not in algs or "ES256" not in algs:
        return None, [f"the 'cryptography' package is not installed ({INSTALL_HINT})"], None

    payload_b64 = _b64url_encode(canonicalize_card(card))
    card_jwks = next(
        (card[k] for k in ("jwksUri", "jwks_uri", "jwksUrl") if isinstance(card.get(k), str)), None
    )
    jwks_cache: Dict[str, Any] = {}
    problems: List[str] = []
    jwks_used: Optional[str] = None

    for i, sig in enumerate(sigs):
        label = f"signature {i + 1}"
        if not isinstance(sig, dict) or not isinstance(sig.get("protected"), str) \
                or not isinstance(sig.get("signature"), str):
            problems.append(f"{label}: missing 'protected' or 'signature'")
            continue
        try:
            header = json.loads(_b64url_decode(sig["protected"]))
            if not isinstance(header, dict):
                raise ValueError("not an object")
            sig_bytes = _b64url_decode(sig["signature"])
        except Exception:
            problems.append(f"{label}: protected header or signature is not valid base64url JSON")
            continue
        unprotected = sig.get("header") if isinstance(sig.get("header"), dict) else {}
        alg = header.get("alg")
        kid = header.get("kid") or unprotected.get("kid")
        if not isinstance(alg, str) or alg.lower() == "none" or alg.upper().startswith("HS") or alg not in algs:
            problems.append(f"{label}: algorithm '{alg}' is missing, symmetric or unsupported")
            continue
        jku = header.get("jku") or card_jwks
        if not isinstance(jku, str) or not jku:
            hint = " (an embedded 'jwk' is self-asserted and cannot establish trust)" if "jwk" in header else ""
            problems.append(f"{label}: signing key cannot be resolved: no 'jku' or card JWKS URL{hint}")
            continue
        if _scheme(jku) != "https":
            problems.append(f"{label}: key set URL '{jku}' is not HTTPS; key not trusted")
            continue
        if jku not in jwks_cache:
            if jwks_cache or fetch is None:
                problems.append(f"{label}: key set '{jku}' not fetched (passive scan fetches at most one JWKS)")
                continue
            try:
                status, _h, body, _f = fetch(jku)
                jwks_cache[jku] = json.loads(body) if status == 200 else None
                if status != 200:
                    problems.append(f"{label}: key set '{jku}' returned HTTP {status}")
            except (SafeFetchError, ValueError, OSError) as e:
                jwks_cache[jku] = None
                problems.append(f"{label}: key set '{jku}' could not be fetched ({type(e).__name__}: {e})")
            except Exception as e:  # network errors from httpx
                jwks_cache[jku] = None
                problems.append(f"{label}: key set '{jku}' could not be fetched ({type(e).__name__})")
            jwks_used = jku
        jwks = jwks_cache.get(jku)
        if jwks is None:
            if not any(p.startswith(label) for p in problems):
                problems.append(f"{label}: key set '{jku}' unavailable")
            continue
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list):
            problems.append(f"{label}: '{jku}' is not a JWKS document")
            continue
        candidates = [k for k in keys if isinstance(k, dict) and (not kid or k.get("kid") == kid)]
        if not candidates:
            problems.append(f"{label}: no key with kid '{kid}' in '{jku}'")
            continue
        signing_input = f"{sig['protected']}.{payload_b64}".encode("ascii")
        algo = algs[alg]
        for jwk in candidates:
            try:
                key = algo.from_jwk(json.dumps(jwk))
                if algo.verify(signing_input, key, sig_bytes):
                    return True, problems, jwks_used
            except Exception:
                continue
        problems.append(f"{label}: signature does not match the card contents (kid '{kid}')")
    return False, problems, jwks_used


# ============================================================
# Analysis
# ============================================================

def analyze_card(
    card: Dict[str, Any],
    card_url: Optional[str] = None,
    discovery_path: Optional[str] = None,
    fetch: Optional[FetchFn] = None,
) -> Tuple[List[Finding], A2AAgentCardSummary, Optional[str]]:
    """Run every check. ``card_url`` is None for file sources; ``fetch`` None disables network."""
    findings: List[Finding] = []
    card_host = _host(card_url)
    is_remote = card_url is not None
    ifaces = _interfaces(card)
    caps = card.get("capabilities") if isinstance(card.get("capabilities"), dict) else {}

    # ---- 1. Transport -------------------------------------------------
    if is_remote and _scheme(card_url) != "https":
        findings.append(_finding(
            "a2a-transport-insecure:card", FindingSeverity.HIGH, FindingCategory.TRANSPORT_SECURITY,
            "Agent card served over plain HTTP",
            f"The agent card was retrieved from {card_url} without TLS. Anyone on the network path "
            "can rewrite the card, e.g. swapping endpoint URLs or removing auth requirements, before "
            "a client agent trusts it.",
            "Serve the agent card only over HTTPS and redirect HTTP to HTTPS.",
            ["ASI07"], ["MCP07:2025"],
        ))
    for i, iface in enumerate(ifaces):
        if _scheme(iface["url"]) in ("http", "ws"):
            findings.append(_finding(
                f"a2a-transport-insecure:interface-{i}", FindingSeverity.HIGH, FindingCategory.TRANSPORT_SECURITY,
                "Agent endpoint advertised without TLS",
                f"Interface {iface['url']} ({iface['binding'] or 'unknown binding'}) is not HTTPS. Tasks, "
                "messages and bearer credentials sent to it travel in clear text.",
                "Advertise only https:// endpoints in supportedInterfaces.",
                ["ASI07"], ["MCP07:2025"],
            ))

    # ---- 2. Schema ----------------------------------------------------
    schema_errors = validate_card_schema(card)
    if schema_errors:
        shown = "; ".join(schema_errors[:6]) + (f" (+{len(schema_errors) - 6} more)" if len(schema_errors) > 6 else "")
        findings.append(_finding(
            "a2a-schema-invalid", FindingSeverity.MEDIUM, FindingCategory.CONFIG_RISK,
            "Agent card does not match the A2A card schema",
            f"The card failed {len(schema_errors)} structural check(s): {shown}. Clients may "
            "reject the card or interpret missing security fields in unsafe ways.",
            "Fix the card so it validates against the A2A 1.0 AgentCard schema.",
            ["ASI07"], None,
        ))

    # ---- 3. Authentication present? ----------------------------------
    schemes = card.get("securitySchemes") if isinstance(card.get("securitySchemes"), dict) else {}
    legacy_auth = _legacy_auth_schemes(card)
    card_auth_required = _has_requirements(_card_requirements(card)) or bool(legacy_auth)
    if not (schemes or legacy_auth) or not card_auth_required:
        missing = "no securitySchemes" if not (schemes or legacy_auth) else "securityRequirements is empty"
        findings.append(_finding(
            "a2a-auth-missing", FindingSeverity.HIGH, FindingCategory.IDENTITY_PRIVILEGE,
            "Agent does not require authentication",
            f"The card declares {missing}, so it tells clients the agent accepts anonymous "
            "requests. Any party that can reach the endpoint can hand it tasks.",
            "Declare securitySchemes (OAuth2 / OpenID Connect or mTLS preferred) and reference them "
            "in securityRequirements.",
            ["ASI03", "ASI07"], ["MCP07:2025"],
        ))

    # ---- 4. Weak schemes ---------------------------------------------
    for name, scheme in schemes.items():
        kind, body = _normalize_scheme(scheme)
        reason = None
        if kind == "apiKey" and str(body.get("location") or body.get("in") or "").lower() == "query":
            reason = "an API key passed in the URL query string (leaks into logs, proxies and Referer headers)"
        elif kind == "http" and str(body.get("scheme") or "").lower() == "basic":
            reason = "HTTP Basic authentication (static reusable password on every request)"
        elif kind == "oauth2" and isinstance(body.get("flows"), dict):
            bad = [f for f in ("implicit", "password") if f in body["flows"]]
            if bad:
                reason = f"deprecated OAuth 2.0 flow(s): {', '.join(bad)} (removed in OAuth 2.1)"
        if reason:
            findings.append(_finding(
                f"a2a-auth-weak:{name}", FindingSeverity.MEDIUM, FindingCategory.IDENTITY_PRIVILEGE,
                f"Weak authentication scheme '{name}'",
                f"Security scheme '{name}' uses {reason}.",
                "Prefer OAuth 2.0 authorization code (with PKCE) or client credentials, OpenID Connect, "
                "or mTLS; send API keys in a header.",
                ["ASI03"], ["MCP07:2025", "MCP01:2025"],
            ))

    # ---- 5. Signatures -----------------------------------------------
    sigs = card.get("signatures")
    signed = isinstance(sigs, list) and len(sigs) > 0
    verified: Optional[bool] = None
    if not signed:
        findings.append(_finding(
            "a2a-card-unsigned", FindingSeverity.MEDIUM, FindingCategory.IDENTITY_PRIVILEGE,
            "Agent card is not signed",
            "The card carries no JWS signature, so a client cannot prove the card was published "
            "by the agent's owner or that it was not altered in transit or in a registry.",
            "Sign the card (A2A 1.0 'signatures', JWS over the RFC 8785 canonical card) and publish "
            "the public key via a JWKS referenced by 'jku'.",
            ["ASI07"], ["MCP04:2025"],
        ))
    else:
        verified, problems, _jwks = _verify_signatures(card, fetch, sigs)
        if verified is None:
            findings.append(_finding(
                "a2a-signature-unverified", FindingSeverity.MEDIUM, FindingCategory.IDENTITY_PRIVILEGE,
                "Card signature present but could not be verified",
                f"Signature present but could not be verified ({INSTALL_HINT}). "
                + "; ".join(problems),
                "Run `pip install \"axiom-scan[a2a]\"` and re-scan to verify the signature.",
                ["ASI07"], ["MCP04:2025"],
            ))
        elif not verified:
            findings.append(_finding(
                "a2a-signature-invalid", FindingSeverity.HIGH, FindingCategory.IDENTITY_PRIVILEGE,
                "Agent card signature failed verification",
                "The card claims to be signed but no signature could be verified: "
                + "; ".join(problems) + ". A failing signature is a sign of tampering or a "
                "broken publishing pipeline; clients must not trust the card.",
                "Re-sign the card over its current canonical contents and make the signing key "
                "resolvable from an HTTPS JWKS ('jku') with a matching 'kid'.",
                ["ASI07"], ["MCP04:2025"],
            ))

    # ---- 6. Interface host differs from card host (unsigned) ---------
    if card_host and not signed:
        for i, iface in enumerate(ifaces):
            ih = _host(iface["url"])
            if ih and ih != card_host:
                findings.append(_finding(
                    f"a2a-interface-host-mismatch:{i}", FindingSeverity.MEDIUM, FindingCategory.INTER_AGENT_COMM,
                    "Unsigned card points to an endpoint on a different host",
                    f"The card at {card_host} sends clients to {ih}. Without a signature, nothing ties "
                    "that endpoint to the card's publisher; a modified card could redirect tasks and "
                    "credentials elsewhere.",
                    "Host the endpoint on the card's domain or sign the card.",
                    ["ASI07"], ["MCP04:2025"],
                ))

    # ---- 7. Skill text poisoning -------------------------------------
    detector = ToolPoisoningDetector()
    skills = [s for s in (card.get("skills") or []) if isinstance(s, dict)] if isinstance(card.get("skills"), list) else []
    texts: List[Tuple[str, str, str, str]] = [
        ("(card)", str(card.get("name") or "agent"), str(card.get("description") or ""), "")
    ]
    for idx, skill in enumerate(skills):
        name, desc, ex = _skill_text(skill)
        texts.append((str(skill.get("id") or idx), name, desc, ex))
    for sid, name, desc, ex in texts:
        full = "\n".join(t for t in (desc, ex) if t)
        tool = MCPToolDefinition(name=name, description=full)
        hits, _risk = detector.analyze_tool(tool)
        hits = [h for h in hits if h.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)]
        hits += detector.check_prompt_injection_risk(f"{name}\n{full}")
        if hits:
            kinds = sorted({h.title.split(":", 1)[-1].split(" in '")[0].strip() for h in hits})
            where = "the agent description" if sid == "(card)" else f"skill '{name}'"
            findings.append(_finding(
                f"a2a-skill-poisoning:{sid}", FindingSeverity.HIGH,
                FindingCategory.PROMPT_INJECTION if all(h.category == FindingCategory.PROMPT_INJECTION for h in hits)
                else FindingCategory.TOOL_POISONING,
                f"Instruction-like or hidden text in {where}",
                f"Text that client agents feed to their LLM when choosing a skill contains "
                f"{', '.join(kinds)}. A calling agent may follow these instructions instead of its "
                "user's intent.",
                "Keep skill names, descriptions and examples purely descriptive; remove imperative "
                "instructions, hidden Unicode and role markers.",
                ["ASI01"], ["MCP03:2025", "MCP06:2025"],
            ))

    # ---- 8. Dangerous skills without auth ----------------------------
    for idx, skill in enumerate(skills):
        skill_auth = _has_requirements(skill.get("securityRequirements")) or _has_requirements(skill.get("security"))
        if card_auth_required or skill_auth:
            continue
        tags = skill.get("tags") if isinstance(skill.get("tags"), list) else []
        hay = " ".join([str(skill.get("id") or ""), *_skill_text(skill), " ".join(map(str, tags))])
        caps_hit = [cap for cap, pats in DANGEROUS_CAPABILITIES.items()
                    if any(re.search(p, hay, re.IGNORECASE) for p in pats)]
        if caps_hit:
            sid = str(skill.get("id") or idx)
            findings.append(_finding(
                f"a2a-skill-dangerous-noauth:{sid}", FindingSeverity.HIGH, FindingCategory.IDENTITY_PRIVILEGE,
                f"High-impact skill '{_skill_text(skill)[0]}' requires no authentication",
                f"The skill advertises {', '.join(caps_hit)} and neither the card nor the skill "
                "declares a security requirement, so an anonymous caller could invoke it.",
                "Require authentication for this skill (card-level or skill-level "
                "securityRequirements) and scope it to least privilege.",
                ["ASI02", "ASI03"], ["MCP02:2025", "MCP07:2025"],
            ))

    # ---- 9. Extended card exposure -----------------------------------
    ext_new = caps.get("extendedAgentCard") is True
    ext_legacy = caps.get("supportsAuthenticatedExtendedCard") is True or card.get("supportsAuthenticatedExtendedCard") is True
    if ext_new or ext_legacy:
        target, why_not = None, None
        if not is_remote or fetch is None:
            why_not = "the card was read from a file, so the endpoint was not contacted"
        else:
            rest = [i for i in ifaces if not i["legacy"] and i["binding"].upper().replace("_", "+") in ("HTTP+JSON", "REST")]
            legacy_url = next((i["url"] for i in ifaces if i["legacy"]), None)
            if ext_new and rest:
                target = rest[0]["url"].rstrip("/") + "/extendedAgentCard"
            elif legacy_url and (ext_legacy or not rest):
                target = legacy_url.rstrip("/") + "/agent/authenticatedExtendedCard"
            else:
                why_not = ("the agent offers no HTTP+JSON interface; JSON-RPC/gRPC retrieval needs an RPC "
                           "call, which this passive scan does not send")
        exposed = False
        if target:
            try:
                status, _h, body, _f = fetch(target)  # type: ignore[misc]
                if status == 200:
                    try:
                        ext = json.loads(body)
                    except ValueError:
                        ext = None
                    exposed = isinstance(ext, dict) and "name" in ext and ("skills" in ext or "capabilities" in ext)
            except Exception as e:
                why_not = f"the request to {target} failed ({type(e).__name__})"
                target = None
        if exposed:
            findings.append(_finding(
                "a2a-extended-card-exposed", FindingSeverity.HIGH, FindingCategory.IDENTITY_PRIVILEGE,
                "Authenticated extended card returned without credentials",
                f"The card says a richer card is available to authenticated clients, but an "
                f"unauthenticated GET of {target} returned it (HTTP 200). Skills and details meant "
                "for vetted callers are public.",
                "Enforce the declared security schemes on the extended card endpoint.",
                ["ASI03"], ["MCP07:2025", "MCP10:2025"],
            ))
        elif not target:
            findings.append(_finding(
                "a2a-extended-card-unchecked", FindingSeverity.INFO, FindingCategory.METADATA,
                "Extended agent card declared; access control not checked",
                f"The card declares an authenticated extended card. Not checked: {why_not}.",
                "Confirm manually that the extended card endpoint rejects unauthenticated requests.",
                ["ASI03"], None,
            ))

    # ---- 10. Legacy protocol ------------------------------------------
    proto_version = next((i["version"] for i in ifaces if isinstance(i["version"], str)), None)
    if proto_version is None and isinstance(card.get("protocolVersion"), str):
        proto_version = card["protocolVersion"]
    if discovery_path == LEGACY_WELL_KNOWN_PATH:
        findings.append(_finding(
            "a2a-legacy-protocol:discovery-path", FindingSeverity.LOW, FindingCategory.CONFIG_RISK,
            "Card only available at the legacy discovery path",
            f"{WELL_KNOWN_PATH} was not found; the card was served from {LEGACY_WELL_KNOWN_PATH}, "
            "which pre-1.0 clients use.",
            f"Publish the card at {WELL_KNOWN_PATH}.",
            ["ASI07"], None,
        ))
    old_versions = sorted({str(v) for v in [card.get("protocolVersion")] + [i["version"] for i in ifaces]
                           if _major_version(v) is not None and _major_version(v) < 1})
    legacy_shape = "supportedInterfaces" not in card and "url" in card
    if old_versions or legacy_shape:
        detail = f"protocol version {', '.join(old_versions)}" if old_versions else "the pre-1.0 card layout (top-level 'url')"
        findings.append(_finding(
            "a2a-legacy-protocol:version", FindingSeverity.LOW, FindingCategory.CONFIG_RISK,
            "Agent uses an older A2A protocol version",
            f"The card uses {detail}. Versions before 1.0 lack 1.0 security features such as "
            "standardised card signing and per-skill security requirements.",
            "Upgrade the agent to A2A 1.0 and publish supportedInterfaces with protocolVersion 1.0.",
            ["ASI07"], None,
        ))

    # ---- 11. Provider --------------------------------------------------
    provider = card.get("provider") if isinstance(card.get("provider"), dict) else None
    if not provider or not provider.get("organization") or not provider.get("url"):
        findings.append(_finding(
            "a2a-provider-missing", FindingSeverity.LOW, FindingCategory.SUPPLY_CHAIN,
            "Agent card does not identify its provider",
            "The card has no complete provider (organization and url), so there is no stated "
            "party accountable for the agent.",
            "Add provider.organization and provider.url to the card.",
            ["ASI04"], ["MCP04:2025"],
        ))
    elif card_host:
        ph = _host(provider.get("url"))
        if ph and not _hosts_related(ph, card_host):
            findings.append(_finding(
                "a2a-provider-host-mismatch", FindingSeverity.LOW, FindingCategory.SUPPLY_CHAIN,
                "Provider URL is on a different domain than the card",
                f"The card is hosted on {card_host} but names a provider at {ph}. This can be "
                "legitimate (hosted platforms) but is also how an impersonating card would look.",
                "Confirm the provider relationship, or host the card under the provider's domain.",
                ["ASI04"], ["MCP04:2025"],
            ))

    # ---- Summary --------------------------------------------------------
    scheme_names = list(schemes.keys()) or legacy_auth
    summary = A2AAgentCardSummary(
        name=card.get("name") if isinstance(card.get("name"), str) else None,
        version=card.get("version") if isinstance(card.get("version"), str) else None,
        description=(str(card.get("description"))[:300] if card.get("description") else None),
        provider_organization=(provider or {}).get("organization"),
        provider_url=(provider or {}).get("url"),
        skill_count=len(skills),
        skill_ids=[str(s.get("id") or s.get("name") or "") for s in skills],
        scheme_names=[str(n) for n in scheme_names],
        interfaces=[i["url"] for i in ifaces],
        signed=signed,
        signature_verified=verified if signed else None,
        extended_card_declared=bool(ext_new or ext_legacy),
    )
    return findings, summary, proto_version


# ============================================================
# Entry point
# ============================================================

def _parse_card(body: bytes, where: str) -> Dict[str, Any]:
    try:
        card = json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as e:
        raise A2AScanError(f"{where} is not valid JSON: {e}") from e
    if not isinstance(card, dict):
        raise A2AScanError(f"{where} is not a JSON object")
    return card


def _risk(findings: List[Finding]) -> Tuple[float, RiskLevel]:
    from app.analysis.engine import engine  # reuse the engine's scoring
    score = engine._calculate_risk_score(findings)
    return score, engine._score_to_level(score)


def scan_agent_card(
    source: str,
    allow_private: bool = False,
    *,
    fetch: Optional[FetchFn] = None,
    max_bytes: int = MAX_CARD_BYTES,
    timeout: float = 10,
) -> A2AScanResult:
    """Statically scan an A2A agent card.

    ``source`` is an agent base URL, a direct card URL, or a local file path.
    ``fetch`` (url -> (status, headers, body, final_url)) replaces the SSRF-safe
    default fetcher, e.g. for tests.

    Raises UnsafeURLError for URLs refused by the SSRF guard and A2AScanError when
    no card could be obtained.
    """
    if fetch is None:
        fetch = functools.partial(safe_get, allow_private=allow_private, max_bytes=max_bytes, timeout=timeout)

    card_url: Optional[str] = None
    discovery: Optional[str] = None

    if _is_http_source(source):
        parts = urlsplit(source)
        path = parts.path or ""
        if path.endswith(".json") or "/.well-known/" in path:
            candidates = [(source, "direct")]
        else:
            origin = f"{parts.scheme}://{parts.netloc}"
            candidates = [(origin + WELL_KNOWN_PATH, WELL_KNOWN_PATH),
                          (origin + LEGACY_WELL_KNOWN_PATH, LEGACY_WELL_KNOWN_PATH)]
        card = None
        attempts: List[str] = []
        for url, label in candidates:
            try:
                status, _headers, body, final = fetch(url)
            except UnsafeURLError:
                raise
            except Exception as e:
                attempts.append(f"{url}: {type(e).__name__}: {e}")
                continue
            if status != 200:
                attempts.append(f"{url}: HTTP {status}")
                continue
            try:
                card = _parse_card(body, url)
            except A2AScanError as e:
                attempts.append(str(e))
                continue
            card_url, discovery = final or url, label
            if label == "direct" and urlsplit(card_url).path.endswith(LEGACY_WELL_KNOWN_PATH):
                discovery = LEGACY_WELL_KNOWN_PATH
            elif label == "direct" and urlsplit(card_url).path.endswith(WELL_KNOWN_PATH):
                discovery = WELL_KNOWN_PATH
            break
        if card is None:
            raise A2AScanError("no agent card found: " + "; ".join(attempts))
    else:
        if "://" in source:
            raise UnsafeURLError(f"unsupported source scheme in '{source}'; use http(s) or a file path")
        p = Path(source).expanduser()
        if not p.is_file():
            raise A2AScanError(f"'{source}' is neither an http(s) URL nor an existing file")
        if p.stat().st_size > max_bytes:
            raise A2AScanError(f"'{source}' is larger than {max_bytes} bytes")
        card = _parse_card(p.read_bytes(), str(p))
        discovery = "file"

    findings, summary, proto = analyze_card(card, card_url=card_url, discovery_path=discovery, fetch=fetch)

    apply_owasp_mappings(findings)
    for f in findings:
        # A2A findings reference MCP analogues via `related`, never via owasp_mcp.
        f.owasp_mcp = None
    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.id))
    score, level = _risk(findings)

    return A2AScanResult(
        source=source,
        final_url=card_url,
        discovery_path_used=discovery,
        protocol_version=proto,
        card=summary,
        findings=findings,
        risk_score=score,
        risk_level=level,
        scope_note=SCOPE_NOTE,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )
