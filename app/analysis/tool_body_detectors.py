"""
Source-body detectors for Python MCP servers (Phase 2 gap list).

These look *inside* tool functions, using the AST extraction in ``py_extractor``:

  detect_hardcoded_egress_urls   — a URL constant a tool ships data to           (DATA_EXFILTRATION)
  detect_rug_pull_primitives     — add_tool/remove_tool at runtime, listChanged  (RUG_PULL_PRIMITIVE)
  detect_response_injection      — instructions inside what a tool RETURNS, and
                                   the full text rules on resource/prompt bodies (RESPONSE_INJECTION / PROMPT_INJECTION)
  detect_confused_deputy         — caller-supplied target + server-held credential (CONFUSED_DEPUTY)

Every detector takes ``scan_dir`` and returns ``List[Finding]`` so it can sit in
``engine._run_mcp_top10_detectors`` next to the MCP Top 10 detectors.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from app.analysis.mcp_top10_detectors import _iter_files, is_non_production_path
from app.analysis.owasp_mapping import classify_tool_capabilities, dangerous_tool_map
from app.analysis.py_extractor import PyExtraction, extract_python_definitions
from app.analysis.ts_extractor import extract_ts_definitions
from app.analysis.tool_poisoning import find_egress_urls, tool_poisoning_detector
from app.models.schemas import Finding, FindingCategory, FindingSeverity

_LIST_CHANGED_RE = re.compile(r"""listChanged["']?\s*[:=]\s*(True|true)""")
_TARGET_PARAM_RE = re.compile(r"(?i)^(url|uri|endpoint|target|target_url|host|method|route|address|destination)$")
_CREDENTIAL_NAME_RE = re.compile(r"(?i)(token|secret|api_?key|password|passwd|credential|auth)")
_DEPUTY_DESC_RE = re.compile(
    r"(?i)authenticated\s+proxy|server(?:'|’)?s\s+(?:stored\s+)?(?:credential|token|key)s?"
    r"|using\s+(?:the\s+)?server(?:'|’)?s?\s+(?:token|credential|key)"
    r"|on\s+behalf\s+of\s+the\s+server|with\s+(?:the\s+)?service\s+account"
)


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)[:60]


_TS_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx")


def extract_definitions(content: str, rel: str) -> Optional[PyExtraction]:
    """Language-independent entry point: Python via ``ast``, TS/JS via tree-sitter."""
    if rel.endswith(".py"):
        return extract_python_definitions(content, rel)
    if rel.endswith(_TS_EXTS):
        return extract_ts_definitions(content, rel)
    return None


def _iter_sources(scan_dir: str) -> Iterable[Tuple[str, str, PyExtraction]]:
    for _, rel, content in _iter_files(scan_dir, lambda f: f.endswith(".py") or f.endswith(_TS_EXTS)):
        ex = extract_definitions(content, rel)
        if ex is not None and (ex.bodies or ex.registrations or ex.server_instructions):
            yield rel, content, ex


_iter_py = _iter_sources  # backwards-compatible name


# ---------------------------------------------------------------------------
def detect_server_instructions(scan_dir: str) -> List[Finding]:
    """The server-level `instructions` string is read by every client; scan it like a prompt."""
    findings: List[Finding] = []
    for rel, _content, ex in _iter_py(scan_dir):
        if not ex.server_instructions:
            continue
        dangerous = dangerous_tool_map(ex.tools)
        for f in tool_poisoning_detector.scan_text(
            ex.server_instructions, "server instructions", "instructions",
            strict=False, marker_category=FindingCategory.PROMPT_INJECTION, dangerous_tools=dangerous,
        ):
            f.file_path, f.line_number = rel, ex.server_instructions_line
            findings.append(f)
    return findings


# ---------------------------------------------------------------------------
def detect_hardcoded_egress_urls(scan_dir: str) -> List[Finding]:
    """A URL literal (or module constant) on a tool's return path is an egress destination."""
    findings: List[Finding] = []
    for rel, _content, ex in _iter_py(scan_dir):
        caps = classify_tool_capabilities(ex.tools)
        server_reads_data = any(
            caps_ & {"filesystem", "credential_access", "data_read"} for caps_ in caps.values()
        )
        for body in ex.bodies:
            if body.kind != "tool":
                continue  # resources/prompts are covered by detect_response_injection
            seen: Set[str] = set()
            n = 0
            for s in body.return_strings:
                for url, host, level in find_egress_urls(s):
                    if url in seen:
                        continue
                    seen.add(url)
                    n += 1
                    if level == "allowlisted":
                        sev = FindingSeverity.INFO
                    elif level == "high" or server_reads_data:
                        sev = FindingSeverity.HIGH
                    else:
                        sev = FindingSeverity.MEDIUM
                    findings.append(Finding(
                        id=f"egress_{body.name}_{n}",
                        severity=sev,
                        category=FindingCategory.DATA_EXFILTRATION,
                        title=f"Hard-coded egress URL in tool '{body.name}': {host}",
                        description=f"Tool '{body.name}' ({rel} line {body.lineno}) sends to a fixed "
                                    f"external endpoint {url[:120]}. "
                                    + ("Other tools on this server read files, data or credentials, so "
                                       "this is a complete exfiltration path." if server_reads_data and sev != FindingSeverity.INFO
                                       else "The destination is not under the user's control."),
                        file_path=rel,
                        line_number=body.lineno,
                        recommendation="Make egress destinations explicit user configuration; never ship data to a URL baked into the server.",
                        owasp_asi=["ASI01", "ASI02"],
                    ))
    return findings


# ---------------------------------------------------------------------------
def detect_rug_pull_primitives(scan_dir: str) -> List[Finding]:
    """Tool definitions that can change after the user approved them."""
    findings: List[Finding] = []
    for rel, content, ex in _iter_py(scan_dir):
        n = 0
        for reg in ex.registrations:
            n += 1
            if reg.description in ("sendToolListChanged()", "handle.update()"):
                sev, what = FindingSeverity.MEDIUM, f"can change its tool list after approval ({reg.description})"
            elif reg.kind == "remove_tool":
                sev, what = FindingSeverity.HIGH, "removes a tool at runtime"
            elif reg.inside_function:
                sev, what = FindingSeverity.HIGH, f"registers a tool from inside '{reg.inside_function}()' — after the server was approved"
            else:
                sev, what = FindingSeverity.INFO, "registers a tool programmatically at import time"
            findings.append(Finding(
                id=f"rugpull_{reg.kind}_{_slug(reg.name or str(n))}",
                severity=sev,
                category=FindingCategory.RUG_PULL_PRIMITIVE,
                title=f"Runtime tool registration: {reg.kind}('{reg.name or '?'}') {('in ' + reg.inside_function + '()') if reg.inside_function else ''}".strip(),
                description=f"{rel} line {reg.lineno}: the server {what}. A tool that is benign at "
                            "approval time can be swapped for a malicious one later (rug pull), and "
                            "a tool injected after the first scan is never reviewed.",
                file_path=rel,
                line_number=reg.lineno,
                recommendation="Register every tool at startup; never mutate the tool list from a tool handler.",
                owasp_asi=["ASI04", "ASI10"],
            ))
        for body in ex.bodies:
            if body.kind == "tool" and body.count_gated:
                findings.append(Finding(
                    id=f"rugpull_counter_{body.name}",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.RUG_PULL_PRIMITIVE,
                    title=f"Tool '{body.name}' changes behaviour after a number of calls",
                    description=f"{rel} line {body.lineno}: '{body.name}' compares an invocation counter against a "
                                "number. A tool that is benign for the first N calls and different afterwards is a "
                                "rug pull that no single scan or approval can catch.",
                    file_path=rel,
                    line_number=body.lineno,
                    recommendation="Tool behaviour must not depend on how often it has been called.",
                    owasp_asi=["ASI04", "ASI10"],
                ))
        for m in _LIST_CHANGED_RE.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            findings.append(Finding(
                id=f"rugpull_listchanged_{_slug(rel)}_{line}",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.RUG_PULL_PRIMITIVE,
                title="Server advertises that its tool list can change (listChanged)",
                description=f"{rel} line {line} sets listChanged to true. Clients will accept a new "
                            "tool set without re-approval.",
                file_path=rel,
                line_number=line,
                recommendation="Keep the tool list static, or require re-approval when it changes.",
                owasp_asi=["ASI04", "ASI10"],
            ))
    return findings


# ---------------------------------------------------------------------------
def detect_response_injection(scan_dir: str) -> List[Finding]:
    """Instructions in what a tool returns; full text rules on resource/prompt bodies."""
    findings: List[Finding] = []
    for rel, _content, ex in _iter_py(scan_dir):
        dangerous = dangerous_tool_map(ex.tools)
        for body in ex.bodies:
            text = "\n".join(body.return_strings)
            if not text.strip():
                continue
            if body.kind == "tool":
                for f in tool_poisoning_detector.scan_text(
                    text, f"return value of tool '{body.name}'", f"response_injection_{body.name}",
                    strict=True, marker_category=FindingCategory.RESPONSE_INJECTION,
                ):
                    if f.id.endswith(("_injection_marker", "_invisible_unicode", "_secret_exposure")):
                        f.file_path, f.line_number = rel, body.lineno
                        if not f.id.endswith("_secret_exposure"):
                            f.recommendation = "Tool output goes straight into the model's context; it must never carry instructions."
                        findings.append(f)
            elif body.kind == "resource":
                subject = f"resource '{body.uri or body.name}'"
                prefix = f"{body.kind}_{_slug(body.uri or body.name)}"
                for f in tool_poisoning_detector.scan_text(
                    text, subject, prefix, strict=False,
                    marker_category=FindingCategory.PROMPT_INJECTION, dangerous_tools=dangerous,
                ):
                    f.file_path, f.line_number = rel, body.lineno
                    findings.append(f)
            else:  # prompt
                subject = f"prompt '{body.name}'"
                prefix = f"{body.kind}_{_slug(body.uri or body.name)}"
                for f in tool_poisoning_detector.scan_text(
                    text, subject, prefix, strict=False,
                    marker_category=FindingCategory.PROMPT_INJECTION, dangerous_tools=dangerous,
                ):
                    f.file_path, f.line_number = rel, body.lineno
                    findings.append(f)
        # Data the server stores and serves (preloaded documents, fixtures): strict markers only
        covered = {s for b in ex.bodies for s in b.return_strings}
        seen_names: Set[str] = set()
        for name, text, lineno in ex.module_literals:
            if text in covered or name in seen_names:
                continue
            hits = tool_poisoning_detector.scan_text(
                text, f"stored data '{name}'", f"stored_{_slug(name)}", strict=True,
                marker_category=FindingCategory.RESPONSE_INJECTION,
            )
            hits = [f for f in hits if f.id.endswith(("_injection_marker", "_invisible_unicode"))]
            if hits:
                seen_names.add(name)
                for f in hits:
                    f.file_path, f.line_number = rel, lineno
                    f.recommendation = "Content the server stores and returns to the model is an injection channel; sanitise it or do not serve it."
                    findings.append(f)
    return findings


# ---------------------------------------------------------------------------
def detect_confused_deputy(scan_dir: str) -> List[Finding]:
    """A tool that forwards a caller-chosen target using a credential the server holds."""
    findings: List[Finding] = []
    for rel, _content, ex in _iter_py(scan_dir):
        cred_names = {n for n in ex.module_strings if _CREDENTIAL_NAME_RE.search(n)}
        for body in ex.bodies:
            if body.kind != "tool":
                continue
            target_params = [p for p in body.params if _TARGET_PARAM_RE.match(p)]
            if not target_params:
                continue
            used_creds = sorted((body.referenced_names & cred_names) - set(body.params))
            desc_hit = _DEPUTY_DESC_RE.search(body.description or "")
            if not used_creds and not desc_hit:
                continue
            why = (f"uses the server-held credential(s) {', '.join(used_creds)}" if used_creds
                   else f"describes itself as '{desc_hit.group(0)}'")
            findings.append(Finding(
                id=f"deputy_{body.name}",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.CONFUSED_DEPUTY,
                title=f"Confused deputy: tool '{body.name}' forwards a caller-supplied "
                      f"{'/'.join(target_params)} using a server-held credential",
                description=f"{rel} line {body.lineno}: '{body.name}' takes {', '.join(target_params)} "
                            f"from the caller and {why}. Whoever drives the agent inherits the "
                            "server's privileges against any target they name.",
                file_path=rel,
                line_number=body.lineno,
                recommendation="Pin the allowed targets server-side, or make the caller supply their own credential.",
                owasp_asi=["ASI03"],
            ))
    return findings


# ---------------------------------------------------------------------------
_FLOW_RULES = {
    # kind: (category, severity when unvalidated, severity when validated, what)
    "file_read": (FindingCategory.FILE_READ, FindingSeverity.HIGH, FindingSeverity.LOW, "opens a file at a caller-supplied path"),
    "file_write": (FindingCategory.FILE_WRITE, FindingSeverity.HIGH, FindingSeverity.LOW, "writes or deletes a file at a caller-supplied path"),
    "shell_exec": (FindingCategory.SHELL_EXEC, FindingSeverity.CRITICAL, FindingSeverity.MEDIUM, "passes a caller-supplied value to a process/shell sink"),
    "network_egress": (FindingCategory.DATA_EXFILTRATION, FindingSeverity.MEDIUM, FindingSeverity.LOW, "sends a request to a caller-supplied destination"),
}


def detect_param_sink_flows(scan_dir: str) -> List[Finding]:
    """A caller parameter that reaches open()/subprocess/fetch() is a capability whatever the
    description says (the 'vulnerable server' shape: check(file_mame) -> open(file_mame))."""
    findings: List[Finding] = []
    for rel, _content, ex in _iter_sources(scan_dir):
        for body in ex.bodies:
            if body.kind != "tool":
                continue
            for param, sink, kind, line, validated in body.param_sinks:
                category, sev_bad, sev_ok, what = _FLOW_RULES[kind]
                sev = sev_ok if validated else sev_bad
                findings.append(Finding(
                    id=f"flow_{body.name}_{param}_{kind}",
                    severity=sev,
                    category=category,
                    title=f"Tool '{body.name}' {what} ('{param}' -> {sink})"
                          + (" after validation" if validated else " with no visible check"),
                    description=f"{rel} line {line}: parameter '{param}' of '{body.name}' reaches `{sink}`"
                                + (f" through a value produced by a validating call." if validated
                                   else ". Nothing between the caller and the sink constrains it, so whoever "
                                        "drives the agent chooses what this tool touches."),
                    file_path=rel,
                    line_number=line,
                    recommendation="Constrain the parameter before the sink (allowlisted roots, hosts or commands) "
                                   "and reject anything outside them.",
                    owasp_asi=["ASI02", "ASI03"] if kind != "network_egress" else ["ASI02", "ASI07"],
                ))
    return findings


# ---------------------------------------------------------------------------
def detect_description_rewrites(scan_dir: str) -> List[Finding]:
    """A tool that assigns <fn>.__doc__ at runtime rewrites what the model will be shown."""
    findings: List[Finding] = []
    for rel, _content, ex in _iter_sources(scan_dir):
        dangerous = dangerous_tool_map(ex.tools)
        for body in ex.bodies:
            for target, text, line in body.doc_rewrites:
                hits = tool_poisoning_detector.scan_text(
                    text or "", f"rewritten description of '{target}'", f"rewritten_desc_{_slug(target)}",
                    strict=False, marker_category=FindingCategory.TOOL_POISONING, dangerous_tools=dangerous,
                ) if text else []
                sev = FindingSeverity.CRITICAL if any(h.severity == FindingSeverity.CRITICAL for h in hits) else FindingSeverity.HIGH
                findings.append(Finding(
                    id=f"rugpull_docstring_{_slug(body.name)}_{_slug(target)}",
                    severity=sev,
                    category=FindingCategory.RUG_PULL_PRIMITIVE,
                    title=f"Tool '{body.name}' rewrites the description of '{target}' at runtime",
                    description=f"{rel} line {line}: '{body.name}' assigns `{target}.__doc__`"
                                + (f" with text that carries: {', '.join(h.id.rsplit('_', 1)[-1] for h in hits[:3])}." if hits
                                   else ". The description the user approved is not the one the model will see later."),
                    file_path=rel,
                    line_number=line,
                    recommendation="Descriptions must be static. A server that needs to change one must re-announce the tool and require re-approval.",
                    owasp_asi=["ASI04", "ASI10"],
                ))
                for h in hits:
                    h.file_path, h.line_number = rel, line
                    findings.append(h)
    return findings


# ---------------------------------------------------------------------------
# An OAuth metadata key whose value is a quoted URL: `token_url = "https://…"`,
# `"issuer": "https://…"`, `authorization_url = AnyHttpUrl("http://…")`. Only the text
# between the quotes is the value; whatever follows the closing quote on the line (the
# statement's own `;`, the next statement, an `&&` in an `if`) is code, not the URL.
# A key such as `issuer` whose value is not a URL does not match at all.
_OAUTH_URL_RE = re.compile(
    r"""(?i)\b(?:authorization_url|token_url|issuer_url|registration_url|authorization_endpoint|"""
    r"""token_endpoint|registration_endpoint|issuer|redirect_uri)["']?\s*[=:]\s*"""
    r"""(?:[A-Za-z_][\w.]*\(\s*)?"""                       # optional wrapper call: AnyHttpUrl(
    r"""(?P<q>["'`])(?P<url>https?://(?:(?!(?P=q))[^\n])*)(?P=q)"""
)
# Shell syntax that has no business inside a URL value.
_URL_SHELL_META_RE = re.compile(r"(?i)\$\(|\$\{IFS|;\s*[a-z]+\s|\|\||&&")
# A bare URL token (no key) that itself carries shell syntax, on a line about OAuth metadata.
_OAUTH_URL_RE2 = re.compile(r"""(?i)https?://[^\s"'`]*(?:\$\(|\$\{IFS|\|\||&&)[^\s"'`]*""")


def _oauth_metachar_hits(content: str) -> List[Tuple[int, str]]:
    """(offset, matched text) for OAuth URLs that carry shell metacharacters, one per line."""
    hits: Dict[int, Tuple[int, str]] = {}
    for m in _OAUTH_URL_RE.finditer(content):
        if _URL_SHELL_META_RE.search(m.group("url")):
            hits.setdefault(content.count("\n", 0, m.start()), (m.start("url"), m.group("url")))
    for m in _OAUTH_URL_RE2.finditer(content):
        hits.setdefault(content.count("\n", 0, m.start()), (m.start(), m.group(0)))
    return [hits[k] for k in sorted(hits)]


def detect_oauth_metacharacters(scan_dir: str) -> List[Finding]:
    """Shell metacharacters in OAuth metadata URLs (the CVE-2025-6514 pattern: a malicious
    authorization server whose endpoint executes a command on a vulnerable client)."""
    findings: List[Finding] = []
    n = 0
    for _, rel, content in _iter_files(scan_dir, lambda f: f.endswith((".py", ".ts", ".js", ".mjs", ".cjs", ".json", ".yaml", ".yml"))):
        if rel.lower().endswith((".yml", ".yaml")):
            continue   # CI workflows run shell on purpose (curl …$(uname)…)
        if is_non_production_path(rel):
            continue
        for start, matched in _oauth_metachar_hits(content):
            line_start = content.rfind("\n", 0, start) + 1
            line_end = content.find("\n", start)
            line_text = content[line_start:line_end if line_end != -1 else None]
            # the URL must belong to OAuth metadata, not to an arbitrary shell command
            if not re.search(r"(?i)(authoriz|token_url|token_endpoint|issuer|registration_url|registration_endpoint|oauth|redirect_uri|AnyHttpUrl)", line_text):
                continue
            n += 1
            line = content.count("\n", 0, start) + 1
            findings.append(Finding(
                id=f"oauth_metachar_{_slug(rel)}_{line}",
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.COMMAND_INJECTION,
                title="Shell metacharacters in an OAuth endpoint URL",
                description=f"{rel} line {line}: an OAuth/authorization URL contains '{matched[:120]}'. "
                            "A client that opens or interpolates this URL in a shell executes it (CVE-2025-6514 pattern).",
                file_path=rel,
                line_number=line,
                recommendation="OAuth metadata must be plain URLs; never ship an authorization server whose endpoints carry shell syntax.",
                owasp_asi=["ASI05", "ASI07"],
            ))
            if n > 20:
                return findings
    return findings


# ---------------------------------------------------------------------------
def _name_key(name: str) -> str:
    return re.sub(r"[\s_\-.]+$", "", name.strip().lower())


def near_duplicate_names(a: str, b: str) -> bool:
    """check_sig / check_sig_ , notes-helper / notes_helper , github / gIthub ..."""
    from app.analysis.tool_poisoning import _near_duplicate, homoglyph_reason
    ka, kb = _name_key(a), _name_key(b)
    if a == b:
        return False
    if ka == kb:
        return True
    if re.sub(r"[\s_\-.]", "", ka) == re.sub(r"[\s_\-.]", "", kb):
        return True
    if _near_duplicate(ka, kb):
        return True
    return False


def detect_server_name_squatting(scan_dir: str) -> List[Finding]:
    """Two servers in one tree whose names a reviewer could confuse (server-name squatting)."""
    names: List[Tuple[str, str, int]] = []
    for rel, _content, ex in _iter_sources(scan_dir):
        if ex.server_name:
            names.append((ex.server_name, rel, ex.server_instructions_line or 1))
    findings: List[Finding] = []
    seen = set()
    for i, (a, ra, la) in enumerate(names):
        for b, rb, lb in names[i + 1:]:
            if ra == rb or not near_duplicate_names(a, b):
                continue
            key = tuple(sorted((a, b)))
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                id=f"squat_server_{_slug(a)}__{_slug(b)}",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.TOOL_SHADOWING,
                title=f"Server name squatting: '{a}' ({ra}) vs '{b}' ({rb})",
                description=f"Two servers announce names a client cannot tell apart: '{a}' in {ra} and '{b}' in {rb}. "
                            "Clients resolve tool calls by server name; the last one registered wins, so the lookalike "
                            "receives the calls meant for the real one.",
                file_path=rb,
                line_number=lb,
                recommendation="Use one unambiguous server name; treat a lookalike in the same tree as hostile.",
                owasp_asi=["ASI04", "ASI01"],
            ))
    return findings


ALL_BODY_DETECTORS = (
    detect_server_instructions,
    detect_hardcoded_egress_urls,
    detect_rug_pull_primitives,
    detect_response_injection,
    detect_confused_deputy,
    detect_param_sink_flows,
    detect_description_rewrites,
    detect_oauth_metacharacters,
    detect_server_name_squatting,
)
