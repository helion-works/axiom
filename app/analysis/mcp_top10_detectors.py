"""
OWASP MCP Top 10 — lightweight static detectors.

These are cheap, heuristic detectors that close obvious gaps in Axiom's
OWASP MCP Top 10 coverage. Each one stamps an explicit ``owasp_mcp`` reference.

  MCP01  detect_hardcoded_secrets        hard-coded keys/tokens in server source
  MCP04  detect_unpinned_installs        npx/uvx/pip installs without a version pin, @latest
  MCP05  detect_tool_input_sinks         shell/exec sinks inside MCP tool handlers
  MCP07  detect_bind_all_interfaces      server bound to 0.0.0.0 / ::
  MCP08  detect_missing_tool_logging     no logging in tool-defining files (low confidence)
  MCP10  detect_broad_data_exposure      tools/resources named for bulk data exposure

Secret values are never copied into findings: only the secret type, the
variable name (when there is one), the file and the line number are reported.
"""

import ast
import os
import re
from typing import Iterable, List, Optional, Set, Tuple

from app.models.schemas import (
    Finding, FindingSeverity, FindingCategory,
    MCPToolDefinition, MCPResourceDefinition,
)

SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', 'venv', '.venv',
    'dist', 'build', 'test', 'tests', '__tests__', 'coverage',
}
SOURCE_EXTENSIONS = {'.py', '.ts', '.js', '.mjs', '.cjs', '.jsx', '.tsx'}
MAX_FILE_BYTES = 1_000_000


def _iter_files(scan_dir: str, accept) -> Iterable[Tuple[str, str, str]]:
    """Yield (filepath, rel_path, content) for files accepted by ``accept(fname)``."""
    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if not accept(fname):
                continue
            filepath = os.path.join(root, fname)
            try:
                if os.path.getsize(filepath) > MAX_FILE_BYTES:
                    continue
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue
            yield filepath, os.path.relpath(filepath, scan_dir), content


_NON_PRODUCTION_DIRS = (
    r"tests?|__tests__|spec|specs|fixtures?|examples?|samples?|mocks?|e2e|docs?|"
    r"smoke|scripts|bench|benchmarks?|demos?|\.github"
)
_NON_PRODUCTION_RE = re.compile(
    rf"(?i)(^|[\\/])({_NON_PRODUCTION_DIRS})([\\/]|$)"      # a whole path segment
    r"|\.(test|spec|smoke)\.|_test\.py$|(^|[\\/])test_"       # file-name conventions
)


def is_non_production_path(rel_path: str) -> bool:
    """True when a path is test, example, tooling or CI material rather than code the server
    ships and runs: tests/, fixtures/, examples/, docs/, smoke/, scripts/, bench/, demo/,
    .github/, and the *.test.* / *.spec.* / *.smoke.* / test_* / *_test.py file names.
    Only whole path segments count, so 'latest/' or 'contest.py' are production paths.
    The one definition every path-sensitive rule shares."""
    return bool(_NON_PRODUCTION_RE.search(rel_path or ""))


def _is_source(fname: str) -> bool:
    return os.path.splitext(fname)[1] in SOURCE_EXTENSIONS


def _line_of(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


# ============================================================
# MCP01: Hard-coded secrets in server source
# ============================================================

SECRET_FILE_EXTENSIONS = SOURCE_EXTENSIONS | {
    '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.env', '.sh',
}

# (label, regex, severity). Patterns only identify the *shape* of a secret.
SECRET_PATTERNS = [
    ("OpenAI/Anthropic-style API key", re.compile(r"\bsk-(?:proj-|ant-|live-)?[A-Za-z0-9_\-]{20,}"), FindingSeverity.CRITICAL),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), FindingSeverity.CRITICAL),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), FindingSeverity.CRITICAL),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), FindingSeverity.CRITICAL),
    ("Private key (PEM)", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"), FindingSeverity.CRITICAL),
    ("Hard-coded Bearer token", re.compile(r"""["'`]Bearer\s+[A-Za-z0-9\-_.=+/]{20,}["'`]"""), FindingSeverity.HIGH),
]

GENERIC_SECRET_RE = re.compile(
    r"""(?i)\b([A-Za-z0-9_]*(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|access[_-]?key)[A-Za-z0-9_]*)"""
    r"""["']?\s*[:=]\s*["']([^"'\s]{20,})["']"""
)

PLACEHOLDER_HINTS = (
    "xxx", "your", "example", "placeholder", "changeme", "dummy", "sample",
    "<", ">", "${", "{{", "process.env", "os.environ", "redacted", "...",
    "test", "fake", "insert", "replace",
)


NON_SECRET_VAR_SUFFIXES = (
    "url", "uri", "endpoint", "path", "file", "name", "type", "header",
    "env", "var", "field", "prefix", "format", "pattern", "regex",
)


PLACEHOLDER_STRUCTURAL = ("<", ">", "${", "{{", "process.env", "os.environ", "...")
PLACEHOLDER_WORDS = {
    "xxx", "xxxx", "your", "example", "placeholder", "changeme", "dummy", "sample", "test",
    "fake", "insert", "replace", "todo", "none", "null", "redacted", "secret", "key", "token",
    "here", "value", "apikey", "api", "my", "the", "a", "an", "enter", "put", "add", "sk", "ghp",
}
# Values copied verbatim from vendor documentation; never real.
KNOWN_DOC_EXAMPLES = {
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE", "ASIAIOSFODNN7EXAMPLE",
    "sk-1234567890abcdef", "sk-xxxxxxxxxxxxxxxxxxxx", "ghp_xxxxxxxxxxxxxxxxxxxx",
}


def _looks_placeholder(value: str) -> bool:
    """True for values that are clearly not a real secret. A real key whose project happens
    to be called "test" must NOT be suppressed, so word hints only count when the whole value
    is made of placeholder words (your_api_key_here), not when they merely appear inside it."""
    low = value.lower()
    if any(h in low for h in PLACEHOLDER_STRUCTURAL):
        return True
    if value in KNOWN_DOC_EXAMPLES:
        return True
    # Vendor documentation marks its sample credentials with an upper-case EXAMPLE
    # (AKIA…EXAMPLE, wJalr…EXAMPLEKEY); a masked value (sk-ab***) is not a credential.
    if "EXAMPLE" in value or "***" in value:
        return True
    if re.match(r"^(your|my|insert|replace|enter|put|add)[-_ ]", low) or \
            re.search(r"[-_ ](here|goes[-_ ]here)$", low):
        return True
    if len(set(low)) <= 3:
        return True
    longest_run = max((len(m.group(0)) for m in re.finditer(r"(.)\1*", low)), default=0)
    if longest_run >= 8 or longest_run * 2 >= len(low):
        return True
    tokens = re.findall(r"[a-z]+", low)
    if tokens and all(t in PLACEHOLDER_WORDS for t in tokens):
        return True
    return False


_REDACTION_CALL_RE = re.compile(
    r"(?i)\b\w*(?:redact|mask|scrub|saniti[sz]e|censor|obfuscate)\w*\s*\(\s*[^()]*$")
_REPLACEMENT_KEY_RE = re.compile(r"""(?i)\breplacement["']?\s*[:=]\s*["'`]?[^"'`]*$""")
_CI_SECRET_FALLBACK_RE = re.compile(r"""\$\{\{\s*secrets\.\w+\s*\|\|\s*["']?$""")
_PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/]{40,}")


def _is_redaction_or_ci_context(line: str, start: int, end: int) -> bool:
    """True when the key-shaped text at line[start:end] is not a stored credential because of
    where it sits: the argument of a redaction/masking call (`redact("sk-…")`), the
    `replacement:` of a redactor, a masked remainder (`sk-ab12***`), or the literal fallback
    of a CI secret expression (`${{ secrets.API_KEY || 'sk-…' }}`)."""
    before = line[:start]
    if _REDACTION_CALL_RE.search(before) or _REPLACEMENT_KEY_RE.search(before):
        return True
    if _CI_SECRET_FALLBACK_RE.search(before):
        return True
    return line[end:end + 3] in ("***", "...") or line[end:end + 1] == "…"


def _pem_has_key_body(lines: List[str], index: int, end: int) -> bool:
    """A PEM private-key header is a credential only when key material follows it: base64
    on the same line (after an escaped newline) or on the next lines. A header on its own
    is a pattern, a redactor's marker or a parser constant."""
    tail = lines[index][end:] + "".join(lines[index + 1:index + 3])
    tail = re.sub(r"""\\[nr]|["'`+\s]""", "", tail)
    return bool(_PEM_BODY_RE.match(tail))


def _generic_value_is_secret(var_name: str, value: str) -> bool:
    """Extra false-positive guards for the generic `api_key = "..."` pattern."""
    if var_name.lower().rstrip("_").endswith(NON_SECRET_VAR_SUFFIXES):
        return False
    if "://" in value or re.fullmatch(r"[A-Z0-9_]+", value):  # URLs, env-var names
        return False
    if not (re.search(r"\d", value) and re.search(r"[A-Za-z]", value)):
        return False
    return not _looks_placeholder(value)


# key: value / key = value lines as they appear in served content (resources, logs, configs)
_KV_SECRET_RE = re.compile(
    r"""(?im)^\s*[\-*]?\s*["']?(?P<key>[A-Za-z0-9_.\-]*(?:password|passwd|secret|token|api[_-]?key|apikey|"""
    r"""master[_\s-]?key|private[_\s-]?key|signing[_\s-]?secret|access[_-]?key|client[_-]?secret|flag))["']?"""
    r"""\s*[:=]\s*["']?(?P<value>[^\s"',]{6,})"""
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*")
_URL_CRED_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s/:@]+:[^\s/@]{3,}@[^\s/]+")
_FLAG_RE = re.compile(r"\b[A-Za-z0-9_]{2,16}\{[^{}\s]{6,}\}")


def find_secrets_in_text(text: str) -> List[Tuple[str, str]]:
    """(label, key-or-shape) for credential-shaped values in free text. Values are never returned."""
    hits: List[Tuple[str, str]] = []
    if not text:
        return hits
    for label, regex, _sev in SECRET_PATTERNS:
        for m in regex.finditer(text):
            if not _looks_placeholder(m.group(0)):
                hits.append((label, m.group(0)[:6] + "…"))
                break
    for m in _KV_SECRET_RE.finditer(text):
        value = m.group("value").strip("'\"")
        if value.lower() in ("none", "null", "true", "false", "redacted", "<redacted>", "hidden", "****", "set", "unset") \
                or value.startswith(("<", "$", "{")) or _looks_placeholder(value):
            continue
        hits.append(("Credential-style key/value", m.group("key")))
    if _BEARER_RE.search(text):
        hits.append(("Bearer token", "Bearer …"))
    for m in _URL_CRED_RE.finditer(text):
        hits.append(("Credentials embedded in a connection URL", m.group(0).split("://")[0] + "://user:pass@…"))
    for m in _FLAG_RE.finditer(text):
        hits.append(("CTF-style flag", m.group(0).split("{")[0] + "{…}"))
    # de-duplicate by (label, key)
    seen, out = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def detect_hardcoded_secrets(scan_dir: str) -> List[Finding]:
    """MCP01: find hard-coded credentials in server source and config files."""
    findings: List[Finding] = []
    counter = 0

    def accept(fname: str) -> bool:
        return os.path.splitext(fname)[1] in SECRET_FILE_EXTENSIONS or fname.startswith(".env")

    for _, rel_path, content in _iter_files(scan_dir, accept):
        if os.path.basename(rel_path) in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            continue
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            label: Optional[str] = None
            severity = FindingSeverity.HIGH
            var_name: Optional[str] = None

            for plabel, regex, sev in SECRET_PATTERNS:
                m = regex.search(line)
                if not m or _looks_placeholder(m.group(0)):
                    continue
                if _is_redaction_or_ci_context(line, m.start(), m.end()):
                    continue
                if plabel.startswith("Private key") and not _pem_has_key_body(lines, line_num - 1, m.end()):
                    continue
                label, severity = plabel, sev
                break

            g = GENERIC_SECRET_RE.search(line)
            if g and _generic_value_is_secret(g.group(1), g.group(2)) \
                    and not _is_redaction_or_ci_context(line, g.start(2), g.end(2)):
                var_name = g.group(1)
                if label is None:
                    label = "Generic API key/secret literal"

            if label is None:
                continue

            counter += 1
            where = f"variable '{var_name}' " if var_name else ""
            findings.append(Finding(
                id=f"mcp01_secret_{counter:04d}",
                severity=(FindingSeverity.LOW if is_non_production_path(rel_path) else severity),
                category=FindingCategory.CREDENTIAL_THEFT,
                title=f"Hard-coded secret in server source: {label}",
                description=f"A value shaped like a {label.lower()} is assigned in "
                            f"{where}{rel_path} at line {line_num}. The value itself is "
                            "not reproduced here. Anyone with read access to the source or "
                            "the published package can use it.",
                file_path=rel_path,
                line_number=line_num,
                recommendation="Revoke and rotate this credential, remove it from source "
                               "(and git history), and load it from the environment or a "
                               "secrets manager at runtime.",
                owasp_mcp=["MCP01"],
            ))
    return findings


# ============================================================
# MCP04: Unpinned install sources
# ============================================================

def _is_install_file(fname: str) -> bool:
    low = fname.lower()
    ext = os.path.splitext(low)[1]
    return (
        low.startswith("dockerfile") or low.endswith(".dockerfile") or low == "makefile"
        or ext in {".sh", ".bash", ".ps1", ".json", ".yml", ".yaml", ".toml"}
    )


NPX_RE = re.compile(r"\bnpx(?:\.cmd)?\s+((?:-{1,2}[\w-]+\s+)*)(?!-)((?:@[\w.\-]+/)?[\w.\-]+(?:@[\w.\-^~<>=]+)?)")
UVX_RE = re.compile(r"\buvx\s+((?:--?[\w-]+(?:\s+(?!-)\S+)?\s+)*)(?!-)([A-Za-z0-9_.\-\[\]]+(?:(?:==|@)[\w.\-]+)?)")
PIP_SELF_PACKAGES = {"pip", "setuptools", "wheel"}
PIP_RE = re.compile(r"\bpip3?\s+install\s+([^&|;\n\\]+)")
LATEST_RE = re.compile(r"(?:@[\w.\-]+/)?[\w.\-]+@latest\b")
JSON_NPX_RE = re.compile(r'"command"\s*:\s*"(npx|uvx)(?:\.cmd)?"\s*,\s*"args"\s*:\s*\[([^\]]*)\]', re.S)


def _npx_pkg_unpinned(pkg: str) -> bool:
    name = pkg[1:] if pkg.startswith("@") else pkg
    if "@" not in name:
        return True
    return name.rsplit("@", 1)[1] in ("latest", "")


def _pip_unpinned(arg_str: str) -> List[str]:
    tokens = arg_str.split()
    unpinned = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok in ("-r", "--requirement", "-c", "--constraint", "-e", "--editable",
                   "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-t", "--target"):
            skip_next = True
            continue
        if tok.startswith("-") or tok.startswith((".", "/", "$", "git+", "http")):
            continue
        tok = tok.strip("'\"")
        if not tok or "/" in tok or tok.endswith((".whl", ".tar.gz", ".txt")):
            continue
        if "==" in tok or "@" in tok:
            continue
        if re.split(r"[<>~!=\[]", tok)[0].lower() in PIP_SELF_PACKAGES:
            continue
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.\-\[\],]*([<>~!]=?.*)?$", tok):
            continue
        unpinned.append(tok)
    return unpinned


def detect_unpinned_installs(scan_dir: str) -> List[Finding]:
    """MCP04: installs that float to whatever version the registry serves today."""
    findings: List[Finding] = []
    counter = 0

    def add(rel_path: str, line_num: int, what: str):
        nonlocal counter
        counter += 1
        findings.append(Finding(
            id=f"mcp04_unpinned_{counter:04d}",
            severity=FindingSeverity.MEDIUM,
            category=FindingCategory.SUPPLY_CHAIN,
            title="Unpinned install source",
            description=f"{what} in {rel_path} at line {line_num}. Without an exact version "
                        "the next install silently picks up whatever is published, including "
                        "a compromised release.",
            file_path=rel_path,
            line_number=line_num,
            recommendation="Pin an exact version (pkg@1.2.3, pkg==1.2.3) and prefer a lockfile "
                           "or hash-checked requirements.",
            owasp_mcp=["MCP04"],
        ))

    for _, rel_path, content in _iter_files(scan_dir, _is_install_file):
        base = os.path.basename(rel_path).lower()
        if base in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"):
            continue
        flagged_lines: Set[int] = set()

        if base.endswith(".json") and base != "package.json":
            for m in JSON_NPX_RE.finditer(content):
                cmd = m.group(1)
                args = re.findall(r'"([^"]*)"', m.group(2))
                pkg = next((a for a in args if not a.startswith("-")), None)
                if not pkg:
                    continue
                line_num = _line_of(content, m.start())
                if cmd == "npx" and _npx_pkg_unpinned(pkg):
                    add(rel_path, line_num, f"`npx {pkg}` without a pinned version")
                    flagged_lines.add(line_num)
                elif cmd == "uvx" and "==" not in pkg and "@" not in pkg:
                    add(rel_path, line_num, f"`uvx {pkg}` without a pinned version")
                    flagged_lines.add(line_num)

        for line_num, line in enumerate(content.splitlines(), 1):
            if line_num in flagged_lines or line.lstrip().startswith("#"):
                continue
            what = None
            # package.json scripts run the locally installed (lockfile-pinned) bin via npx
            m = None if base == "package.json" else NPX_RE.search(line)
            if m and _npx_pkg_unpinned(m.group(2)):
                what = f"`npx {m.group(2)}` without a pinned version"
            if what is None:
                m = UVX_RE.search(line)
                if m and "==" not in m.group(2) and "@" not in m.group(2):
                    what = f"`uvx {m.group(2)}` without a pinned version"
            if what is None:
                m = PIP_RE.search(line)
                if m:
                    pkgs = _pip_unpinned(m.group(1))
                    if pkgs:
                        what = f"`pip install` of unpinned package(s) {', '.join(pkgs[:5])}"
            if what is None:
                m = LATEST_RE.search(line)
                if m:
                    what = f"`{m.group(0)}` floating tag"
            if what:
                add(rel_path, line_num, what)
    return findings


# ============================================================
# MCP07: Server bound to all interfaces
# ============================================================

BIND_ALL_PATTERNS = [
    re.compile(r"""(?i)\b(?:host|hostname|bind|bind_host|listen_host)["']?\s*[:=]\s*["'](0\.0\.0\.0|::|\[::\])["']"""),
    re.compile(r"""\.listen\s*\(\s*[^,()]+,\s*["'](0\.0\.0\.0|::)["']"""),
    re.compile(r"""["']--host["']\s*,\s*["'](0\.0\.0\.0|::)["']"""),
    re.compile(r"""--(?:host|bind)[= ]+["']?(0\.0\.0\.0|::)(?![\w:.])"""),
    re.compile(r"""(?i)\b(?:host|bind|bind_host|listen_host)\s*:\s*[\w\[\]|, ]+=\s*["'](0\.0\.0\.0|::)["']"""),
]


def _is_bind_file(fname: str) -> bool:
    low = fname.lower()
    return _is_source(fname) or low.startswith("dockerfile") or low.endswith((".sh", ".toml"))


def detect_bind_all_interfaces(scan_dir: str) -> List[Finding]:
    """MCP07: listeners on 0.0.0.0 / :: expose the server to the whole network."""
    findings: List[Finding] = []
    counter = 0
    for _, rel_path, content in _iter_files(scan_dir, _is_bind_file):
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//")):
                continue
            for pattern in BIND_ALL_PATTERNS:
                m = pattern.search(line)
                if m:
                    counter += 1
                    findings.append(Finding(
                        id=f"mcp07_bind_all_{counter:04d}",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.TRANSPORT_SECURITY,
                        title=f"MCP server binds to all interfaces ({m.group(1)})",
                        description=f"{rel_path} line {line_num} listens on {m.group(1)}, so any "
                                    "host that can reach this machine can connect. Combined with "
                                    "weak or missing authentication this exposes every tool.",
                        file_path=rel_path,
                        line_number=line_num,
                        recommendation="Bind to 127.0.0.1 for local use; if remote access is "
                                       "required (including inside containers, where 0.0.0.0 is "
                                       "normal), put the server behind authentication and TLS and "
                                       "do not publish the port beyond trusted networks.",
                        owasp_mcp=["MCP07"],
                    ))
                    break
    return findings


# ============================================================
# MCP05: Tool input reaches an exec/shell sink (heuristic)
# ============================================================

PY_TOOL_DECORATOR_ATTRS = {"tool", "call_tool"}
PY_SINK_ATTRS = {
    "subprocess": {"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"},
    "os": {"system", "popen", "execv", "execve", "execvp", "execl", "execlp", "spawnl", "spawnv"},
    "asyncio": {"create_subprocess_shell", "create_subprocess_exec"},
}
PY_SINK_NAMES = {"eval", "exec"}


def _is_tool_decorator(dec: ast.expr) -> bool:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr in PY_TOOL_DECORATOR_ATTRS
    if isinstance(target, ast.Name):
        return target.id in PY_TOOL_DECORATOR_ATTRS
    return False


def _sink_name(call: ast.Call) -> Optional[str]:
    func = call.func
    if isinstance(func, ast.Name) and func.id in PY_SINK_NAMES:
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        mod = func.value.id
        if func.attr in PY_SINK_ATTRS.get(mod, set()):
            return f"{mod}.{func.attr}"
    return None


def _names_in(node: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _py_tool_sinks(content: str) -> List[Tuple[str, int, str, bool]]:
    """Return (tool_name, line, sink, tainted) for sinks inside @*.tool functions."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_is_tool_decorator(d) for d in node.decorator_list):
            continue
        params = {a.arg for a in node.args.args + node.args.kwonlyargs} - {"self", "cls", "ctx", "context"}
        if node.args.vararg:
            params.add(node.args.vararg.arg)
        if node.args.kwarg:
            params.add(node.args.kwarg.arg)
        # One-hop propagation: names assigned from expressions that use params.
        tainted = set(params)
        for _ in range(2):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign) and _names_in(sub.value) & tainted:
                    for tgt in sub.targets:
                        tainted |= _names_in(tgt)
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                sink = _sink_name(sub)
                if not sink:
                    continue
                arg_names: Set[str] = set()
                for a in sub.args:
                    arg_names |= _names_in(a)
                for kw in sub.keywords:
                    arg_names |= _names_in(kw.value)
                results.append((node.name, sub.lineno, sink, bool(arg_names & tainted)))
    return results


JS_TOOL_START_RE = re.compile(
    r"\b(?:server|mcp|mcpServer|app)\.(?:tool|registerTool)\s*\(|setRequestHandler\s*\(\s*CallToolRequestSchema"
)
JS_SINK_RE = re.compile(
    r"(?<![\w$.])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|execa|eval)\s*\("
    r"|\b(?:child_process|childProcess|cp)\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\("
    r"|\bnew\s+Function\s*\("
)


def _js_tool_sinks(content: str) -> List[Tuple[int, str]]:
    starts = [m.start() for m in JS_TOOL_START_RE.finditer(content)]
    results = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(content)
        # cap the window at ~80 lines to keep this local to the handler
        window_end = start
        for _ in range(80):
            nxt = content.find("\n", window_end + 1)
            if nxt == -1 or nxt >= end:
                window_end = end
                break
            window_end = nxt
        for m in JS_SINK_RE.finditer(content, start, window_end):
            results.append((_line_of(content, m.start()), m.group(0).rstrip("(").strip()))
    return results


def detect_tool_input_sinks(scan_dir: str) -> List[Finding]:
    """MCP05: exec/shell sinks inside functions registered as MCP tools."""
    findings: List[Finding] = []
    counter = 0
    seen: Set[Tuple[str, int]] = set()
    for _, rel_path, content in _iter_files(scan_dir, _is_source):
        ext = os.path.splitext(rel_path)[1]
        if ext == ".py":
            hits = [(ln, sink, tool, tainted) for tool, ln, sink, tainted in _py_tool_sinks(content)]
        else:
            hits = [(ln, sink, None, False) for ln, sink in _js_tool_sinks(content)]
        for line_num, sink, tool, tainted in hits:
            if (rel_path, line_num) in seen:
                continue
            seen.add((rel_path, line_num))
            counter += 1
            subject = f"tool '{tool}'" if tool else "an MCP tool handler"
            if tainted:
                severity = FindingSeverity.CRITICAL
                detail = "A tool parameter flows (directly or via one assignment) into the sink."
            else:
                severity = FindingSeverity.HIGH
                detail = "The sink sits inside the tool body; data flow from tool input was not proven."
            findings.append(Finding(
                id=f"mcp05_tool_sink_{counter:04d}",
                severity=severity,
                category=FindingCategory.COMMAND_INJECTION,
                title=f"Exec/shell sink `{sink}` inside {subject}",
                description=f"{rel_path} line {line_num}: {subject} calls `{sink}`. Tool arguments "
                            f"are chosen by the model and can be steered by injected content. {detail} "
                            "This is a heuristic, not full taint analysis.",
                file_path=rel_path,
                line_number=line_num,
                recommendation="Avoid shells in tool handlers. Use argument lists (no shell=True), "
                               "strict allowlists for commands and paths, and validate every "
                               "tool argument before use.",
                owasp_mcp=["MCP05"],
            ))
    return findings


# ============================================================
# MCP08: No logging of tool invocations (low confidence)
# ============================================================

TOOL_DEFINITION_RE = re.compile(
    r"@\w+\.(?:tool|call_tool)\b|\b(?:server|mcp|mcpServer|app)\.(?:tool|registerTool)\s*\(|CallToolRequestSchema"
)
LOGGING_RE = re.compile(
    r"\b(?:import\s+logging|logging\.|logger\.|getLogger|structlog|loguru|"
    r"console\.(?:log|info|warn|error|debug)|pino|winston|bunyan|"
    r"sendLoggingMessage|sys\.stderr|ctx\.(?:info|debug|warning|error|log)|log\.(?:info|debug|warn|warning|error))"
)


def detect_missing_tool_logging(scan_dir: str) -> List[Finding]:
    """MCP08: informational — tool-defining files with no visible logging at all."""
    tool_files: List[str] = []
    logged = False
    for _, rel_path, content in _iter_files(scan_dir, _is_source):
        if TOOL_DEFINITION_RE.search(content):
            tool_files.append(rel_path)
            if LOGGING_RE.search(content):
                logged = True
    if not tool_files or logged:
        return []
    shown = ", ".join(sorted(tool_files)[:5])
    return [Finding(
        id="mcp08_no_tool_logging",
        severity=FindingSeverity.INFO,
        category=FindingCategory.AUDIT_TELEMETRY,
        title="No logging found in files that define MCP tools (low confidence)",
        description=f"None of the tool-defining files ({shown}) reference a logging library "
                    "or logger call. Tool invocations may leave no audit trail. Confidence is "
                    "low: logging could be configured elsewhere or by the host.",
        file_path=sorted(tool_files)[0],
        recommendation="Log each tool invocation (tool name, caller/session, outcome, and "
                       "redacted arguments) to a durable, tamper-evident sink.",
        owasp_mcp=["MCP08"],
    )]


# ============================================================
# MCP10: Broad data exposure via tool/resource naming
# ============================================================

BROAD_NAME_TOKENS = {"all", "dump", "export", "entire", "everything", "bulk", "database", "listall", "dumpall"}
BROAD_DESC_RE = re.compile(
    r"(?i)\b(?:dump|export)s?\b|"
    r"\b(?:all|entire|every|whole|complete|full)\s+(?:the\s+|of\s+the\s+)?"
    r"(?:data(?:base)?|records?|rows|files|tables|users|customers|contents|history|messages|emails|documents|context)\b"
)


def _name_tokens(name: str) -> Set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    tokens = {t.lower() for t in re.split(r"[^A-Za-z0-9]+", spaced) if t}
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    for word in ("listall", "dumpall"):
        if word in compact:
            tokens.add(word)
    return tokens


def detect_broad_data_exposure(
    tools: List[MCPToolDefinition],
    resources: Optional[List[MCPResourceDefinition]] = None,
) -> List[Finding]:
    """MCP10: tools/resources whose name or description suggests bulk data exposure."""
    findings: List[Finding] = []
    items: List[Tuple[str, str, str]] = [("tool", t.name, t.description or "") for t in tools]
    for r in resources or []:
        items.append(("resource", r.name or r.uri, f"{r.uri} {r.description or ''}"))

    counter = 0
    for kind, name, desc in items:
        hits = sorted(_name_tokens(name) & BROAD_NAME_TOKENS)
        m = BROAD_DESC_RE.search(desc)
        if not hits and not m:
            continue
        counter += 1
        signal = f"name tokens {hits}" if hits else f"description phrase '{m.group(0)}'"
        findings.append(Finding(
            id=f"mcp10_broad_exposure_{counter:04d}",
            severity=FindingSeverity.LOW,
            category=FindingCategory.CONTEXT_OVERSHARING,
            title=f"{kind.capitalize()} '{name}' suggests broad data exposure",
            description=f"The {kind} '{name}' ({signal}) appears to return bulk data into the "
                        "model context, where it can be over-shared with other tools, sessions "
                        "or users. What is actually returned at runtime is not checked "
                        "(runtime over-sharing remains a coverage gap).",
            recommendation="Scope results (pagination, filters, per-user access checks) and "
                           "avoid returning whole tables, histories or file trees to the model.",
            owasp_mcp=["MCP10"],
        ))
    return findings
