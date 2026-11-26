"""
AST-based extraction of MCP definitions from Python server source.

Replaces the regex extractor for Python files. It sees what the regex could not:
  - ``@mcp.tool(name="fetch_urI")`` (decorator arguments; ``name=`` wins over the function name)
  - single-line ``"..."`` docstrings and ``description=`` kwargs
  - ``@mcp.resource("notes://welcome")`` and ``@mcp.prompt()`` (FastMCP style)
  - ``server.add_tool(fn, name=..., description=...)`` / ``remove_tool(...)`` (runtime registration)
  - parameter defaults (for the excessive-scope check) and the string literals a
    function returns (for response-injection and egress-URL checks)

Only the standard library ``ast`` module is used. A file that does not parse returns
``None`` so callers can fall back to the regex path.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from app.models.schemas import (
    MCPPromptDefinition,
    MCPResourceDefinition,
    MCPToolDefinition,
)

# Decorator attribute/name -> definition kind
_DECORATOR_KINDS = {
    "tool": "tool",
    "call_tool": "tool",
    "resource": "resource",
    "prompt": "prompt",
}
_REGISTRATION_ATTRS = {"add_tool", "remove_tool"}
_SKIP_PARAMS = {"self", "cls", "ctx", "context"}
_COUNTER_NAME_RE = __import__("re").compile(r"(?i)(call_?count|_?calls\b|invocation|counter|_count\b|times_called|_rug|_triggered|usage_count)")

_ANNOTATION_TYPES = {
    "str": "string", "int": "integer", "float": "number", "bool": "boolean",
    "list": "array", "List": "array", "dict": "object", "Dict": "object",
}


@dataclass
class ToolBody:
    """What a decorated or registered function looks like inside."""
    name: str
    func_name: str
    kind: str                      # "tool" | "resource" | "prompt"
    lineno: int
    description: str = ""
    uri: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)   # name -> default literal (None if none)
    required: List[str] = field(default_factory=list)      # params without a default
    return_strings: List[str] = field(default_factory=list)
    referenced_names: Set[str] = field(default_factory=set)
    registered_at_runtime: bool = False
    registered_in: Optional[str] = None                    # enclosing function of add_tool()
    count_gated: bool = False                              # behaviour depends on an invocation counter
    calls: Set[str] = field(default_factory=set)           # dotted call names of interest (fs.readFile, exec, fetch, process.env)
    param_sinks: List[Tuple[str, str, str, int, bool]] = field(default_factory=list)  # (param, sink, kind, lineno, validated)
    doc_rewrites: List[Tuple[str, str, int]] = field(default_factory=list)            # (target, new text, lineno)


@dataclass
class DynamicRegistration:
    """An ``add_tool`` / ``remove_tool`` call found in source."""
    kind: str                      # "add_tool" | "remove_tool"
    name: Optional[str]
    lineno: int
    inside_function: Optional[str]
    description: Optional[str] = None


@dataclass
class PyExtraction:
    server_name: str = ""                  # FastMCP("name") / MCPServer(name="...")
    server_instructions: str = ""          # FastMCP("name", instructions="...")
    server_instructions_line: int = 0
    tools: List[MCPToolDefinition] = field(default_factory=list)
    resources: List[MCPResourceDefinition] = field(default_factory=list)
    prompts: List[MCPPromptDefinition] = field(default_factory=list)
    bodies: List[ToolBody] = field(default_factory=list)
    registrations: List[DynamicRegistration] = field(default_factory=list)
    module_strings: Dict[str, str] = field(default_factory=dict)
    module_literals: List[Tuple[str, str, int]] = field(default_factory=list)   # (name, string, lineno) inside module-level data


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------

def _decorator_kind(dec: ast.expr) -> Optional[str]:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return _DECORATOR_KINDS.get(target.attr)
    if isinstance(target, ast.Name):
        return _DECORATOR_KINDS.get(target.id)
    return None


def _const_str(node: Optional[ast.AST], module_strings: Dict[str, str]) -> Optional[str]:
    """A string literal, or a Name that resolves to a module-level string constant."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return module_strings.get(node.id)
    if isinstance(node, ast.JoinedStr):
        return "".join(_strings_in_expr(node, module_strings, {}))
    return None


def _literal(node: Optional[ast.AST]) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return ast.unparse(node) if hasattr(ast, "unparse") else None


def _annotation_type(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Name):
        return _ANNOTATION_TYPES.get(node.id)
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        return _ANNOTATION_TYPES.get(node.value.id)
    return None


_DATA_KEY = "\x00data"   # names of function-local dict/list literals (see _function_body_info)


def _data_names(local_strings: Dict[str, str]) -> Set[str]:
    return set(n for n in local_strings.get(_DATA_KEY, "").split(",") if n)


def _strings_in_expr(node: ast.AST, module_strings: Dict[str, str],
                     local_strings: Dict[str, str]) -> List[str]:
    """Collect the string literals an expression can evaluate to or contain."""
    out: List[str] = []
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            out.append(node.value)
    elif isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                inner = v.value
                if isinstance(inner, ast.Name):
                    resolved = local_strings.get(inner.id) or module_strings.get(inner.id)
                    parts.append(resolved if resolved is not None else "{" + inner.id + "}")
                elif isinstance(inner, ast.Subscript) and isinstance(inner.value, ast.Name) \
                        and inner.value.id in _data_names(local_strings):
                    parts.append(local_strings[inner.value.id])
                else:
                    parts.append("{...}")
        out.append("".join(parts))
    elif isinstance(node, ast.Name):
        resolved = local_strings.get(node.id) or module_strings.get(node.id)
        if resolved is not None:
            out.append(resolved)
    elif isinstance(node, ast.Subscript):
        # users[username] -> every string the function-local dict/list literal `users` holds.
        # A slice of a string constant (KEY[-4:]) is not on the return path.
        if isinstance(node.value, ast.Name) and node.value.id in _data_names(local_strings):
            out.extend(_strings_in_expr(node.value, module_strings, local_strings))
    elif isinstance(node, ast.BinOp):
        out.extend(_strings_in_expr(node.left, module_strings, local_strings))
        out.extend(_strings_in_expr(node.right, module_strings, local_strings))
    elif isinstance(node, (ast.Tuple, ast.List)):
        for elt in node.elts:
            out.extend(_strings_in_expr(elt, module_strings, local_strings))
    elif isinstance(node, ast.IfExp):
        out.extend(_strings_in_expr(node.body, module_strings, local_strings))
        out.extend(_strings_in_expr(node.orelse, module_strings, local_strings))
    elif isinstance(node, ast.Call):
        # str.format / " ".join([...]) / json.dumps(...) — look at the arguments
        for a in node.args:
            out.extend(_strings_in_expr(a, module_strings, local_strings))
        if isinstance(node.func, ast.Attribute):
            out.extend(_strings_in_expr(node.func.value, module_strings, local_strings))
    return out


def _params(node: ast.AST) -> Tuple[Dict[str, Any], List[str], Dict[str, Optional[str]]]:
    """Return (name -> default literal or None, required names, name -> json type)."""
    args = node.args
    positional = list(args.posonlyargs) + list(args.args)
    defaults: List[Optional[ast.AST]] = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    params: Dict[str, Any] = {}
    required: List[str] = []
    types: Dict[str, Optional[str]] = {}
    for arg, default in zip(positional, defaults):
        if arg.arg in _SKIP_PARAMS:
            continue
        params[arg.arg] = _literal(default)
        types[arg.arg] = _annotation_type(arg.annotation)
        if default is None:
            required.append(arg.arg)
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if arg.arg in _SKIP_PARAMS:
            continue
        params[arg.arg] = _literal(default)
        types[arg.arg] = _annotation_type(arg.annotation)
        if default is None:
            required.append(arg.arg)
    return params, required, types


def _input_schema(params: Dict[str, Any], required: List[str],
                  types: Dict[str, Optional[str]]) -> Dict[str, Any]:
    props: Dict[str, Any] = {}
    for name, default in params.items():
        prop: Dict[str, Any] = {}
        if types.get(name):
            prop["type"] = types[name]
        if name not in required and default is not None:
            prop["default"] = default
        props[name] = prop
    return {"type": "object", "properties": props, "required": list(required)}


def _count_gated(node: ast.AST, names: Set[str]) -> bool:
    """True when the body compares a counter-like name against a number (rug pull after N calls)."""
    if not any(_COUNTER_NAME_RE.search(n) for n in names):
        return False
    for n in ast.walk(node):
        if isinstance(n, ast.Compare):
            sides = [n.left] + list(n.comparators)
            if any(isinstance(s, ast.Constant) and isinstance(s.value, int) and not isinstance(s.value, bool) for s in sides) \
                    and any(isinstance(s, ast.Name) and _COUNTER_NAME_RE.search(s.id) for s in sides):
                return True
    return False


_PY_CALL_OF_INTEREST_RE = __import__("re").compile(
    r"^(?:open|os\.(?:system|popen|environ|getenv|remove|unlink|rmdir|listdir|walk|makedirs|rename|chmod)"
    r"|subprocess\.\w+|shutil\.\w+|eval|exec|compile|__import__|importlib\.\w+"
    r"|requests\.\w+|httpx\.\w+|urllib\.request\.\w+|urlopen|aiohttp\.\w+|socket\.\w+"
    r"|(?:pathlib\.)?Path(?:\.\w+)*|\w+\.(?:read_text|read_bytes|write_text|write_bytes|unlink|rmtree|glob|rglob|iterdir)"
    r"|pip\.\w+|ctypes\.\w+)$"
)


def _calls_in(node: ast.AST) -> Set[str]:
    """Dotted names of the calls a body makes that touch files, processes, network, env or code."""
    out: Set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            parts: List[str] = []
            obj: ast.AST = n.func
            while isinstance(obj, ast.Attribute):
                parts.append(obj.attr)
                obj = obj.value
            if isinstance(obj, ast.Name):
                parts.append(obj.id)
            name = ".".join(reversed(parts))
            if name and _PY_CALL_OF_INTEREST_RE.match(name):
                out.add(name)
        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "os" and n.attr == "environ":
            out.add("os.environ")
    return out


_SINK_KINDS = [
    (__import__("re").compile(r"^(open|io\.open|codecs\.open|os\.(listdir|walk|scandir|stat)|\w+\.(read_text|read_bytes|glob|rglob|iterdir)|shutil\.(copy|copyfile|copytree))$"), "file_read"),
    (__import__("re").compile(r"^(os\.(remove|unlink|rmdir|makedirs|rename|replace|chmod|chown)|shutil\.(rmtree|move)|\w+\.(write_text|write_bytes|unlink|rmdir|touch|mkdir))$"), "file_write"),
    (__import__("re").compile(r"^(os\.(system|popen|exec\w*|spawn\w*)|subprocess\.\w+|eval|exec|compile|commands\.\w+|pty\.spawn)$"), "shell_exec"),
    (__import__("re").compile(r"^(requests\.\w+|httpx\.\w+|httpx\.AsyncClient\.\w+|urllib\.request\.(urlopen|Request)|urlopen|aiohttp\.\w+|(client|session|http|http_client|httpclient|api|conn|s|async_client)\.(get|post|put|patch|delete|request|fetch|stream)|socket\.\w+|websockets\.connect)$"), "network_egress"),
]
_VALIDATOR_RE = __import__("re").compile(r"(?i)(valid|sanit|normal|resolve|check|allow|safe|secure|clean|escape|quote|canonical|is_within|relative_to|realpath|abspath)")
_WRITE_MODE_RE = __import__("re").compile(r"[wax+]")


def _call_name_of(node: ast.Call) -> str:
    parts: List[str] = []
    obj: ast.AST = node.func
    while isinstance(obj, ast.Attribute):
        parts.append(obj.attr)
        obj = obj.value
    if isinstance(obj, ast.Name):
        parts.append(obj.id)
    elif isinstance(obj, ast.Call):           # Path(x).read_text() -> "Path.read_text"
        inner = _call_name_of(obj)
        if inner:
            parts.append(inner.split(".")[-1])
    return ".".join(reversed(parts))


def _body_extras(node: ast.AST, params: List[str]) -> Tuple[List[Tuple[str, str, str, int, bool]], List[Tuple[str, str, int]]]:
    """(param->sink flows, __doc__ rewrites) for a function body.

    A flow is a caller parameter (or a local derived from it in one step) used as an
    argument of a file/process/network sink. It is *validated* when the local was produced
    by a call whose name says so (validatePath, sanitize, resolve_safe, ...)."""
    pset = set(params)
    derived: Dict[str, Tuple[str, bool]] = {}      # local -> (param, validated)
    for stmt in ast.walk(node):
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            names = {n.id for n in ast.walk(stmt.value) if isinstance(n, ast.Name)}
            src = next((p for p in params if p in names), None)
            if src is None:
                src_local = next((l for l in derived if l in names), None)
                if src_local is None:
                    continue
                src, prev_valid = derived[src_local]
            else:
                prev_valid = False
            validated = prev_valid
            val = stmt.value
            if isinstance(val, ast.Await):
                val = val.value
            if isinstance(val, ast.Call) and _VALIDATOR_RE.search(_call_name_of(val) or ""):
                validated = True
            derived[stmt.targets[0].id] = (src, validated)
    flows: List[Tuple[str, str, str, int, bool]] = []
    seen = set()
    for call in ast.walk(node):
        if not isinstance(call, ast.Call):
            continue
        name = _call_name_of(call)
        if not name:
            continue
        kind = next((k for rx, k in _SINK_KINDS if rx.match(name)), None)
        if kind is None:
            continue
        if kind == "file_read" and name in ("open", "io.open", "codecs.open"):
            mode = None
            if len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
                mode = str(call.args[1].value)
            for kw in call.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = str(kw.value.value)
            if mode and _WRITE_MODE_RE.search(mode):
                kind = "file_write"
        arg_names = set()
        # file sinks: only the path argument (first positional / path= / file=) carries the capability
        if kind in ("file_read", "file_write"):
            cands = list(call.args[:1]) + [kw.value for kw in call.keywords if kw.arg in ("path", "file", "filename", "fp", "src", "dst", "target")]
        else:
            cands = list(call.args) + [kw.value for kw in call.keywords]
        for a in cands:
            arg_names |= {n.id for n in ast.walk(a) if isinstance(n, ast.Name)}
        for p in params:
            if p in arg_names:
                key = (p, kind)
                if key not in seen:
                    seen.add(key)
                    flows.append((p, name, kind, call.lineno, False))
        for local, (p, validated) in derived.items():
            if local in arg_names and (p, kind) not in seen:
                seen.add((p, kind))
                flows.append((p, name, kind, call.lineno, validated))
    rewrites: List[Tuple[str, str, int]] = []
    for stmt in ast.walk(node):
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Attribute) and t.attr == "__doc__":
                    text = stmt.value.value if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str) else ""
                    target = t.value.id if isinstance(t.value, ast.Name) else ast.unparse(t.value)
                    rewrites.append((target, text, stmt.lineno))
    return flows, rewrites


def _function_body_info(node: ast.AST, module_strings: Dict[str, str]) -> Tuple[List[str], Set[str]]:
    """Strings on the return path (with Name resolution) and every Name the body references."""
    local_strings: Dict[str, str] = {}
    for stmt in ast.walk(node):
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            val = _const_str(stmt.value, module_strings)
            if val is not None:
                local_strings[stmt.targets[0].id] = val
            elif isinstance(stmt.value, (ast.Dict, ast.List, ast.Tuple)):
                # function-local data that may reach the return value (users = {"user1": "..."})
                lits = [c.value for c in ast.walk(stmt.value)
                        if isinstance(c, ast.Constant) and isinstance(c.value, str) and len(c.value) >= 12]
                if lits:
                    local_strings[stmt.targets[0].id] = "\n".join(lits)
                    local_strings[_DATA_KEY] = (local_strings.get(_DATA_KEY, "") + "," + stmt.targets[0].id).strip(",")
    returns: List[str] = []
    for stmt in ast.walk(node):
        if isinstance(stmt, ast.Return) and stmt.value is not None:
            returns.extend(_strings_in_expr(stmt.value, module_strings, local_strings))
    names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    return [r for r in returns if r], names


# ----------------------------------------------------------------------------
# main entry point
# ----------------------------------------------------------------------------

def extract_python_definitions(source: str, path: str = "<src>") -> Optional[PyExtraction]:
    """Extract tools, resources, prompts, bodies and runtime registrations. ``None`` if unparsable."""
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, RecursionError):
        return None

    ex = PyExtraction()

    # Module-level string constants (EXFIL_URL = "https://...", RUGPULL_EVIL_DESC = "...")
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                ex.module_strings[stmt.targets[0].id] = stmt.value.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                ex.module_strings[stmt.target.id] = stmt.value.value

    # Every string literal inside module-level data (dicts/lists of documents, configs, fixtures)
    for stmt in tree.body:
        targets = []
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            targets = [(stmt.targets[0].id, stmt.value)]
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            targets = [(stmt.target.id, stmt.value)]
        for name, value in targets:
            if isinstance(value, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
                for sub in ast.walk(value):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and len(sub.value) >= 20:
                        ex.module_literals.append((name, sub.value, getattr(sub, "lineno", stmt.lineno)))

    # Server-level instructions passed to the server constructor (and the server's name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = node.func.attr if isinstance(node.func, ast.Attribute) else (node.func.id if isinstance(node.func, ast.Name) else "")
            if callee in ("FastMCP", "MCPServer", "Server", "McpServer") and not ex.server_name:
                nm = None
                for kw in node.keywords:
                    if kw.arg == "name":
                        nm = _const_str(kw.value, ex.module_strings)
                if nm is None and node.args:
                    nm = _const_str(node.args[0], ex.module_strings)
                if nm:
                    ex.server_name = nm
            for kw in node.keywords:
                if kw.arg == "instructions":
                    text = _const_str(kw.value, ex.module_strings)
                    if text and not ex.server_instructions:
                        ex.server_instructions = text
                        ex.server_instructions_line = node.lineno

    # Every function, keyed by name, for add_tool(fn) lookups
    functions: Dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, node)

    seen_tool_names: Set[str] = set()

    def add_body(body: ToolBody) -> None:
        ex.bodies.append(body)
        if body.kind == "tool":
            if body.name not in seen_tool_names:
                seen_tool_names.add(body.name)
                ex.tools.append(MCPToolDefinition(
                    name=body.name, description=body.description,
                    input_schema=_input_schema(body.params, body.required, body_types.get(id(body), {})),
                ))
        elif body.kind == "resource":
            ex.resources.append(MCPResourceDefinition(
                uri=body.uri or body.name, name=body.func_name, description=body.description,
            ))
        elif body.kind == "prompt":
            ex.prompts.append(MCPPromptDefinition(
                name=body.name, description=body.description,
                arguments=[{"name": p, "required": p in body.required} for p in body.params],
            ))

    body_types: Dict[int, Dict[str, Optional[str]]] = {}

    def make_body(node: ast.AST, kind: str, name: Optional[str], description: Optional[str],
                  uri: Optional[str], runtime: bool = False, registered_in: Optional[str] = None) -> ToolBody:
        params, required, types = _params(node)
        returns, names = _function_body_info(node, ex.module_strings)
        body = ToolBody(
            name=name or node.name, func_name=node.name, kind=kind, lineno=node.lineno,
            description=(description if description is not None else (ast.get_docstring(node) or "")).strip(),
            uri=uri, params=params, required=required, return_strings=returns,
            referenced_names=names, registered_at_runtime=runtime, registered_in=registered_in,
            count_gated=_count_gated(node, names), calls=_calls_in(node),
        )
        body.param_sinks, body.doc_rewrites = _body_extras(node, list(params))
        body_types[id(body)] = types
        return body

    # 1. Decorated functions
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            kind = _decorator_kind(dec)
            if not kind:
                continue
            name = description = uri = None
            if isinstance(dec, ast.Call):
                for kw in dec.keywords:
                    if kw.arg == "name":
                        name = _const_str(kw.value, ex.module_strings)
                    elif kw.arg == "description":
                        description = _const_str(kw.value, ex.module_strings)
                    elif kw.arg == "uri":
                        uri = _const_str(kw.value, ex.module_strings)
                if dec.args:
                    first = _const_str(dec.args[0], ex.module_strings)
                    if first:
                        if kind == "resource":
                            uri = uri or first
                        else:
                            name = name or first
            add_body(make_body(node, kind, name, description, uri))
            break

    # 2. add_tool / remove_tool calls, with their enclosing function
    class _RegVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: List[str] = []
            self.named_funcs: Set[str] = set()   # functions already registered under an explicit name

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            attr = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else None)
            if attr in _REGISTRATION_ATTRS:
                inside = self.stack[-1] if self.stack else None
                name = description = None
                fn_node: Optional[ast.AST] = None
                for kw in node.keywords:
                    if kw.arg == "name":
                        name = _const_str(kw.value, ex.module_strings)
                    elif kw.arg == "description":
                        description = _const_str(kw.value, ex.module_strings)
                if node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Name):
                        fn_node = functions.get(first.id)
                        if attr == "remove_tool":
                            name = name or first.id
                        elif fn_node is not None:
                            name = name or first.id
                    else:
                        s = _const_str(first, ex.module_strings)
                        if s:
                            name = name or s
                ex.registrations.append(DynamicRegistration(
                    kind=attr, name=name, lineno=node.lineno, inside_function=inside,
                    description=description,
                ))
                if attr == "add_tool" and fn_node is not None:
                    fn_id = node.args[0].id  # type: ignore[union-attr]
                    explicit = any(kw.arg == "name" for kw in node.keywords)
                    if explicit:
                        self.named_funcs.add(fn_id)
                    # `except TypeError: add_tool(fn)` fallbacks re-register the same function
                    # under its bare name; one tool per function is enough.
                    if explicit or fn_id not in self.named_funcs:
                        add_body(make_body(fn_node, "tool", name, description, None,
                                           runtime=inside is not None, registered_in=inside))
            self.generic_visit(node)

    _RegVisitor().visit(tree)
    return ex
