"""
tree-sitter extraction of MCP definitions from TypeScript / JavaScript server source.

Replaces the regex fallback for ``.ts/.tsx/.js/.mjs/.cjs/.jsx`` files. It produces the
same :class:`~app.analysis.py_extractor.PyExtraction` record the Python extractor
produces, so every text rule (poisoned descriptions, response injection, egress URLs,
rug-pull primitives, confused deputies) runs identically on both languages.

Registration patterns verified against the official TypeScript SDK and the
``modelcontextprotocol/servers`` reference servers:

  * ``server.tool(name, [description], [schema], [annotations], cb)``
  * ``server.registerTool(name, {title, description, inputSchema}, cb)``
  * ``server.resource(name, uri | new ResourceTemplate(...), [meta], cb)`` /
    ``server.registerResource(name, uri, {description, mimeType}, cb)``
  * ``server.prompt(name, [description], [argsSchema], cb)`` /
    ``server.registerPrompt(name, {description, argsSchema}, cb)``
  * low level: ``server.setRequestHandler(ListToolsRequestSchema, () => ({tools: [...]}))``
    with ``CallToolRequestSchema`` handlers attributed per ``case "name":`` / ``if (name === "x")``
  * module-level ``const TOOLS: Tool[] = [{name, description, inputSchema}, ...]``
  * ``new McpServer({name, version}, {instructions})`` / ``new Server(...)``
  * handles returned by ``registerTool`` being ``.remove()``'d, ``.disable()``'d or
    ``.update()``'d, and ``server.removeTool(...)`` — rug-pull primitives.

A registration that happens inside the callback of another tool/resource/prompt (or
inside a request handler) is *runtime* registration. A registration inside an ordinary
``createServer()`` factory is not: that is how every reference server is written.

Only ``tree-sitter`` plus the two grammar wheels are needed; when they are missing
``extract_ts_definitions`` returns ``None`` and callers fall back to the regex path.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from app.analysis.py_extractor import (
    DynamicRegistration,
    PyExtraction,
    ToolBody,
    _COUNTER_NAME_RE,
    _input_schema,
)
from app.models.schemas import (
    MCPPromptDefinition,
    MCPResourceDefinition,
    MCPToolDefinition,
)

try:  # optional dependency
    from tree_sitter import Language, Node, Parser
    import tree_sitter_javascript as _tsj
    import tree_sitter_typescript as _tst
    HAS_TREE_SITTER = True
except Exception:  # pragma: no cover - exercised only when the wheels are absent
    HAS_TREE_SITTER = False
    Node = Any  # type: ignore[misc,assignment]

_LANGS: Dict[str, Any] = {}

_TOOL_METHODS = {"tool", "registerTool", "addTool", "add_tool"}
_RESOURCE_METHODS = {"resource", "registerResource", "addResource"}
_PROMPT_METHODS = {"prompt", "registerPrompt", "addPrompt"}
_REMOVE_METHODS = {"removeTool", "unregisterTool", "remove_tool", "deleteTool"}
_HANDLE_MUTATIONS = {"remove", "disable", "update"}
_HANDLER_METHODS = {"setRequestHandler"}
_SERVER_CTORS = {"McpServer", "Server", "FastMCP", "MCPServer"}
_SCHEMA_KEYS = ("inputSchema", "input_schema", "paramsSchema", "parameters", "argsSchema", "schema")
_ZOD_TYPES = {
    "string": "string", "number": "number", "boolean": "boolean", "array": "array",
    "object": "object", "enum": "string", "literal": "string", "record": "object",
    "int": "integer", "bigint": "integer", "date": "string", "any": None, "unknown": None,
}
_NAME_CHECK_RE = re.compile(r"""(?:name|toolName|tool)\s*===?\s*["'`]([^"'`]+)["'`]""")
_TS_SINK_KINDS = [
    (re.compile(r"^(fs(\.promises)?\.(readFile|readFileSync|readdir|readdirSync|createReadStream|stat|statSync|access|accessSync|open|openSync)|readFile|readFileSync|readdir|readdirSync)$"), "file_read"),
    (re.compile(r"^(fs(\.promises)?\.(writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rename|renameSync|mkdir|mkdirSync|createWriteStream|copyFile|copyFileSync)|writeFile|writeFileSync|unlink|unlinkSync|rm|rmSync)$"), "file_write"),
    (re.compile(r"^((child_process\.)?(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)|eval|Function|vm\.(runInNewContext|runInThisContext|runInContext))$"), "shell_exec"),
    (re.compile(r"^(fetch|axios(\.(get|post|put|patch|delete|request))?|got(\.(get|post|put|patch|delete))?|request|https?\.(request|get)|node-fetch|ky(\.\w+)?|superagent(\.\w+)?)$"), "network_egress"),
]
_TS_VALIDATOR_RE = re.compile(r"(?i)(valid|sanit|normal|resolve|check|allow|safe|secure|clean|escape|canonical|isWithin|realpath)")

_CALL_OF_INTEREST_RE = re.compile(
    r"^(?:fs(?:\.promises)?\.(?:readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|appendFile|appendFileSync|rename|renameSync|createWriteStream|createReadStream)"
    r"|(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)"
    r"|fetch|axios(?:\.\w+)?|got(?:\.\w+)?|request|http\.request|https\.request|node-fetch"
    r"|eval|Function|vm\.\w+|process\.env|require|import"
    r"|os\.homedir|os\.userInfo|os\.networkInterfaces|dns\.\w+|net\.\w+)$"
)


# ----------------------------------------------------------------------------
# parser plumbing
# ----------------------------------------------------------------------------

def _language_for(path: str):
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else "js"
    if ext in ("ts", "mts", "cts"):
        key = "typescript"
    elif ext == "tsx":
        key = "tsx"
    else:
        key = "javascript"
    if key not in _LANGS:
        if key == "typescript":
            _LANGS[key] = Language(_tst.language_typescript())
        elif key == "tsx":
            _LANGS[key] = Language(_tst.language_tsx())
        else:
            _LANGS[key] = Language(_tsj.language())
    return _LANGS[key]


def _parse(source: bytes, path: str):
    parser = Parser(_language_for(path))
    return parser.parse(source)


class _Src:
    """Byte-slice helpers bound to one source buffer."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def text(self, n: Node) -> str:
        return self.data[n.start_byte:n.end_byte].decode("utf-8", "replace")

    @staticmethod
    def line(n: Node) -> int:
        return n.start_point[0] + 1


def _named(n: Node) -> List[Node]:
    return [c for c in n.children if c.is_named and c.type != "comment"]


def _field(n: Node, name: str) -> Optional[Node]:
    return n.child_by_field_name(name)


def _unquote(raw: str) -> str:
    """Decode a JS string literal body (handles the common escapes)."""
    try:
        if raw.startswith('"'):
            return json.loads(raw)
        inner = raw[1:-1]
        return bytes(inner, "utf-8").decode("unicode_escape", "replace") if "\\" in inner else inner
    except Exception:
        return raw[1:-1] if len(raw) >= 2 else raw


_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0",
                   "`": "`", "$": "$", "\\": "\\", '"': '"', "'": "'", "{": "{", "}": "}"}


def _template_escape(raw: str) -> str:
    """Decode one escape sequence inside a template literal: backtick, dollar, \\n, \\u1234, \\x41."""
    body = raw[1:] if raw.startswith("\\") else raw
    if body in _SIMPLE_ESCAPES:
        return _SIMPLE_ESCAPES[body]
    try:
        if body.startswith("u{"):
            return chr(int(body[2:-1], 16))
        if body.startswith("u"):
            return chr(int(body[1:5], 16))
        if body.startswith("x"):
            return chr(int(body[1:3], 16))
    except ValueError:
        pass
    return body


def _is_function(n: Node) -> bool:
    return n.type in ("arrow_function", "function_expression", "function", "function_declaration",
                      "method_definition", "generator_function", "generator_function_declaration")


# ----------------------------------------------------------------------------
# string evaluation
# ----------------------------------------------------------------------------

class _Resolver:
    def __init__(self, src: _Src, module_strings: Dict[str, str]) -> None:
        self.src = src
        self.module_strings = module_strings

    def const_str(self, n: Optional[Node], local: Optional[Dict[str, str]] = None) -> Optional[str]:
        """A string the expression evaluates to, or None when it is not (mostly) literal."""
        if n is None:
            return None
        local = local or {}
        t = n.type
        if t == "string":
            return _unquote(self.src.text(n))
        if t == "template_string":
            parts: List[str] = []
            for c in n.children:
                if c.type == "string_fragment":
                    parts.append(self.src.text(c))
                elif c.type == "template_substitution":
                    inner = _named(c)
                    val = self.const_str(inner[0], local) if inner else None
                    if val is None:
                        parts.append("{" + (self.src.text(inner[0]) if inner else "...") + "}")
                    else:
                        parts.append(val)
                elif c.type == "escape_sequence":
                    parts.append(_template_escape(self.src.text(c)))
            return "".join(parts)
        if t == "identifier":
            name = self.src.text(n)
            if name in local:
                return local[name]
            return self.module_strings.get(name)
        if t == "binary_expression":
            op = _field(n, "operator")
            if op is not None and self.src.text(op) == "+":
                left = self.const_str(_field(n, "left"), local)
                right = self.const_str(_field(n, "right"), local)
                if left is None and right is None:
                    return None
                return (left or "") + (right or "")
            return None
        if t == "parenthesized_expression":
            inner = _named(n)
            return self.const_str(inner[0], local) if inner else None
        if t in ("as_expression", "satisfies_expression", "non_null_expression", "await_expression"):
            inner = _named(n)
            return self.const_str(inner[0], local) if inner else None
        if t == "ternary_expression":
            a = self.const_str(_field(n, "consequence"), local)
            b = self.const_str(_field(n, "alternative"), local)
            if a is None and b is None:
                return None
            return (a or "") + ("\n" if a and b else "") + (b or "")
        if t == "call_expression":
            # "a b c".trim(), [..].join("\n"), String.raw`...`
            fn = _field(n, "function")
            if fn is not None and fn.type == "member_expression":
                obj = _field(fn, "object")
                prop = _field(fn, "property")
                if prop is not None and self.src.text(prop) in ("trim", "trimEnd", "trimStart", "toString", "join"):
                    base = self.const_str(obj, local)
                    if base is not None:
                        return base
                    if obj is not None and obj.type == "array":
                        vals = [self.const_str(e, local) for e in _named(obj)]
                        if any(v is not None for v in vals):
                            return "\n".join(v for v in vals if v is not None)
            return None
        return None

    def strings_in(self, n: Optional[Node], local: Optional[Dict[str, str]] = None,
                   out: Optional[List[str]] = None, depth: int = 0) -> List[str]:
        """Every string literal an expression contains or can resolve to (deep)."""
        if out is None:
            out = []
        if n is None or depth > 40:
            return out
        local = local or {}
        t = n.type
        if t in ("string", "template_string", "binary_expression", "ternary_expression"):
            v = self.const_str(n, local)
            if v is not None:
                out.append(v)
            if t == "template_string":
                for c in n.children:
                    if c.type == "template_substitution":
                        for inner in _named(c):
                            if inner.type != "identifier":
                                self.strings_in(inner, local, out, depth + 1)
            elif t == "binary_expression":
                for c in _named(n):
                    if c.type not in ("string", "template_string", "identifier", "binary_expression",
                                      "parenthesized_expression"):
                        self.strings_in(c, local, out, depth + 1)
            elif t == "ternary_expression":
                for c in _named(n)[1:]:
                    if c.type not in ("string", "template_string", "identifier"):
                        self.strings_in(c, local, out, depth + 1)
            return out
        if t == "identifier":
            parent = n.parent
            # KEY.slice(-4) / KEY[0]: the value itself is not on the return path (parity with Python)
            if parent is not None and parent.type in ("member_expression", "subscript_expression"):
                return out
            v = self.const_str(n, local)
            if v is not None:
                out.append(v)
            return out
        if _is_function(n):
            return out  # nested callbacks are not on this return path
        for c in _named(n):
            self.strings_in(c, local, out, depth + 1)
        return out

    # literal objects -------------------------------------------------------
    def literal(self, n: Optional[Node], local: Optional[Dict[str, str]] = None, depth: int = 0) -> Any:
        if n is None or depth > 30:
            return None
        local = local or {}
        t = n.type
        if t in ("string", "template_string"):
            return self.const_str(n, local)
        if t == "number":
            txt = self.src.text(n).replace("_", "")
            try:
                return int(txt, 0) if re.fullmatch(r"-?(0[xXoObB])?[0-9a-fA-F]+", txt) else float(txt)
            except ValueError:
                return txt
        if t == "true":
            return True
        if t == "false":
            return False
        if t in ("null", "undefined"):
            return None
        if t == "array":
            return [self.literal(c, local, depth + 1) for c in _named(n)]
        if t == "object":
            out: Dict[str, Any] = {}
            for p in _named(n):
                if p.type == "pair":
                    key = self.key_name(_field(p, "key"))
                    if key is not None:
                        out[key] = self.literal(_field(p, "value"), local, depth + 1)
                elif p.type == "shorthand_property_identifier":
                    out[self.src.text(p)] = self.const_str(p, local)
            return out
        if t == "identifier":
            v = self.const_str(n, local)
            return v if v is not None else self.src.text(n)
        if t in ("parenthesized_expression", "as_expression", "satisfies_expression", "non_null_expression"):
            inner = _named(n)
            return self.literal(inner[0], local, depth + 1) if inner else None
        if t == "unary_expression" and self.src.text(n).startswith("-"):
            inner = _named(n)
            v = self.literal(inner[0], local, depth + 1) if inner else None
            return -v if isinstance(v, (int, float)) else v
        return self.src.text(n)[:200]

    def key_name(self, k: Optional[Node]) -> Optional[str]:
        if k is None:
            return None
        if k.type in ("property_identifier", "identifier", "shorthand_property_identifier"):
            return self.src.text(k)
        if k.type == "string":
            return _unquote(self.src.text(k))
        if k.type == "computed_property_name":
            inner = _named(k)
            return self.const_str(inner[0]) if inner else None
        return None


def _pairs(obj: Node, res: _Resolver) -> Dict[str, Node]:
    """Key -> value node for an object literal."""
    out: Dict[str, Node] = {}
    if obj is None or obj.type != "object":
        return out
    for p in _named(obj):
        if p.type == "pair":
            key = res.key_name(_field(p, "key"))
            val = _field(p, "value")
            if key is not None and val is not None:
                out[key] = val
        elif p.type == "shorthand_property_identifier":
            out[res.src.text(p)] = p
        elif p.type == "method_definition":
            key = res.key_name(_field(p, "name"))
            if key is not None:
                out[key] = p
    return out


# ----------------------------------------------------------------------------
# schema parsing (zod shapes and JSON-schema literals)
# ----------------------------------------------------------------------------

def _zod_chain(n: Node, res: _Resolver) -> Optional[Dict[str, Any]]:
    """``z.string().describe("x").optional().default("y")`` -> {type, default, optional, description}."""
    info: Dict[str, Any] = {"optional": False}
    node = n
    seen_root = False
    for _ in range(40):
        if node.type in ("as_expression", "satisfies_expression", "non_null_expression", "parenthesized_expression"):
            inner = _named(node)
            if not inner:
                break
            node = inner[0]
            continue
        if node.type != "call_expression":
            break
        fn = _field(node, "function")
        args = _field(node, "arguments")
        arg_nodes = _named(args) if args is not None else []
        if fn is None:
            break
        if fn.type == "member_expression":
            prop = _field(fn, "property")
            obj = _field(fn, "object")
            method = res.src.text(prop) if prop is not None else ""
            if obj is not None and obj.type == "identifier" and res.src.text(obj) == "z":
                info["type"] = _ZOD_TYPES.get(method, None)
                if method == "object" and arg_nodes and arg_nodes[0].type == "object":
                    info["properties"] = _zod_object(arg_nodes[0], res)
                if method == "enum" and arg_nodes:
                    info["enum"] = res.literal(arg_nodes[0])
                if method == "literal" and arg_nodes:
                    info["enum"] = [res.literal(arg_nodes[0])]
                seen_root = True
                break
            if method in ("optional", "nullable", "nullish"):
                info["optional"] = True
            elif method == "default" and arg_nodes:
                info["default"] = res.literal(arg_nodes[0])
                info["optional"] = True
            elif method == "describe" and arg_nodes:
                info["description"] = res.const_str(arg_nodes[0])
            elif method in ("array",):
                info.setdefault("type", "array")
            node = obj if obj is not None else node
            continue
        if fn.type == "identifier":
            break
        break
    return info if seen_root or "default" in info or "description" in info else None


def _zod_object(obj: Node, res: _Resolver) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for key, val in _pairs(obj, res).items():
        info = _zod_chain(val, res)
        out[key] = info if info is not None else {"optional": False}
    return out


def _schema_from_node(n: Optional[Node], res: _Resolver, module_nodes: Dict[str, Node],
                      depth: int = 0) -> Optional[Dict[str, Any]]:
    """Return a JSON-schema-ish dict {type, properties, required} from a schema expression."""
    if n is None or depth > 6:
        return None
    t = n.type
    if t in ("as_expression", "satisfies_expression", "non_null_expression", "parenthesized_expression"):
        inner = _named(n)
        return _schema_from_node(inner[0], res, module_nodes, depth + 1) if inner else None
    if t == "identifier":
        target = module_nodes.get(res.src.text(n))
        return _schema_from_node(target, res, module_nodes, depth + 1) if target is not None else None
    if t == "member_expression":
        # XSchema.shape
        prop = _field(n, "property")
        if prop is not None and res.src.text(prop) == "shape":
            return _schema_from_node(_field(n, "object"), res, module_nodes, depth + 1)
        return None
    if t == "call_expression":
        fn = _field(n, "function")
        args = _field(n, "arguments")
        arg_nodes = _named(args) if args is not None else []
        fn_text = res.src.text(fn) if fn is not None else ""
        if fn_text.startswith("z.") or fn_text == "z":
            chain = _zod_chain(n, res)
            if chain and "properties" in chain:
                return _props_to_schema(chain["properties"])
            return None
        # zodToJsonSchema(X), jsonSchema2020(X.shape), toJsonSchema(X), ...
        if arg_nodes:
            return _schema_from_node(arg_nodes[0], res, module_nodes, depth + 1)
        return None
    if t == "object":
        pairs = _pairs(n, res)
        if "properties" in pairs or ("type" in pairs and res.const_str(pairs["type"]) == "object"):
            lit = res.literal(n)
            if isinstance(lit, dict):
                props = lit.get("properties") if isinstance(lit.get("properties"), dict) else {}
                req = lit.get("required") if isinstance(lit.get("required"), list) else []
                return {"type": "object", "properties": props, "required": [r for r in req if isinstance(r, str)]}
        # a zod shape object: { path: z.string(), ... }
        return _props_to_schema(_zod_object(n, res))
    return None


def _props_to_schema(props: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    schema_props: Dict[str, Any] = {}
    required: List[str] = []
    for name, info in props.items():
        prop: Dict[str, Any] = {}
        if info.get("type"):
            prop["type"] = info["type"]
        if "default" in info and info["default"] is not None:
            prop["default"] = info["default"]
        if info.get("description"):
            prop["description"] = info["description"]
        if info.get("enum") is not None:
            prop["enum"] = info["enum"]
        schema_props[name] = prop
        if not info.get("optional"):
            required.append(name)
    return {"type": "object", "properties": schema_props, "required": required}


# ----------------------------------------------------------------------------
# function bodies
# ----------------------------------------------------------------------------

def _enclosing_function_name(n: Node, src: _Src) -> Optional[str]:
    cur = n.parent
    while cur is not None:
        if cur.type in ("function_declaration", "generator_function_declaration", "method_definition"):
            name = _field(cur, "name")
            return src.text(name) if name is not None else "<anonymous>"
        if cur.type in ("arrow_function", "function_expression", "function"):
            p = cur.parent
            if p is not None and p.type == "variable_declarator":
                name = _field(p, "name")
                return src.text(name) if name is not None else "<anonymous>"
            if p is not None and p.type == "pair":
                key = _field(p, "key")
                return src.text(key) if key is not None else "<anonymous>"
            name = _field(cur, "name")
            return src.text(name) if name is not None else "<anonymous>"
        cur = cur.parent
    return None


def _walk(n: Node, skip_nested_functions: bool = False):
    stack = [n]
    while stack:
        cur = stack.pop()
        yield cur
        for c in reversed(cur.children):
            if skip_nested_functions and _is_function(c) and c is not n:
                continue
            stack.append(c)


def _call_name(n: Node, src: _Src) -> Optional[str]:
    fn = _field(n, "function")
    if fn is None:
        return None
    if fn.type in ("identifier", "member_expression"):
        txt = src.text(fn)
        return txt if len(txt) <= 60 and re.fullmatch(r"[\w$.]+", txt) else None
    return None


def _param_sinks(fn: Optional[Node], res: _Resolver, params: List[str]) -> List[Tuple[str, str, str, int, bool]]:
    """Caller parameters (destructured names, or args.<name> / request.params.arguments.<name>)
    that reach a file/process/network sink, one step of local derivation allowed."""
    if fn is None or not params:
        return []
    src = res.src
    body = _field(fn, "body")
    if body is None:
        return []
    pset = set(params)

    def params_in(n: Node) -> Set[str]:
        found: Set[str] = set()
        for x in _walk(n):
            if x.type == "identifier" and src.text(x) in pset:
                found.add(src.text(x))
            elif x.type == "member_expression":
                txt = src.text(x)
                tail = txt.rsplit(".", 1)[-1]
                if tail in pset and re.match(r"^(args|params|input|arguments|request\.params\.arguments|req\.params\.arguments|a|p)\.", txt):
                    found.add(tail)
        return found

    derived: Dict[str, Tuple[str, bool]] = {}
    for n in _walk(body):
        if n.type == "variable_declarator":
            nm, val = _field(n, "name"), _field(n, "value")
            if nm is None or val is None or nm.type != "identifier":
                continue
            ps = params_in(val)
            validated = False
            if not ps:
                locs = {src.text(x) for x in _walk(val) if x.type == "identifier"} & set(derived)
                if not locs:
                    continue
                p, validated = derived[next(iter(locs))]
            else:
                p = next(iter(ps))
            inner = val
            while inner.type in ("await_expression", "as_expression", "non_null_expression", "parenthesized_expression"):
                kids = _named(inner)
                if not kids:
                    break
                inner = kids[0]
            if inner.type == "call_expression":
                cn = _call_name(inner, src) or ""
                if _TS_VALIDATOR_RE.search(cn):
                    validated = True
            derived[src.text(nm)] = (p, validated)
    flows: List[Tuple[str, str, str, int, bool]] = []
    seen: Set[Tuple[str, str]] = set()
    for n in _walk(body):
        if n.type != "call_expression":
            continue
        cn = _call_name(n, src)
        if not cn:
            continue
        kind = next((k for rx, k in _TS_SINK_KINDS if rx.match(cn) or rx.match(cn.split(".")[-1]) and cn.startswith("fs")), None)
        if kind is None:
            continue
        args = _field(n, "arguments")
        if args is None:
            continue
        if kind in ("file_read", "file_write"):
            first = _named(args)
            scope = first[0] if first else args      # the path argument only
        else:
            scope = args
        direct = params_in(scope)
        for p in direct:
            if (p, kind) not in seen:
                seen.add((p, kind))
                flows.append((p, cn, kind, src.line(n), False))
        locals_used = {src.text(x) for x in _walk(scope) if x.type == "identifier"} & set(derived)
        for l in locals_used:
            p, validated = derived[l]
            if (p, kind) not in seen:
                seen.add((p, kind))
                flows.append((p, cn, kind, src.line(n), validated))
    return flows


def _body_info(fn: Optional[Node], res: _Resolver) -> Tuple[List[str], Set[str], Set[str], bool, Dict[str, str]]:
    """(return strings, referenced names, call names, count_gated, local strings) for a function node."""
    if fn is None:
        return [], set(), set(), False, {}
    src = res.src
    body = _field(fn, "body")
    local: Dict[str, str] = {}
    names: Set[str] = set()
    calls: Set[str] = set()
    returns: List[str] = []
    count_gated = False
    if body is None:
        return returns, names, calls, count_gated, local
    # local string constants first (in source order)
    for node in _walk(body):
        if node.type == "variable_declarator":
            nm = _field(node, "name")
            val = _field(node, "value")
            if nm is not None and nm.type == "identifier" and val is not None:
                s = res.const_str(val, local)
                if s is not None:
                    local[src.text(nm)] = s
    for node in _walk(body):
        t = node.type
        if t in ("identifier", "property_identifier", "shorthand_property_identifier"):
            names.add(src.text(node))
        elif t == "member_expression":
            txt = src.text(node)
            if txt.startswith("process.env"):
                calls.add("process.env")
                names.add("process.env")
        elif t == "call_expression":
            cn = _call_name(node, src)
            if cn:
                if _CALL_OF_INTEREST_RE.match(cn) or _CALL_OF_INTEREST_RE.match(cn.split(".")[-1]):
                    calls.add(cn)
        elif t == "binary_expression" and not count_gated:
            op = _field(node, "operator")
            if op is not None and src.text(op) in (">", ">=", "<", "<=", "==", "===", "!=", "!=="):
                l, r = _field(node, "left"), _field(node, "right")
                sides = [x for x in (l, r) if x is not None]
                if any(x.type == "number" for x in sides) and any(
                        x.type in ("identifier", "member_expression") and _COUNTER_NAME_RE.search(src.text(x)) for x in sides):
                    count_gated = True
        elif t == "update_expression" and not count_gated:
            # callCount++ paired with a later comparison is caught above; nothing here
            pass
    # return paths
    if body.type != "statement_block":
        # arrow with expression body
        res.strings_in(body, local, returns)
    else:
        for node in _walk(body, skip_nested_functions=True):
            if node.type == "return_statement":
                for c in _named(node):
                    res.strings_in(c, local, returns)
    returns = [r for r in returns if r]
    return returns, names, calls, count_gated, local


def _callback_params(fn: Optional[Node], res: _Resolver) -> Tuple[Dict[str, Any], List[str]]:
    """Parameter names from a destructured first parameter: ``async ({ title, body = "" }) =>``."""
    params: Dict[str, Any] = {}
    required: List[str] = []
    if fn is None:
        return params, required
    fp = _field(fn, "parameters")
    if fp is None:
        fp = _field(fn, "parameter")
    if fp is None:
        return params, required
    first = None
    for c in _named(fp):
        first = c
        break
    if first is None:
        return params, required
    pattern = first
    if first.type in ("required_parameter", "optional_parameter"):
        pattern = _field(first, "pattern") or first
    if pattern.type != "object_pattern":
        return params, required
    for p in _named(pattern):
        if p.type == "shorthand_property_identifier_pattern":
            params[res.src.text(p)] = None
            required.append(res.src.text(p))
        elif p.type == "object_assignment_pattern":
            l = _field(p, "left")
            r = _field(p, "right")
            if l is not None:
                params[res.src.text(l)] = res.literal(r)
        elif p.type == "pair_pattern":
            k = res.key_name(_field(p, "key"))
            if k:
                params[k] = None
                required.append(k)
    return params, required


# ----------------------------------------------------------------------------
# main entry point
# ----------------------------------------------------------------------------

def extract_ts_definitions(source: str, path: str = "<src>") -> Optional[PyExtraction]:
    """Extract tools, resources, prompts, bodies and runtime registrations from TS/JS source.

    Returns ``None`` only when tree-sitter is unavailable; a file with syntax errors still
    yields whatever could be recovered.
    """
    if not HAS_TREE_SITTER:
        return None
    data = source.encode("utf-8", "surrogatepass")
    try:
        tree = _parse(data, path)
    except Exception:
        return None
    src = _Src(data)
    root = tree.root_node
    ex = PyExtraction()
    res = _Resolver(src, ex.module_strings)
    module_nodes: Dict[str, Node] = {}      # name -> value node of module-level declarations
    tool_handles: Dict[str, str] = {}       # variable -> tool name for registerTool() results

    # 1. module-level declarations --------------------------------------------------------
    def top_level_statements(n: Node):
        for s in _named(n):
            if s.type == "export_statement":
                for inner in _named(s):
                    yield inner
            else:
                yield s

    for stmt in top_level_statements(root):
        if stmt.type in ("lexical_declaration", "variable_declaration"):
            for decl in _named(stmt):
                if decl.type != "variable_declarator":
                    continue
                nm = _field(decl, "name")
                val = _field(decl, "value")
                if nm is None or val is None or nm.type != "identifier":
                    continue
                name = src.text(nm)
                module_nodes[name] = val
                s = res.const_str(val)
                if s is not None:
                    ex.module_strings[name] = s
                elif src.text(val).startswith("process.env"):
                    ex.module_strings[name] = ""      # a server-held secret; value unknown
                elif val.type in ("object", "array"):
                    for sub in _walk(val):
                        if sub.type in ("string", "template_string"):
                            v = res.const_str(sub)
                            if v and len(v) >= 20:
                                ex.module_literals.append((name, v, src.line(sub)))

    # 2. server constructor: name + instructions -----------------------------------------
    for node in _walk(root):
        if node.type == "new_expression":
            ctor = _field(node, "constructor")
            if ctor is None or src.text(ctor).split(".")[-1] not in _SERVER_CTORS:
                continue
            args = _field(node, "arguments")
            for a in (_named(args) if args is not None else []):
                target = a
                if a.type == "identifier" and src.text(a) in module_nodes:
                    target = module_nodes[src.text(a)]
                if target.type != "object":
                    continue
                pairs = _pairs(target, res)
                if "name" in pairs and not ex.server_name:
                    nm = res.const_str(pairs["name"])
                    if nm:
                        ex.server_name = nm
                if "instructions" in pairs and not ex.server_instructions:
                    text = res.const_str(pairs["instructions"])
                    if text:
                        ex.server_instructions = text
                        ex.server_instructions_line = src.line(pairs["instructions"])
        elif node.type == "pair" and not ex.server_instructions:
            key = res.key_name(_field(node, "key"))
            if key == "instructions":
                text = res.const_str(_field(node, "value"))
                if text:
                    ex.server_instructions = text
                    ex.server_instructions_line = src.line(node)

    # 3. registration calls --------------------------------------------------------------
    seen_tool_names: Set[str] = set()
    callback_ranges: List[Tuple[int, int, str]] = []   # (start, end, owner tool name)
    bodies_by_name: Dict[str, ToolBody] = {}

    def inside_callback(n: Node) -> Optional[str]:
        for start, end, owner in callback_ranges:
            if start < n.start_byte and n.end_byte <= end:
                return owner
        return None

    def add_body(body: ToolBody, schema: Optional[Dict[str, Any]], uri: Optional[str] = None) -> None:
        ex.bodies.append(body)
        bodies_by_name.setdefault((body.kind, body.name), body)  # type: ignore[arg-type]
        if body.kind == "tool":
            if body.name not in seen_tool_names:
                seen_tool_names.add(body.name)
                ex.tools.append(MCPToolDefinition(
                    name=body.name, description=body.description,
                    input_schema=schema or _input_schema(body.params, body.required, {}),
                ))
        elif body.kind == "resource":
            ex.resources.append(MCPResourceDefinition(
                uri=body.uri or body.name, name=body.name, description=body.description,
            ))
        elif body.kind == "prompt":
            ex.prompts.append(MCPPromptDefinition(
                name=body.name, description=body.description,
                arguments=[{"name": p, "required": p in body.required} for p in body.params],
            ))

    def make_body(kind: str, name: str, description: str, fn: Optional[Node], line: int,
                  uri: Optional[str], schema: Optional[Dict[str, Any]], runtime_owner: Optional[str]) -> ToolBody:
        returns, names, calls, gated, _local = _body_info(fn, res)
        params: Dict[str, Any] = {}
        required: List[str] = []
        if schema and isinstance(schema.get("properties"), dict):
            for p, info in schema["properties"].items():
                params[p] = info.get("default") if isinstance(info, dict) else None
            required = list(schema.get("required") or [])
        else:
            params, required = _callback_params(fn, res)
        body = ToolBody(
            name=name, func_name=name, kind=kind, lineno=line, description=(description or "").strip(),
            uri=uri, params=params, required=required, return_strings=returns, referenced_names=names,
            registered_at_runtime=runtime_owner is not None, registered_in=runtime_owner,
            count_gated=gated,
        )
        body.calls = calls  # type: ignore[attr-defined]
        body.param_sinks = _param_sinks(fn, res, list(params))
        return body

    # Collect calls in source order
    calls_in_order: List[Node] = [n for n in _walk(root) if n.type == "call_expression"]
    calls_in_order.sort(key=lambda n: n.start_byte)

    for call in calls_in_order:
        fn = _field(call, "function")
        args_node = _field(call, "arguments")
        if fn is None or args_node is None:
            continue
        if fn.type == "member_expression":
            prop = _field(fn, "property")
            obj = _field(fn, "object")
            method = src.text(prop) if prop is not None else ""
            obj_text = src.text(obj) if obj is not None else ""
        elif fn.type == "identifier":
            method, obj_text = src.text(fn), ""
            if method not in ("registerTool", "defineTool"):
                continue
        else:
            continue
        args = _named(args_node)
        line = src.line(call)
        owner = inside_callback(call)
        enclosing = _enclosing_function_name(call, src)

        # ---- tools ----
        if method in _TOOL_METHODS and args and (obj_text or method == "registerTool"):
            name = res.const_str(args[0])
            if not name:
                continue
            description = ""
            schema: Optional[Dict[str, Any]] = None
            cb: Optional[Node] = None
            for a in args[1:]:
                if _is_function(a):
                    cb = a
                elif a.type == "object":
                    pairs = _pairs(a, res)
                    if "description" in pairs or "title" in pairs or any(k in pairs for k in _SCHEMA_KEYS) or "annotations" in pairs:
                        if "description" in pairs:
                            description = res.const_str(pairs["description"]) or description
                        for k in _SCHEMA_KEYS:
                            if k in pairs:
                                schema = _schema_from_node(pairs[k], res, module_nodes) or schema
                                break
                        if "annotations" in pairs or "title" in pairs or "description" in pairs:
                            continue
                    if schema is None and "description" not in pairs:
                        schema = _schema_from_node(a, res, module_nodes)
                elif a.type in ("string", "template_string", "binary_expression", "identifier") and not description:
                    s = res.const_str(a)
                    if s is not None and not (a.type == "identifier" and s == ""):
                        description = s
                elif a.type in ("identifier", "call_expression", "member_expression") and schema is None:
                    schema = _schema_from_node(a, res, module_nodes)
            body = make_body("tool", name, description, cb, line, None, schema, owner)
            add_body(body, schema)
            if cb is not None:
                callback_ranges.append((cb.start_byte, cb.end_byte, name))
            # const handle = server.registerTool(...)
            parent = call.parent
            while parent is not None and parent.type in ("await_expression", "as_expression", "non_null_expression"):
                parent = parent.parent
            if parent is not None and parent.type == "variable_declarator":
                nm = _field(parent, "name")
                if nm is not None and nm.type == "identifier":
                    tool_handles[src.text(nm)] = name
            if owner is not None:
                ex.registrations.append(DynamicRegistration(
                    kind="add_tool", name=name, lineno=line, inside_function=owner, description=description))
            continue

        # ---- resources ----
        if method in _RESOURCE_METHODS and args and obj_text:
            name = res.const_str(args[0]) or ""
            uri: Optional[str] = None
            description = ""
            cb = None
            for a in args[1:]:
                if _is_function(a):
                    cb = a
                elif a.type == "new_expression":
                    na = _field(a, "arguments")
                    inner = _named(na) if na is not None else []
                    if inner:
                        uri = res.const_str(inner[0]) or uri
                elif a.type in ("string", "template_string", "identifier", "binary_expression") and uri is None:
                    uri = res.const_str(a)
                elif a.type == "object":
                    pairs = _pairs(a, res)
                    if "description" in pairs:
                        description = res.const_str(pairs["description"]) or ""
                    if "uri" in pairs and uri is None:
                        uri = res.const_str(pairs["uri"])
            if not name and not uri:
                continue
            body = make_body("resource", name or (uri or ""), description, cb, line, uri, None, owner)
            add_body(body, None, uri)
            if cb is not None:
                callback_ranges.append((cb.start_byte, cb.end_byte, name or uri or "resource"))
            continue

        # ---- prompts ----
        if method in _PROMPT_METHODS and args and obj_text:
            name = res.const_str(args[0])
            if not name:
                continue
            description = ""
            schema = None
            cb = None
            for a in args[1:]:
                if _is_function(a):
                    cb = a
                elif a.type == "object":
                    pairs = _pairs(a, res)
                    if "description" in pairs or "argsSchema" in pairs or "title" in pairs:
                        if "description" in pairs:
                            description = res.const_str(pairs["description"]) or ""
                        if "argsSchema" in pairs:
                            schema = _schema_from_node(pairs["argsSchema"], res, module_nodes)
                    else:
                        schema = _schema_from_node(a, res, module_nodes)
                elif a.type in ("string", "template_string", "binary_expression", "identifier") and not description:
                    description = res.const_str(a) or ""
            body = make_body("prompt", name, description, cb, line, None, schema, owner)
            add_body(body, None)
            if cb is not None:
                callback_ranges.append((cb.start_byte, cb.end_byte, name))
            continue

        # ---- removal / mutation ----
        if method in _REMOVE_METHODS and obj_text:
            name = res.const_str(args[0]) if args else None
            ex.registrations.append(DynamicRegistration(
                kind="remove_tool", name=name or (src.text(args[0]) if args else None), lineno=line,
                inside_function=owner or enclosing))
            continue
        if method in _HANDLE_MUTATIONS and obj_text in tool_handles:
            kind = "remove_tool" if method in ("remove", "disable") else "add_tool"
            ex.registrations.append(DynamicRegistration(
                kind=kind, name=tool_handles[obj_text], lineno=line,
                inside_function=owner or enclosing or "<module>",
                description=f"handle.{method}()"))
            continue
        if method == "sendToolListChanged" and obj_text:
            ex.registrations.append(DynamicRegistration(
                kind="add_tool", name="tools/list_changed", lineno=line,
                inside_function=owner or enclosing, description="sendToolListChanged()"))
            continue

        # ---- low-level request handlers ----
        if method in _HANDLER_METHODS and len(args) >= 2:
            which = src.text(args[0]).strip("\"'`")
            cb = args[-1] if _is_function(args[-1]) else None
            if cb is None:
                continue
            if "ListTools" in which or which.endswith("tools/list"):
                for obj in _tool_objects_in(cb, res, module_nodes):
                    _add_static_tool(obj, res, module_nodes, add_body, make_body, seen_tool_names, src)
                callback_ranges.append((cb.start_byte, cb.end_byte, "tools/list"))
            elif "ListResources" in which or which.endswith("resources/list"):
                for obj in _objects_in(cb, res, module_nodes, must_have=("uri",)):
                    pairs = _pairs(obj, res)
                    uri = res.const_str(pairs.get("uri"))
                    if not uri:
                        continue
                    body = make_body("resource", res.const_str(pairs.get("name")) or uri,
                                     res.const_str(pairs.get("description")) or "", None, src.line(obj), uri, None, None)
                    add_body(body, None, uri)
            elif "ListPrompts" in which or which.endswith("prompts/list"):
                for obj in _objects_in(cb, res, module_nodes, must_have=("name",)):
                    pairs = _pairs(obj, res)
                    name = res.const_str(pairs.get("name"))
                    if not name:
                        continue
                    body = make_body("prompt", name, res.const_str(pairs.get("description")) or "", None,
                                     src.line(obj), None, None, None)
                    add_body(body, None)
            elif "CallTool" in which or which.endswith("tools/call"):
                callback_ranges.append((cb.start_byte, cb.end_byte, "tools/call"))
                _attribute_call_handler(cb, res, bodies_by_name, ex, src, module_nodes)
            elif "ReadResource" in which or which.endswith("resources/read"):
                returns, _n, _c, _g, _l = _body_info(cb, res)
                _attach_handler_strings("resource", returns, bodies_by_name, ex, src.line(cb))
            elif "GetPrompt" in which or which.endswith("prompts/get"):
                returns, _n, _c, _g, _l = _body_info(cb, res)
                _attach_handler_strings("prompt", returns, bodies_by_name, ex, src.line(cb))
            continue

    # 4. module-level tool objects not reached through a handler --------------------------
    for name, val in module_nodes.items():
        if val.type in ("array", "object"):
            for obj in _tool_objects_in(val, res, module_nodes, include_self=True):
                _add_static_tool(obj, res, module_nodes, add_body, make_body, seen_tool_names, src)

    return ex


# ----------------------------------------------------------------------------
# low-level style helpers
# ----------------------------------------------------------------------------

def _objects_in(node: Node, res: _Resolver, module_nodes: Dict[str, Node], must_have: Tuple[str, ...],
                include_self: bool = False, depth: int = 0) -> List[Node]:
    """Object literals (possibly behind identifiers) under ``node`` that carry the given keys."""
    out: List[Node] = []
    seen: Set[int] = set()
    for n in _walk(node):
        if n.type == "object":
            pairs = _pairs(n, res)
            if all(k in pairs for k in must_have):
                if n.id not in seen:
                    seen.add(n.id)
                    out.append(n)
        elif n.type == "identifier" and depth < 2:
            target = module_nodes.get(res.src.text(n))
            if target is not None and target.type in ("array", "object") and target is not node:
                for o in _objects_in(target, res, module_nodes, must_have, depth=depth + 1):
                    if o.id not in seen:
                        seen.add(o.id)
                        out.append(o)
        elif n.type == "spread_element":
            pass
    return out


def _tool_objects_in(node: Node, res: _Resolver, module_nodes: Dict[str, Node], include_self: bool = False) -> List[Node]:
    objs = _objects_in(node, res, module_nodes, must_have=("name", "description"), include_self=include_self)
    out = []
    for o in objs:
        pairs = _pairs(o, res)
        if any(k in pairs for k in _SCHEMA_KEYS) or _parent_is_tool_list(o, res):
            out.append(o)
    return out


def _parent_is_tool_list(obj: Node, res: _Resolver) -> bool:
    p = obj.parent
    while p is not None and p.type in ("array", "as_expression", "satisfies_expression"):
        gp = p.parent
        if gp is not None and gp.type == "variable_declarator":
            nm = _field(gp, "name")
            return bool(nm is not None and re.search(r"(?i)tool", res.src.text(nm)))
        if gp is not None and gp.type == "pair":
            key = res.key_name(_field(gp, "key"))
            return key == "tools"
        p = gp
    return False


def _add_static_tool(obj: Node, res: _Resolver, module_nodes: Dict[str, Node], add_body, make_body,
                     seen: Set[str], src: _Src) -> None:
    pairs = _pairs(obj, res)
    name = res.const_str(pairs.get("name"))
    if not name or name in seen:
        return
    description = res.const_str(pairs.get("description")) or ""
    schema = None
    for k in _SCHEMA_KEYS:
        if k in pairs:
            schema = _schema_from_node(pairs[k], res, module_nodes)
            break
    body = make_body("tool", name, description, None, src.line(obj), None, schema, None)
    add_body(body, schema)


def _attribute_call_handler(cb: Node, res: _Resolver, bodies_by_name: Dict, ex: PyExtraction, src: _Src,
                            module_nodes: Dict[str, Node]) -> None:
    """Attach return strings of a tools/call handler to the tools it names (switch/if), else to a synthetic body."""
    attributed = False
    body_node = _field(cb, "body")
    if body_node is None:
        return
    for n in _walk(body_node):
        if n.type == "switch_case":
            val = _field(n, "value")
            name = res.const_str(val) if val is not None else None
            if not name:
                continue
            strings: List[str] = []
            for c in _named(n):
                if c is not val:
                    res.strings_in(c, None, strings)
            _merge_strings(("tool", name), strings, bodies_by_name, ex, src.line(n), cb, res)
            attributed = True
        elif n.type == "if_statement":
            cond = _field(n, "condition")
            m = _NAME_CHECK_RE.search(src.text(cond)) if cond is not None else None
            if m:
                strings = []
                cons = _field(n, "consequence")
                if cons is not None:
                    res.strings_in(cons, None, strings)
                _merge_strings(("tool", m.group(1)), strings, bodies_by_name, ex, src.line(n), cb, res)
                attributed = True
    if not attributed:
        returns, names, calls, gated, _l = _body_info(cb, res)
        if returns:
            body = ToolBody(name="tools/call", func_name="tools/call", kind="tool", lineno=src.line(cb),
                            description="", return_strings=returns, referenced_names=names, count_gated=gated)
            body.calls = calls  # type: ignore[attr-defined]
            ex.bodies.append(body)   # bodies only: not a tool the agent sees


def _merge_strings(key: Tuple[str, str], strings: List[str], bodies_by_name: Dict, ex: PyExtraction,
                   line: int, cb: Node, res: _Resolver) -> None:
    strings = [s for s in strings if s]
    body = bodies_by_name.get(key)
    if body is None:
        body = ToolBody(name=key[1], func_name=key[1], kind=key[0], lineno=line, description="")
        bodies_by_name[key] = body
        ex.bodies.append(body)
        if key[0] == "tool" and all(t.name != key[1] for t in ex.tools):
            ex.tools.append(MCPToolDefinition(name=key[1], description=""))
    body.return_strings.extend(s for s in strings if s not in body.return_strings)
    # names + calls from the handler branch feed capability tags
    returns, names, calls, gated, _l = _body_info(cb, res)
    body.referenced_names |= names
    body.calls = getattr(body, "calls", set()) | calls  # type: ignore[attr-defined]
    body.count_gated = body.count_gated or gated


def _attach_handler_strings(kind: str, strings: List[str], bodies_by_name: Dict, ex: PyExtraction, line: int) -> None:
    strings = [s for s in strings if s]
    if not strings:
        return
    targets = [b for b in ex.bodies if b.kind == kind]
    if len(targets) == 1:
        targets[0].return_strings.extend(s for s in strings if s not in targets[0].return_strings)
    else:
        body = ToolBody(name=f"{kind}s/read" if kind == "resource" else "prompts/get",
                        func_name="handler", kind=kind, lineno=line, description="",
                        uri=None, return_strings=strings)
        ex.bodies.append(body)
