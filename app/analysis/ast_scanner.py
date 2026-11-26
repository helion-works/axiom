"""
AST-based Python code scanner for Axiom.

Uses Python's ast module to detect dangerous patterns with much higher
accuracy than regex — correctly handles comments, strings, multi-line
expressions, and obfuscation that regex misses.

For JavaScript/TypeScript, regex remains the primary approach since
Python's ast module can't parse those languages.
"""

import ast
from typing import List, Tuple
from app.models.schemas import Finding, FindingSeverity, FindingCategory


class PythonASTScanner(ast.NodeVisitor):
    """Walk a Python AST and collect security findings."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self._counter = 0

    def _add(self, node: ast.AST, severity: FindingSeverity,
             category: FindingCategory, title: str, desc: str,
             recommendation: str = ""):
        self._counter += 1
        self.findings.append(Finding(
            id=f"ast_{self._counter:04d}",
            severity=severity,
            category=category,
            title=title,
            description=f"{desc} in {self.file_path} at line {node.lineno}",
            file_path=self.file_path,
            line_number=node.lineno,
            recommendation=recommendation,
        ))

    # ---- Dangerous function calls ----

    def visit_Call(self, node: ast.Call):
        func_name = self._resolve_call_name(node)
        if not func_name:
            self.generic_visit(node)
            return

        # eval() / exec() — a sink, not an attack; tool-level detectors escalate it
        if func_name in ("eval", "exec"):
            self._add(
                node, FindingSeverity.LOW, FindingCategory.CODE_EXECUTION,
                f"Arbitrary code execution via {func_name}()",
                f"Call to `{func_name}()` can execute arbitrary code",
                "Avoid eval/exec. Use ast.literal_eval for safe parsing.",
            )

        # os.system / os.popen
        elif func_name in ("os.system", "os.popen"):
            self._add(
                node, FindingSeverity.LOW, FindingCategory.CODE_EXECUTION,
                f"Shell command execution via {func_name}()",
                f"Call to `{func_name}()` executes shell commands",
                "Use subprocess with shell=False and a list of arguments.",
            )

        # subprocess with shell=True
        elif func_name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add(
                        node, FindingSeverity.MEDIUM, FindingCategory.COMMAND_INJECTION,
                        "subprocess called with shell=True",
                        f"Call to `{func_name}()` with `shell=True` enables command injection",
                        "Use shell=False with a list of arguments.",
                    )
                    break

            # subprocess with f-string or format() as first arg
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.JoinedStr):
                    self._add(
                        node, FindingSeverity.HIGH, FindingCategory.COMMAND_INJECTION,
                        f"Command injection — f-string in {func_name}()",
                        f"Call to `{func_name}()` uses an f-string for the command",
                        "Never interpolate user input into shell commands.",
                    )

        # os.symlink
        elif func_name == "os.symlink":
            self._add(
                node, FindingSeverity.LOW, FindingCategory.SANDBOX_ESCAPE,
                "Symlink creation via os.symlink()",
                "Call to `os.symlink()` can escape sandboxed directories",
                "Validate all paths and prevent symlink outside allowed directories.",
            )

        # requests/httpx/urllib outbound calls
        elif func_name in ("requests.get", "requests.post", "requests.put",
                           "httpx.get", "httpx.post", "httpx.put",
                           "urllib.request.urlopen"):
            self._add(
                node, FindingSeverity.INFO, FindingCategory.DATA_EXFILTRATION,
                f"Outbound HTTP request via {func_name}()",
                f"Call to `{func_name}()` makes outbound network request",
                "Verify this is expected. Outbound requests can exfiltrate data.",
            )

        # base64 decoding (obfuscation)
        elif func_name in ("base64.b64decode", "base64.decodebytes", "codecs.decode"):
            self._add(
                node, FindingSeverity.LOW, FindingCategory.OBFUSCATION,
                f"Encoded/obfuscated content via {func_name}()",
                f"Call to `{func_name}()` decodes obfuscated content",
                "Review what is being decoded — obfuscation hides malicious payloads.",
            )

        # os.environ.get / os.getenv — credential access via function call
        elif func_name in ("os.environ.get", "os.getenv"):
            self._add(
                node, FindingSeverity.INFO, FindingCategory.CREDENTIAL_THEFT,
                f"Environment variable access via {func_name}()",
                f"Call to `{func_name}()` reads an environment variable (capability note)",
                "Document which env vars are needed. Avoid reading arbitrary env vars.",
            )

        # shutil destructive ops
        elif func_name in ("shutil.rmtree", "shutil.copytree", "shutil.move"):
            self._add(
                node, FindingSeverity.INFO, FindingCategory.PERMISSION_OVERSCOPE,
                f"Broad filesystem operation: {func_name}()",
                f"Call to `{func_name}()` performs bulk filesystem operations",
                "Ensure paths are validated and constrained.",
            )

        # os.walk — broad enumeration
        elif func_name == "os.walk":
            self._add(
                node, FindingSeverity.INFO, FindingCategory.PERMISSION_OVERSCOPE,
                "Filesystem enumeration via os.walk()",
                "Call to `os.walk()` recursively enumerates directories",
                "Ensure the walk is constrained to expected directories.",
            )

        self.generic_visit(node)

    # ---- Environment variable access ----

    def visit_Subscript(self, node: ast.Subscript):
        # os.environ["KEY"] or os.environ[var]
        if (isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "os"
                and node.value.attr == "environ"):
            self._add(
                node, FindingSeverity.INFO, FindingCategory.CREDENTIAL_THEFT,
                "Environment variable access via os.environ[]",
                "Direct access to `os.environ[]` reads an environment variable (capability note)",
                "Document which env vars are needed. Avoid reading arbitrary env vars.",
            )
        self.generic_visit(node)

    # ---- Path traversal in os.path.join ----

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            val = node.value
            # Path traversal literals
            if "../../" in val or "..\\..\\" in val:
                self._add(
                    node, FindingSeverity.LOW, FindingCategory.SANDBOX_ESCAPE,
                    "Path traversal literal detected",
                    f"String literal `{val[:60]}` contains path traversal",
                    "Never use relative path traversal. Validate and canonicalize paths.",
                )
            # Sensitive file paths
            for sensitive in ("/etc/passwd", "/etc/shadow", ".ssh/", ".aws/credentials",
                              ".npmrc", ".pypirc", ".netrc"):
                if sensitive in val:
                    self._add(
                        node, FindingSeverity.LOW, FindingCategory.CREDENTIAL_THEFT,
                        f"Reference to sensitive file: {sensitive}",
                        f"String literal references `{sensitive}`",
                        "Verify this access is intentional and authorized.",
                    )
                    break
        self.generic_visit(node)

    # ---- Helpers ----

    @staticmethod
    def _resolve_call_name(node: ast.Call) -> str:
        """Resolve a Call node to a dotted name like 'os.system'."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            obj = node.func
            while isinstance(obj, ast.Attribute):
                parts.append(obj.attr)
                obj = obj.value
            if isinstance(obj, ast.Name):
                parts.append(obj.id)
            return ".".join(reversed(parts))
        return ""


def scan_python_ast(source: str, file_path: str) -> List[Finding]:
    """Parse Python source and return AST-based security findings.

    Falls back to empty list on parse errors (e.g. Python 2 syntax).
    """
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []

    scanner = PythonASTScanner(file_path)
    scanner.visit(tree)
    return scanner.findings
