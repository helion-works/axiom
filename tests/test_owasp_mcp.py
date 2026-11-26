"""
Tests for OWASP MCP Top 10 mapping (Workstream A, v0.5).
"""

import json
import shutil
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from app.analysis import owasp_mapping
from app.analysis.owasp_mapping import (
    CATEGORY_TO_ASI,
    CATEGORY_TO_MCP,
    OWASP_MCP_TOP_10_DATA,
    OWASP_MCP_REQUIRED_KEYS,
    apply_owasp_mappings,
    generate_owasp_coverage,
    generate_owasp_mcp_coverage,
    get_coverage_matrix,
    load_owasp_mcp_data,
)
from app.analysis.mcp_top10_detectors import (
    detect_hardcoded_secrets,
    detect_unpinned_installs,
    detect_tool_input_sinks,
    detect_bind_all_interfaces,
    detect_missing_tool_logging,
    detect_broad_data_exposure,
)
from app.analysis.engine import MCPAnalysisEngine
from app.analysis.live_scanner import LiveScanResult
from app.analysis.local_config import LocalConfigScanner
from app.models.schemas import (
    Finding, FindingCategory, FindingSeverity, MCPConfigEntry,
    MCPResourceDefinition, MCPToolDefinition, OwaspMcp,
    ScanResponse, LocalConfigScanResponse, RiskLevel,
)

ALL_IDS = [f"MCP{i:02d}" for i in range(1, 11)]

# Fake but well-formed secrets, assembled so the literal never appears whole in this file.
FAKE_GHP = "ghp_" + "Zq8Lm2Np4Rt6Vx8Bz0Cd2Fg4Hj6Kl8Mn0Pq2S"
FAKE_GENERIC = "a8F3kL9q" + "P2xZ7mN4vB6cR1tY"


def _write(base, rel, text):
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ============================================================
# Enum, schema and data file
# ============================================================

class TestSchemaAndData:
    def test_enum_members(self):
        assert [m.name for m in OwaspMcp] == ALL_IDS
        assert [m.value for m in OwaspMcp] == ALL_IDS
        assert OwaspMcp.MCP09 == "MCP09"

    def test_finding_field_is_additive(self):
        f = Finding(id="x", severity=FindingSeverity.LOW,
                    category=FindingCategory.METADATA, title="t", description="d")
        assert f.owasp_mcp is None
        assert "owasp_mcp" in f.model_dump()

    def test_schema_version(self):
        r = ScanResponse(id="1", target="t", status="completed",
                         risk_score=0, risk_level=RiskLevel.SAFE)
        assert r.schema_version == "0.5"
        assert r.owasp_mcp_coverage is None
        assert LocalConfigScanResponse().schema_version == "0.5"

    def test_data_file_loads_with_ten_items(self):
        data = load_owasp_mcp_data()
        assert len(data["items"]) == 10
        assert [i["short_id"] for i in data["items"]] == ALL_IDS
        for item in data["items"]:
            for key in OWASP_MCP_REQUIRED_KEYS:
                assert key in item, (item["id"], key)
            assert item["id"] == f"{item['short_id']}:2025"
            assert item["coverage"] in ("strong", "partial", "gap")
            if item["coverage"] in ("partial", "gap"):
                assert item["reason"].strip()
            assert isinstance(item["detector_ids"], list) and item["detector_ids"]

    def test_titles_match_spec(self):
        titles = {i["short_id"]: i["title"] for i in OWASP_MCP_TOP_10_DATA["items"]}
        assert titles["MCP03"] == "Tool Poisoning"
        assert titles["MCP09"] == "Shadow MCP Servers"
        assert titles["MCP10"] == "Context Injection & Over-Sharing"

    def test_invalid_data_rejected(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"items": [{"id": "MCP01:2025", "coverage": "gap"}]}))
        with pytest.raises(ValueError):
            load_owasp_mcp_data(str(bad))

    def test_category_mapping_covers_all_but_metadata(self):
        unmapped = {c for c in FindingCategory if c not in CATEGORY_TO_MCP}
        assert unmapped == {FindingCategory.METADATA}
        assert CATEGORY_TO_MCP[FindingCategory.TOOL_POISONING] == ["MCP03"]
        assert CATEGORY_TO_MCP[FindingCategory.COMMAND_INJECTION] == ["MCP05"]
        assert CATEGORY_TO_MCP[FindingCategory.SUPPLY_CHAIN] == ["MCP04"]


# ============================================================
# Coverage matrix
# ============================================================

class TestCoverageMatrix:
    def test_default_is_asi_unchanged(self):
        assert get_coverage_matrix() is owasp_mapping.OWASP_AGENTIC_TOP_10
        assert get_coverage_matrix("asi") is owasp_mapping.OWASP_AGENTIC_TOP_10

    def test_mcp_matrix(self):
        m = get_coverage_matrix("mcp")
        assert list(m) == ALL_IDS
        assert m["MCP03"]["mcpguard_coverage"] == "strong"
        assert m["MCP08"]["mcpguard_coverage"] == "gap"
        assert m["MCP05"]["mcpguard_coverage"] == "partial"
        for v in m.values():
            if v["mcpguard_coverage"] != "strong":
                assert v["reason"]

    def test_all_matrix(self):
        m = get_coverage_matrix("all")
        assert set(m) == {"asi", "mcp"}
        assert "ASI01" in m["asi"] and "MCP01" in m["mcp"]

    def test_bad_framework(self):
        with pytest.raises(ValueError):
            get_coverage_matrix("nope")

    def test_title_change_changes_matrix(self, monkeypatch):
        item = OWASP_MCP_TOP_10_DATA["items"][0]
        monkeypatch.setitem(item, "title", "Renamed Item For Test")
        assert get_coverage_matrix("mcp")["MCP01"]["name"] == "Renamed Item For Test"
        cov = generate_owasp_mcp_coverage([])
        assert cov["coverage"]["MCP01"]["name"] == "Renamed Item For Test"

    def test_mcp_coverage_counts(self):
        findings = [
            Finding(id="a", severity=FindingSeverity.HIGH, category=FindingCategory.TOOL_POISONING,
                    title="t", description="d"),
            Finding(id="b", severity=FindingSeverity.HIGH, category=FindingCategory.METADATA,
                    title="t", description="d", owasp_mcp=["MCP09"]),
        ]
        cov = generate_owasp_mcp_coverage(findings)
        assert cov["coverage"]["MCP03"]["finding_ids"] == ["a"]
        assert cov["coverage"]["MCP09"]["finding_ids"] == ["b"]
        assert cov["total_mcp_categories_with_findings"] == 2
        assert cov["framework_version"] == OWASP_MCP_TOP_10_DATA["framework_version"]


# ============================================================
# Detectors: positive and negative fixtures
# ============================================================

class TestMCP01Secrets:
    def test_positive(self, tmp_path):
        _write(tmp_path, "server.py",
               f'GITHUB_TOKEN = "{FAKE_GHP}"\n'
               f'api_key = "{FAKE_GENERIC}"\n'
               '-----BEGIN RSA PRIVATE KEY-----\n'
               # Phase 5 (1c): a header counts only when key material follows it
               + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj" + "AgEAAoIBAQC7VJTUt9Us8cKj\n")
        findings = detect_hardcoded_secrets(str(tmp_path))
        assert len(findings) == 3
        assert all(f.owasp_mcp == ["MCP01"] for f in findings)
        assert {f.line_number for f in findings} == {1, 2, 3}
        # The secret value must never be echoed
        for f in findings:
            blob = f.model_dump_json()
            assert FAKE_GHP not in blob and FAKE_GHP[4:12] not in blob
            assert FAKE_GENERIC not in blob and FAKE_GENERIC[:8] not in blob
        assert any("api_key" in f.description for f in findings)

    def test_negative(self, tmp_path):
        _write(tmp_path, "server.py",
               'import os\n'
               'api_key = os.environ["API_KEY"]\n'
               'api_key = "your-api-key-here-xxxxxxxxxxxx"\n'
               'TOKEN_URL = "https://github.com/login/oauth/access_token"\n'
               'TOKEN_ENV = "GITHUB_PERSONAL_ACCESS_TOKEN"\n'
               'secret_name = "my_secret_setting_name_long"\n')
        assert detect_hardcoded_secrets(str(tmp_path)) == []


class TestMCP04Unpinned:
    def test_positive(self, tmp_path):
        _write(tmp_path, "Dockerfile",
               "FROM python:3.12\nRUN pip install fastapi uvicorn\n")
        _write(tmp_path, "run.sh",
               "npx -y some-mcp-server /data\nuvx mcp-server-fetch\nnpm i tool@latest\n")
        _write(tmp_path, "examples/mcp.json", json.dumps(
            {"mcpServers": {"x": {"command": "npx", "args": ["-y", "@acme/mcp-server"]}}}))
        findings = detect_unpinned_installs(str(tmp_path))
        texts = " ".join(f.description for f in findings)
        assert len(findings) == 5
        assert all(f.owasp_mcp == ["MCP04"] for f in findings)
        assert "fastapi" in texts and "some-mcp-server" in texts
        assert "mcp-server-fetch" in texts and "@latest" in texts and "@acme/mcp-server" in texts

    def test_negative(self, tmp_path):
        _write(tmp_path, "Dockerfile",
               "FROM python:3.12\nRUN pip install -r requirements.txt\n"
               "RUN pip install --upgrade pip && pip install fastapi==0.115.0\n")
        _write(tmp_path, "run.sh",
               "npx -y some-mcp-server@1.2.3 /data\nuvx mcp-server-fetch==1.0.0\n")
        _write(tmp_path, "package.json", json.dumps({"scripts": {"build": "npx tsc"}}))
        _write(tmp_path, "examples/mcp.json", json.dumps(
            {"mcpServers": {"x": {"command": "npx", "args": ["-y", "@acme/mcp-server@2.0.1"]}}}))
        assert detect_unpinned_installs(str(tmp_path)) == []


class TestMCP07BindAll:
    def test_positive(self, tmp_path):
        _write(tmp_path, "server.py",
               "import uvicorn\nuvicorn.run(app, host=\"0.0.0.0\", port=8000)\n")
        _write(tmp_path, "index.js", "app.listen(3000, '0.0.0.0');\n")
        findings = detect_bind_all_interfaces(str(tmp_path))
        assert len(findings) == 2
        assert all(f.owasp_mcp == ["MCP07"] for f in findings)
        assert all(f.category == FindingCategory.TRANSPORT_SECURITY for f in findings)

    def test_negative(self, tmp_path):
        _write(tmp_path, "server.py",
               "uvicorn.run(app, host=\"127.0.0.1\", port=8000)\n# host='0.0.0.0'\n")
        _write(tmp_path, "index.js", "app.listen(3000, 'localhost');\n")
        assert detect_bind_all_interfaces(str(tmp_path)) == []


TOOL_SERVER_NO_LOG = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    return a + b
'''


class TestMCP08Logging:
    def test_positive(self, tmp_path):
        _write(tmp_path, "server.py", TOOL_SERVER_NO_LOG)
        findings = detect_missing_tool_logging(str(tmp_path))
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == FindingSeverity.INFO
        assert f.owasp_mcp == ["MCP08"]
        assert "low" in f.description.lower() and "confidence" in f.description.lower()

    def test_negative_with_logging(self, tmp_path):
        _write(tmp_path, "server.py", "import logging\n" + TOOL_SERVER_NO_LOG)
        assert detect_missing_tool_logging(str(tmp_path)) == []

    def test_negative_no_tools(self, tmp_path):
        _write(tmp_path, "util.py", "def helper():\n    return 1\n")
        assert detect_missing_tool_logging(str(tmp_path)) == []


class TestMCP10BroadExposure:
    def test_positive(self):
        tools = [
            MCPToolDefinition(name="dump_database", description="Returns rows"),
            MCPToolDefinition(name="listAllUsers", description="Users"),
            MCPToolDefinition(name="fetch", description="Return the entire history of messages"),
        ]
        resources = [MCPResourceDefinition(uri="db://export", name="export_all")]
        findings = detect_broad_data_exposure(tools, resources)
        assert len(findings) == 4
        assert all(f.owasp_mcp == ["MCP10"] for f in findings)
        assert all(f.severity == FindingSeverity.LOW for f in findings)
        assert all("gap" in f.description for f in findings)

    def test_negative(self):
        tools = [
            MCPToolDefinition(name="get_weather", description="Get weather for a city"),
            MCPToolDefinition(name="install_package", description="Install one package"),
            MCPToolDefinition(name="call_api", description="Call a single endpoint"),
            MCPToolDefinition(name="get_full_name", description="Look up a user's name"),
        ]
        assert detect_broad_data_exposure(tools, []) == []


class TestMCP05ToolSinks:
    def test_positive_python_tainted(self, tmp_path):
        _write(tmp_path, "server.py", '''import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def run(cmd: str) -> str:
    """Run a command"""
    full = f"bash -c {cmd}"
    return subprocess.run(full, shell=True, capture_output=True).stdout
''')
        findings = detect_tool_input_sinks(str(tmp_path))
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == FindingSeverity.CRITICAL
        assert f.owasp_mcp == ["MCP05"]
        assert f.category == FindingCategory.COMMAND_INJECTION
        assert "run" in f.title and f.line_number == 9

    def test_positive_python_untainted_is_high(self, tmp_path):
        _write(tmp_path, "server.py", '''import os

@server.call_tool()
async def handle(name, arguments):
    os.system("uptime")
''')
        findings = detect_tool_input_sinks(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.HIGH

    def test_positive_js(self, tmp_path):
        _write(tmp_path, "index.ts", '''import { execSync } from "child_process";
server.tool("run", "Run a command", { cmd: z.string() }, async ({ cmd }) => {
  const out = execSync(cmd);
  return { content: [{ type: "text", text: out.toString() }] };
});
''')
        findings = detect_tool_input_sinks(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].owasp_mcp == ["MCP05"]
        assert findings[0].line_number == 3

    def test_negative(self, tmp_path):
        _write(tmp_path, "server.py", '''import subprocess

def build():
    subprocess.run(["make"])   # not a tool

@mcp.tool()
def add(a: int, b: int) -> int:
    """Add"""
    return a + b
''')
        _write(tmp_path, "index.js", '''server.tool("match", "Regex", {}, async ({ s }) => {
  const m = /a+/.exec(s);
  return { content: [] };
});
''')
        assert detect_tool_input_sinks(str(tmp_path)) == []


# ============================================================
# Pipelines: static engine, local config, live scanner
# ============================================================

FIXTURE_SERVER = f'''import subprocess
import uvicorn
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture")
API_TOKEN = "{FAKE_GHP}"

@mcp.tool()
def run_command(cmd: str) -> str:
    """Run a shell command on the host"""
    return subprocess.run(cmd, shell=True, capture_output=True).stdout

@mcp.tool()
def dump_database(table: str) -> str:
    """Return every row"""
    return ""

if __name__ == "__main__":
    uvicorn.run(mcp, host="0.0.0.0", port=8000)
'''


class TestStaticScanPipeline:
    @pytest.mark.asyncio
    async def test_scan_stamps_owasp_mcp(self, tmp_path):
        src = tmp_path / "src"
        _write(src, "server.py", FIXTURE_SERVER)
        _write(src, "Dockerfile", "FROM python:3.12\nRUN pip install mcp uvicorn\n")
        _write(src, "package.json", json.dumps({"name": "x", "scripts": {"postinstall": "node x.js"}}))

        async def fake_clone(url):
            dest = tmp_path / "clone"
            shutil.copytree(src, dest)
            return str(dest)

        eng = MCPAnalysisEngine()
        with patch.object(eng, "_clone_repo", side_effect=fake_clone), \
             patch.object(eng, "_get_commit_sha", return_value=None), \
             patch.object(eng, "_check_known_vulnerable", new=AsyncMock(return_value=[])), \
             patch.object(eng, "_get_repo_health", new=AsyncMock(return_value=None)), \
             patch("app.analysis.engine.run_semgrep", return_value=[]):
            result = await eng.scan("https://github.com/acme/fixture-mcp")

        findings = result["findings"]
        assert findings
        for f in findings:
            if f.category != FindingCategory.METADATA:
                assert f.owasp_mcp, f"{f.id} ({f.category}) missing owasp_mcp"
            if f.category in CATEGORY_TO_ASI:
                assert f.owasp_asi, f"{f.id} ({f.category}) missing owasp_asi"

        refs = {r for f in findings for r in (f.owasp_mcp or [])}
        for expected in ("MCP01", "MCP04", "MCP05", "MCP07", "MCP08", "MCP10"):
            assert expected in refs, expected

        ids = {f.id for f in findings}
        assert any(i.startswith("mcp05_tool_sink") for i in ids)
        assert any(i.startswith("mcp01_secret") for i in ids)
        assert "mcp08_no_tool_logging" in ids

        # Both coverage matrices are present; ASI one unchanged in shape
        assert result["owasp_coverage"]["framework"].startswith("OWASP Top 10 for Agentic")
        mcp_cov = result["owasp_mcp_coverage"]
        assert list(mcp_cov["coverage"]) == ALL_IDS
        assert mcp_cov["coverage"]["MCP05"]["findings_count"] >= 1

        # Secret value never leaks into findings
        blob = json.dumps([f.model_dump() for f in findings
                           if f.id.startswith("mcp01_")], default=str)
        assert FAKE_GHP not in blob

    def test_existing_ast_findings_keep_asi_and_gain_mcp(self, tmp_path):
        from app.analysis.ast_scanner import scan_python_ast
        findings = scan_python_ast("import os\nos.system('ls')\n", "x.py")
        assert findings
        apply_owasp_mappings(findings)
        for f in findings:
            assert f.owasp_asi
            assert f.owasp_mcp


class TestLocalConfigPipeline:
    def test_local_config_findings_get_both_mappings(self):
        scanner = LocalConfigScanner()
        entry = MCPConfigEntry(
            name="gh", command="npx", args=["-y", "some-server"],
            env={"GITHUB_TOKEN": FAKE_GHP}, source_file="mcp.json",
        )
        findings = scanner.analyze_entry(entry)
        apply_owasp_mappings(findings)
        assert findings
        for f in findings:
            assert f.owasp_asi
            assert f.owasp_mcp
        cats = {f.category: f.owasp_mcp for f in findings}
        assert cats[FindingCategory.CREDENTIAL_THEFT] == ["MCP01"]
        assert cats[FindingCategory.SUPPLY_CHAIN] == ["MCP04"]

    def test_explicit_mcp09_preserved(self):
        f = Finding(id="shadow", severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.CONFIG_RISK, title="t", description="d",
                    owasp_mcp=[OwaspMcp.MCP09.value])
        apply_owasp_mappings([f])
        assert f.owasp_mcp == ["MCP09"]
        assert f.owasp_asi == CATEGORY_TO_ASI[FindingCategory.CONFIG_RISK]


class TestLiveScannerPipeline:
    def test_live_result_has_mcp_coverage_key(self):
        r = LiveScanResult(server_name="s", transport="stdio")
        assert "owasp_mcp_coverage" in r.to_dict()
        assert "owasp_coverage" in r.to_dict()


# ============================================================
# CLI
# ============================================================

class TestOwaspCLI:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def cli_app(self):
        from cli.axiom_cli import app
        return app

    def test_mcp_table_lists_all_ids(self, runner, cli_app):
        res = runner.invoke(cli_app, ["owasp", "--framework", "mcp"])
        assert res.exit_code == 0, res.output
        for mid in ALL_IDS:
            assert mid in res.output
        assert "STRONG" in res.output and "PARTIAL" in res.output and "GAP" in res.output

    def test_default_is_asi_only(self, runner, cli_app):
        res = runner.invoke(cli_app, ["owasp"])
        assert res.exit_code == 0, res.output
        # (the unchanged v0.4 ASI table collapses its ID column at 80 cols; the notes carry IDs)
        assert "Agentic" in res.output and "ASI10" in res.output
        assert "MCP01" not in res.output

    def test_json_default_unchanged(self, runner, cli_app):
        res = runner.invoke(cli_app, ["owasp", "-o", "json"])
        assert res.exit_code == 0
        data = json.loads(res.output)
        assert list(data) == [f"ASI{i:02d}" for i in range(1, 11)]

    def test_json_all_has_both(self, runner, cli_app):
        res = runner.invoke(cli_app, ["owasp", "--framework", "all", "-o", "json"])
        assert res.exit_code == 0
        data = json.loads(res.output)
        assert set(data) == {"asi", "mcp"}
        assert list(data["mcp"]) == ALL_IDS
        for v in data["mcp"].values():
            assert v["mcpguard_coverage"] in ("strong", "partial", "gap")
            if v["mcpguard_coverage"] != "strong":
                assert v["reason"]

    def test_json_mcp(self, runner, cli_app):
        res = runner.invoke(cli_app, ["owasp", "--framework", "mcp", "-o", "json"])
        assert res.exit_code == 0
        assert list(json.loads(res.output)) == ALL_IDS

    def test_bad_framework(self, runner, cli_app):
        res = runner.invoke(cli_app, ["owasp", "--framework", "bogus"])
        assert res.exit_code == 2
