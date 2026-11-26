"""
Tests for shadow MCP discovery (`axiom discover`, app/analysis/discovery.py).

All tests are offline: config files come from tests/fixtures/discover, the
home directory / platform / APPDATA are monkeypatched to point there, the
static engine and process listing are faked.
"""

import json
import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from app.analysis import discovery
from app.analysis.discovery import (
    REDACTED,
    Allowlist,
    DiscoveredServer,
    classify,
    discover_servers,
    infer_install_source,
    redact_args,
    redact_text,
    redact_url,
    result_to_json,
    result_to_markdown,
    run_static_scans,
)
from app.analysis.local_config import (
    MCP_CONFIG_PATHS,
    LocalConfigScanner,
    extract_server_configs,
    load_json_tolerant,
)
from app.models.schemas import FindingSeverity

FIX = Path(__file__).parent / "fixtures" / "discover"
ALLOWLIST = FIX / "approved_servers.json"
SECRETS = ["ghp_FAKEFAKEFAKE1234567890", "hunter2", "abc123def456"]
PLATFORM = {"macos": "darwin", "linux": "linux", "windows": "windows"}

BASE_EXPECTED = {
    ("claude_desktop", "github", "approved"),
    ("claude_desktop", "filesystem", "approved"),
    ("cursor", "remote-docs", "approved"),
    ("cursor", "fetch", "approved"),
    ("claude_code", "github", "unknown-version"),
    ("claude_code", "sketchy-scraper", "unapproved"),
    ("vscode", "time", "approved"),
}
EXPECTED = {
    "macos": BASE_EXPECTED,
    "windows": BASE_EXPECTED,
    "linux": BASE_EXPECTED | {("zed", "postgres", "approved")},
}


@pytest.fixture
def fake_home(monkeypatch, tmp_path):
    """Point HOME/USERPROFILE/APPDATA and platform detection at a fixture layout."""

    def _apply(layout: str) -> Path:
        home = FIX / layout / "home"
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
        monkeypatch.setenv("COLUMNS", "220")
        monkeypatch.setattr(discovery, "_platform_key", lambda: PLATFORM[layout])
        monkeypatch.chdir(tmp_path)  # empty cwd: no project-level configs
        return home

    return _apply


def _inventory(result):
    return {(s.client, s.server_name, s.classification) for s in result.servers}


def _assert_no_secrets(text: str):
    for secret in SECRETS:
        assert secret not in text, f"secret {secret!r} leaked"


# ============================================================
# Inventory per platform layout
# ============================================================

class TestInventory:
    @pytest.mark.parametrize("layout", ["macos", "linux", "windows"])
    def test_inventory_matches_layout(self, fake_home, layout):
        fake_home(layout)
        result = discover_servers(allowlist_path=str(ALLOWLIST))
        assert _inventory(result) == EXPECTED[layout]
        assert result.platform == PLATFORM[layout]
        assert result.summary["total"] == len(EXPECTED[layout])
        assert result.summary["unapproved"] == 1
        assert result.summary["unknown_version"] == 1
        assert result.config_errors == []

    @pytest.mark.parametrize("layout", ["macos", "linux", "windows"])
    def test_exactly_one_mcp09_finding(self, fake_home, layout):
        fake_home(layout)
        result = discover_servers(allowlist_path=str(ALLOWLIST))
        mcp09 = [f for f in result.findings if "MCP09" in (f.owasp_mcp or [])]
        assert len(mcp09) == 1
        f = mcp09[0]
        assert f.title == "Unapproved MCP server 'sketchy-scraper' configured in claude_code"
        assert f.severity == FindingSeverity.HIGH
        assert f.owasp_asi == ["ASI04"]
        assert f.owasp_mcp == ["MCP09"]
        assert f.file_path.endswith(".claude.json")

    def test_record_details(self, fake_home):
        fake_home("macos")
        result = discover_servers(allowlist_path=str(ALLOWLIST))
        by_key = {(s.client, s.server_name): s for s in result.servers}

        gh = by_key[("claude_desktop", "github")]
        assert gh.transport == "stdio"
        assert gh.install_source == "npm"
        assert gh.package == "@modelcontextprotocol/server-github"
        assert gh.version_pin == "2025.4.8"
        assert gh.env_var_names == ["GITHUB_TOKEN"]
        assert gh.allowlist_match == "github"

        remote = by_key[("cursor", "remote-docs")]
        assert remote.transport == "remote"
        assert remote.remote_type == "sse"
        assert remote.install_source == "remote_url"
        assert remote.url == f"https://{REDACTED}@example.com/sse?token={REDACTED}"
        assert remote.command is None

        fetch = by_key[("cursor", "fetch")]
        assert (fetch.install_source, fetch.package, fetch.version_pin) == ("pypi", "mcp-server-fetch", None)

        scraper = by_key[("claude_code", "sketchy-scraper")]
        assert scraper.scope == "project"
        assert scraper.project == "/Users/demo/work/app"
        assert scraper.version_pin == "0.0.1"

        unpinned = by_key[("claude_code", "github")]
        assert unpinned.version_pin is None
        assert unpinned.classification == "unknown-version"

        time_srv = by_key[("vscode", "time")]
        assert time_srv.version_pin == "0.6.2"

    def test_no_allowlist_means_unchecked(self, fake_home):
        fake_home("windows")
        result = discover_servers()
        assert {s.classification for s in result.servers} == {"unchecked"}
        assert result.findings == []
        assert result.allowlist is None

    def test_inline_allowlist(self, fake_home):
        fake_home("macos")
        allow = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
        result = discover_servers(allowlist=allow)
        assert result.allowlist == "inline"
        assert result.summary["unapproved"] == 1

    def test_project_level_config(self, fake_home, monkeypatch):
        fake_home("macos")
        result = discover_servers(cwd=str(FIX / "project"))
        proj = [s for s in result.servers if s.config_path.endswith(".mcp.json")]
        assert len(proj) == 1
        assert proj[0].client == "claude_code"
        assert proj[0].scope == "project"

    def test_custom_paths_only(self, fake_home):
        fake_home("macos")
        cursor = FIX / "macos" / "home" / ".cursor" / "mcp.json"
        result = discover_servers(custom_paths=[str(cursor)], include_defaults=False)
        assert {s.server_name for s in result.servers} == {"remote-docs", "fetch"}
        assert all(s.client == "cursor" and s.scope == "custom" for s in result.servers)

    def test_bad_allowlist_raises(self, tmp_path):
        bad = tmp_path / "allow.json"
        bad.write_text(json.dumps({"version": 2, "servers": []}))
        with pytest.raises(ValueError):
            discover_servers(allowlist_path=str(bad), include_defaults=False)


# ============================================================
# Redaction
# ============================================================

class TestRedaction:
    @pytest.mark.parametrize("layout", ["macos", "linux", "windows"])
    def test_result_json_and_logs_have_no_secrets(self, fake_home, caplog, monkeypatch, layout):
        fake_home(layout)
        monkeypatch.setattr(logging.getLogger("axiom"), "propagate", True)
        with caplog.at_level(logging.DEBUG, logger="axiom"):
            result = discover_servers(allowlist_path=str(ALLOWLIST), scan=True)
        assert "MCP discovery complete" in caplog.text
        assert "remote-docs" in caplog.text  # per-server debug lines were captured
        _assert_no_secrets(caplog.text)
        _assert_no_secrets(result_to_json(result))
        _assert_no_secrets(result.model_dump_json())
        _assert_no_secrets(result_to_markdown(result))
        # --scan merged the config checks, and they flag the hardcoded token by prefix only
        assert any("hardcoded" in f.title.lower() for f in result.findings)
        # every merged config finding carries both OWASP mappings
        assert result.findings and all(f.owasp_asi and f.owasp_mcp for f in result.findings)

    @pytest.mark.parametrize("fmt", ["table", "json", "md"])
    def test_cli_output_has_no_secrets(self, fake_home, fmt):
        from cli.axiom_cli import app
        fake_home("macos")
        res = CliRunner().invoke(app, ["discover", "--format", fmt, "--scan", "--offline"])
        assert res.exit_code == 0, res.output
        assert "sketchy-scraper" in res.output
        _assert_no_secrets(res.output)

    def test_redact_url(self):
        out = redact_url("https://user:hunter2@example.com/sse?token=abc123def456&page=2#access_token=zz")
        assert out == f"https://{REDACTED}@example.com/sse?token={REDACTED}&page=2#access_token={REDACTED}"

    def test_redact_args(self):
        args = ["--api-key", "abcd", "--token=xyz", "API_KEY=foo", "-y",
                "Authorization: Bearer abcdefgh1234", "AKIAABCDEFGHIJKLMNOP",
                "xoxb-1234567890-abcdef", "sk-abcdefghijklmnop1234",
                "@modelcontextprotocol/server-filesystem", "/tmp"]
        out = redact_args(args)
        assert out == ["--api-key", REDACTED, f"--token={REDACTED}", f"API_KEY={REDACTED}", "-y",
                       f"Authorization: Bearer {REDACTED}", REDACTED, REDACTED, REDACTED,
                       "@modelcontextprotocol/server-filesystem", "/tmp"]

    def test_high_entropy_blob_redacted_but_package_names_kept(self):
        assert redact_text("a1b2c3d4e5f6A7B8C9D0e1f2a3b4c5d6e7f8") == REDACTED
        assert redact_text("mcp-server-a-very-long-package-name-here") == "mcp-server-a-very-long-package-name-here"


# ============================================================
# Install source inference & allowlist semantics
# ============================================================

class TestInference:
    @pytest.mark.parametrize("command,args,url,expected", [
        ("npx", ["-y", "@scope/pkg@1.2.3"], None, ("npm", "@scope/pkg", "1.2.3")),
        ("npx.cmd", ["-y", "some-mcp@latest"], None, ("npm", "some-mcp", None)),
        ("uvx", ["mcp-server-fetch==1.0.0"], None, ("pypi", "mcp-server-fetch", "1.0.0")),
        ("uvx", ["--from", "mcp-x@0.3", "mcp-x"], None, ("pypi", "mcp-x", "0.3")),
        ("docker", ["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/org/mcp:v1"], None,
         ("container", "ghcr.io/org/mcp", "v1")),
        ("node", ["/opt/server/index.js"], None, ("local_path", None, None)),
        ("/usr/local/bin/my-mcp", [], None, ("local_path", None, None)),
        ("python", ["-m", "something"], None, ("unknown", None, None)),
        (None, [], "https://x.example/mcp", ("remote_url", None, None)),
    ])
    def test_infer_install_source(self, command, args, url, expected):
        assert infer_install_source(command, args, url) == expected

    def test_name_match_with_conflicting_package_is_unapproved(self):
        allow = Allowlist.model_validate({"version": 1, "servers": [
            {"name": "github", "package": "@modelcontextprotocol/server-github"}]})
        srv = DiscoveredServer(client="cursor", config_path="x", server_name="github",
                               install_source="npm", package="evil-github-mcp")
        classify(srv, allow)
        assert srv.classification == "unapproved"

    def test_package_match_with_pinned_version(self):
        allow = Allowlist.model_validate({"version": 1, "servers": [
            {"name": "gh", "package": "@modelcontextprotocol/server-github", "version": "1.0.0"}]})
        srv = DiscoveredServer(client="cursor", config_path="x", server_name="other-name",
                               install_source="npm", package="@modelcontextprotocol/server-github",
                               version_pin="1.0.0")
        classify(srv, allow)
        assert srv.classification == "approved"
        srv.version_pin = "0.9.0"
        classify(srv, allow)
        assert srv.classification == "unknown-version"


# ============================================================
# local_config compatibility & tolerant parsing
# ============================================================

class TestLocalConfigCompat:
    def test_mcp_config_paths_loaded_from_json(self):
        for plat in ("darwin", "linux", "windows"):
            paths = MCP_CONFIG_PATHS[plat]
            for key in ("claude_desktop", "cursor", "windsurf", "vscode_settings", "continue",
                        "claude_code", "vscode_user_mcp", "cline", "zed", "gemini_cli"):
                assert key in paths, (plat, key)

    def test_parse_claude_code_user_file_includes_projects(self):
        path = FIX / "macos" / "home" / ".claude.json"
        names = [e.name for e in LocalConfigScanner().parse_config_file(str(path))]
        assert names == ["github", "sketchy-scraper"]

    def test_parse_vscode_servers_key_and_remote_entries(self):
        scanner = LocalConfigScanner()
        vs = scanner.parse_config_file(str(FIX / "linux" / "home" / ".config" / "Code" / "User" / "mcp.json"))
        assert [e.name for e in vs] == ["time"]
        cur = scanner.parse_config_file(str(FIX / "linux" / "home" / ".cursor" / "mcp.json"))
        remote = [e for e in cur if e.name == "remote-docs"][0]
        assert remote.transport.value == "sse" and remote.command == ""

    def test_zed_jsonc_context_servers(self):
        data = load_json_tolerant(str(FIX / "linux" / "home" / ".config" / "zed" / "settings.json"))
        servers = extract_server_configs(data)
        assert [(n, c["command"]) for n, c, _ in servers] == [("postgres", "npx")]


# ============================================================
# Processes, --scan static engine, CLI exit codes, REST
# ============================================================

class TestProcessesAndScan:
    def test_process_detection_with_fake_listing(self, fake_home, monkeypatch):
        fake_home("macos")
        fake = [
            (101, "node", "npx -y @modelcontextprotocol/server-github --token=ghp_FAKEFAKEFAKE1234567890"),
            (102, "python", "python -m mcp_server_time"),
            (103, "bash", "bash -l"),
            (104, "python", "python -m axiom discover"),
        ]
        monkeypatch.setattr(discovery, "_list_processes", lambda: (fake, None))
        result = discover_servers(include_processes=True)
        pids = {p.pid: p for p in result.processes}
        assert set(pids) == {101, 102}
        assert pids[101].matches_server == "github"
        _assert_no_secrets(result_to_json(result))
        assert any("Port probing" in n for n in result.notes)

    async def test_static_scans_use_engine_without_network(self, fake_home):
        fake_home("macos")
        result = discover_servers(allowlist_path=str(ALLOWLIST))
        calls = []

        class FakeEngine:
            async def scan(self, target, target_url=None):
                calls.append((target, target_url))
                from app.models.schemas import Finding, FindingCategory, RiskLevel
                return {
                    "status": "completed", "risk_score": 10.0, "risk_level": RiskLevel.LOW,
                    "findings": [Finding(id=f"f_{target}", severity=FindingSeverity.LOW,
                                         category=FindingCategory.CODE_EXECUTION, title="demo",
                                         description="demo")],
                }

        before = len(result.findings)
        await run_static_scans(result, scan_engine=FakeEngine())
        targets = {t for t, _ in calls}
        assert "@modelcontextprotocol/server-github" in targets
        assert "mcp-server-fetch" in targets
        assert "totally-legit-scraper-mcp" in targets
        assert len(calls) == len(set(calls))  # each package scanned once
        assert len(result.findings) == before + len(calls)
        # static scan findings are stamped with both OWASP mappings
        merged = result.findings[before:]
        assert all(f.owasp_asi == ["ASI05"] and f.owasp_mcp for f in merged)
        assert all(s.status == "completed" for s in result.static_scans)
        assert result.summary["findings"] == len(result.findings)


class TestCLI:
    def test_exit_code_with_allowlist(self, fake_home):
        from cli.axiom_cli import app
        fake_home("linux")
        res = CliRunner().invoke(app, ["discover", "--allowlist", str(ALLOWLIST), "--format", "json"])
        assert res.exit_code == 1
        data = json.loads(res.output)
        assert data["summary"]["unapproved"] == 1
        assert len(data["servers"]) == len(EXPECTED["linux"])

    def test_markdown_and_table(self, fake_home):
        from cli.axiom_cli import app
        fake_home("windows")
        md = CliRunner().invoke(app, ["discover", "--format", "md"])
        assert md.exit_code == 0
        assert "| Client | Server |" in md.output
        table = CliRunner().invoke(app, ["discover", "--allowlist", str(ALLOWLIST)])
        assert table.exit_code == 1
        assert "unapproved" in table.output

    def test_no_defaults_with_config(self, fake_home):
        from cli.axiom_cli import app
        fake_home("macos")
        cfg = FIX / "macos" / "home" / ".cursor" / "mcp.json"
        res = CliRunner().invoke(app, ["discover", "--no-defaults", "--config", str(cfg), "-f", "json"])
        assert res.exit_code == 0
        assert {s["server_name"] for s in json.loads(res.output)["servers"]} == {"remote-docs", "fetch"}

    def test_bad_format(self, fake_home):
        from cli.axiom_cli import app
        fake_home("macos")
        res = CliRunner().invoke(app, ["discover", "--format", "xml"])
        assert res.exit_code == 2


class TestDiscoverAPI:
    @pytest.fixture
    def client(self):
        from main import app
        return TestClient(app)

    def test_discover_endpoint(self, client, fake_home):
        home = fake_home("macos")
        paths = [
            str(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"),
            str(home / ".cursor" / "mcp.json"),
            str(home / ".claude.json"),
            str(home / "Library" / "Application Support" / "Code" / "User" / "mcp.json"),
        ]
        allow = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
        resp = client.post("/api/v1/discover", json={"config_paths": paths, "allowlist": allow})
        assert resp.status_code == 200
        data = resp.json()
        assert {(s["client"], s["server_name"], s["classification"]) for s in data["servers"]} == BASE_EXPECTED
        assert data["processes"] == []
        assert sum(1 for f in data["findings"] if "MCP09" in (f.get("owasp_mcp") or [])) == 1
        _assert_no_secrets(resp.text)

    def test_discover_endpoint_bad_allowlist(self, client, fake_home):
        fake_home("macos")
        resp = client.post("/api/v1/discover", json={"config_paths": [], "allowlist": {"version": 9}})
        assert resp.status_code == 400
