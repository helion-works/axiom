"""
Scanning by package name (`axiom scan mcp-remote`, `npm:pkg`, `pypi:pkg`, `pkg@1.2.3`).
The name is resolved to its source repository, which is what gets scanned. No test here
contacts a registry or clones anything.
"""

import os
import sys
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analysis.engine import MCPAnalysisEngine  # noqa: E402
from app.analysis.package_resolver import PackageInfo, is_package_name, split_target  # noqa: E402


@pytest.fixture
def engine():
    return MCPAnalysisEngine()


class TestTargetParsing:
    @pytest.mark.parametrize("target,expected", [
        ("mcp-remote", (None, "mcp-remote", None)),
        ("mcp-remote@0.1.10", (None, "mcp-remote", "0.1.10")),
        ("@modelcontextprotocol/inspector", (None, "@modelcontextprotocol/inspector", None)),
        ("@modelcontextprotocol/inspector@0.13.0", (None, "@modelcontextprotocol/inspector", "0.13.0")),
        ("npm:my-mcp-package", ("npm", "my-mcp-package", None)),
        ("npm:@scope/pkg@1.0.0", ("npm", "@scope/pkg", "1.0.0")),
        ("pypi:mcp-server-fetch", ("pypi", "mcp-server-fetch", None)),
        ("mcp_server==1.2.3", (None, "mcp_server", "1.2.3")),
    ])
    def test_split_target(self, target, expected):
        assert split_target(target) == expected
        assert is_package_name(target) is True

    @pytest.mark.parametrize("target", [
        "https://github.com/user/repo", "./server", "../server", "/srv/server", "user/repo", "@scope-only", "-rf",
    ])
    def test_not_a_package_name(self, target):
        assert is_package_name(target) is False


def _resolved(requested=None, latest="0.16.7"):
    return PackageInfo(name="mcp-remote", ecosystem="npm", repo_url="https://github.com/example/mcp-remote",
                       version=latest, requested_version=requested)


async def _scan_by_name(engine, tmp_path, target, info):
    (tmp_path / "index.js").write_text("// nothing here\n", encoding="utf-8")
    with patch("app.analysis.package_resolver.resolve_package", new=AsyncMock(return_value=info)), \
            patch.object(engine, "_clone_repo", new=AsyncMock(return_value=str(tmp_path))), \
            patch.object(engine, "_get_repo_health", new=AsyncMock(return_value=None)), \
            patch("shutil.rmtree"):
        return await engine.scan(target, check_deps=False)


class TestScanByName:
    @pytest.mark.asyncio
    async def test_scan_by_package_name_runs(self, engine, tmp_path):
        # This used to raise ImportError before any scanning happened.
        result = await _scan_by_name(engine, tmp_path, "mcp-remote", _resolved())
        assert result["status"] == "completed"
        assert [f.id for f in result["findings"] if f.id.startswith("CVE-")] == []   # latest is patched

    @pytest.mark.asyncio
    async def test_requested_version_is_what_gets_matched(self, engine, tmp_path):
        result = await _scan_by_name(engine, tmp_path, "mcp-remote@0.1.10", _resolved(requested="0.1.10"))
        hits = [f for f in result["findings"] if f.id == "CVE-2025-6514"]
        assert len(hits) == 1 and "mcp-remote@0.1.10" in hits[0].title

    @pytest.mark.asyncio
    async def test_unknown_package_is_reported_not_raised(self, engine):
        with patch("app.analysis.package_resolver.resolve_package", new=AsyncMock(return_value=None)):
            result = await engine.scan("npm:no-such-package-anywhere", check_deps=False)
        assert result["status"] == "completed"
        assert [f.id for f in result["findings"]] == ["no_source"]

    @pytest.mark.asyncio
    async def test_resolver_error_is_reported_not_raised(self, engine):
        with patch("app.analysis.package_resolver.resolve_package", new=AsyncMock(side_effect=RuntimeError("offline"))):
            result = await engine.scan("mcp-remote", check_deps=False)
        assert [f.id for f in result["findings"]] == ["no_source"]
