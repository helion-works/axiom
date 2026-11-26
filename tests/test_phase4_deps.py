"""
Phase 4 / Part C — dependency advisories are version-aware and advisory-rated.

The reference `fetch` server locks mcp==2.3.0 and was reported with 16 `mcp` advisories
(all for 1.x) because OSV was queried without a version. These tests pin the fix.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analysis import dependencies as deps_mod  # noqa: E402
from app.analysis.dependencies import advisory_severity, extract_dependencies, osv_findings, read_lockfiles  # noqa: E402
from app.models.schemas import DependencyInfo, FindingSeverity  # noqa: E402


class TestManifestsAndLockfiles:
    def test_pyproject_plus_uv_lock(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = [\n    "mcp>=2.3,<3",\n    "requests==2.32.3",\n]\n', encoding="utf-8")
        (tmp_path / "uv.lock").write_text('[[package]]\nname = "mcp"\nversion = "2.3.0"\n\n[[package]]\nname = "anyio"\nversion = "4.9.0"\n', encoding="utf-8")
        deps = {d.name: d for d in extract_dependencies(str(tmp_path))}
        assert deps["mcp"].version == "2.3.0" and deps["mcp"].direct and "lock" in deps["mcp"].source
        assert deps["requests"].version == "2.32.3"
        assert deps["anyio"].version == "4.9.0" and not deps["anyio"].direct

    def test_package_json_plus_lock_v3(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"zod": "^3.23.8", "express": "*"}}), encoding="utf-8")
        (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "x"}, "node_modules/zod": {"version": "3.23.8"}, "node_modules/express": {"version": "4.21.2"},
            "node_modules/express/node_modules/qs": {"version": "6.13.0"}}}), encoding="utf-8")
        deps = {d.name: d for d in extract_dependencies(str(tmp_path))}
        assert deps["zod"].version == "3.23.8" and deps["express"].version == "4.21.2"
        assert deps["qs"].version == "6.13.0" and not deps["qs"].direct

    def test_unpinned_without_lock_is_unknown(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("gitpython>=3.1\nmcp\n", encoding="utf-8")
        deps = {d.name: d for d in extract_dependencies(str(tmp_path))}
        assert deps["gitpython"].version == "unknown" and deps["mcp"].version == "unknown"

    def test_read_lockfiles_pipfile(self, tmp_path):
        (tmp_path / "Pipfile.lock").write_text(json.dumps({"default": {"requests": {"version": "==2.31.0"}}}), encoding="utf-8")
        assert read_lockfiles(str(tmp_path)) == {("pypi", "requests"): "2.31.0"}


class TestAdvisorySeverity:
    def test_labels(self):
        assert advisory_severity({"database_specific": {"severity": "CRITICAL"}})[0] == FindingSeverity.HIGH   # capped
        assert advisory_severity({"database_specific": {"severity": "HIGH"}})[0] == FindingSeverity.HIGH
        assert advisory_severity({"database_specific": {"severity": "MODERATE"}})[0] == FindingSeverity.MEDIUM
        assert advisory_severity({"database_specific": {"severity": "LOW"}})[0] == FindingSeverity.LOW
        assert advisory_severity({})[0] == FindingSeverity.MEDIUM


class _FakeResp:
    def __init__(self, payload):
        self.status_code = 200
        self._payload = payload

    def json(self):
        return self._payload


class _FakeClient:
    sent = []

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None, timeout=None):
        _FakeClient.sent.append(json)
        results = []
        for q in json["queries"]:
            if q["package"]["name"] == "mcp" and q.get("version") == "2.3.0":
                results.append({"vulns": []})                       # fixed version: nothing
            elif q["package"]["name"] == "mcp":
                results.append({"vulns": [{"id": f"GHSA-old-{i}", "summary": "1.x issue",
                                           "database_specific": {"severity": "HIGH"}} for i in range(16)]})
            elif q["package"]["name"] == "gitpython":
                results.append({"vulns": [{"id": "GHSA-git-1", "summary": "path traversal",
                                           "database_specific": {"severity": "HIGH"}}]})
            else:
                results.append({"vulns": []})
        return _FakeResp({"results": results})


@pytest.fixture
def fake_httpx(monkeypatch, tmp_path):
    import types
    import app.analysis.scan_history as sh
    monkeypatch.setattr(sh, "MCPGUARD_DIR", str(tmp_path))
    fake = types.SimpleNamespace(AsyncClient=_FakeClient)
    monkeypatch.setitem(sys.modules, "httpx", fake)
    _FakeClient.sent.clear()
    return fake


class TestOsvLookup:
    @pytest.mark.asyncio
    async def test_version_is_sent_and_fixed_versions_are_clean(self, fake_httpx):
        deps = [DependencyInfo(name="mcp", version="2.3.0", ecosystem="pypi", direct=True, source="uv.lock")]
        out = await osv_findings(deps, "https://osv.invalid/v1", cache_enabled=False)
        assert out == []
        assert _FakeClient.sent[0]["queries"][0] == {"package": {"name": "mcp", "ecosystem": "PyPI"}, "version": "2.3.0"}

    @pytest.mark.asyncio
    async def test_unknown_version_is_one_info_note(self, fake_httpx):
        deps = [DependencyInfo(name="mcp", version="unknown", ecosystem="pypi", direct=True, source="requirements.txt")]
        out = await osv_findings(deps, "https://osv.invalid/v1", cache_enabled=False)
        assert len(out) == 1 and out[0].severity == FindingSeverity.INFO and "16 advisories" in out[0].title

    @pytest.mark.asyncio
    async def test_direct_high_transitive_medium(self, fake_httpx):
        deps = [DependencyInfo(name="gitpython", version="3.1.0", ecosystem="pypi", direct=True, source="pyproject.toml"),
                DependencyInfo(name="gitpython", version="3.1.0", ecosystem="pypi", direct=False, source="lockfile")]
        out = await osv_findings(deps, "https://osv.invalid/v1", cache_enabled=False)
        assert [f.severity for f in out] == [FindingSeverity.HIGH, FindingSeverity.MEDIUM]
        assert out[0].cve_id == "GHSA-git-1"

    @pytest.mark.asyncio
    async def test_cache_prevents_second_query(self, fake_httpx):
        deps = [DependencyInfo(name="gitpython", version="3.1.0", ecosystem="pypi", direct=True)]
        await osv_findings(deps, "https://osv.invalid/v1")
        n = len(_FakeClient.sent)
        deps2 = [DependencyInfo(name="gitpython", version="3.1.0", ecosystem="pypi", direct=True)]
        out = await osv_findings(deps2, "https://osv.invalid/v1")
        assert len(_FakeClient.sent) == n and out and out[0].cve_id == "GHSA-git-1"
